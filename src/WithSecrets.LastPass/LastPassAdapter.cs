using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace WithSecrets.LastPass;

/// <summary>
/// The authority supplies the trusted lpass path, unlock-session cancellation token and configuration decryptor.
/// lpass is a POSIX CLI, so Windows authorities fail closed: the CLI is never launched through WSL or a wrapper
/// that would move the master password across a second trust boundary.
/// </summary>
public sealed class LastPassAdapter(
    string trustedExecutablePath,
    Func<CancellationToken> getAuthorityLockToken,
    Func<string, CancellationToken, ValueTask<string?>> decryptConfiguration,
    Func<bool>? isPlatformSupported = null) : ProviderAdapter<LastPassConfiguration>
{
    public const string ProviderType = "lastpass";
    public const string AdapterVersion = "1.0";

    private static readonly UTF8Encoding StrictUtf8 = new(false, true);
    private static readonly string[] ValueFields = ["password", "username", "url", "note"];
    private readonly object _gate = new();
    private readonly CancellationTokenSource _lifetime = new();
    private readonly Func<bool> _platformSupported = isPlatformSupported ?? (() => OperatingSystem.IsLinux() || OperatingSystem.IsMacOS());
    private LastPassConfiguration? _active;
    private IAdapterStatusReporter? _status;
    private CancellationTokenSource? _connection;
    private LastPassCli? _cli;
    private Task _probe = Task.CompletedTask;
    private Task _cleanup = Task.CompletedTask;

    protected override Task InitializeAsync(LastPassConfiguration configuration, AdapterInitializationContext context, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        lock (_gate)
        {
            _status = context.StatusReporter;
            _status.Report(new LifecycleChangedEvent(AdapterLifecycleState.Ready));
            StartProbe(configuration, invalidate: false);
        }

        return Task.CompletedTask;
    }

    protected override Task UpdateConfigurationAsync(LastPassConfiguration configuration, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        lock (_gate)
        {
            if (_active is not null)
            {
                StartProbe(configuration, invalidate: true);
            }
        }

        return Task.CompletedTask;
    }

    public override async Task ShutdownAsync(CancellationToken cancellationToken)
    {
        Task pending;
        lock (_gate)
        {
            _lifetime.Cancel();
            RetireConnection();
            _active = null;
            _status = null;
            pending = _cleanup;
        }

        await pending.WaitAsync(cancellationToken).ConfigureAwait(false);
    }

    protected override async Task<IReadOnlyList<ProviderValidationIssue>> ValidateConfigurationAsync(
        LastPassConfiguration configuration, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        IReadOnlyList<ProviderValidationIssue> issues = StaticValidate(configuration);
        if (issues.Count != 0)
        {
            return issues;
        }

        return await ValidateWithCliAsync(configuration, cancellationToken, async (cli, password, token) =>
        {
            await cli.CheckConnectionAsync(password, token).ConfigureAwait(false);
            return issues;
        }).ConfigureAwait(false);
    }

    protected override async Task<IReadOnlyList<ProviderValidationIssue>> ValidateMountAsync(
        LastPassConfiguration configuration, string basePath, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (!TryPath(basePath, out string[] segments))
        {
            return [new("Use a LastPass account ID and field path.", ValidationSeverity.Error, "basePath")];
        }

        List<ProviderValidationIssue> issues = [.. StaticValidate(configuration)];
        if (issues.Count != 0)
        {
            return issues;
        }

        return await ValidateWithCliAsync(configuration, cancellationToken, async (cli, password, token) =>
        {
            try
            {
                Dictionary<string, string> fields = await ShowAsync(cli, segments[0], password, token).ConfigureAwait(false);
                if (segments.Length == 2 && !fields.ContainsKey(segments[1]))
                {
                    issues.Add(new("The LastPass item does not contain that field.", ValidationSeverity.Error, "basePath"));
                }
            }
            catch (ProviderAdapterException error) when (error.Kind == ProviderErrorKind.SecretNotFound)
            {
                issues.Add(new("The LastPass account item was not found.", ValidationSeverity.Error, "basePath"));
            }

            return issues;
        }).ConfigureAwait(false);
    }

    public override async Task<IReadOnlyList<ProviderSecretResult>> RetrieveSecretsAsync(
        IReadOnlyList<ProviderSecretRequest> requests, CancellationToken cancellationToken)
    {
        LastPassConfiguration? configuration = Snapshot();
        try
        {
            return await RetrieveAsync(requests, cancellationToken).ConfigureAwait(false);
        }
        catch (ProviderAdapterException error)
        {
            ReportFailure(configuration, error);
            throw;
        }
    }

    public override async Task<ListSecretsResult> ListSecretsAsync(ListSecretsRequest request, CancellationToken cancellationToken)
    {
        LastPassConfiguration? configuration = Snapshot();
        try
        {
            return await ListAsync(request, cancellationToken).ConfigureAwait(false);
        }
        catch (ProviderAdapterException error)
        {
            ReportFailure(configuration, error);
            throw;
        }
    }

    private LastPassConfiguration? Snapshot()
    {
        lock (_gate)
        {
            return _active;
        }
    }

    /// <summary>A failed retrieval or listing is visible as health, unless the configuration has been replaced meanwhile. An unlock or secret-level failure says nothing about the provider.</summary>
    private void ReportFailure(LastPassConfiguration? configuration, ProviderAdapterException error)
    {
        if (configuration is null || !ProviderPolicy.SaysAboutProvider(error.Kind))
        {
            return;
        }

        lock (_gate)
        {
            if (ReferenceEquals(_active, configuration))
            {
                _status?.Report(new HealthChangedEvent(ProviderPolicy.HealthFor(error.Kind)));
            }
        }
    }

    private async Task<IReadOnlyList<ProviderSecretResult>> RetrieveAsync(
        IReadOnlyList<ProviderSecretRequest> requests, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (requests.Count == 0)
        {
            return [];
        }

        (LastPassConfiguration configuration, LastPassCli cli, CancellationToken configurationToken) = Active();
        using var operation = BeginOperation(cancellationToken, configurationToken);
        cancellationToken = operation.Token;
        string password = await ResolvePasswordAsync(configuration, cancellationToken).ConfigureAwait(false);
        var parsed = requests.Select(request => (Request: request, Path: TryPath(request.Path, out string[] path) && path.Length == 2 ? path : null)).ToArray();
        List<ProviderSecretResult> results = [];
        List<ProviderAdapterException> failures = [];
        try
        {
            foreach (var group in parsed.GroupBy(entry => entry.Path is { } path ? path[0] : null))
            {
                cancellationToken.ThrowIfCancellationRequested();
                if (group.Key is null)
                {
                    results.AddRange(group.Select(entry => new ProviderSecretResult(entry.Request.RequestId, null, ProviderErrorKind.InvalidConfiguration)));
                    continue;
                }

                string account = group.Key;
                try
                {
                    results.AddRange(await cli.ReadJsonAsync(ShowArguments(account), password, root =>
                    {
                        Dictionary<string, string> fields = ReadAccount(root, account);
                        return group.Select(entry =>
                        {
                            Guid id = entry.Request.RequestId;
                            if (!fields.TryGetValue(entry.Path![1], out string? value))
                            {
                                return new ProviderSecretResult(id, null, ProviderErrorKind.SecretNotFound);
                            }

                            try
                            {
                                byte[] bytes = StrictUtf8.GetBytes(value);
                                return new ProviderSecretResult(id, new RetrieveSecretResult(bytes));
                            }
                            catch (EncoderFallbackException)
                            {
                                return new ProviderSecretResult(id, null, ProviderErrorKind.InvalidResponse);
                            }
                        }).ToArray();
                    }, cancellationToken).ConfigureAwait(false));
                }
                catch (ProviderAdapterException error) when (error.Kind is not (ProviderErrorKind.InvalidConfiguration or ProviderErrorKind.AuthenticationFailed or ProviderErrorKind.InteractionRequired))
                {
                    failures.Add(error);
                    results.AddRange(group.Select(entry => new ProviderSecretResult(entry.Request.RequestId, null, error.Kind, error.ProviderCode, error.RetryAfter)));
                }
            }

            cancellationToken.ThrowIfCancellationRequested();
            string[] removed = results.Where(result => result.ErrorKind == ProviderErrorKind.SecretNotFound)
                .Select(result => result.RequestId)
                .Join(requests, id => id, request => request.RequestId, (_, request) => request.Path)
                .Distinct(StringComparer.Ordinal)
                .ToArray();
            if (removed.Length != 0)
            {
                lock (_gate)
                {
                    if (ReferenceEquals(_active, configuration))
                    {
                        _status?.Report(new InvalidateProviderDataEvent(ExternalSecretIds: removed));
                    }
                }
            }

            cancellationToken.ThrowIfCancellationRequested();
            ProviderAdapterException? first = failures.FirstOrDefault(error => ProviderPolicy.SaysAboutProvider(error.Kind));
            if (first is not null)
            {
                ReportFailure(configuration, first);
            }
            else if (results.Any(result => result.Secret is not null || result.ErrorKind == ProviderErrorKind.SecretNotFound))
            {
                ReportHealthy(configuration, cancellationToken);
            }

            return results;
        }
        catch
        {
            foreach (ProviderSecretResult result in results)
            {
                if (result.Secret is { } secret)
                {
                    CryptographicOperations.ZeroMemory(secret.Value);
                }
            }

            throw;
        }
    }

    private async Task<ListSecretsResult> ListAsync(ListSecretsRequest request, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (request.ContinuationToken is not null || !ValidId(request.Path)
            || (request.Filter is not null && !TryFieldName(request.Filter, out _)))
        {
            throw new ProviderAdapterException(ProviderErrorKind.InvalidConfiguration, "Invalid LastPass listing scope.");
        }

        (LastPassConfiguration configuration, LastPassCli cli, CancellationToken configurationToken) = Active();
        using var operation = BeginOperation(cancellationToken, configurationToken);
        cancellationToken = operation.Token;
        string password = await ResolvePasswordAsync(configuration, cancellationToken).ConfigureAwait(false);
        Dictionary<string, string> fields;
        try
        {
            fields = await ShowAsync(cli, request.Path, password, cancellationToken).ConfigureAwait(false);
        }
        catch (ProviderAdapterException error) when (error.Kind == ProviderErrorKind.SecretNotFound)
        {
            ReportHealthy(configuration, cancellationToken);
            return new([], null, IsComplete: true);
        }
        List<ProviderSecretInfo> secrets = [];
        foreach (string leaf in fields.Keys.Order(StringComparer.Ordinal))
        {
            if (request.Filter is null || request.Filter == leaf)
            {
                secrets.Add(new(leaf, request.Path + "/" + leaf, null));
            }
        }

        ReportHealthy(configuration, cancellationToken);
        return new(secrets, null, IsComplete: true);
    }

    private void ReportHealthy(LastPassConfiguration configuration, CancellationToken cancellationToken)
    {
        lock (_gate)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (ReferenceEquals(_active, configuration))
            {
                _status?.Report(new HealthChangedEvent(AdapterHealthState.Healthy));
            }
        }
    }

    private void StartProbe(LastPassConfiguration configuration, bool invalidate)
    {
        RetireConnection();
        LastPassCli? cli = StaticValidate(configuration).Count == 0
            ? new LastPassCli(trustedExecutablePath, configuration.Username)
            : null;
        _cli = cli;
        _active = configuration;
        _status!.Report(new HealthChangedEvent(AdapterHealthState.Initializing));
        if (invalidate)
        {
            // A new account or credential may resolve the same instance to a different vault.
            _status.Report(new InvalidateProviderDataEvent(InvalidateEntireProviderInstance: true));
        }

        _connection = new CancellationTokenSource();
        CancellationToken token = _connection.Token;
        _probe = Task.Run(() => ProbeAsync(configuration, cli, token));
    }

    private void RetireConnection()
    {
        _connection?.Cancel();
        _connection?.Dispose();
        _connection = null;
        if (_cli is not null)
        {
            _cleanup = Task.WhenAll(_cleanup, _probe, _cli.DisposeAsync().AsTask());
            _cli = null;
        }
        else
        {
            _cleanup = Task.WhenAll(_cleanup, _probe);
        }
        _probe = Task.CompletedTask;
    }

    private async Task ProbeAsync(LastPassConfiguration configuration, LastPassCli? cli, CancellationToken token)
    {
        AdapterHealthState health;
        try
        {
            health = AdapterHealthState.Misconfigured;
            if (cli is not null)
            {
                using var operation = BeginOperation(token);
                string password = await ResolvePasswordAsync(configuration, operation.Token).ConfigureAwait(false);
                await cli.CheckConnectionAsync(password, operation.Token).ConfigureAwait(false);
                health = AdapterHealthState.Healthy;
            }
        }
        catch (OperationCanceledException) when (token.IsCancellationRequested)
        {
            return;
        }
        catch (OperationCanceledException)
        {
            health = AdapterHealthState.Degraded;
        }
        catch (ProviderAdapterException error)
        {
            health = ProviderPolicy.HealthFor(error.Kind);
        }

        lock (_gate)
        {
            if (!token.IsCancellationRequested)
            {
                _status?.Report(new HealthChangedEvent(health));
            }
        }
    }

    private IReadOnlyList<ProviderValidationIssue> StaticValidate(LastPassConfiguration configuration)
    {
        List<ProviderValidationIssue> issues = [];
        if (!_platformSupported())
        {
            issues.Add(new("LastPass CLI is available on Linux and macOS only; a Windows authority cannot run it.", ValidationSeverity.Error));
        }

        if (!ValidExecutable(trustedExecutablePath))
        {
            issues.Add(new("Install lpass at the authority-configured executable path.", ValidationSeverity.Error));
        }

        if (!IsUsername(configuration.Username))
        {
            issues.Add(new("Specify the LastPass account username.", ValidationSeverity.Error, "username"));
        }

        if (!IsEncryptedConfiguration(configuration.EncryptedConfiguration))
        {
            issues.Add(new("Supply an encrypted LastPass configuration.", ValidationSeverity.Error, "encryptedConfiguration"));
        }

        return issues;
    }

    private (LastPassConfiguration Configuration, LastPassCli Cli, CancellationToken CancellationToken) Active()
    {
        lock (_gate)
        {
            if (_active is null || _connection is null)
            {
                throw new ProviderAdapterException(ProviderErrorKind.InvalidConfiguration, "The LastPass adapter is inactive.");
            }

            if (!_platformSupported())
            {
                throw new ProviderAdapterException(ProviderErrorKind.Unavailable, "LastPass CLI is available on Linux and macOS only.");
            }

            return (_active, _cli ?? throw new ProviderAdapterException(ProviderErrorKind.InvalidConfiguration,
                "The LastPass account or executable configuration is incomplete."), _connection.Token);
        }
    }

    private CancellationTokenSource BeginOperation(CancellationToken callerToken, CancellationToken configurationToken = default)
    {
        callerToken.ThrowIfCancellationRequested();
        CancellationToken authorityLockToken = getAuthorityLockToken();
        if (authorityLockToken.IsCancellationRequested)
        {
            throw new ProviderAdapterException(ProviderErrorKind.InteractionRequired, "Unlock the authority to use the LastPass credential.");
        }

        return CancellationTokenSource.CreateLinkedTokenSource(callerToken, authorityLockToken, configurationToken, _lifetime.Token);
    }

    private async Task<IReadOnlyList<ProviderValidationIssue>> ValidateWithCliAsync(LastPassConfiguration configuration,
        CancellationToken cancellationToken, Func<LastPassCli, string, CancellationToken, Task<IReadOnlyList<ProviderValidationIssue>>> validate)
    {
        LastPassCli? activeCli = null;
        CancellationToken configurationToken = default;
        lock (_gate)
        {
            if (_active?.Username == configuration.Username && _active.EncryptedConfiguration == configuration.EncryptedConfiguration)
            {
                activeCli = _cli;
                configurationToken = _connection!.Token;
            }
        }

        using var operation = BeginOperation(cancellationToken, configurationToken);
        string password = await ResolvePasswordAsync(configuration, operation.Token).ConfigureAwait(false);
        if (activeCli is not null)
        {
            return await validate(activeCli, password, operation.Token).ConfigureAwait(false);
        }

        await using var candidate = new LastPassCli(trustedExecutablePath, configuration.Username);
        return await validate(candidate, password, operation.Token).ConfigureAwait(false);
    }

    private async Task<string> ResolvePasswordAsync(LastPassConfiguration configuration, CancellationToken cancellationToken)
    {
        string ciphertext = configuration.EncryptedConfiguration;
        if (!IsEncryptedConfiguration(ciphertext))
        {
            throw new ProviderAdapterException(ProviderErrorKind.InvalidConfiguration, "Supply an encrypted LastPass configuration.");
        }

        string? plaintext;
        try
        {
            plaintext = await decryptConfiguration(ciphertext, cancellationToken).ConfigureAwait(false);
        }
        catch (AuthorityLockedException)
        {
            throw new ProviderAdapterException(ProviderErrorKind.InteractionRequired, "Unlock the authority to use the LastPass configuration.");
        }

        cancellationToken.ThrowIfCancellationRequested();
        string? password = ReadMasterPassword(plaintext);
        // lpass reads one line from stdin: an embedded newline would split the master password.
        if (!IsMasterPassword(password))
        {
            throw new ProviderAdapterException(ProviderErrorKind.InvalidConfiguration, "The sealed LastPass master password is missing or invalid.");
        }

        return password!;
    }

    private static string? ReadMasterPassword(string? plaintext)
    {
        if (plaintext is null)
        {
            return null;
        }

        try
        {
            using JsonDocument contents = JsonDocument.Parse(plaintext);
            if (contents.RootElement.ValueKind == JsonValueKind.Object
                && contents.RootElement.TryGetProperty("masterPassword", out JsonElement entry)
                && entry.ValueKind == JsonValueKind.String)
            {
                return entry.GetString();
            }
        }
        catch (JsonException)
        {
        }

        return null;
    }

    internal static bool IsEncryptedConfiguration(string value)
        => JweCipher.IsCiphertext(value);

    private static Task<Dictionary<string, string>> ShowAsync(LastPassCli cli, string account, string password, CancellationToken cancellationToken)
        => cli.ReadJsonAsync(ShowArguments(account), password, root => ReadAccount(root, account), cancellationToken);

    private static string[] ShowArguments(string account) => ["show", "--json", "--color=never", "--sync=now", account];

    private static Dictionary<string, string> ReadAccount(JsonElement root, string account)
    {
        if (root.ValueKind != JsonValueKind.Array)
        {
            throw LastPassCli.InvalidResponse();
        }

        JsonElement found = default;
        bool have = false;
        foreach (JsonElement entry in root.EnumerateArray())
        {
            string id = Field(entry, "id") ?? throw LastPassCli.InvalidResponse();
            if (!ValidId(id))
            {
                throw LastPassCli.InvalidResponse();
            }

            if (id == account)
            {
                if (have)
                {
                    throw LastPassCli.InvalidResponse();
                }

                found = entry;
                have = true;
            }
        }

        if (!have)
        {
            throw LastPassCli.InvalidResponse();
        }

        Dictionary<string, string> fields = new(StringComparer.Ordinal);
        foreach (string name in ValueFields)
        {
            // lpass omits a JSON string for a field it has no value for; that is a missing secret, not a broken response.
            if (found.TryGetProperty(name, out JsonElement value))
            {
                fields.Add(Leaf(name), value.ValueKind == JsonValueKind.String
                    ? value.GetString()!
                    : throw LastPassCli.InvalidResponse());
            }
        }

        return fields.Count == 0 ? throw LastPassCli.InvalidResponse() : fields;
    }

    private static string? Field(JsonElement element, string name)
        => element.ValueKind == JsonValueKind.Object && element.TryGetProperty(name, out JsonElement value)
            && value.ValueKind == JsonValueKind.String ? value.GetString()! : null;

    private static string Leaf(string field) => "F_" + Convert.ToHexString(Encoding.ASCII.GetBytes(field));

    private static bool TryFieldName(string leaf, out string name)
    {
        name = "";
        if (!ValidLeaf(leaf))
        {
            return false;
        }

        try
        {
            string decoded = Encoding.ASCII.GetString(Convert.FromHexString(leaf.AsSpan(2)));
            if (ValueFields.Contains(decoded, StringComparer.Ordinal))
            {
                name = decoded;
                return true;
            }
        }
        catch (FormatException)
        {
        }
        catch (DecoderFallbackException)
        {
        }

        return false;
    }

    private static bool TryPath(string value, out string[] segments)
    {
        segments = value.Split('/');
        return segments.Length is 1 or 2 && ValidId(segments[0])
            && (segments.Length == 1 || TryFieldName(segments[1], out _));
    }

    private static bool ValidId(string value) => value.Length is > 0 and <= 32 && value[0] is >= '1' and <= '9' && value.All(char.IsAsciiDigit);

    private static bool ValidLeaf(string value) => value.Length is >= 4 and <= 130 && value.Length % 2 == 0
        && value.StartsWith("F_", StringComparison.Ordinal) && value.Skip(2).All(character => char.IsAsciiDigit(character) || character is >= 'A' and <= 'F');

    internal static bool IsUsername(string? value) => value is { Length: > 0 and <= 256 }
        && value.All(character => character is >= '!' and <= '~');

    internal static bool IsMasterPassword(string? value) => value is { Length: > 0 and <= 8192 }
        && value.All(character => character is not ('\0' or '\r' or '\n'));

    private static bool ValidExecutable(string path) => Path.IsPathFullyQualified(path) && File.Exists(path);

}
