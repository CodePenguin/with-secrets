using System.Text;
using System.Text.Json;

namespace WithSecrets.OnePassword;

/// <summary>The authority supplies the trusted CLI path, unlock-session cancellation token and configuration decryptor.</summary>
public sealed class OnePasswordAdapter(
    string trustedExecutablePath,
    Func<CancellationToken> getAuthorityLockToken,
    Func<string, CancellationToken, ValueTask<string?>> decryptConfiguration) : IProviderAdapter
{
    public const string ProviderType = "onepassword";
    public const string AdapterVersion = "1.0";

    private static readonly UTF8Encoding StrictUtf8 = new(false, true);
    private readonly object _gate = new();
    private readonly CancellationTokenSource _lifetime = new();
    private OnePasswordConfiguration? _active;
    private IAdapterStatusReporter? _status;
    private CancellationTokenSource? _connection;
    private Task _probe = Task.CompletedTask;

    public Task InitializeAsync(IAdapterConfiguration supplied, AdapterInitializationContext context, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        OnePasswordConfiguration configuration = RequireConfiguration(supplied);
        lock (_gate)
        {
            _status = context.StatusReporter;
            _status.Report(new LifecycleChangedEvent(AdapterLifecycleState.Ready));
            StartProbe(configuration, invalidate: false);
        }

        return Task.CompletedTask;
    }

    public Task UpdateConfigurationAsync(IAdapterConfiguration supplied, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        OnePasswordConfiguration configuration = RequireConfiguration(supplied);
        lock (_gate)
        {
            if (_active is not null)
            {
                StartProbe(configuration, invalidate: true);
            }
        }

        return Task.CompletedTask;
    }

    public async Task ShutdownAsync(CancellationToken cancellationToken)
    {
        Task pending;
        lock (_gate)
        {
            _lifetime.Cancel();
            StopProbe();
            _active = null;
            _status = null;
            pending = _probe;
        }

        await pending.WaitAsync(cancellationToken).ConfigureAwait(false);
    }

    private void StartProbe(OnePasswordConfiguration configuration, bool invalidate)
    {
        StopProbe();
        _active = configuration;
        _status!.Report(new HealthChangedEvent(AdapterHealthState.Initializing));
        if (invalidate)
        {
            // A new executable or credential may resolve the same path against a different account.
            _status.Report(new InvalidateProviderDataEvent(InvalidateEntireProviderInstance: true));
        }

        _connection = new CancellationTokenSource();
        CancellationToken token = _connection.Token;
        _probe = Task.Run(() => ProbeAsync(configuration, token));
    }

    private void StopProbe()
    {
        _connection?.Cancel();
        _connection?.Dispose();
        _connection = null;
    }

    private async Task ProbeAsync(OnePasswordConfiguration configuration, CancellationToken token)
    {
        AdapterHealthState health;
        try
        {
            IReadOnlyList<ProviderValidationIssue> issues = await ValidateConfigurationAsync(configuration, token).ConfigureAwait(false);
            health = issues.Count == 0 ? AdapterHealthState.Healthy : AdapterHealthState.Misconfigured;
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
            health = error.Kind switch
            {
                ProviderErrorKind.Unavailable => AdapterHealthState.Unavailable,
                ProviderErrorKind.InvalidConfiguration or ProviderErrorKind.AuthenticationFailed or ProviderErrorKind.AccessDenied => AdapterHealthState.Misconfigured,
                _ => AdapterHealthState.Degraded,
            };
        }

        lock (_gate)
        {
            if (!token.IsCancellationRequested)
            {
                _status?.Report(new HealthChangedEvent(health));
            }
        }
    }

    public async Task<IReadOnlyList<ProviderValidationIssue>> ValidateConfigurationAsync(
        IAdapterConfiguration supplied, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        OnePasswordConfiguration configuration = RequireConfiguration(supplied);
        List<ProviderValidationIssue> issues = [];
        if (!ValidExecutable(trustedExecutablePath))
        {
            issues.Add(new("Install 1Password CLI at the authority-configured executable path.", ValidationSeverity.Error));
        }

        if (!IsEncryptedConfiguration(configuration.EncryptedConfiguration))
        {
            issues.Add(new("Supply an encrypted 1Password configuration.", ValidationSeverity.Error, "encryptedConfiguration"));
        }


        if (issues.Count == 0)
        {
            using var operation = BeginOperation(cancellationToken);
            OnePasswordCli cli = await OpenAsync(configuration, operation.Token).ConfigureAwait(false);
            await cli.ReadJsonAsync(["user", "get", "--me", "--format", "json"],
                root => Id(root), operation.Token).ConfigureAwait(false);
            operation.Token.ThrowIfCancellationRequested();
        }

        return issues;
    }

    public async Task<IReadOnlyList<ProviderValidationIssue>> ValidateMountAsync(
        IAdapterConfiguration supplied, string basePath, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        OnePasswordConfiguration configuration = RequireConfiguration(supplied);
        if (!TryPath(basePath, out string[] segments))
        {
            return [new("Use a 1Password vault, item, or field ID path.", ValidationSeverity.Error, "basePath")];
        }

        using var operation = BeginOperation(cancellationToken);
        cancellationToken = operation.Token;
        OnePasswordCli cli = await OpenAsync(configuration, cancellationToken).ConfigureAwait(false);
        if (segments.Length == 1)
        {
            await cli.ReadJsonAsync(["vault", "get", segments[0], "--format", "json"],
                root => Id(root) == segments[0] ? true : throw OnePasswordCli.InvalidResponse(), cancellationToken).ConfigureAwait(false);
        }
        else
        {
            string[] fields = await FieldsAsync(cli, segments[0], segments[1], cancellationToken).ConfigureAwait(false);
            cancellationToken.ThrowIfCancellationRequested();
            if (segments.Length == 3 && !fields.Contains(segments[2], StringComparer.Ordinal))
            {
                return [new("The 1Password item does not contain that field ID.", ValidationSeverity.Error, "basePath")];
            }
        }

        cancellationToken.ThrowIfCancellationRequested();
        return [];
    }

    public async Task<IReadOnlyList<ProviderSecretResult>> RetrieveSecretsAsync(
        IReadOnlyList<ProviderSecretRequest> requests, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (requests.Count == 0)
        {
            return [];
        }

        (OnePasswordConfiguration configuration, CancellationToken configurationToken) = Active();
        using var operation = BeginOperation(cancellationToken, configurationToken);
        cancellationToken = operation.Token;
        OnePasswordCli cli = await OpenAsync(configuration, cancellationToken).ConfigureAwait(false);
        var parsed = requests.Select(request => (Request: request, Path: TryPath(request.Path, out string[] path) && path.Length == 3 ? path : null)).ToArray();
        List<ProviderSecretResult> results = [];
        foreach (var group in parsed.GroupBy(entry => entry.Path is { } path ? (Vault: path[0], Item: path[1]) : default))
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (group.Key.Vault is null)
            {
                results.AddRange(group.Select(entry => new ProviderSecretResult(entry.Request.RequestId, null, ProviderErrorKind.InvalidConfiguration)));
                continue;
            }

            try
            {
                string vault = group.Key.Vault;
                string item = group.Key.Item!;
                results.AddRange(await cli.ReadJsonAsync([.. ItemArguments(vault, item), "--reveal"], root =>
                {
                    Dictionary<string, JsonElement> fields = ReadFields(root, vault, item);
                    return group.Select(entry =>
                    {
                        if (!fields.TryGetValue(entry.Path![2], out JsonElement field))
                        {
                            return new ProviderSecretResult(entry.Request.RequestId, null, ProviderErrorKind.SecretNotFound);
                        }

                        Guid id = entry.Request.RequestId;
                        try
                        {
                            byte[] value = field.TryGetProperty("value", out JsonElement raw) && raw.ValueKind != JsonValueKind.Null
                                ? StrictUtf8.GetBytes(raw.GetString()!) : [];
                            return new ProviderSecretResult(id, new RetrieveSecretResult(value));
                        }
                        catch (Exception error) when (error is InvalidOperationException or EncoderFallbackException)
                        {
                            return new ProviderSecretResult(id, null, ProviderErrorKind.InvalidResponse);
                        }
                    }).ToArray();
                }, cancellationToken).ConfigureAwait(false));
            }
            catch (ProviderAdapterException error) when (error.Kind is not (ProviderErrorKind.InvalidConfiguration or ProviderErrorKind.AuthenticationFailed or ProviderErrorKind.InteractionRequired))
            {
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
        if (results.Any(result => result.Secret is not null))
        {
            ReportHealthy(configuration, cancellationToken);
        }

        return results;
    }

    public async Task<ListSecretsResult> ListSecretsAsync(ListSecretsRequest request, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (request.ContinuationToken is not null || !TryPath(request.Path, out string[] scope) || scope.Length > 2
            || (request.Filter is not null && (scope.Length != 2 || !ValidLeaf(request.Filter))))
        {
            throw new ProviderAdapterException(ProviderErrorKind.InvalidConfiguration, "Invalid 1Password listing scope.");
        }

        (OnePasswordConfiguration configuration, CancellationToken configurationToken) = Active();
        using var operation = BeginOperation(cancellationToken, configurationToken);
        cancellationToken = operation.Token;
        OnePasswordCli cli = await OpenAsync(configuration, cancellationToken).ConfigureAwait(false);
        string vault = scope[0];
        string[] items = scope.Length == 2 ? [scope[1]] : await cli.ReadJsonAsync(
            ["item", "list", "--vault", vault, "--format", "json"], ReadItems, cancellationToken).ConfigureAwait(false);
        List<ProviderSecretInfo> secrets = [];
        foreach (string item in items)
        {
            string[] fields = await FieldsAsync(cli, vault, item, cancellationToken).ConfigureAwait(false);
            foreach (string leaf in fields)
            {
                if (request.Filter is null || request.Filter == leaf)
                {
                    string relative = scope.Length == 2 ? leaf : item + "/" + leaf;
                    secrets.Add(new(relative, vault + "/" + item + "/" + leaf, null));
                }
            }
        }

        cancellationToken.ThrowIfCancellationRequested();
        ReportHealthy(configuration, cancellationToken);
        return new(secrets, null, IsComplete: true);
    }

    private void ReportHealthy(OnePasswordConfiguration configuration, CancellationToken cancellationToken)
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


    public Type ConfigurationType => typeof(OnePasswordConfiguration);

    private static OnePasswordConfiguration RequireConfiguration(IAdapterConfiguration configuration)
        => configuration as OnePasswordConfiguration
            ?? throw new ProviderAdapterException(ProviderErrorKind.InvalidConfiguration, "Expected 1Password adapter configuration.");


    private (OnePasswordConfiguration Configuration, CancellationToken CancellationToken) Active()
    {
        lock (_gate)
        {
            if (_active is null || _connection is null)
            {
                throw new ProviderAdapterException(ProviderErrorKind.InvalidConfiguration, "The 1Password adapter is inactive.");
            }

            return (_active, _connection.Token);
        }
    }

    private CancellationTokenSource BeginOperation(CancellationToken callerToken, CancellationToken configurationToken = default)
    {
        callerToken.ThrowIfCancellationRequested();
        CancellationToken authorityLockToken = getAuthorityLockToken();
        if (authorityLockToken.IsCancellationRequested)
        {
            throw new ProviderAdapterException(ProviderErrorKind.InteractionRequired, "Unlock the authority to use the 1Password credential.");
        }

        return CancellationTokenSource.CreateLinkedTokenSource(callerToken, authorityLockToken, configurationToken, _lifetime.Token);
    }


    private async Task<OnePasswordCli> OpenAsync(OnePasswordConfiguration configuration, CancellationToken cancellationToken)
    {
        if (!ValidExecutable(trustedExecutablePath))
        {
            throw new ProviderAdapterException(ProviderErrorKind.InvalidConfiguration, "Install 1Password CLI at the authority-configured executable path.");
        }

        string ciphertext = configuration.EncryptedConfiguration;
        if (!IsEncryptedConfiguration(ciphertext))
        {
            throw new ProviderAdapterException(ProviderErrorKind.InvalidConfiguration, "Supply an encrypted 1Password configuration.");
        }

        string? plaintext;
        try
        {
            plaintext = await decryptConfiguration(ciphertext, cancellationToken).ConfigureAwait(false);
        }
        catch (AuthorityLockedException)
        {
            throw new ProviderAdapterException(ProviderErrorKind.InteractionRequired, "Unlock the authority to use the 1Password configuration.");
        }

        cancellationToken.ThrowIfCancellationRequested();
        string? token = ReadToken(plaintext);
        return new(trustedExecutablePath, token ?? throw new ProviderAdapterException(
            ProviderErrorKind.InvalidConfiguration, "The encrypted 1Password configuration could not be opened or did not contain a valid service-account token."));
    }

    private const string CiphertextPrefix = "encrypted:";

    private static bool IsEncryptedConfiguration(string value)
        => value.StartsWith(CiphertextPrefix, StringComparison.Ordinal) && value.Length > CiphertextPrefix.Length
            && value.AsSpan(CiphertextPrefix.Length).IndexOfAnyExcept("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=") < 0;

    internal static bool IsServiceAccountToken(string? token)
        => token is { Length: > 0 and <= 8192 }
            && token.All(c => char.IsAsciiLetterOrDigit(c) || c is '.' or '_' or '-' or '=' or '+' or '/');

    private static string? ReadToken(string? plaintext)
    {
        if (plaintext is null)
        {
            return null;
        }

        try
        {
            using JsonDocument contents = JsonDocument.Parse(plaintext);
            if (contents.RootElement.ValueKind == JsonValueKind.Object
                && contents.RootElement.TryGetProperty("serviceAccountToken", out JsonElement entry)
                && entry.ValueKind == JsonValueKind.String && IsServiceAccountToken(entry.GetString()))
            {
                return entry.GetString();
            }
        }
        catch (JsonException)
        {
        }

        return null;
    }


    private static bool ValidExecutable(string path) => Path.IsPathFullyQualified(path) && File.Exists(path);

    private static string[] ItemArguments(string vault, string item) => ["item", "get", item, "--vault", vault, "--format", "json"];

    private static Task<string[]> FieldsAsync(OnePasswordCli cli, string vault, string item, CancellationToken cancellationToken)
        => cli.ReadJsonAsync(ItemArguments(vault, item), root => ReadFields(root, vault, item).Keys.ToArray(), cancellationToken);

    private static Dictionary<string, JsonElement> ReadFields(JsonElement root, string vault, string item)
    {
        if (Id(root) != item || Id(root.GetProperty("vault")) != vault)
        {
            throw OnePasswordCli.InvalidResponse();
        }

        Dictionary<string, JsonElement> fields = new(StringComparer.Ordinal);
        foreach (JsonElement field in root.GetProperty("fields").EnumerateArray())
        {
            string leaf = "F_" + Convert.ToHexString(Encoding.ASCII.GetBytes(Id(field)));
            if (!fields.TryAdd(leaf, field))
            {
                throw OnePasswordCli.InvalidResponse();
            }
        }

        return fields;
    }

    private static string[] ReadItems(JsonElement root)
    {
        HashSet<string> items = new(StringComparer.Ordinal);
        foreach (JsonElement entry in root.EnumerateArray())
        {
            if (entry.TryGetProperty("state", out JsonElement state) && state.GetString() is "ARCHIVED" or "DELETED")
            {
                continue;
            }

            if (!items.Add(Id(entry)))
            {
                throw OnePasswordCli.InvalidResponse();
            }
        }

        return [.. items.Order(StringComparer.Ordinal)];
    }

    private static string Id(JsonElement element)
    {
        string? id = element.GetProperty("id").GetString();
        return ValidId(id) ? id! : throw OnePasswordCli.InvalidResponse();
    }

    private static bool ValidId(string? value) => value is { Length: > 0 and <= 64 } && char.IsAsciiLetterOrDigit(value[0])
        && value.All(c => char.IsAsciiLetterOrDigit(c) || c is '_' or '-');

    private static bool ValidLeaf(string value) => value.Length is >= 4 and <= 130 && value.Length % 2 == 0
        && value.StartsWith("F_", StringComparison.Ordinal) && value.Skip(2).All(c => char.IsAsciiDigit(c) || c is >= 'A' and <= 'F');

    private static bool TryPath(string value, out string[] segments)
    {
        segments = value.Split('/');
        return segments.Length is >= 1 and <= 3 && segments.Take(2).All(ValidId)
            && (segments.Length != 3 || ValidLeaf(segments[2]));
    }
}
