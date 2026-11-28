using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace ArcanaGuardian.OnePassword;

/// <summary>The authority supplies the trusted CLI path, unlock-session cancellation token and configuration decryptor.</summary>
public sealed class OnePasswordAdapter(
    string trustedExecutablePath,
    Func<CancellationToken> getAuthorityLockToken,
    Func<string, CancellationToken, ValueTask<string?>> decryptConfiguration) : ProviderAdapter<OnePasswordConfiguration>
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

    protected override Task InitializeAsync(OnePasswordConfiguration configuration, AdapterInitializationContext context, CancellationToken cancellationToken)
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

    protected override Task UpdateConfigurationAsync(OnePasswordConfiguration configuration, CancellationToken cancellationToken)
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

    /// <summary>A failed retrieval or listing is visible as health, unless the configuration has been replaced meanwhile. An unlock or secret-level failure says nothing about the provider.</summary>
    private void ReportFailure(OnePasswordConfiguration configuration, ProviderAdapterException error)
    {
        if (!ProviderPolicy.SaysAboutProvider(error.Kind))
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

    protected override async Task<IReadOnlyList<ProviderValidationIssue>> ValidateConfigurationAsync(
        OnePasswordConfiguration configuration, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
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

    protected override async Task<IReadOnlyList<ProviderValidationIssue>> ValidateMountAsync(
        OnePasswordConfiguration configuration, string basePath, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (!TryPath(basePath, out string[] segments))
        {
            return [new("Use a 1Password vault, item, or field ID path.", ValidationSeverity.Error, "basePath")];
        }

        using var operation = BeginOperation(cancellationToken);
        cancellationToken = operation.Token;
        OnePasswordCli cli = await OpenAsync(configuration, cancellationToken).ConfigureAwait(false);
        try
        {
            if (segments.Length == 1)
            {
                await cli.ReadJsonAsync(["vault", "get", segments[0], "--format", "json"],
                    root => Id(root) == segments[0] ? true : throw OnePasswordCli.InvalidResponse(), cancellationToken).ConfigureAwait(false);
            }
            else
            {
                (string[] fields, HashSet<string> ambiguous) = await cli.ReadJsonAsync(ItemArguments(segments[0], segments[1]), root =>
                {
                    string[] keys = [.. ReadFields(root, segments[0], segments[1], out HashSet<string> duplicated).Keys];

                    return (keys, duplicated);
                }, cancellationToken).ConfigureAwait(false);
                cancellationToken.ThrowIfCancellationRequested();
                if (segments.Length == 3 && ambiguous.Contains(segments[2]))
                {
                    return [new("The 1Password item has more than one field with that ID.", ValidationSeverity.Error, "basePath")];
                }

                if (segments.Length == 3 && !fields.Contains(segments[2], StringComparer.Ordinal))
                {
                    return [new("The 1Password item does not contain that field ID.", ValidationSeverity.Error, "basePath")];
                }
            }
        }
        catch (ProviderAdapterException error) when (error.Kind == ProviderErrorKind.SecretNotFound)
        {
            return [new(segments.Length == 1 ? "The 1Password vault was not found." : "The 1Password vault or item was not found.", ValidationSeverity.Error, "basePath")];
        }

        cancellationToken.ThrowIfCancellationRequested();
        return [];
    }

    public override async Task<IReadOnlyList<ProviderSecretResult>> RetrieveSecretsAsync(
        IReadOnlyList<ProviderSecretRequest> requests, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (requests.Count == 0)
        {
            return [];
        }

        (OnePasswordConfiguration configuration, CancellationToken configurationToken) = Active();
        List<Task<ProviderSecretResult[]>> tasks = [];
        try
        {
            using var operation = BeginOperation(cancellationToken, configurationToken);
            cancellationToken = operation.Token;
            OnePasswordCli cli = await OpenAsync(configuration, cancellationToken).ConfigureAwait(false);
            var parsed = requests.Select(request => (Request: request, Path: TryPath(request.Path, out string[] path) && path.Length == 3 ? path : null)).ToArray();

            // One CLI call per item, a few at a time: each is bounded by the command timeout, the batch by the core's deadline.
            using var slots = new SemaphoreSlim(ProviderPolicy.CommandConcurrency);
            var failures = new System.Collections.Concurrent.ConcurrentQueue<ProviderAdapterException>();
            using var batch = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            var fatal = new System.Runtime.CompilerServices.StrongBox<ProviderAdapterException?>();
            foreach (var group in parsed.GroupBy(entry => entry.Path is { } path ? (Vault: path[0], Item: path[1]) : default))
            {
                if (group.Key.Vault is null)
                {
                    tasks.Add(Task.FromResult(group.Select(entry => new ProviderSecretResult(entry.Request.RequestId, null, ProviderErrorKind.InvalidConfiguration)).ToArray()));
                    continue;
                }

                var entries = group.Select(entry => (entry.Request, Leaf: entry.Path![2])).ToArray();
                tasks.Add(RetrieveItemAsync(cli, configuration, group.Key.Vault, group.Key.Item!, entries, slots, failures, batch, fatal));
            }

            ProviderSecretResult[][] answered;
            try
            {
                answered = await Task.WhenAll(tasks).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (fatal.Value is not null && !cancellationToken.IsCancellationRequested)
            {
                throw fatal.Value;
            }

            List<ProviderSecretResult> results = [.. answered.SelectMany(group => group)];

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
            // One health report per batch: the first failure about the provider (a gone secret or a locked authority is not one), else healthy.
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
        catch (Exception failure)
        {
            // A failed batch delivers nothing: wipe what the items that did finish retrieved.
            foreach (Task<ProviderSecretResult[]> task in tasks)
            {
                if (task.IsCompletedSuccessfully)
                {
                    foreach (ProviderSecretResult result in task.Result)
                    {
                        if (result.Secret is { } secret)
                        {
                            CryptographicOperations.ZeroMemory(secret.Value);
                        }
                    }
                }
            }

            if (failure is ProviderAdapterException error)
            {
                ReportFailure(configuration, error);
            }

            throw;
        }
    }

    private async Task<ProviderSecretResult[]> RetrieveItemAsync(OnePasswordCli cli, OnePasswordConfiguration configuration, string vault, string item,
        (ProviderSecretRequest Request, string Leaf)[] entries, SemaphoreSlim slots, System.Collections.Concurrent.ConcurrentQueue<ProviderAdapterException> failures,
        CancellationTokenSource batch, System.Runtime.CompilerServices.StrongBox<ProviderAdapterException?> fatal)
    {
        await slots.WaitAsync(batch.Token).ConfigureAwait(false);
        try
        {
            return await cli.ReadJsonAsync([.. ItemArguments(vault, item), "--reveal"], root =>
            {
                Dictionary<string, JsonElement> fields = ReadFields(root, vault, item, out HashSet<string> ambiguous);
                return entries.Select(entry =>
                {
                    Guid id = entry.Request.RequestId;
                    if (ambiguous.Contains(entry.Leaf))
                    {
                        failures.Enqueue(OnePasswordCli.InvalidResponse());
                        return new ProviderSecretResult(id, null, ProviderErrorKind.InvalidResponse);
                    }

                    if (!fields.TryGetValue(entry.Leaf, out JsonElement field))
                    {
                        return new ProviderSecretResult(id, null, ProviderErrorKind.SecretNotFound);
                    }

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
            }, batch.Token).ConfigureAwait(false);
        }
        catch (ProviderAdapterException error) when (error.Kind is not (ProviderErrorKind.InvalidConfiguration or ProviderErrorKind.AuthenticationFailed or ProviderErrorKind.InteractionRequired))
        {
            failures.Enqueue(error);

            return [.. entries.Select(entry => new ProviderSecretResult(entry.Request.RequestId, null, error.Kind, error.ProviderCode, error.RetryAfter))];
        }
        catch (ProviderAdapterException error)
        {
            Interlocked.CompareExchange(ref fatal.Value, error, null);
            await batch.CancelAsync().ConfigureAwait(false);
            throw;
        }
        finally
        {
            slots.Release();
        }
    }

    public override async Task<ListSecretsResult> ListSecretsAsync(ListSecretsRequest request, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (request.ContinuationToken is not null || !TryPath(request.Path, out string[] scope) || scope.Length > 2
            || (request.Filter is not null && (scope.Length != 2 || !ValidLeaf(request.Filter))))
        {
            throw new ProviderAdapterException(ProviderErrorKind.InvalidConfiguration, "Invalid 1Password listing scope.");
        }

        (OnePasswordConfiguration configuration, CancellationToken configurationToken) = Active();
        try
        {
            using var operation = BeginOperation(cancellationToken, configurationToken);
            cancellationToken = operation.Token;
            OnePasswordCli cli = await OpenAsync(configuration, cancellationToken).ConfigureAwait(false);
            string vault = scope[0];
            string[] items;
            try
            {
                items = scope.Length == 2 ? [scope[1]] : await cli.ReadJsonAsync(
                    ["item", "list", "--vault", vault, "--format", "json"], ReadItems, cancellationToken).ConfigureAwait(false);
            }
            catch (ProviderAdapterException error) when (error.Kind == ProviderErrorKind.SecretNotFound)
            {
                items = [];
            }

            List<ProviderSecretInfo> secrets = [];
            foreach (string item in items)
            {
                string[] fields;
                try
                {
                    fields = await FieldsAsync(cli, vault, item, cancellationToken).ConfigureAwait(false);
                }
                catch (ProviderAdapterException error) when (error.Kind == ProviderErrorKind.SecretNotFound)
                {
                    continue;
                }

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
        catch (ProviderAdapterException error)
        {
            ReportFailure(configuration, error);
            throw;
        }
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


    private static bool IsEncryptedConfiguration(string value)
        => JweCipher.IsCiphertext(value);

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
        => cli.ReadJsonAsync(ItemArguments(vault, item), root => ReadFields(root, vault, item, out _).Keys.ToArray(), cancellationToken);

    /// <summary>
    /// The item's fields by leaf. Field ids are only unique within a section, so an id that occurs twice names no single field: it is left out (never guessed),
    /// which leaves it neither listed nor retrievable while the item's other fields stay usable.
    /// </summary>
    private static Dictionary<string, JsonElement> ReadFields(JsonElement root, string vault, string item, out HashSet<string> ambiguous)
    {
        if (Id(root) != item || Id(root.GetProperty("vault")) != vault)
        {
            throw OnePasswordCli.InvalidResponse();
        }

        Dictionary<string, JsonElement> fields = new(StringComparer.Ordinal);
        ambiguous = new(StringComparer.Ordinal);
        foreach (JsonElement field in root.GetProperty("fields").EnumerateArray())
        {
            string leaf = "F_" + Convert.ToHexString(Encoding.ASCII.GetBytes(Id(field)));
            if (ambiguous.Contains(leaf))
            {
                continue;
            }

            if (!fields.TryAdd(leaf, field))
            {
                fields.Remove(leaf);
                ambiguous.Add(leaf);
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
