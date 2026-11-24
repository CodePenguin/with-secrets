using System.Text;
using System.Text.Json;

namespace WithSecrets.Vault;

public sealed class VaultAdapter(
    string trustedAddress,
    string trustedMount,
    string? trustedNamespace,
    Func<CancellationToken> getAuthorityLockToken,
    Func<string, CancellationToken, ValueTask<string?>> decryptConfiguration,
    HttpClient? httpClient = null) : ProviderAdapter<VaultConfiguration>
{
    public const string ProviderType = "vault";
    public const string AdapterVersion = "1.0";

    private const int MaxPathLength = 1024;
    private const int DocumentConcurrency = 4;
    private static readonly TimeSpan BatchBudget = ProviderPolicy.Deadline - TimeSpan.FromSeconds(2);
    private readonly object _gate = new();
    private readonly CancellationTokenSource _lifetime = new();
    private IAdapterStatusReporter? _status;
    private VaultConfiguration? _active;
    private CancellationTokenSource? _connection;
    private Task _probe = Task.CompletedTask;

    protected override Task InitializeAsync(VaultConfiguration configuration, AdapterInitializationContext context, CancellationToken cancellationToken)
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

    protected override Task UpdateConfigurationAsync(VaultConfiguration configuration, CancellationToken cancellationToken)
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

    protected override async Task<IReadOnlyList<ProviderValidationIssue>> ValidateConfigurationAsync(
        VaultConfiguration configuration, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (TrustedAddress() is null)
        {
            return [new("Set an HTTPS Vault address and a valid KV v2 mount on the authority host.", ValidationSeverity.Error)];
        }

        if (!configuration.IsEncrypted)
        {
            return [new("Supply an encrypted Vault configuration.", ValidationSeverity.Error, "encryptedConfiguration")];
        }

        using var operation = BeginOperation(cancellationToken);
        VaultApi api = await OpenAsync(configuration, operation.Token).ConfigureAwait(false);
        await api.CheckTokenAsync(operation.Token).ConfigureAwait(false);
        return [];
    }

    protected override Task<IReadOnlyList<ProviderValidationIssue>> ValidateMountAsync(
        VaultConfiguration configuration, string basePath, CancellationToken cancellationToken)
        => ValidateMountAsync(configuration, basePath, null, cancellationToken);

    protected override async Task<IReadOnlyList<ProviderValidationIssue>> ValidateMountAsync(
        VaultConfiguration configuration, string basePath, MountKind? kind, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        switch (kind)
        {
            case MountKind.Single when TryField(basePath, out string document, out string field):
                return await ValidateScopeAsync(configuration, document, false, field, cancellationToken).ConfigureAwait(false);
            case MountKind.Tree when TryScope(basePath, out string scope, out bool directory):
                return await ValidateScopeAsync(configuration, scope, directory, null, cancellationToken).ConfigureAwait(false);
            default:
                string message = kind switch
                {
                    MountKind.Single => "Use a Vault document/field path for a single secret.",
                    MountKind.Tree => "Use a Vault document path, or end a directory path with '/'.",
                    _ => "Choose a mount kind to validate a Vault path.",
                };
                return [new(message, ValidationSeverity.Error, "basePath")];
        }
    }

    private async Task<IReadOnlyList<ProviderValidationIssue>> ValidateScopeAsync(
        VaultConfiguration configuration, string scope, bool directory, string? field, CancellationToken cancellationToken)
    {
        using var operation = BeginOperation(cancellationToken);
        VaultApi api = await OpenAsync(configuration, operation.Token).ConfigureAwait(false);
        try
        {
            if (directory)
            {
                await api.ReadDirectoryAsync(scope, operation.Token).ConfigureAwait(false);
                return [];
            }

            string[] fields = await api.ReadFieldsAsync(scope, operation.Token).ConfigureAwait(false);
            if (field is null || fields.Contains(field, StringComparer.Ordinal))
            {
                return [];
            }
        }
        catch (ProviderAdapterException error) when (error.Kind == ProviderErrorKind.SecretNotFound)
        {
        }

        return [new("The Vault path does not exist for this mount kind.", ValidationSeverity.Error, "basePath")];
    }

    public override async Task<IReadOnlyList<ProviderSecretResult>> RetrieveSecretsAsync(
        IReadOnlyList<ProviderSecretRequest> requests, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (requests.Count == 0)
        {
            return [];
        }

        var (configuration, generation) = Active();
        using var operation = BeginOperation(cancellationToken, generation);
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(operation.Token);
        deadline.CancelAfter(BatchBudget);
        VaultApi api = await OpenAsync(configuration, operation.Token).ConfigureAwait(false);
        var parsed = requests.Select((request, index) =>
            (Request: request, Index: index, Document: TryField(request.Path, out string document, out string field) ? document : null, Field: field));
        var completed = new ProviderSecretResult?[requests.Count];

        try
        {
            var options = new ParallelOptions { MaxDegreeOfParallelism = DocumentConcurrency, CancellationToken = deadline.Token };
            await Parallel.ForEachAsync(parsed.GroupBy(entry => entry.Document, StringComparer.Ordinal), options, async (group, token) =>
            {
                if (group.Key is null)
                {
                    foreach (var entry in group)
                    {
                        completed[entry.Index] = new(entry.Request.RequestId, null, ProviderErrorKind.InvalidConfiguration);
                    }

                    return;
                }

                try
                {
                    var values = await api.ReadSecretAsync(group.Key, fields => group.Select(entry =>
                    {
                        Guid id = entry.Request.RequestId;
                        if (!fields.TryGetProperty(entry.Field, out var value))
                        {
                            return (entry.Index, Result: new ProviderSecretResult(id, null, ProviderErrorKind.SecretNotFound));
                        }

                        string contents = value.ValueKind == JsonValueKind.String ? value.GetString()! : value.GetRawText();
                        return (entry.Index, Result: new ProviderSecretResult(id, new RetrieveSecretResult(Encoding.UTF8.GetBytes(contents))));
                    }).ToArray(), token).ConfigureAwait(false);
                    foreach (var (index, result) in values)
                    {
                        completed[index] = result;
                    }
                }
                catch (ProviderAdapterException error)
                {
                    foreach (var entry in group)
                    {
                        completed[entry.Index] = new(entry.Request.RequestId, null, error.Kind, error.ProviderCode, error.RetryAfter);
                    }
                }
            }).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (deadline.IsCancellationRequested && !operation.IsCancellationRequested)
        {
            // Return completed documents before the authority's batch deadline, so only unfinished reads are retried.
        }

        ProviderSecretResult[] results = requests.Select((request, index) =>
            completed[index] ?? new ProviderSecretResult(request.RequestId, null, ProviderErrorKind.Unavailable)).ToArray();
        string[] removed = requests.Where((_, index) => results[index].ErrorKind == ProviderErrorKind.SecretNotFound)
            .Select(request => request.Path).Distinct(StringComparer.Ordinal).ToArray();
        lock (_gate)
        {
            operation.Token.ThrowIfCancellationRequested();
            if (removed.Length != 0)
            {
                _status?.Report(new InvalidateProviderDataEvent(ExternalSecretIds: removed));
            }

            if (results.Any(result => result.Secret is not null))
            {
                _status?.Report(new HealthChangedEvent(AdapterHealthState.Healthy));
            }
        }

        return results;
    }

    public override async Task<ListSecretsResult> ListSecretsAsync(ListSecretsRequest request, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (request.ContinuationToken is not null || !TryScope(request.Path, out string scope, out bool directory)
            || request.Filter is { } filter && (directory || !ValidField(filter)))
        {
            throw new ProviderAdapterException(ProviderErrorKind.InvalidConfiguration, "Invalid Vault listing scope.");
        }

        var (configuration, generation) = Active();
        using var operation = BeginOperation(cancellationToken, generation);
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(operation.Token);
        deadline.CancelAfter(TimeSpan.FromSeconds(30));
        VaultApi api = await OpenAsync(configuration, deadline.Token).ConfigureAwait(false);
        List<ProviderSecretInfo> secrets = [];
        try
        {
            if (directory)
            {
                await ListDirectoryAsync(api, scope, secrets, deadline.Token).ConfigureAwait(false);
            }
            else
            {
                await AddFieldsAsync(api, scope, "", request.Filter, secrets, deadline.Token).ConfigureAwait(false);
            }
        }
        catch (OperationCanceledException) when (!operation.IsCancellationRequested)
        {
            throw new ProviderAdapterException(ProviderErrorKind.Unavailable, "Vault discovery timed out.");
        }

        lock (_gate)
        {
            operation.Token.ThrowIfCancellationRequested();
            _status?.Report(new HealthChangedEvent(AdapterHealthState.Healthy));
        }

        return new(secrets, null, IsComplete: true);
    }

    private static async Task ListDirectoryAsync(VaultApi api, string scope, List<ProviderSecretInfo> secrets, CancellationToken cancellationToken)
    {
        Stack<string> directories = new();
        directories.Push(scope);
        while (directories.TryPop(out string? directory))
        {
            string[] entries = await api.ReadDirectoryAsync(directory, cancellationToken).ConfigureAwait(false);

            foreach (string entry in entries.Distinct(StringComparer.Ordinal))
            {
                if (directory.Length + entry.Length >= MaxPathLength || !SecretNames.IsFolderSegment(entry.TrimEnd('/'))
                    || entry.EndsWith("//", StringComparison.Ordinal))
                {
                    continue;
                }

                string path = directory + entry;
                if (entry.EndsWith('/'))
                {
                    directories.Push(path);
                }
                else
                {
                    await AddFieldsAsync(api, path, path[scope.Length..] + "/", null, secrets, cancellationToken).ConfigureAwait(false);
                }
            }
        }
    }

    private static async Task AddFieldsAsync(VaultApi api, string document, string relativePrefix, string? filter,
        List<ProviderSecretInfo> secrets, CancellationToken cancellationToken)
    {
        string[] fields;
        try
        {
            fields = await api.ReadFieldsAsync(document, cancellationToken).ConfigureAwait(false);
        }
        catch (ProviderAdapterException error) when (error.Kind == ProviderErrorKind.SecretNotFound)
        {
            return;
        }

        foreach (string field in fields)
        {
            if (ValidField(field) && document.Length + 1 + field.Length <= MaxPathLength && (filter is null || field == filter))
            {
                secrets.Add(new(relativePrefix + field, document + "/" + field, null));
            }
        }
    }

    private void StartProbe(VaultConfiguration configuration, bool invalidate)
    {
        StopProbe();
        _active = configuration;
        _status!.Report(new HealthChangedEvent(AdapterHealthState.Initializing));
        if (invalidate)
        {
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

    private async Task ProbeAsync(VaultConfiguration configuration, CancellationToken token)
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

    private (VaultConfiguration Configuration, CancellationToken Generation) Active()
    {
        lock (_gate)
        {
            if (_active is null || _connection is null)
            {
                throw new ProviderAdapterException(ProviderErrorKind.InvalidConfiguration, "The Vault adapter is inactive.");
            }

            return (_active, _connection.Token);
        }
    }

    private CancellationTokenSource BeginOperation(CancellationToken callerToken, CancellationToken generation = default)
    {
        callerToken.ThrowIfCancellationRequested();
        CancellationToken authorityToken = getAuthorityLockToken();
        if (authorityToken.IsCancellationRequested)
        {
            throw new ProviderAdapterException(ProviderErrorKind.InteractionRequired, "Unlock the authority to use the Vault token.");
        }

        return CancellationTokenSource.CreateLinkedTokenSource(callerToken, authorityToken, generation, _lifetime.Token);
    }

    private async Task<VaultApi> OpenAsync(VaultConfiguration configuration, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        Uri address = TrustedAddress() ?? throw new ProviderAdapterException(ProviderErrorKind.InvalidConfiguration,
            "Set an HTTPS Vault address and a valid KV v2 mount on the authority host.");
        if (!configuration.IsEncrypted)
        {
            throw new ProviderAdapterException(ProviderErrorKind.InvalidConfiguration, "Supply an encrypted Vault configuration.");
        }

        string? plaintext;
        try
        {
            plaintext = await decryptConfiguration(configuration.EncryptedConfiguration, cancellationToken).ConfigureAwait(false);
        }
        catch (AuthorityLockedException)
        {
            throw new ProviderAdapterException(ProviderErrorKind.InteractionRequired, "Unlock the authority to use the Vault token.");
        }

        cancellationToken.ThrowIfCancellationRequested();
        string token = VaultConfiguration.ReadToken(plaintext) ?? throw new ProviderAdapterException(
            ProviderErrorKind.InvalidConfiguration, "The encrypted Vault configuration could not be opened or did not contain a valid token.");
        return new VaultApi(httpClient ?? VaultApi.SharedClient, address, trustedMount.TrimEnd('/'),
            string.IsNullOrEmpty(trustedNamespace) ? null : trustedNamespace, token);
    }

    private Uri? TrustedAddress()
        => Uri.TryCreate(trustedAddress, UriKind.Absolute, out Uri? address) && address.Scheme == Uri.UriSchemeHttps
            && address.UserInfo.Length == 0 && address.Query.Length == 0 && address.Fragment.Length == 0
            && ValidDocument(trustedMount.TrimEnd('/'))
            && (string.IsNullOrEmpty(trustedNamespace) || ValidDocument(trustedNamespace.TrimEnd('/')))
            ? new Uri(address.AbsoluteUri.TrimEnd('/') + "/") : null;

    private static bool TryScope(string value, out string path, out bool directory)
    {
        directory = value.Length == 0 || value.EndsWith('/');
        path = value == "/" ? "" : value;
        return path.Length == 0 || ValidDocument(directory ? path[..^1] : path);
    }

    private static bool TryField(string path, out string document, out string field)
    {
        int slash = path.LastIndexOf('/');
        document = slash > 0 ? path[..slash] : "";
        field = path[(slash + 1)..];
        return slash > 0 && path.Length <= MaxPathLength && ValidDocument(document) && ValidField(field);
    }

    private static bool ValidDocument(string path)
        => path.Length <= MaxPathLength && path.Split('/').All(SecretNames.IsFolderSegment);

    private static bool ValidField(string field)
        => field.Length is > 0 and <= SecretNames.MaxNameLength && field is not "." and not ".."
            && field.All(c => char.IsAsciiLetterOrDigit(c) || c is '_' or '.' or '-');
}
