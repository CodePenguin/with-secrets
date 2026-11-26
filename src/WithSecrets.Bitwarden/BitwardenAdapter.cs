using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace WithSecrets.Bitwarden;

/// <summary>Read-only Bitwarden Secrets Manager integration. Credentials are resolved on the authority.</summary>
public sealed class BitwardenAdapter(string executablePath, Func<string, string?> decryptConfiguration,
    Func<CancellationToken> unlockedSession)
    : ProviderAdapter<BitwardenConfiguration>
{
    public const string ProviderType = "bitwarden";
    public const string AdapterVersion = "1.0";

    private sealed record Connection(BitwardenConfiguration Configuration, IAdapterStatusReporter Reporter);

    private readonly object _gate = new();
    private Connection? _active;

    protected override Task InitializeAsync(BitwardenConfiguration configuration, AdapterInitializationContext context,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        lock (_gate)
        {
            _active = new(configuration, context.StatusReporter);
            context.StatusReporter.Report(new LifecycleChangedEvent(AdapterLifecycleState.Ready));
        }

        return Task.CompletedTask;
    }

    protected override Task UpdateConfigurationAsync(BitwardenConfiguration configuration, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        lock (_gate)
        {
            if (_active is { } active)
            {
                _active = new(configuration, active.Reporter);
                active.Reporter.Report(new HealthChangedEvent(AdapterHealthState.Initializing));
                active.Reporter.Report(new InvalidateProviderDataEvent(InvalidateEntireProviderInstance: true));
            }
        }

        return Task.CompletedTask;
    }

    public override Task ShutdownAsync(CancellationToken cancellationToken)
    {
        lock (_gate)
        {
            _active = null;
        }

        return Task.CompletedTask;
    }

    protected override async Task<IReadOnlyList<ProviderValidationIssue>> ValidateConfigurationAsync(
        BitwardenConfiguration configuration, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        IReadOnlyList<ProviderValidationIssue> issues = ConfigurationIssues(configuration);
        if (issues.Count == 0)
        {
            try
            {
                BitwardenCli cli = Open(configuration, cancellationToken);
                await cli.ReadJsonAsync(["project", "list"], root => root.EnumerateArray().Select(project => ReadId(project, "id")).ToArray(),
                    cancellationToken).ConfigureAwait(false);
            }
            catch (ProviderAdapterException error) when (error.Kind == ProviderErrorKind.AuthenticationFailed)
            {
                return [new("Bitwarden could not use this access token with the selected server.", ValidationSeverity.Error, "bitwardenToken")];
            }
        }

        return issues;
    }

    protected override async Task<IReadOnlyList<ProviderValidationIssue>> ValidateMountAsync(
        BitwardenConfiguration configuration, string basePath, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        string[] path = basePath.Split('/');
        Guid secret = default;
        if (path.Length > 2 || !TryProject(path[0], out Guid project)
            || (path.Length == 2 && !TrySecret(path[1], out secret)))
        {
            return [new("Use a Bitwarden project UUID, optionally followed by /S_ and a 32-digit secret UUID.",
                ValidationSeverity.Error, "basePath")];
        }

        BitwardenCli cli = Open(configuration, cancellationToken);
        try
        {
            if (path.Length == 1)
            {
                await cli.ReadJsonAsync(["project", "get", project.ToString("D")], root =>
                    ReadId(root, "id") == project ? true : throw BitwardenCli.InvalidResponse(), cancellationToken).ConfigureAwait(false);
            }
            else
            {
                bool exists = await ReadSecretAsync(cli, secret, row => ReadProjects(row).Contains(project), cancellationToken).ConfigureAwait(false);
                if (!exists)
                {
                    return [new("The Bitwarden project does not contain that secret.", ValidationSeverity.Error, "basePath")];
                }
            }
        }
        catch (ProviderAdapterException error) when (error.Kind == ProviderErrorKind.SecretNotFound)
        {
            // bws answers 404 for an unknown project or secret: a finding about the mount, not a failure to validate.
            return [new(path.Length == 1 ? "The Bitwarden project was not found." : "The Bitwarden secret was not found.", ValidationSeverity.Error, "basePath")];
        }

        return [];
    }

    public override async Task<IReadOnlyList<ProviderSecretResult>> RetrieveSecretsAsync(
        IReadOnlyList<ProviderSecretRequest> requests, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var results = new ProviderSecretResult[requests.Count];
        var pending = new List<(int Index, Guid Project, Guid Secret)>();
        for (int index = 0; index < requests.Count; index++)
        {
            string[] path = requests[index].Path.Split('/');
            if (path.Length == 2 && TryProject(path[0], out Guid project) && TrySecret(path[1], out Guid secret))
            {
                pending.Add((index, project, secret));
            }
            else
            {
                results[index] = new(requests[index].RequestId, null, ProviderErrorKind.InvalidConfiguration);
            }
        }

        if (pending.Count == 0)
        {
            return results;
        }

        Connection connection = Active();
        try
        {
            BitwardenCli cli = Open(connection.Configuration, cancellationToken);
            // bws supports one ID per get: one process per secret, a few at a time, each task writing only its own result slots.
            using var slots = new SemaphoreSlim(ProviderPolicy.CommandConcurrency);
            var failures = new System.Collections.Concurrent.ConcurrentQueue<ProviderAdapterException>();
            using var batch = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            ProviderAdapterException? fatal = null;
            async Task ReadGroupAsync(IGrouping<Guid, (int Index, Guid Project, Guid Secret)> group)
            {
                await slots.WaitAsync(batch.Token).ConfigureAwait(false);
                try
                {
                    await ReadSecretAsync(cli, group.Key, row =>
                    {
                        Guid[] projects = ReadProjects(row);
                        foreach (var item in group)
                        {
                            Guid requestId = requests[item.Index].RequestId;
                            results[item.Index] = projects.Contains(item.Project)
                                ? ReadValue(requestId, row)
                                : new(requestId, null, ProviderErrorKind.SecretNotFound);
                        }

                        return true;
                    }, batch.Token).ConfigureAwait(false);
                }
                catch (ProviderAdapterException error) when (error.Kind is not (ProviderErrorKind.InvalidConfiguration or ProviderErrorKind.InteractionRequired))
                {
                    failures.Enqueue(error);
                    foreach (var item in group)
                    {
                        results[item.Index] = new(requests[item.Index].RequestId, null, error.Kind);
                    }
                }
                catch (ProviderAdapterException error)
                {
                    Interlocked.CompareExchange(ref fatal, error, null);
                    await batch.CancelAsync().ConfigureAwait(false);
                    throw;
                }
                finally
                {
                    slots.Release();
                }
            }

            try
            {
                await Task.WhenAll(pending.GroupBy(item => item.Secret).Select(ReadGroupAsync)).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (fatal is not null && !cancellationToken.IsCancellationRequested)
            {
                throw fatal;
            }

            cancellationToken.ThrowIfCancellationRequested();
            cli.EnsureUnlocked();

            // One health report per batch: the first failure about the provider (a gone secret is not one), else healthy.
            ProviderAdapterException? first = failures.FirstOrDefault(error => ProviderPolicy.SaysAboutProvider(error.Kind));
            if (first is not null)
            {
                ReportFailure(connection, first);
            }
            else
            {
                ReportHealth(connection, AdapterHealthState.Healthy);
            }

            ReportRemoved(connection, requests, results);
            return results;
        }
        catch (Exception failure)
        {
            foreach (ProviderSecretResult? result in results)
            {
                if (result?.Secret is { } secret)
                {
                    CryptographicOperations.ZeroMemory(secret.Value);
                }
            }

            if (failure is ProviderAdapterException error)
            {
                ReportFailure(connection, error);
            }

            throw;
        }
    }

    /// <summary>A secret the provider says is gone: its cached value and the grants that name it end.</summary>
    private void ReportRemoved(Connection connection, IReadOnlyList<ProviderSecretRequest> requests, ProviderSecretResult[] results)
    {
        string[] removed = [.. results.Where(result => result?.ErrorKind == ProviderErrorKind.SecretNotFound)
            .Select(result => result.RequestId)
            .Join(requests, id => id, request => request.RequestId, (_, request) => request.Path)
            .Distinct(StringComparer.Ordinal)];
        if (removed.Length == 0)
        {
            return;
        }

        lock (_gate)
        {
            if (ReferenceEquals(connection, _active))
            {
                connection.Reporter.Report(new InvalidateProviderDataEvent(ExternalSecretIds: removed));
            }
        }
    }

    private static Task<T> ReadSecretAsync<T>(BitwardenCli cli, Guid secret, Func<JsonElement, T> select, CancellationToken cancellationToken)
        => cli.ReadJsonAsync(["secret", "get", secret.ToString("D")], row =>
        {
            if (ReadId(row, "id") != secret)
            {
                throw BitwardenCli.InvalidResponse();
            }

            return select(row);
        }, cancellationToken);

    public override async Task<ListSecretsResult> ListSecretsAsync(ListSecretsRequest request, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        Guid secret = default;
        if (request.ContinuationToken is not null || !TryProject(request.Path, out Guid project)
            || (request.Filter is not null && !TrySecret(request.Filter, out secret)))
        {
            throw new ProviderAdapterException(ProviderErrorKind.InvalidConfiguration, "Invalid Bitwarden listing scope.");
        }

        Connection connection = Active();
        try
        {
            BitwardenCli cli = Open(connection.Configuration, cancellationToken);
            ProviderSecretInfo[] secrets;
            try
            {
                if (request.Filter is not null)
                {
                    secrets = await ReadSecretAsync<ProviderSecretInfo[]>(cli, secret,
                        row => ReadProjects(row).Contains(project) ? [SecretInfo(project, secret)] : [], cancellationToken).ConfigureAwait(false);
                }
                else
                {
                    secrets = await ListProjectAsync(cli, project, cancellationToken).ConfigureAwait(false);
                }
            }
            catch (ProviderAdapterException error) when (error.Kind == ProviderErrorKind.SecretNotFound)
            {
                // An unknown project or secret has nothing to list.
                secrets = [];
            }

            cancellationToken.ThrowIfCancellationRequested();
            cli.EnsureUnlocked();
            ReportHealth(connection, AdapterHealthState.Healthy);
            return new(secrets, null, IsComplete: true);
        }
        catch (ProviderAdapterException error)
        {
            ReportFailure(connection, error);
            throw;
        }
    }

    private static Task<ProviderSecretInfo[]> ListProjectAsync(BitwardenCli cli, Guid project, CancellationToken cancellationToken)
        => cli.ReadJsonAsync(["secret", "list", project.ToString("D")], root =>
        {
            var ids = new HashSet<Guid>();
            foreach (JsonElement row in root.EnumerateArray())
            {
                cancellationToken.ThrowIfCancellationRequested();
                if (!ReadProjects(row).Contains(project) || !ids.Add(ReadId(row, "id")))
                {
                    throw BitwardenCli.InvalidResponse();
                }
            }

            return ids.Select(id => SecretInfo(project, id)).OrderBy(secret => secret.Path, StringComparer.Ordinal).ToArray();
        }, cancellationToken);

    private static ProviderSecretInfo SecretInfo(Guid project, Guid secret)
    {
        string leaf = "S_" + secret.ToString("N");
        return new(leaf, project.ToString("D") + "/" + leaf, null);
    }

    private static Guid[] ReadProjects(JsonElement row)
    {
        if (row.TryGetProperty("projectIds", out JsonElement projects))
        {
            return projects.EnumerateArray().Select(ReadUuid).ToArray();
        }

        JsonElement project = row.GetProperty("projectId");
        return project.ValueKind == JsonValueKind.Null ? [] : [ReadUuid(project)];
    }

    private static Guid ReadId(JsonElement row, string name) => ReadUuid(row.GetProperty(name));

    private static Guid ReadUuid(JsonElement id)
        => id.TryGetGuid(out Guid parsed) && parsed != Guid.Empty ? parsed : throw BitwardenCli.InvalidResponse();

    private static ProviderSecretResult ReadValue(Guid requestId, JsonElement row)
    {
        try
        {
            if (row.TryGetProperty("value", out JsonElement value) && value.ValueKind == JsonValueKind.String)
            {
                return new(requestId, new RetrieveSecretResult(Encoding.UTF8.GetBytes(value.GetString()!)));
            }
        }
        catch (InvalidOperationException)
        {
            // The JSON string may contain an invalid Unicode escape.
        }

        return new(requestId, null, ProviderErrorKind.InvalidResponse);
    }

    private static bool TryProject(string path, out Guid project)
        => Guid.TryParseExact(path, "D", out project) && project != Guid.Empty && path == project.ToString("D");

    private static bool TrySecret(string path, out Guid secret)
    {
        secret = default;
        return path.Length == 34 && path.StartsWith("S_", StringComparison.Ordinal)
            && Guid.TryParseExact(path.AsSpan(2), "N", out secret) && secret != Guid.Empty && path == "S_" + secret.ToString("N");
    }

    private IReadOnlyList<ProviderValidationIssue> ConfigurationIssues(BitwardenConfiguration configuration)
    {
        List<ProviderValidationIssue> issues = [];
        if (!Path.IsPathFullyQualified(executablePath) || !File.Exists(executablePath))
        {
            issues.Add(new("Install bws on the authority service's PATH and restart the service.", ValidationSeverity.Error));
        }

        if (!JweCipher.IsCiphertext(configuration.EncryptedConfiguration))
        {
            issues.Add(new("Enter a Bitwarden access token.", ValidationSeverity.Error, "bitwardenToken"));
        }

        if (BitwardenConfiguration.ParseServerUrl(configuration.ServerUrl) is null)
        {
            issues.Add(new("Specify an absolute HTTPS Bitwarden server URL without credentials, a query, or a fragment.",
                ValidationSeverity.Error, "serverUrl"));
        }

        return issues;
    }

    private BitwardenCli Open(BitwardenConfiguration configuration, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (ConfigurationIssues(configuration).Count != 0)
        {
            throw new ProviderAdapterException(ProviderErrorKind.InvalidConfiguration, "Bitwarden configuration is invalid.");
        }

        CancellationToken session = unlockedSession();
        BitwardenCli.EnsureUnlocked(session);
        Uri server = BitwardenConfiguration.ParseServerUrl(configuration.ServerUrl)!;
        string? token = BitwardenConfiguration.ReadToken(decryptConfiguration(configuration.EncryptedConfiguration), server);
        if (string.IsNullOrWhiteSpace(token) || token.Contains('\0'))
        {
            throw new ProviderAdapterException(ProviderErrorKind.AuthenticationFailed, "The Bitwarden credential is missing or invalid.");
        }

        return new BitwardenCli(executablePath, token, server, session);
    }

    private Connection Active()
    {
        lock (_gate)
        {
            return _active ?? throw new ProviderAdapterException(ProviderErrorKind.InvalidConfiguration, "The Bitwarden adapter is inactive.");
        }
    }

    private void ReportFailure(Connection connection, ProviderAdapterException error)
    {
        if (ProviderPolicy.SaysAboutProvider(error.Kind))
        {
            ReportHealth(connection, ProviderPolicy.HealthFor(error.Kind));
        }
    }

    private void ReportHealth(Connection connection, AdapterHealthState health)
    {
        lock (_gate)
        {
            if (ReferenceEquals(connection, _active))
            {
                connection.Reporter.Report(new HealthChangedEvent(health));
            }
        }
    }
}
