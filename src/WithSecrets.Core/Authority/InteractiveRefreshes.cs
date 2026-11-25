using System.Security.Cryptography;
using System.Buffers.Text;
using System.Text;
using System.Text.Json;

namespace WithSecrets;

internal sealed record InteractiveRefreshMapping(string ProviderPath, string LocalName);

internal sealed record InteractiveRefreshView(Guid Id, string State, string RequestedBy,
    string ProviderName, string Account, string Region, DateTimeOffset Expires, IReadOnlyList<InteractiveRefreshMapping> Mappings);

internal sealed record InteractiveRefreshLaunched(InteractiveRefreshView Refresh, string EncryptedCode);

/// <summary>Owns in-memory refreshes from terminal launch through passkey approval or cancellation.</summary>
internal sealed class InteractiveRefreshes(ProviderAuthority providers, AdminAudit audit, AuthorityKeyRing keys, TimeProvider clock,
    Func<string?> storePublicKey, Func<InteractiveProviderRefreshRequest, ISigningKey, CancellationToken, Task<IInteractiveProviderRefresh>> launch)
{
    private static readonly TimeSpan Lifetime = TimeSpan.FromMinutes(4);
    private readonly Lock _gate = new();
    private readonly Dictionary<Guid, Flow> _flows = [];

    private sealed class Flow(InteractiveProviderRefreshRequest request, string owner, long generation, int revision,
        IReadOnlyDictionary<string, string> pathToExternal)
    {
        public InteractiveProviderRefreshRequest Request { get; } = request;
        public string Owner { get; } = owner;
        public long Generation { get; } = generation;
        public int Revision { get; } = revision;
        public IReadOnlyDictionary<string, string> PathToExternal { get; } = pathToExternal;
        public CancellationTokenSource Stop { get; } = new();
        public bool Launched { get; set; }
        public Stage? Staged { get; set; }
        public bool Failed { get; set; }
    }

    private sealed record Stage(DateTimeOffset Verified, string Digest, IReadOnlyDictionary<string, string> Ciphertexts);

    public async Task<InteractiveRefreshLaunched> StartAsync(Guid instanceId, AdminSession session, RSA browserKey, CancellationToken cancel)
    {
        // Take the baseline before reading instance or namespace data, just as the regular retrieval path does.
        long generation = providers.Store.Generation(instanceId);
        ProviderInstance? instance = providers.Store.Instance(instanceId);
        if (instance is null || instance.MaxStale <= TimeSpan.Zero || providers.InteractiveAdapter(instanceId) is not { } adapter)
            throw Refusal("This provider instance does not support interactive refresh with its current cache policy.");

        (string account, bool european) = adapter.ReadAccount(instance.Configuration);
        IReadOnlyList<Mount> mounts = [.. providers.Store.Mounts().Where(mount => mount.InstanceId == instanceId)];
        NamespaceEntry[] entries = [.. mounts.SelectMany(mount => providers.Store.Entries(mount.Id)).OrderBy(entry => entry.LogicalPath, StringComparer.Ordinal)];
        if (entries.Length is < 1 or > 100 || entries.Length != mounts.Count
            || entries.GroupBy(entry => entry.ProviderPath, StringComparer.Ordinal).Any(group => group.Select(entry => entry.ExternalId).Distinct(StringComparer.Ordinal).Count() != 1))
            throw Refusal("Mount between 1 and 100 individual provider fields before refreshing.");

        string? publicKey = storePublicKey();
        if (string.IsNullOrEmpty(publicKey))
            throw Refusal("The WithSecrets store needs a key before it can stage a refresh.");
        if (providers.Store.Generation(instanceId) != generation)
            throw Refusal("The provider mounts changed. Start the refresh again.");

        InteractiveProviderRefreshRequest request = new(Guid.NewGuid(), instanceId, session.Identity, instance.Name,
            account, european, clock.GetUtcNow() + Lifetime, publicKey,
            [.. entries.Select(entry => (entry.ProviderPath, entry.LogicalPath))]);
        Dictionary<string, string> pathToExternal = entries.GroupBy(entry => entry.ProviderPath, StringComparer.Ordinal)
            .ToDictionary(group => group.Key, group => group.First().ExternalId, StringComparer.Ordinal);
        if (pathToExternal.Values.Distinct(StringComparer.Ordinal).Count() != pathToExternal.Count)
            throw Refusal("The provider returned ambiguous field mappings.");
        Flow flow = new(request, session.Id, generation, instance.Revision, pathToExternal);
        CancellationToken lifetime = flow.Stop.Token;
        lock (_gate)
        {
            if (providers.Cache.IsLocked || _flows.Count >= AdminSessions.MaxSessions
                || _flows.Values.Any(item => item.Request.InstanceId == instanceId))
            {
                flow.Stop.Dispose();
                throw Refusal("A refresh cannot start now. Check the authority or wait for the current refresh to end.");
            }
            _flows.Add(request.Id, flow);
        }
        _ = ExpireAsync(request.Id, lifetime);

        IInteractiveProviderRefresh? connection = null;
        try
        {
            using CancellationTokenSource startup = CancellationTokenSource.CreateLinkedTokenSource(lifetime, cancel);
            connection = await launch(request, keys.Current(), startup.Token).ConfigureAwait(false);
            byte[] code = Encoding.ASCII.GetBytes(connection.MatchingCode);
            string encryptedCode;
            try { encryptedCode = Base64Url.EncodeToString(browserKey.Encrypt(code, RSAEncryptionPadding.OaepSHA256)); }
            finally { CryptographicOperations.ZeroMemory(code); }
            startup.Token.ThrowIfCancellationRequested();
            lock (_gate)
            {
                if (!_flows.ContainsKey(request.Id)) throw new OperationCanceledException(lifetime);
                flow.Launched = true;
            }
            _ = ReceiveAsync(flow, connection, lifetime);
            connection = null;
            return new InteractiveRefreshLaunched(View(request.Id, session) ?? throw new OperationCanceledException(lifetime), encryptedCode);
        }
        catch
        {
            Remove(request.Id, session.Id);
            throw;
        }
        finally { connection?.Dispose(); }
    }

    public InteractiveRefreshView? View(Guid id, AdminSession owner)
    {
        lock (_gate)
        {
            if (!Find(id, owner.Id, out Flow? flow) || !flow!.Launched) return null;
            InteractiveProviderRefreshRequest request = flow.Request;
            return new InteractiveRefreshView(id, flow.Failed ? "stopped" : flow.Staged is null ? "waiting" : "ready",
                request.RequestedBy, request.ProviderName, request.Account, request.European ? "lastpass.eu" : "lastpass.com",
                request.Expires, [.. request.Mappings.Select(mapping => new InteractiveRefreshMapping(mapping.Path, mapping.LocalName))]);
        }
    }

    public bool Cancel(Guid id, AdminSession owner) => Remove(id, owner.Id) is not null;

    public void CancelAll()
    {
        Flow[] flows;
        lock (_gate)
        {
            flows = [.. _flows.Values];
            _flows.Clear();
        }
        foreach (Flow flow in flows) Stop(flow);
    }

    public void CancelSession(string owner)
    {
        Guid[] ids;
        lock (_gate) ids = [.. _flows.Where(entry => entry.Value.Owner == owner).Select(entry => entry.Key)];
        foreach (Guid id in ids) Remove(id, owner);
    }

    public bool TryDescribe(Guid id, AdminSession owner, out string sentence, out (string, string)[] parameters)
    {
        lock (_gate)
        {
            if (!Find(id, owner.Id, out Flow? flow) || flow!.Staged is not { } stage)
            {
                sentence = "";
                parameters = [];
                return false;
            }
            InteractiveProviderRefreshRequest request = flow.Request;
            sentence = $"refresh the encrypted values of {request.ProviderName} for {request.Account}. "
                + $"Requested by {request.RequestedBy}. The mounted fields are "
                + string.Join(", ", request.Mappings.Select(mapping => $"{mapping.LocalName} from {mapping.Path}"));
            parameters = [("id", id.ToString("D")), ("instance", request.InstanceId.ToString("D")),
                ("encrypted-batch-sha256", stage.Digest)];
            return true;
        }
    }

    public string? Commit(Guid id, AdminSession owner, string digest, string signer)
    {
        Flow? flow = Remove(id, owner.Id);
        if (flow?.Staged is not { } stage || stage.Digest != digest || flow.Request.Expires <= clock.GetUtcNow())
            return "The staged refresh expired or was already used. Start a new refresh.";

        InteractiveProviderRefreshRequest request = flow.Request;
        ProviderInstance? current = providers.Store.Instance(request.InstanceId);
        DateTimeOffset now = clock.GetUtcNow();
        if (current is null || current.Revision != flow.Revision || providers.Store.Generation(request.InstanceId) != flow.Generation
            || now < stage.Verified || !ProviderPolicy.WithinStaleWindow(now - stage.Verified, current.MaxStale))
            return "The provider or its mounts changed, or the staged values are too old. Start a new refresh.";

        CacheWrite written = providers.Cache.PutInteractive(request.InstanceId, stage.Ciphertexts, stage.Verified,
            request.StorePublicKey, flow.Generation, (connection, transaction) => audit.Append(connection, transaction,
                AdminEvent.Provider("provider-values-refreshed", [.. request.Mappings.Select(mapping => mapping.LocalName)],
                    $"refreshed {request.ProviderName} ({request.InstanceId:D})", signer)));
        return written == CacheWrite.Written ? null : "The provider cache changed. Start a new refresh.";
    }

    private async Task ReceiveAsync(Flow flow, IInteractiveProviderRefresh connection, CancellationToken cancel)
    {
        try
        {
            using (connection)
            {
                IReadOnlyDictionary<string, string> selected = await connection.ReceiveAsync(cancel).ConfigureAwait(false);
                if (selected.Count != flow.PathToExternal.Count
                    || flow.PathToExternal.Keys.Any(path => !selected.TryGetValue(path, out string? value)
                        || value is null || !JweCipher.IsCiphertext(value)))
                    throw Refusal("The terminal returned an invalid encrypted selection.");
                // The passkey signs a digest over the sorted store rows, the exact mapping, and the store public key.
                Dictionary<string, string> ciphertexts = flow.PathToExternal.OrderBy(item => item.Value, StringComparer.Ordinal)
                    .ToDictionary(item => item.Value, item => selected[item.Key], StringComparer.Ordinal);
                string digest = Convert.ToHexStringLower(SHA256.HashData(JsonSerializer.SerializeToUtf8Bytes(new
                {
                    flow.Request.InstanceId, flow.Request.StorePublicKey,
                    mappings = flow.Request.Mappings.Select(item => new { item.Path, item.LocalName }),
                    ciphertexts,
                })));
                lock (_gate)
                {
                    if (Find(flow.Request.Id, flow.Owner, out _)) flow.Staged = new Stage(clock.GetUtcNow(), digest, ciphertexts);
                }
            }
        }
        catch (Exception error) when (error is not OutOfMemoryException)
        {
            lock (_gate)
            {
                if (Find(flow.Request.Id, flow.Owner, out _)) flow.Failed = true;
            }
        }
    }

    private async Task ExpireAsync(Guid id, CancellationToken cancel)
    {
        try { await Task.Delay(Lifetime, clock, cancel).ConfigureAwait(false); }
        catch (OperationCanceledException) { return; }
        Remove(id, null);
    }

    private bool Find(Guid id, string owner, out Flow? flow) => _flows.TryGetValue(id, out flow)
        && flow.Owner == owner && flow.Request.Expires > clock.GetUtcNow();

    private Flow? Remove(Guid id, string? owner)
    {
        Flow? flow;
        lock (_gate)
        {
            if (!_flows.TryGetValue(id, out flow) || (owner is not null && owner != flow.Owner)) return null;
            _flows.Remove(id);
        }
        Stop(flow);
        return flow;
    }

    private static void Stop(Flow flow)
    {
        flow.Stop.Cancel();
        flow.Stop.Dispose();
    }

    private static ProviderConfigurationException Refusal(string detail) => new(detail);
}
