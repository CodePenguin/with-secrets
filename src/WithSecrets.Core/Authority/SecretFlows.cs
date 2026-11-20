using System.Buffers.Text;
using System.Security.Cryptography;
using System.Text.Json;

namespace WithSecrets;

/// <summary>One name of a secret entry: <see cref="Replace" /> when a secret of that name is stored already.</summary>
public sealed record SecretField(string Name, bool Replace);

/// <summary>What the browser needs to enter secrets: the text the passkey will sign, the passkey request and the key the values are sealed to (public).</summary>
public sealed record SecretEntryDto(string Id, string Text, IReadOnlyList<SecretField> Fields, JsonElement Payload, string PublicKey, DateTimeOffset Expires);

/// <summary>What the browser needs to remove secrets: the text, the exact next state the passkey will sign, and the passkey request.</summary>
public sealed record SecretRemovalDto(string Id, string Text, string Manifest, JsonElement Payload, DateTimeOffset Expires);

/// <summary>What the browser needs to change the page settings: the text, the exact next state the passkey will sign, and the passkey request.</summary>
public sealed record SettingsChangeDto(string Id, string Text, string Manifest, JsonElement Payload, DateTimeOffset Expires);

/// <summary>
/// Changes to the secret store made in the administration web app: the same protocol as the set page of the command line, with the same
/// checks, hosted by the service. Values are sealed in the browser to a key that lives here (the page and the network never carry a value
/// in the clear), the program checks them and encrypts each to the store key, and one admin passkey assertion over the values and the new
/// state stores them. A removal is one admin assertion over the next state. Each entry belongs to the session that made it, lives for a few
/// minutes, and ends at its first outcome; the number of open entries is small.
/// </summary>
internal sealed class SecretFlows(SecretStore store, AdminAudit audit, Func<IProofMethod?> proof, TimeProvider clock) : IDisposable
{
    public static readonly TimeSpan Lifetime = TimeSpan.FromMinutes(5);

    /// <summary>How often an expired entry is found and closed when nobody calls: an abandoned entry lives at most <see cref="Lifetime" /> plus this.</summary>
    public static readonly TimeSpan SweepEvery = TimeSpan.FromSeconds(5);
    public const int MaxOpen = 4;
    public const string RemoveCommand = "secrets-removed";
    public const string SettingsCommand = "settings-changed";

    private readonly Lock _gate = new();
    private readonly Dictionary<string, Flow> _flows = new(StringComparer.Ordinal);
    private ITimer? _sweeper;

    private abstract class Flow(string id, string sessionId, DateTimeOffset expires, IReadOnlyList<string> names)
    {
        public string Id { get; } = id;
        public string SessionId { get; } = sessionId;
        public DateTimeOffset Expires { get; } = expires;
        public IReadOnlyList<string> Names { get; } = names;

        private int _closed;

        /// <summary>Ends the flow. Whoever calls first does it; every later call finds it done.</summary>
        public void Close()
        {
            if (Interlocked.Exchange(ref _closed, 1) == 0)
            {
                Release();
            }
        }

        protected abstract void Release();
    }

    private sealed class SetFlow(string id, string sessionId, DateTimeOffset expires, IReadOnlyList<string> names, SecretEntry.Session session) : Flow(id, sessionId, expires, names)
    {
        public SecretEntry.Session Session { get; } = session;

        protected override void Release()
        {
            Session.Handle("POST", "deny", "");
            Session.Close();
        }
    }

    private sealed class RemoveFlow(string id, string sessionId, DateTimeOffset expires, IReadOnlyList<string> names, IProofMethod method, Manifest current, Manifest next, byte[] bind, string origin) : Flow(id, sessionId, expires, names)
    {
        /// <summary>True for a change of the page settings: it carries no names, and only <see cref="SaveSettings" /> may finish it.</summary>
        public bool ForSettings { get; init; }

        public IProofMethod Method { get; } = method;
        public Manifest Current { get; } = current;
        public Manifest Next { get; } = next;
        public byte[] Bind { get; } = bind;
        public string Origin { get; } = origin;
        public bool Done { get; set; }

        protected override void Release() => Done = true;
    }

    /// <summary>The names of the stored secrets (names only), or why they cannot be read.</summary>
    public (IReadOnlyList<string>? Names, string? Problem) List()
    {
        try
        {
            (_, IReadOnlyList<string> names) = store.Current();

            return ([.. names.Order(StringComparer.Ordinal)], null);
        }
        catch (SecretStoreException failure)
        {
            return (null, "cannot use the secret store: " + failure.Message);
        }
    }

    /// <summary>Starts an entry of values for these names. Nothing is stored until the passkey tap.</summary>
    public (SecretEntryDto? Entry, string? Problem) StartSet(IReadOnlyList<string> names, string sessionId, string origin)
    {
        if (SecretEntry.CheckNames(names) is { } refused)
        {
            return (null, refused.Detail);
        }

        IProofMethod? method = AdminMethod();
        if (method is null)
        {
            return (null, "no passkey proof method is available");
        }

        try
        {
            (Manifest? manifest, IReadOnlyList<string> storedNames) = store.Current();
            if (manifest is null)
            {
                return (null, PasskeyRegistration.NothingEnrolled);
            }

            if (manifest.Store.Length == 0)
            {
                return (null, "the state has no secret store key; set up again with: with-secrets admin");
            }

            HashSet<string> stored = [.. storedNames];
            string text = SecretEntry.SetText(names, stored, method);
            string nonce = Base64Url.EncodeToString(RandomNumberGenerator.GetBytes(16));
            byte[] bind = RequestBinding.Compute(nonce, text);
            ProofStart start = method.Start(new ProofContext(bind, origin));
            (byte[] serverKey, string publicKey) = SecretCrypto.NewServerKey();
            SecretEntry.Session session = new(method, store, manifest, manifest.Store, [.. names], serverKey);
            session.Open(origin, bind);
            string id = NewId();
            DateTimeOffset expires = clock.GetUtcNow() + Lifetime;
            if (!Add(new SetFlow(id, sessionId, expires, [.. names], session)))
            {
                session.Close();

                return (null, "too many secret entries are open; finish or cancel one first");
            }

            using JsonDocument payload = JsonDocument.Parse(start.Payload);

            return (new SecretEntryDto(id, text, [.. names.Select(name => new SecretField(name, stored.Contains(name)))], payload.RootElement.Clone(), publicKey, expires), null);
        }
        catch (ProofUnavailableException failure)
        {
            return (null, failure.Message);
        }
        catch (SecretStoreException failure)
        {
            return (null, "cannot use the secret store: " + failure.Message);
        }
    }

    /// <summary>The sealed values the browser typed, to be checked and prepared. Answers as the set page does (status and JSON body).</summary>
    public (int Status, string Body)? Seal(string id, string sessionId, string body)
    {
        return Find<SetFlow>(id, sessionId) is { } flow ? Relay(flow.Session.Handle("POST", "seal", body)) : null;
    }

    /// <summary>The passkey assertion over the values and the new state. Ends the entry.</summary>
    public (int Status, string Body)? SaveSet(string id, string sessionId, string body)
    {
        if (Find<SetFlow>(id, sessionId) is not { } flow)
        {
            return null;
        }

        (int Status, string Body) answer = Relay(flow.Session.Handle("POST", "save", body));
        End(flow);
        if (answer.Status != 200)
        {
            audit.TryWriteDenied("set-secrets", [.. flow.Names.Where(SecretNames.IsValid)], "the entry in the web app ended without storing (" + answer.Status.ToString(System.Globalization.CultureInfo.InvariantCulture) + ")");
        }

        return answer;
    }

    /// <summary>Starts the removal of these stored secrets: the passkey signs the next state, without them.</summary>
    public (SecretRemovalDto? Removal, string? Problem) StartRemove(IReadOnlyList<string> names, string sessionId, string origin)
    {
        if (SecretEntry.CheckNames(names) is { } refused)
        {
            return (null, refused.Detail);
        }

        IProofMethod? method = AdminMethod();
        if (method is null)
        {
            return (null, "no passkey proof method is available");
        }

        try
        {
            (Manifest? manifest, IReadOnlyList<string> storedNames) = store.Current();
            if (manifest is null)
            {
                return (null, PasskeyRegistration.NothingEnrolled);
            }

            HashSet<string> stored = [.. storedNames];
            List<string> unknown = [.. names.Where(name => !stored.Contains(name))];
            if (unknown.Count > 0)
            {
                return (null, "Unknown secret: " + string.Join(", ", unknown));
            }

            Manifest next = SecretStore.Next(manifest, manifest.Store, new Dictionary<string, string>(), names);
            string text = "Remove these secrets: " + string.Join(", ", names) + ". They will be deleted.";
            string nonce = Base64Url.EncodeToString(RandomNumberGenerator.GetBytes(16));
            byte[] bind = RequestBinding.Compute(nonce, text);
            ProofStart start = method.Start(new ProofContext(bind, origin));
            string id = NewId();
            DateTimeOffset expires = clock.GetUtcNow() + Lifetime;
            if (!Add(new RemoveFlow(id, sessionId, expires, [.. names], method, manifest, next, bind, origin)))
            {
                return (null, "too many secret entries are open; finish or cancel one first");
            }

            using JsonDocument payload = JsonDocument.Parse(start.Payload);

            return (new SecretRemovalDto(id, text, next.Canonical(), payload.RootElement.Clone(), expires), null);
        }
        catch (ProofUnavailableException failure)
        {
            return (null, failure.Message);
        }
        catch (SecretStoreException failure)
        {
            return (null, "cannot use the secret store: " + failure.Message);
        }
    }

    /// <summary>The passkey assertion over the next state. Deletes the secrets with it, in one transaction. Ends the removal.</summary>
    public (int Status, string Detail)? SaveRemove(string id, string sessionId, string assertion)
    {
        if (Find<RemoveFlow>(id, sessionId) is not { ForSettings: false } flow)
        {
            return null;
        }

        try
        {
            if (flow.Done)
            {
                return (404, "this removal has ended");
            }

            flow.Done = true;
            ProofResult result;
            try
            {
                result = flow.Method.Verify(new ProofContext(Manifest.Challenge(flow.Bind, flow.Next.Canonical()), flow.Origin), assertion);
            }
            catch (Exception)
            {
                result = new ProofResult(false, "the proof could not be checked");
            }

            if (!result.Ok)
            {
                audit.TryWriteDenied("remove-secrets", [.. flow.Names.Where(SecretNames.IsValid)], "the proof was not accepted");

                return (403, "the proof was not accepted; nothing was removed");
            }

            SignedManifest signed = new(flow.Next.Canonical(), flow.Bind, assertion);
            string? written = store.TryApply(flow.Current.Version, signed, new Dictionary<string, string>(), [.. flow.Names], AdminEvent.Secrets(RemoveCommand, [.. flow.Names], result.Detail, AdminAudit.KeyName(result.Detail)));

            return written is null ? (200, "Removed " + string.Join(", ", flow.Names) + ".") : (500, written);
        }
        finally
        {
            End(flow);
        }
    }

    /// <summary>The settings of the pages this machine serves (the ceiling of a grant time, the address, the port, the time limit), or why they cannot be read.</summary>
    public (ToolSettings? Settings, string? Problem) PageSettings()
    {
        try
        {
            (Manifest? manifest, _) = store.Current();

            return manifest is null ? (null, PasskeyRegistration.NothingEnrolled) : (manifest.Settings, null);
        }
        catch (SecretStoreException failure)
        {
            return (null, "cannot use the secret store: " + failure.Message);
        }
    }

    /// <summary>Starts a change of the page settings: the passkey signs the next state, which differs only in the settings.</summary>
    public (SettingsChangeDto? Change, string? Problem) StartSettings(ToolSettings requested, string sessionId, string origin)
    {
        if (requested.Problem() is { } invalid)
        {
            return (null, invalid);
        }

        IProofMethod? method = AdminMethod();
        if (method is null)
        {
            return (null, "no passkey proof method is available");
        }

        try
        {
            (Manifest? manifest, _) = store.Current();
            if (manifest is null)
            {
                return (null, PasskeyRegistration.NothingEnrolled);
            }

            IReadOnlyList<SettingChange> changes = manifest.Settings.Changes(requested);
            if (changes.Count == 0)
            {
                return (null, "Nothing is changed.");
            }

            Manifest next = manifest.WithSettings(requested);
            string text = "Change the page settings: " + string.Join("; ", changes.Select(change => $"{change.Name} {change.Old} -> {change.New}")) + ".";
            string nonce = Base64Url.EncodeToString(RandomNumberGenerator.GetBytes(16));
            byte[] bind = RequestBinding.Compute(nonce, text);
            ProofStart start = method.Start(new ProofContext(bind, origin));
            string id = NewId();
            DateTimeOffset expires = clock.GetUtcNow() + Lifetime;
            if (!Add(new RemoveFlow(id, sessionId, expires, [], method, manifest, next, bind, origin) { ForSettings = true }))
            {
                return (null, "too many changes are open; finish or cancel one first");
            }

            using JsonDocument payload = JsonDocument.Parse(start.Payload);

            return (new SettingsChangeDto(id, text, next.Canonical(), payload.RootElement.Clone(), expires), null);
        }
        catch (ProofUnavailableException failure)
        {
            return (null, failure.Message);
        }
        catch (SecretStoreException failure)
        {
            return (null, "cannot use the secret store: " + failure.Message);
        }
    }

    /// <summary>The passkey assertion over the next state. Writes the state and the audit event in one transaction. Ends the change.</summary>
    public (int Status, string Detail)? SaveSettings(string id, string sessionId, string assertion)
    {
        if (Find<RemoveFlow>(id, sessionId) is not { ForSettings: true } flow)
        {
            return null;
        }

        try
        {
            if (flow.Done)
            {
                return (404, "this change has ended");
            }

            flow.Done = true;
            ProofResult result;
            try
            {
                result = flow.Method.Verify(new ProofContext(Manifest.Challenge(flow.Bind, flow.Next.Canonical()), flow.Origin), assertion);
            }
            catch (Exception)
            {
                result = new ProofResult(false, "the proof could not be checked");
            }

            if (!result.Ok)
            {
                audit.TryWriteDenied(SettingsCommand, [], "the proof was not accepted");

                return (403, "the proof was not accepted; nothing was changed");
            }

            SignedManifest signed = new(flow.Next.Canonical(), flow.Bind, assertion);
            AdminEvent changed = AdminEvent.Settings(SettingsCommand, flow.Current.Settings.Changes(flow.Next.Settings), AdminAudit.KeyName(result.Detail));
            string? written = store.TryApply(flow.Current.Version, signed, new Dictionary<string, string>(), [], changed);

            return written is null ? (200, "Changed the page settings.") : (500, written);
        }
        finally
        {
            End(flow);
        }
    }

    /// <summary>Ends an entry without storing anything (the person left it).</summary>
    public bool Cancel(string id, string sessionId)
    {
        if (Find<Flow>(id, sessionId) is not { } flow)
        {
            return false;
        }

        End(flow);

        return true;
    }

    /// <summary>The page of an open entry (null for none), so that a test can see that its key and sealed values are gone once it ends.</summary>
    internal SecretEntry.Session? SessionOf(string id)
    {
        lock (_gate)
        {
            return _flows.TryGetValue(id, out Flow? flow) ? (flow as SetFlow)?.Session : null;
        }
    }

    /// <summary>The number of entries and removals open now.</summary>
    internal int OpenCount
    {
        get
        {
            lock (_gate)
            {
                return _flows.Count;
            }
        }
    }

    /// <summary>Ends every entry (the authority locked, or the service is stopping).</summary>
    public void CancelAll() => CloseWhere(_ => true);

    /// <summary>Ends the entries of a session that ended (sign out, timeout).</summary>
    public void CancelSession(string sessionId) => CloseWhere(flow => flow.SessionId == sessionId);

    /// <summary>Closes every entry that has run out of time. The timer calls this, so an abandoned entry loses its key and sealed values without another request.</summary>
    internal void Sweep()
    {
        DateTimeOffset now = clock.GetUtcNow();
        CloseWhere(flow => flow.Expires <= now);
    }

    public void Dispose()
    {
        _sweeper?.Dispose();
        CancelAll();
    }

    // Taken out of the table under the lock (so each is closed exactly once), closed outside it.
    private void CloseWhere(Func<Flow, bool> match)
    {
        List<Flow> taken = [];
        lock (_gate)
        {
            foreach (Flow flow in _flows.Values.Where(match).ToList())
            {
                _flows.Remove(flow.Id);
                taken.Add(flow);
            }
        }

        foreach (Flow flow in taken)
        {
            flow.Close();
        }
    }

    private IProofMethod? AdminMethod()
    {
        IProofMethod? method = proof();

        // Only an admin key may change the secret store.
        return method is PasskeyMethod passkey ? passkey.ForAdmin() : method;
    }

    private bool Add(Flow flow)
    {
        List<Flow> expired = [];
        lock (_gate)
        {
            DateTimeOffset now = clock.GetUtcNow();
            foreach (Flow old in _flows.Values.Where(item => item.Expires <= now).ToList())
            {
                _flows.Remove(old.Id);
                expired.Add(old);
            }

            if (_flows.Count >= MaxOpen)
            {
                foreach (Flow old in expired)
                {
                    old.Close();
                }

                return false;
            }

            _flows[flow.Id] = flow;
            // The first entry starts the sweep; with none open there is nothing to find.
            _sweeper ??= clock.CreateTimer(static state => ((SecretFlows)state!).Sweep(), this, SweepEvery, SweepEvery);
        }

        foreach (Flow old in expired)
        {
            old.Close();
        }

        return true;
    }

    private T? Find<T>(string id, string sessionId)
        where T : Flow
    {
        Flow? expired = null;
        T? found = null;
        lock (_gate)
        {
            if (_flows.TryGetValue(id, out Flow? flow) && flow.SessionId == sessionId)
            {
                if (flow.Expires <= clock.GetUtcNow())
                {
                    _flows.Remove(id);
                    expired = flow;
                }
                else
                {
                    found = flow as T;
                }
            }
        }

        expired?.Close();

        return found;
    }

    private void End(Flow flow)
    {
        lock (_gate)
        {
            _flows.Remove(flow.Id);
        }

        flow.Close();
    }

    private static string NewId() => Base64Url.EncodeToString(RandomNumberGenerator.GetBytes(18));

    private static (int Status, string Body) Relay(OneShotResponse response) => (response.Status, response.Body);
}
