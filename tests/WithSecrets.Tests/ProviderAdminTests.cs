using Microsoft.Extensions.Logging.Abstractions;

namespace WithSecrets.Tests;

/// <summary>The provider administration facade (10.3.1, 10.5): views, proposed-configuration validation, the configuration screen, namespace refresh and the store's beforeCommit.</summary>
internal static class ProviderAdminTests
{
    private static readonly VerifiedCredential Laptop = new("test-laptop-id", "laptop", true);

    private static readonly TimeSpan Hour = TimeSpan.FromHours(1);

    private sealed class CapturingAudit : IHostAudit
    {
        public List<AuditFacts> Events { get; } = [];

        /// <summary>When set, nothing can be committed (an outbox that cannot be written).</summary>
        public bool Fail { get; set; }

        public void RecordIn(Microsoft.Data.Sqlite.SqliteConnection connection, Microsoft.Data.Sqlite.SqliteTransaction transaction, AuditFacts facts)
        {
            if (Fail)
            {
                throw new AuditOutboxException("test audit refused");
            }
            WithSecretsDatabase.AfterCommit(transaction, () => TryRecord(facts));
        }

        public bool TryRecord(AuditFacts facts)
        {
            if (Fail)
            {
                return false;
            }

            Events.Add(facts);

            return true;
        }
    }

    private sealed class Rig : IDisposable
    {
        private readonly string _folder = Path.Combine(Path.GetTempPath(), "ws-provideradmin-" + Guid.NewGuid().ToString("N"));
        private readonly SoftwareSigningKey _machine = new();
        private readonly SoftwareSigningKey _signing = new();

        public Rig()
        {
            StateDatabase state = TestState.Seeded(Path.Combine(_folder, "state", WithSecretsDatabase.FileName));
            SecretStore native = new(state);
            if (SecretStoreTests.Put(native, new Dictionary<string, string> { ["NATIVE_ONE"] = "native" }) is { } problem)
            {
                throw new InvalidOperationException(problem);
            }

            Native = native;
            HostAuditOutbox outbox = HostAuditOutbox.InFolder(_folder, _machine);
            HostAudit hostAudit = new(outbox, new AuditUploader(outbox, () => throw new InvalidOperationException(), (_, _, _, _) => Task.FromResult<string?>(null), "fp"));
            AuthorityStore authority = AuthorityStore.InFolder(Path.Combine(_folder, "authority"));
            AuthorityKeyRing keys = new(authority, _ => _signing) { LockState = AuthorityLock.UnlockedForTests() };
            Registry.RegisterType("test", "1.0", () => Next ?? Adapter, () => new FakeConfiguration());
            Providers = new ProviderAuthority(native, authority, keys, Registry, hostAudit, TimeProvider.System);
            Admin = new ProviderAdmin(Providers, new AdminAudit(() => Captured, authority.Database));
        }

        public SecretStore Native { get; }

        public void Exec(string sql)
        {
            using Microsoft.Data.Sqlite.SqliteConnection connection = new("Data Source=" + Path.Combine(_folder, "authority", WithSecretsDatabase.FileName) + ";Pooling=False");
            connection.Open();
            using Microsoft.Data.Sqlite.SqliteCommand command = connection.CreateCommand();
            command.CommandText = sql;
            command.ExecuteNonQuery();
        }

        public long Count(string sql)
        {
            using Microsoft.Data.Sqlite.SqliteConnection connection = new("Data Source=" + Path.Combine(_folder, "authority", WithSecretsDatabase.FileName) + ";Pooling=False");
            connection.Open();
            using Microsoft.Data.Sqlite.SqliteCommand command = connection.CreateCommand();
            command.CommandText = sql;

            return Convert.ToInt64(command.ExecuteScalar());
        }

        public ProviderRegistry Registry { get; } = new();

        public FakeProviderAdapter Adapter { get; } = new();

        /// <summary>When set, the registered factory returns this adapter instead of <see cref="Adapter" />.</summary>
        public FakeProviderAdapter? Next { get; set; }

        public CapturingAudit Captured { get; } = new();

        public ProviderAuthority Providers { get; }

        public ProviderAdmin Admin { get; }

        public ProviderStore Store => Providers.Store;

        public async Task<ProviderInstance> Running(string name = "vault-one", string configuration = """{"label":"one"}""")
        {
            ProviderInstance instance = Store.AddInstance(name, "test", configuration, Hour);
            await Registry.AddInstanceAsync(instance.Id, "test", configuration, NullLogger.Instance, CancellationToken.None);

            return instance;
        }

        public void Dispose()
        {
            _machine.Dispose();
            _signing.Dispose();
            try
            {
                Directory.Delete(_folder, true);
            }
            catch (IOException)
            {
            }
        }
    }

    public static async Task Run(Action<bool, string> check)
    {
        Screen(check);
        await Views(check);
        await Validation(check);
        await ValidationBounds(check);
        await Refresh(check);
        BeforeCommit(check);
        InsideTransaction(check);
        await Actions(check);
        FailClosed(check);
    }

    /// <summary>Each change of the admin operations commits its audit event in its own transaction: an event that cannot be committed leaves nothing changed.</summary>
    private static void FailClosed(Action<bool, string> check)
    {
        using Rig rig = new();
        ProviderStore store = rig.Store;
        rig.Captured.Fail = true;
        check(Fails(() => rig.Admin.AddInstance("vault-a", "test", """{"label":"a"}""", Hour, Laptop)) && store.Instances().Count == 0, "fail closed: no provider-added event, no instance");
        ProviderInstance instance = store.AddInstance("vault-a", "test", """{"label":"a"}""", Hour);
        check(Fails(() => rig.Admin.Reconfigure(instance, """{"label":"b"}""", Laptop)) && store.Instance(instance.Id) is { Revision: 1, Configuration: """{"label":"a"}""" }, "fail closed: no provider-config-changed event, no configuration change");
        check(Fails(() => rig.Admin.SetMaxStale(instance, TimeSpan.FromMinutes(5), Laptop)) && store.Instance(instance.Id)!.MaxStale == Hour, "fail closed: no provider-max-stale-changed event, no change");
        rig.Exec("INSERT INTO grants (id, fingerprint, scope_key, program, working_directory, secret_names, created, updated, grant_revision, security_revision, status, approved_by, usage) VALUES ('g1', 'fp', 'scope', 'p', 'd', 'team/A', 't', 't', 1, 1, 'active', 'x', 'reusable')");
        check(Fails(() => rig.Admin.AddMount(instance, MountKind.Tree, "team", "kv", 1, Laptop)) && store.Mounts().Count == 0 && rig.Count("SELECT COUNT(*) FROM grants WHERE status = 'active'") == 1, "fail closed: no mount-added event, no mount, no grant ended");
        Mount mount = store.AddMount(instance.Id, MountKind.Tree, "other", "kv");
        check(Fails(() => rig.Admin.RemoveMount(mount, "vault-a", 0, Laptop)) && store.Mounts().Count == 1, "fail closed: no mount-removed event, the mount stays");
        rig.Captured.Fail = false;
        check(Throws<ProviderConfigurationException>(() => rig.Admin.AddMount(instance, MountKind.Tree, "team", "kv", 0, Laptop)) && store.Mounts().Count == 1 && rig.Count("SELECT COUNT(*) FROM grants WHERE status = 'active'") == 1 && rig.Captured.Events.Count == 0,
            "grant count: a mount that would end another number of grants than signed is rolled back inside its transaction (no mount, no grant ended, no event)");
        rig.Captured.Fail = true;
        store.RemoveMount(mount.Id);
        check(Fails(() => rig.Admin.RemoveInstance(instance, Laptop)) && store.Instance(instance.Id) is not null, "fail closed: no provider-removed event, the instance stays");

        rig.Captured.Fail = false;
        rig.Admin.AddMount(instance, MountKind.Tree, "team", "kv", 1, Laptop);
        AuditFacts added = rig.Captured.Events.Single();
        check(added is { Outcome: "mount-added" } && added.Reason.Contains("1 active grants ended", StringComparison.Ordinal) && added.Arguments.SequenceEqual(["team"]), "audit: mount-added names the path and the number of grants that ended");
        check(added.Metadata is { } metadata && metadata.GetValueOrDefault("keyId") == Laptop.Id
            && metadata.GetValueOrDefault("keyName") == Laptop.Name && metadata.GetValueOrDefault("keyAdmin") == "true",
            "audit: mount-added records the verifying admin credential in signed-event metadata");
    }

    private static void Screen(Action<bool, string> check)
    {
        check(ProviderAdmin.ConfigurationScreen("""{"url":"https://vault.example","vault":"v1","nested":{"a":[1,2,{"b":"c"}]}}""") is null, "screen: a plain configuration is accepted");
        foreach (string name in new[] { "token", "Password", "client_secret", "apiKey", "API_KEY", "credentials", "privateKey" })
        {
            string message = ProviderAdmin.ConfigurationScreen($$"""{"url":"u","{{name}}":"hunter2-value"}""") ?? "";
            check(message.Contains(name, StringComparison.Ordinal) && !message.Contains("hunter2", StringComparison.Ordinal) && !message.Contains("\"url\"", StringComparison.Ordinal), $"screen: '{name}' is refused naming only the field");
        }

        // An environment-variable field names the variable that holds the credential: accepted only with such a name (ruling P3).
        foreach (string accepted in new[]
        {
            """{"tokenEnv":"VAULT_TOKEN"}""", """{"secretEnvVar":"A"}""", """{"api_key_ENV":"MY_KEY_2"}""", """{"x":{"passwordenv":"DB_PASS"}}""", """{"list":[{"clientSecretEnv":"CS"}]}""",
            "{\"tokenEnv\":\"" + new string('A', 64) + "\"}",
        })
        {
            check(ProviderAdmin.ConfigurationScreen(accepted) is null, "screen: an environment-variable name is accepted: " + accepted[..Math.Min(40, accepted.Length)]);
        }

        foreach (string refused in new[]
        {
            """{"tokenEnv":"hunter2-value"}""", """{"tokenEnv":"lower"}""", """{"tokenEnv":"HAS SPACE"}""", """{"tokenEnv":"1ABC"}""", """{"tokenEnv":""}""", "{\"tokenEnv\":\"A\\n\"}",
            "{\"tokenEnv\":\"" + new string('A', 65) + "\"}", """{"tokenEnv":12345}""", """{"tokenEnv":{"v":"VAULT_TOKEN"}}""", """{"tokenEnv":["VAULT_TOKEN"]}""", """{"tokenEnv":null}""",
            """{"x":{"secretEnvVar":"bad value 77"}}""", """{"l":[{"api_key_ENV":"bad value 77"}]}""", """{"token":"VAULT_TOKEN"}""", """{"Password":"VAULT_TOKEN"}""",
        })
        {
            string message = ProviderAdmin.ConfigurationScreen(refused) ?? "";
            check(message.Contains("Env", StringComparison.OrdinalIgnoreCase) || message.Contains("token", StringComparison.OrdinalIgnoreCase) || message.Contains("password", StringComparison.OrdinalIgnoreCase),
                "screen: refused naming the property: " + refused[..Math.Min(40, refused.Length)]);
            check(!message.Contains("hunter2") && !message.Contains("lower") && !message.Contains("SPACE") && !message.Contains("VAULT_TOKEN") && !message.Contains("bad value") && !message.Contains("12345") && !message.Contains("AAAA"),
                "screen: the refusal never contains the value: " + refused[..Math.Min(40, refused.Length)]);
        }

        string deep = ProviderAdmin.ConfigurationScreen("""{"a":{"b":[{"c":{"Client_Secret":"x"}}]}}""") ?? "";
        check(deep.Contains("Client_Secret", StringComparison.Ordinal), "screen: a field at any depth, inside an array, is refused");
        string first = ProviderAdmin.ConfigurationScreen("""{"password":"1","token":"2"}""") ?? "";
        check(first.Contains("password", StringComparison.Ordinal) && !first.Contains("token", StringComparison.Ordinal), "screen: the first offending field in document order is named");
        check(ProviderAdmin.ConfigurationScreen("""{"note":"my password is here"}""") is null, "screen: a value is not screened, only a field name");

        check(ProviderAdmin.ConfigurationScreen("{not json") is { Length: > 0 } invalid && !invalid.Contains("not json", StringComparison.Ordinal), "screen: invalid JSON is refused with a constant message");
        check(ProviderAdmin.ConfigurationScreen("[1,2]") is not null, "screen: an array at the top level is refused");
        check(ProviderAdmin.ConfigurationScreen("\"text\"") is not null && ProviderAdmin.ConfigurationScreen("42") is not null && ProviderAdmin.ConfigurationScreen("null") is not null, "screen: any non-object top level is refused");
        string big = "{\"a\":\"" + new string('x', 2000) + "\"}";
        check(ProviderAdmin.ConfigurationScreen(big) is { Length: > 0 } tooLong && !tooLong.Contains("xxxx", StringComparison.Ordinal), "screen: more than 2000 characters is refused with a constant message");
        string limit = "{\"a\":\"" + new string('x', 2000 - 8) + "\"}";
        check(limit.Length == 2000 && ProviderAdmin.ConfigurationScreen(limit) is null, "screen: exactly 2000 characters is accepted");
    }

    private static async Task Views(Action<bool, string> check)
    {
        using Rig rig = new();
        check(rig.Admin.Types() is [{ Type: "test", AdapterVersion: "1.0" }], "types lists the registered types");

        ProviderInstance stored = rig.Store.AddInstance("vault-stored", "test", """{"label":"stored"}""", TimeSpan.FromSeconds(90));
        ProviderDto? unregistered = rig.Admin.Provider(stored.Id);
        check(unregistered is { Status: null, Name: "vault-stored", Type: "test", MaxStaleSeconds: 90, Revision: 1, Mounts: 0 } && unregistered.Configuration == """{"label":"stored"}""", "view: an unregistered instance has no status");

        ProviderInstance running = await rig.Running();
        ProviderDto? view = rig.Admin.Provider(running.Id);
        check(view?.Status is { Lifecycle: "ready", Health: "initializing", LifecycleMessage: null }, "view: the status comes from the registry, enum names in lower case");
        check(rig.Admin.Providers().Select(item => item.Name).SequenceEqual(["vault-one", "vault-stored"]), "view: Providers lists every instance ordered by name");
        check(rig.Admin.Provider(Guid.NewGuid()) is null, "view: an unknown instance is null");

        // Nothing but the stored, screened configuration is in a view: no cache row, ciphertext or other table content.
        Mount mount = rig.Store.AddMount(running.Id, MountKind.Tree, "team", "kv");
        rig.Store.ReplaceEntries(mount.Id, [new NamespaceEntry(mount.Id, "team/A", "kv/A", "ext-a", "desc", DescriptionSource.Local)]);
        const string Canary = "CANARY-CACHED-VALUE-9f3a";
        check(rig.Providers.Cache.PutAll(running.Id, [("ext-a", System.Text.Encoding.UTF8.GetBytes(Canary))], DateTimeOffset.UtcNow, rig.Native.Current().Manifest!.Store) == CacheWrite.Written && rig.Store.ReadCache(running.Id, "ext-a") is not null, "view: a cache row with a canary exists");
        string everything = string.Join("|", rig.Admin.Providers().Select(item => item.ToString())) + "|" + string.Join("|", rig.Admin.Mounts().Select(item => item.ToString())) + "|" + string.Join("|", rig.Admin.Entries(mount.Id).Select(item => item.ToString()));
        check(everything.Contains("""{"label":"one"}""", StringComparison.Ordinal) && !everything.Contains(Canary, StringComparison.Ordinal) && !everything.Contains(rig.Store.ReadCache(running.Id, "ext-a")!.Ciphertext, StringComparison.Ordinal), "view: carries the stored configuration and no cached value or ciphertext");

        check(rig.Admin.Mounts().Single() is { Kind: "tree", LogicalPath: "team", BasePath: "kv", InstanceName: "vault-one", Entries: 1 } m && m.InstanceId == running.Id && m.Id == mount.Id, "view: a mount shows its instance, kind and entry count");
        check(rig.Admin.Mounts(stored.Id).Count == 0 && rig.Admin.Mounts(running.Id).Count == 1, "view: Mounts filters by instance");
        check(rig.Admin.Provider(running.Id)?.Mounts == 1, "view: an instance counts its mounts");
        check(rig.Admin.Entries(mount.Id).Single() is { LogicalPath: "team/A", ProviderPath: "kv/A", ExternalId: "ext-a", Description: "desc", DescriptionSource: "local" }, "view: an entry shows both paths, the external id and the description source");
        check(rig.Admin.Entries(Guid.NewGuid()).Count == 0, "view: the entries of an unknown mount are empty");
    }

    private static async Task Validation(Action<bool, string> check)
    {
        using Rig rig = new();
        rig.Adapter.ValidateConfigurationHandler = _ => Task.FromResult<IReadOnlyList<ProviderValidationIssue>>([
            new ProviderValidationIssue("first problem", ValidationSeverity.Error, "url", "E1"),
            new ProviderValidationIssue("second note", ValidationSeverity.Warning)]);
        ValidationDto result = await rig.Admin.ValidateConfigurationAsync("test", """{"label":"x"}""", CancellationToken.None);
        check(!result.Ok && result.Issues.Count == 2 && result.Issues[0] is { Message: "first problem", Severity: "error", Target: "url", ProviderCode: "E1" } && result.Issues[1] is { Message: "second note", Severity: "warning", Target: null }, "validate: adapter issues come back in order with severity");

        rig.Adapter.ValidateConfigurationHandler = _ => Task.FromResult<IReadOnlyList<ProviderValidationIssue>>([new ProviderValidationIssue("just a warning", ValidationSeverity.Warning)]);
        check((await rig.Admin.ValidateConfigurationAsync("test", """{"label":"x"}""", CancellationToken.None)).Ok, "validate: warnings alone leave Ok true");
        rig.Adapter.ValidateConfigurationHandler = null;
        check((await rig.Admin.ValidateConfigurationAsync("test", """{"label":"x"}""", CancellationToken.None)) is { Ok: true, Issues.Count: 0 }, "validate: no issues is Ok");

        // Not registered, not left running.
        check(rig.Adapter.Calls.SequenceEqual(["initialize", "validate-configuration", "shutdown", "initialize", "validate-configuration", "shutdown", "initialize", "validate-configuration", "shutdown"])
            && rig.Adapter.Context is { } context && Throws<KeyNotFoundException>(() => rig.Registry.Status(context.InstanceId)), "validate: the temporary adapter is shut down and never registered");

        // A throwing adapter: one constant Error issue, none of the exception text.
        rig.Adapter.ValidateConfigurationHandler = _ => throw new ProviderAdapterException(ProviderErrorKind.Unknown, "provider said hunter2 at https://secret.example");
        ValidationDto thrown = await rig.Admin.ValidateConfigurationAsync("test", """{"label":"canary-config-text"}""", CancellationToken.None);
        check(!thrown.Ok && thrown.Issues is [{ Severity: "error" } only] && !only.Message.Contains("hunter2") && !only.Message.Contains("canary-config-text") && only.Message.Length > 0 && rig.Adapter.Calls[^1] == "shutdown", "validate: a throwing adapter yields one constant Error issue without the exception text, and is shut down");

        ValidationDto badConfig = await rig.Admin.ValidateConfigurationAsync("test", "{\"nolabel\":1}", CancellationToken.None);
        check(badConfig.Issues is [{ Severity: "error" } load] && !load.Message.Contains("nolabel"), "validate: a configuration the adapter cannot load is one constant Error issue");
        ValidationDto unknownType = await rig.Admin.ValidateConfigurationAsync("nope", "{}", CancellationToken.None);
        check(unknownType.Issues is [{ Severity: "error" }] && !unknownType.Ok, "validate: an unregistered type is one Error issue");

        // The initialization failure of the adapter: one constant issue, shut down still.
        FakeProviderAdapter failing = new() { InitializeBehavior = _ => throw new InvalidOperationException("init said hunter2") };
        rig.Next = failing;
        ValidationDto initFailed = await rig.Admin.ValidateConfigurationAsync("test", """{"label":"x"}""", CancellationToken.None);
        check(initFailed.Issues is [{ Severity: "error" } init] && !init.Message.Contains("hunter2") && failing.Calls.Contains("shutdown") && !failing.Calls.Contains("validate-configuration"), "validate: an initialization failure is one constant Error issue and the adapter is shut down");

        // A mount validation uses the proposed configuration, not the stored one.
        FakeProviderAdapter mounting = new();
        string? seen = null;
        string? seenPath = null;
        mounting.ValidateMountHandler = (configuration, basePath) =>
        {
            seen = configuration.Label;
            seenPath = basePath;

            return Task.FromResult<IReadOnlyList<ProviderValidationIssue>>([new ProviderValidationIssue("path unknown", ValidationSeverity.Warning, "basePath")]);
        };
        rig.Next = mounting;
        ProviderInstance instance = rig.Store.AddInstance("vault-m", "test", """{"label":"stored"}""", Hour);
        ValidationDto proposed = await rig.Admin.ValidateMountAsync(instance.Id, """{"label":"proposed"}""", "kv/dev", CancellationToken.None);
        check(seen == "proposed" && seenPath == "kv/dev" && proposed is { Ok: true, Issues: [{ Message: "path unknown", Severity: "warning" }] }, "validate mount: the proposed configuration is used");
        await rig.Admin.ValidateMountAsync(instance.Id, null, "kv/dev", CancellationToken.None);
        check(seen == "stored", "validate mount: without a proposal the stored configuration is used");
        ValidationDto missing = await rig.Admin.ValidateMountAsync(Guid.NewGuid(), null, "kv", CancellationToken.None);
        check(missing.Issues is [{ Severity: "error" }] && !missing.Ok, "validate mount: an unknown instance is one Error issue");
    }

    private static async Task ValidationBounds(Action<bool, string> check)
    {
        // An adapter that ignores its token and never returns: the deadline yields ONE constant Error issue, shutdown still runs, the temporary adapter is not registered.
        using Rig rig = new();
        rig.Registry.ValidationDeadline = TimeSpan.FromMilliseconds(300);
        TaskCompletionSource<bool> never = new();
        FakeProviderAdapter stuck = new() { InitializeBehavior = _ => never.Task };
        rig.Next = stuck;
        DateTime started = DateTime.UtcNow;
        ValidationDto overrun = await rig.Admin.ValidateConfigurationAsync("test", """{"label":"canary-config-text"}""", CancellationToken.None);
        check(overrun.Issues is [{ Severity: "error" } only] && !only.Message.Contains("canary") && DateTime.UtcNow - started < TimeSpan.FromSeconds(5) && stuck.Calls.Contains("shutdown") && !stuck.Calls.Contains("validate-configuration"),
            "validate bound: an adapter that ignores its token ends in one constant Error issue at the deadline and is shut down");
        check(stuck.Context is { } stuckContext && Throws<KeyNotFoundException>(() => rig.Registry.Status(stuckContext.InstanceId)), "validate bound: the overrunning adapter was never registered");

        // The abandoned initialization faults later: nothing is left unobserved.
        List<Exception> unobserved = [];
        void Watch(object? sender, UnobservedTaskExceptionEventArgs args) => unobserved.Add(args.Exception);
        TaskScheduler.UnobservedTaskException += Watch;
        try
        {
            never.SetException(new InvalidOperationException("late fault"));
            await Task.Delay(100);
            GC.Collect();
            GC.WaitForPendingFinalizers();
            GC.Collect();
            GC.WaitForPendingFinalizers();
            check(unobserved.Count == 0, "validate bound: a fault of the abandoned run is observed");
        }
        finally
        {
            TaskScheduler.UnobservedTaskException -= Watch;
        }

        // Caller cancellation is rethrown and the adapter is still shut down.
        rig.Registry.ValidationDeadline = TimeSpan.FromSeconds(10);
        using CancellationTokenSource cancel = new();
        FakeProviderAdapter waiting = new() { InitializeBehavior = _ => new TaskCompletionSource<bool>().Task };
        rig.Next = waiting;
        Task<ValidationDto> pending = rig.Admin.ValidateConfigurationAsync("test", "{\"label\":\"x\"}", cancel.Token);
        await Task.Delay(200);
        cancel.Cancel();
        bool cancelled = false;
        try
        {
            await pending;
        }
        catch (OperationCanceledException)
        {
            cancelled = true;
        }

        check(cancelled && waiting.Calls.Contains("shutdown"), "validate bound: caller cancellation is rethrown and the adapter is shut down");
    }

    private static async Task Refresh(Action<bool, string> check)
    {
        using Rig rig = new();
        ProviderInstance instance = await rig.Running();
        Mount mount = rig.Store.AddMount(instance.Id, MountKind.Tree, "team", "kv");
        rig.Adapter.ListHandler = (_, _) => Task.FromResult(new ListSecretsResult([new ProviderSecretInfo("A", "ext-canary-a", "d"), new ProviderSecretInfo("B", "ext-canary-b", null)], null, true));

        ReconcileResult result = await rig.Admin.RefreshAsync(mount.Id, "admin-app", CancellationToken.None);
        check(result is { Complete: true, Added: 2, Removed: 0, Changed: 0 } && rig.Admin.Entries(mount.Id).Count == 2, "refresh: reconciles the mount's entries");
        AuditFacts? facts = rig.Captured.Events.SingleOrDefault();
        string text = facts is null ? "" : facts.Reason + "|" + string.Join(",", facts.Arguments) + "|" + string.Join(",", facts.Metadata?.Values ?? []);
        check(facts is { Type: AuditEventTypes.Admin, Outcome: "namespace-refreshed" } && text.Contains("added 2") && text.Contains("removed 0") && text.Contains("changed 0") && facts.Arguments.SequenceEqual(["team"])
            && !text.Contains("ext-canary") && !text.Contains("kv/A"), "refresh: audits namespace-refreshed with counts and the mount name only");

        // Not registered: refused cleanly, nothing audited, nothing changed.
        ProviderInstance idle = rig.Store.AddInstance("vault-idle", "test", """{"label":"idle"}""", Hour);
        Mount idleMount = rig.Store.AddMount(idle.Id, MountKind.Tree, "idle", "kv");
        int before = rig.Captured.Events.Count;
        bool refused = false;
        try
        {
            await rig.Admin.RefreshAsync(idleMount.Id, "admin-app", CancellationToken.None);
        }
        catch (ProviderConfigurationException error)
        {
            refused = error.Message.Length > 0 && !error.Message.Contains("vault-idle");
        }

        check(refused && rig.Captured.Events.Count == before, "refresh: a mount whose instance is not registered is refused with a constant message and not audited");

        bool unknown = false;
        try
        {
            await rig.Admin.RefreshAsync(Guid.NewGuid(), "admin-app", CancellationToken.None);
        }
        catch (ProviderConfigurationException)
        {
            unknown = true;
        }

        check(unknown, "refresh: an unknown mount is refused");

        // A provider failure: a constant refusal, none of the adapter's text, nothing audited.
        rig.Adapter.ListHandler = (_, _) => throw new ProviderAdapterException(ProviderErrorKind.Unavailable, "upstream said hunter2-canary at https://secret.example");
        before = rig.Captured.Events.Count;
        string? failureText = null;
        try
        {
            await rig.Admin.RefreshAsync(mount.Id, "admin-app", CancellationToken.None);
        }
        catch (ProviderConfigurationException error)
        {
            failureText = error.Message;
        }

        check(failureText is { Length: > 0 } && !failureText.Contains("hunter2") && !failureText.Contains("secret.example") && rig.Captured.Events.Count == before, "refresh: a provider failure becomes a constant refusal without the adapter's text and is not audited");

        // Caller cancellation stays a cancellation.
        using CancellationTokenSource cancel = new();
        rig.Adapter.ListHandler = (_, token) =>
        {
            cancel.Cancel();
            token.ThrowIfCancellationRequested();

            return Task.FromResult(new ListSecretsResult([], null, true));
        };
        bool cancelled = false;
        try
        {
            await rig.Admin.RefreshAsync(mount.Id, "admin-app", cancel.Token);
        }
        catch (OperationCanceledException)
        {
            cancelled = true;
        }

        check(cancelled, "refresh: a cancellation is not turned into a refusal");
    }

    private static void BeforeCommit(Action<bool, string> check)
    {
        using Rig rig = new();
        ProviderStore store = rig.Store;
        bool ran = false;
        Exception? failure = null;
        try
        {
            store.AddInstance("vault-a", "test", "{}", Hour, (_, _) => throw new StateDatabaseException("scripted"));
        }
        catch (StateDatabaseException error)
        {
            failure = error;
        }

        check(failure is not null && store.Instances().Count == 0, "beforeCommit: a failing callback rolls the instance back (not added)");
        ProviderInstance instance = store.AddInstance("vault-a", "test", """{"label":"a"}""", Hour, (_, _) => ran = true);
        check(ran && store.Instances().Count == 1 && rig.Providers.Store.Instance(instance.Id) is not null, "beforeCommit: a passing callback runs and the change commits");

        // Each writer: the callback runs after the rows changed (it sees them) and a failure leaves the stored state as it was.
        int seenRevision = 0;
        store.UpdateConfiguration(instance.Id, """{"label":"b"}""", (_, _) => seenRevision = 1);
        check(seenRevision == 1 && store.Instance(instance.Id) is { Revision: 2 }, "beforeCommit: UpdateConfiguration runs the callback");
        check(Fails(() => store.UpdateConfiguration(instance.Id, """{"label":"c"}""", (_, _) => throw new StateDatabaseException("x"))) && store.Instance(instance.Id) is { Revision: 2, Configuration: """{"label":"b"}""" }, "beforeCommit: a failing UpdateConfiguration changes nothing");
        check(Fails(() => store.SetMaxStale(instance.Id, TimeSpan.FromMinutes(5), (_, _) => throw new StateDatabaseException("x"))) && store.Instance(instance.Id)?.MaxStale == Hour, "beforeCommit: a failing SetMaxStale changes nothing");
        store.SetMaxStale(instance.Id, TimeSpan.FromMinutes(5), (_, _) => seenRevision = 2);
        check(seenRevision == 2 && store.Instance(instance.Id)?.MaxStale == TimeSpan.FromMinutes(5), "beforeCommit: SetMaxStale runs the callback");

        long generation = store.Generation(instance.Id);
        check(Fails(() => store.AddMount(instance.Id, MountKind.Tree, "team", "kv", (_, _, _) => throw new StateDatabaseException("x"))) && store.Mounts().Count == 0, "beforeCommit: a failing AddMount adds nothing");
        Mount mount = store.AddMount(instance.Id, MountKind.Tree, "team", "kv", (_, _, ended) => seenRevision = 3 + ended);
        check(seenRevision == 3 && store.Mounts().Count == 1 && store.Generation(instance.Id) > generation, "beforeCommit: AddMount runs the callback and the generation moved");
        check(Fails(() => store.RemoveMount(mount.Id, (_, _, _) => throw new StateDatabaseException("x"))) && store.Mounts().Count == 1, "beforeCommit: a failing RemoveMount keeps the mount");
        store.RemoveMount(mount.Id, (_, _, ended) => seenRevision = 4 + ended);
        check(seenRevision == 4 && store.Mounts().Count == 0, "beforeCommit: RemoveMount runs the callback");
        check(Fails(() => store.RemoveInstance(instance.Id, (_, _, _) => throw new StateDatabaseException("x"))) && store.Instance(instance.Id) is not null, "beforeCommit: a failing RemoveInstance keeps the instance");
        store.RemoveInstance(instance.Id, (_, _, deleted) => seenRevision = 5 + deleted);
        check(seenRevision == 5 && store.Instance(instance.Id) is null, "beforeCommit: RemoveInstance runs the callback");
    }

    private static void InsideTransaction(Action<bool, string> check)
    {
        using Rig rig = new();
        ProviderStore store = rig.Store;

        // The callback runs before the commit: a reader on another connection does not see the change yet, and sees it once the call returned.
        int seenInside = -1;
        ProviderInstance instance = store.AddInstance("vault-a", "test", """{"label":"a"}""", Hour, (_, _) => seenInside = store.Instances().Count);
        check(seenInside == 0 && store.Instances().Count == 1, "beforeCommit: runs inside the transaction (another reader sees nothing yet, the commit follows)");

        // Plan-2 discipline: the generation moves inside the transaction (the callback sees it); a failing callback leaves that ONE move (no post-commit bump) and the rows
        // untouched; a commit moves it twice.
        Mount mount = store.AddMount(instance.Id, MountKind.Tree, "team", "kv");
        long start = store.Generation(instance.Id);
        long insideRemoveMount = -1;
        check(Fails(() => store.RemoveMount(mount.Id, (_, _, _) =>
        {
            insideRemoveMount = store.Generation(instance.Id);

            throw new StateDatabaseException("x");
        })) && insideRemoveMount == start + 1 && store.Generation(instance.Id) == start + 1 && store.Mounts().Count == 1, "beforeCommit: a failing RemoveMount callback saw the inside bump, no post-commit bump happened, the mount is kept");
        store.RemoveMount(mount.Id, (_, _, _) => { });
        check(store.Generation(instance.Id) == start + 3, "beforeCommit: a committed RemoveMount bumps inside and after the commit");

        long beforeRemove = store.Generation(instance.Id);
        long insideRemoveInstance = -1;
        check(Fails(() => store.RemoveInstance(instance.Id, (_, _, _) =>
        {
            insideRemoveInstance = store.Generation(instance.Id);

            throw new StateDatabaseException("x");
        })) && insideRemoveInstance == beforeRemove + 1 && store.Generation(instance.Id) == beforeRemove + 1 && store.Instance(instance.Id) is not null, "beforeCommit: a failing RemoveInstance callback saw the inside bump, no post-commit bump happened, the instance is kept");
    }

    private static async Task Actions(Action<bool, string> check)
    {
        using Rig rig = new();
        ProviderInstance instance = await rig.Running();
        check(rig.Admin.Provider(instance.Id)?.Actions.SequenceEqual(["config", "max-stale", "remove", "add-mount"]) == true, "actions: an instance without mounts offers config, max-stale, remove, add-mount");
        Mount mount = rig.Store.AddMount(instance.Id, MountKind.Tree, "team", "kv");
        check(rig.Admin.Provider(instance.Id)?.Actions.SequenceEqual(["config", "max-stale", "add-mount"]) == true, "actions: remove is absent while mounts exist, add-mount stays");
        check(rig.Admin.Mounts().Single().Actions.SequenceEqual(["remove", "refresh"]) && rig.Admin.MountActions(mount).SequenceEqual(["remove", "refresh"]), "actions: a mount of a running instance offers remove and refresh");
        ProviderInstance idle = rig.Store.AddInstance("vault-idle", "test", """{"label":"idle"}""", Hour);
        Mount idleMount = rig.Store.AddMount(idle.Id, MountKind.Tree, "idle", "kv");
        check(rig.Admin.MountActions(idleMount).SequenceEqual(["remove"]) && rig.Admin.Mounts().Single(item => item.Id == idleMount.Id).Actions.SequenceEqual(["remove"]), "actions: a mount of an instance that is not registered offers no refresh");
    }

    private static bool Throws<T>(Action action) where T : Exception
    {
        try
        {
            action();
        }
        catch (T)
        {
            return true;
        }

        return false;
    }

    private static bool Fails(Action action) => Throws<StateDatabaseException>(action);
}
