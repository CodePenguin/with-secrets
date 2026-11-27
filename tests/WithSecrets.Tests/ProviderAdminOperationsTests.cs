namespace WithSecrets.Tests;

/// <summary>
/// The passkey-bound provider and mount operations of the admin service (10.3.1, 10.5): each is planned (and refused early) before any page exists, signs exactly what it
/// changes, is applied once at the verified tap after re-checking the state it was planned on, commits its audit event with the change, and only then updates the
/// running registry and refreshes the affected namespaces. Asked of the service as the API asks it (the routes are not there yet).
/// </summary>
internal static class ProviderAdminOperationsTests
{
    private const string Config = """{"label":"one","url":"https://vault.example/canary-url"}""";

    private sealed record Asked(AuthorizationView? View, AdminStart Start, int Tap, AuthorizationView? Settled)
    {
        public bool Applied => Settled?.Result?.Outcome == "applied";

        public string Detail => Settled?.Result?.Detail ?? "";
    }

    private sealed class Rig : IDisposable
    {
        public Rig(string root, bool providers = true)
        {
            if (providers)
            {
                Registry = new ProviderRegistry();
                Registry.RegisterType("test", "1.0", Make, () => new FakeConfiguration());
            }

            App = new AdminApp(root, providers: Registry);
            (string ticket, string code) = Service.Sessions.BeginLogin("provider-browser")!.Value;
            Service.Sessions.CompleteLogin(code, "laptop", null, SessionScope.Admin);
            Session = Service.Sessions.Claim(ticket, "provider-browser")!;
        }

        public ProviderRegistry? Registry { get; }

        public AdminApp App { get; }

        public AdminSession Session { get; }

        public List<FakeProviderAdapter> Made { get; } = [];

        public Func<FakeConfiguration, Task<IReadOnlyList<ProviderValidationIssue>>>? ValidateConfiguration { get; set; }

        public Func<FakeConfiguration, string, Task<IReadOnlyList<ProviderValidationIssue>>>? ValidateMount { get; set; }

        public Func<ListSecretsRequest, CancellationToken, Task<ListSecretsResult>>? List { get; set; }

        public Func<Task>? Update { get; set; }

        public AdminService Service => App.Service.Admin;

        public ProviderStore Store => App.Service.Providers!.Store;

        public FakeProviderAdapter Running(Guid id) => (FakeProviderAdapter)Registry!.Adapter(id);

        public bool Registered(Guid id)
        {
            try
            {
                Registry!.Status(id);

                return true;
            }
            catch (KeyNotFoundException)
            {
                return false;
            }
        }

        private FakeProviderAdapter Make()
        {
            FakeProviderAdapter made = new()
            {
                ValidateConfigurationHandler = configuration => ValidateConfiguration?.Invoke(configuration) ?? Task.FromResult<IReadOnlyList<ProviderValidationIssue>>([]),
                ValidateMountHandler = (configuration, path) => ValidateMount?.Invoke(configuration, path) ?? Task.FromResult<IReadOnlyList<ProviderValidationIssue>>([]),
                ListHandler = (request, token) => List?.Invoke(request, token) ?? Task.FromResult(new ListSecretsResult([], null, true)),
                UpdateBehavior = () => Update?.Invoke() ?? Task.CompletedTask,
            };
            lock (Made)
            {
                Made.Add(made);
            }

            return made;
        }

        public async Task<Asked> Ask(string op, bool tap, params (string Name, string Value)[] args)
        {
            App.Clock.Advance(TimeSpan.FromSeconds(13));
            (AuthorizationView? view, AdminStart start) = await Service.BeginAuthorizationAsync(Session, op, args.ToDictionary(item => item.Name, item => item.Value), CancellationToken.None);
            if (view is null || start.Link is null || !tap)
            {
                return new Asked(view, start, 0, view);
            }

            return await Tap(view, start);
        }

        public async Task<Asked> Tap(AuthorizationView view, AdminStart start)
        {
            Uri link = new(start.Link!);
            (int status, _) = TestState.Approve(App.Http, "http://127.0.0.1:" + link.Port + link.AbsolutePath, "http://localhost:" + link.Port, "localhost", App.Laptop);
            AuthorizationView? settled = view;
            for (int i = 0; i < 400; i++)
            {
                settled = Service.FindAuthorization(Session, view.Id);
                if (settled is null || settled.State is not (AuthorizationState.Pending or AuthorizationState.Verified) && (settled.State != AuthorizationState.Consumed || settled.Result is not null))
                {
                    break;
                }

                await Task.Delay(50);
            }

            return new Asked(view, start, status, settled);
        }

        /// <summary>Every signed event of this machine (outbox and uploaded).</summary>
        public IReadOnlyList<AuditEvent> Events()
        {
            Dictionary<string, AuditEvent> all = new(StringComparer.Ordinal);
            foreach (AuditEvent item in App.Service.Audit.Outbox.Pending(10000).Concat(App.Store.AuditHistory(new AuditQuery(Limit: 1000)).Select(record => record.Event)))
            {
                all[item.EventId] = item;
            }

            return [.. all.Values.OrderBy(item => item.Sequence)];
        }

        public static string Text(AuditEvent item) => item.Outcome + "|" + item.Reason + "|" + string.Join(",", item.Arguments) + "|" + string.Join(",", item.Metadata?.Values ?? []);

        public void Exec(string sql)
        {
            using Microsoft.Data.Sqlite.SqliteConnection connection = new("Data Source=" + App.Store.FilePath + ";Pooling=False");
            connection.Open();
            using Microsoft.Data.Sqlite.SqliteCommand command = connection.CreateCommand();
            command.CommandText = sql;
            command.ExecuteNonQuery();
        }

        public long Count(string sql)
        {
            using Microsoft.Data.Sqlite.SqliteConnection connection = new("Data Source=" + App.Store.FilePath + ";Pooling=False");
            connection.Open();
            using Microsoft.Data.Sqlite.SqliteCommand command = connection.CreateCommand();
            command.CommandText = sql;

            return Convert.ToInt64(command.ExecuteScalar());
        }

        public void Grant(string id, string names) => Exec($"INSERT INTO grants (id, fingerprint, scope_key, program, working_directory, secret_names, created, updated, grant_revision, security_revision, status, approved_by, usage) VALUES ('{id}', 'fp', 'scope', 'p', 'd', '{names}', 't', 't', 1, 1, 'active', 'x', 'reusable')");

        public string GrantStatus(string id) => Count($"SELECT COUNT(*) FROM grants WHERE id = '{id}' AND status = 'active'") == 1 ? "active" : Count($"SELECT COUNT(*) FROM grants WHERE id = '{id}' AND status = 'invalidated'") == 1 ? "invalidated" : "other";

        public void Cache(Guid instance, string externalId) => Exec($"INSERT INTO provider_cache (instance_id, external_id, ciphertext, last_verified, store_public_key, authority_key, signature) VALUES ('{instance:D}', '{externalId}', 'c', 1, 'k', 'a', x'00')");

        public void Dispose() => App.Dispose();
    }

    private static IReadOnlyList<ProviderValidationIssue> Issues(params (string Message, ValidationSeverity Severity)[] issues) => [.. issues.Select(item => new ProviderValidationIssue(item.Message, item.Severity))];

    public static async Task Run(Action<bool, string> check)
    {
        string root = Path.Combine(Path.GetTempPath(), "ws-provider-ops-" + Guid.NewGuid().ToString("N")[..8]);
        Directory.CreateDirectory(root);
        try
        {
            await AddProvider(check, root);
            await ChangeConfiguration(check, root);
            await MaxStale(check, root);
            await WarningDrift(check, root);
            await RemoveProvider(check, root);
            await Mounts(check, root);
            await Binding(check, root);
            await RegistryFailure(check, root);
            await Remote(check, root);
        }
        finally
        {
            try
            {
                Directory.Delete(root, true);
            }
            catch (Exception error) when (error is IOException or UnauthorizedAccessException)
            {
            }
        }
    }

    private static async Task AddProvider(Action<bool, string> check, string root)
    {
        using Rig rig = new(root);

        // Refused before any page: a credential-looking field, invalid input, an unknown type, a validation error, a warning without its confirmation.
        int asked = rig.App.Asked;
        Asked credential = await rig.Ask("provider-add", false, ("name", "vault-one"), ("type", "test"), ("config", """{"label":"x","token":"hunter2-canary"}"""), ("max-stale-seconds", "3600"));
        check(credential.Start.Link is null && credential.Start.Status == 400 && credential.Start.Error is { } screened && screened.Contains("token", StringComparison.Ordinal) && !screened.Contains("hunter2", StringComparison.Ordinal),
            "provider-add: a credential-looking configuration is refused at plan time naming only the field (" + credential.Start.Status + " " + credential.Start.Error + ")");
        check((await rig.Ask("provider-add", false, ("name", "vault-one"), ("type", "nope"), ("config", Config), ("max-stale-seconds", "3600"))).Start is { Link: null, Status: 400 }, "provider-add: an unknown type is refused (400)");
        check((await rig.Ask("provider-add", false, ("name", "vault-one"), ("type", "test"), ("config", Config), ("max-stale-seconds", "90000"))).Start is { Link: null, Status: 400 }, "provider-add: more than 24 hours of staleness is refused (400)");
        check((await rig.Ask("provider-add", false, ("name", " "), ("type", "test"), ("config", Config), ("max-stale-seconds", "3600"))).Start is { Link: null, Status: 400 }, "provider-add: an empty name is refused (400)");
        check((await rig.Ask("provider-add", false, ("name", "vault-one"), ("type", "test"), ("config", "{\n\"label\":\"x\"}"), ("max-stale-seconds", "3600"))).Start is { Link: null, Status: 400 }, "provider-add: a configuration over several lines is refused (it is signed as one parameter line)");

        rig.ValidateConfiguration = _ => Task.FromResult(Issues(("ADAPTER-ERROR-canary", ValidationSeverity.Error)));
        Asked error = await rig.Ask("provider-add", false, ("name", "vault-one"), ("type", "test"), ("config", Config), ("max-stale-seconds", "3600"));
        check(error.Start.Link is null && error.Start.Status == 409 && error.Start.Error is { } blocked && !blocked.Contains("canary", StringComparison.Ordinal) && rig.Store.Instances().Count == 0,
            "provider-add: a validation error refuses it before any page, without the adapter's text (" + error.Start.Error + ")");

        rig.ValidateConfiguration = _ => Task.FromResult(Issues(("ADAPTER-WARNING-canary", ValidationSeverity.Warning)));
        Asked unconfirmed = await rig.Ask("provider-add", false, ("name", "vault-one"), ("type", "test"), ("config", Config), ("max-stale-seconds", "3600"));
        check(unconfirmed.Start.Link is null && unconfirmed.Start.Error is { } needs && needs.Contains("confirm-warnings", StringComparison.Ordinal) && !needs.Contains("canary", StringComparison.Ordinal), "provider-add: a warning needs confirm-warnings=yes");
        check((await rig.Ask("provider-add", false, ("name", "vault-one"), ("type", "test"), ("config", Config), ("max-stale-seconds", "3600"), ("confirm-warnings", "no"))).Start is { Link: null, Status: 400 }, "provider-add: confirm-warnings takes only yes");
        check(rig.App.Asked == asked, "provider-add: no passkey page was asked for any refusal");

        Asked added = await rig.Ask("provider-add", true, ("name", "vault-one"), ("type", "test"), ("config", Config), ("max-stale-seconds", "3600"), ("confirm-warnings", "yes"));
        ProviderInstance? instance = rig.Store.Instances().SingleOrDefault();
        check(added.Tap == 200 && added.Applied && instance is { Name: "vault-one", ProviderType: "test", Configuration: Config, Revision: 1 } && instance.MaxStale == TimeSpan.FromHours(1),
            "provider-add: the tap stores the instance exactly as planned (" + added.Tap + " " + added.Settled?.Result?.Outcome + " " + added.Detail + ")");
        check(added.View is { } page && page.Sentence.Contains("test", StringComparison.Ordinal) && page.Sentence.Contains(Config, StringComparison.Ordinal) && page.Sentence.Contains("Parameter confirm-warnings: yes", StringComparison.Ordinal)
            && page.Sentence.Contains("vault-one", StringComparison.Ordinal) && !page.Sentence.Contains("ADAPTER-WARNING", StringComparison.Ordinal)
            && page.Parameters.Select(item => item.Name).SequenceEqual(["name", "type", "config", "max-stale-seconds", "confirm-warnings"]),
            "provider-add: the signed page names the name, type and exact configuration, signs the confirmation, and carries no adapter text");
        check(instance is not null && rig.Registered(instance.Id) && rig.Running(instance.Id).CurrentLabel == "one", "provider-add: the instance is registered with its configuration after the commit");
        AuditEvent? audited = rig.Events().LastOrDefault(item => item.Outcome == "provider-added");
        check(audited is not null && audited.Type == AuditEventTypes.Admin && audited.Arguments.Contains("vault-one") && !Rig.Text(audited).Contains("canary-url", StringComparison.Ordinal) && !Rig.Text(audited).Contains("vault.example", StringComparison.Ordinal),
            "provider-add: a provider-added event (names only, no configuration value) is committed");

        rig.ValidateConfiguration = null;
        check((await rig.Ask("provider-add", false, ("name", "vault-one"), ("type", "test"), ("config", Config), ("max-stale-seconds", "60"))).Start is { Link: null, Status: 409 }, "provider-add: a duplicate name is refused (409)");
    }

    private static async Task ChangeConfiguration(Action<bool, string> check, string root)
    {
        using Rig rig = new(root);
        Asked added = await rig.Ask("provider-add", true, ("name", "vault-one"), ("type", "test"), ("config", Config), ("max-stale-seconds", "3600"));
        ProviderInstance instance = rig.Store.Instances().Single();
        string id = instance.Id.ToString("D");
        check(added.Applied, "provider-config: setup");

        check((await rig.Ask("provider-config", false, ("id", id), ("revision", "7"), ("config", """{"label":"two"}"""))).Start is { Link: null, Status: 409 }, "provider-config: a stale revision is refused at plan time");
        check((await rig.Ask("provider-config", false, ("id", Guid.NewGuid().ToString("D")), ("revision", "1"), ("config", """{"label":"two"}"""))).Start is { Link: null, Status: 404 }, "provider-config: an unknown instance is refused (404)");
        check((await rig.Ask("provider-config", false, ("id", id), ("revision", "1"), ("config", Config))).Start is { Link: null, Status: 409 }, "provider-config: an unchanged configuration is refused");
        check((await rig.Ask("provider-config", false, ("id", id), ("revision", "1"), ("config", """{"label":"two","password":"pw-canary"}"""))).Start is { Link: null, Status: 400, Error: { } pw } && pw.Contains("password") && !pw.Contains("pw-canary"),
            "provider-config: a credential-looking configuration is refused at plan time");

        // Invalid at plan time: nothing changes.
        rig.ValidateConfiguration = configuration => Task.FromResult(configuration.Label == "bad" ? Issues(("bad label", ValidationSeverity.Error)) : Issues());
        check((await rig.Ask("provider-config", false, ("id", id), ("revision", "1"), ("config", """{"label":"bad"}"""))).Start is { Link: null, Status: 409 } && rig.Store.Instance(instance.Id)!.Configuration == Config && rig.Running(instance.Id).CurrentLabel == "one",
            "provider-config: an invalid configuration is refused; the stored configuration and the running adapter keep the old one");

        // Valid when planned, invalid at the tap: re-validated at apply, nothing changes.
        Asked planned = await rig.Ask("provider-config", false, ("id", id), ("revision", "1"), ("config", """{"label":"two"}"""));
        rig.ValidateConfiguration = _ => Task.FromResult(Issues(("now invalid", ValidationSeverity.Error)));
        Asked late = planned.View is null ? planned : await rig.Tap(planned.View, planned.Start);
        check(late.Settled?.Result is { Outcome: "failed" } && rig.Store.Instance(instance.Id) is { Revision: 1, Configuration: Config } && rig.Running(instance.Id).CurrentLabel == "one",
            "provider-config: re-validated at the tap; an error then leaves the old configuration and adapter (" + late.Settled?.Result?.Outcome + " " + late.Detail + ")");
        rig.ValidateConfiguration = null;

        // Mount + entries: the change refreshes the namespace afterwards.
        Mount mount = rig.Store.AddMount(instance.Id, MountKind.Tree, "team", "kv");
        rig.List = (_, _) => Task.FromResult(new ListSecretsResult([new ProviderSecretInfo("A", "ext-a", null)], null, true));
        Asked changed = await rig.Ask("provider-config", true, ("id", id), ("revision", "1"), ("config", """{"label":"two"}"""), ("max-stale-seconds", "1200"));
        check(changed.Applied && rig.Store.Instance(instance.Id) is { Revision: 2, Configuration: """{"label":"two"}""" } updated
            && updated.MaxStale == TimeSpan.FromMinutes(20) && rig.Running(instance.Id).CurrentLabel == "two" && rig.Running(instance.Id).Calls.Contains("update"),
            "provider-config: one tap updates the live adapter and cache policy (" + changed.Detail + ")");
        check(changed.View is { } page && page.Sentence.Contains("""{"label":"two"}""", StringComparison.Ordinal) && page.Parameters.Any(item => item.Name == "revision" && item.Value == "1"), "provider-config: the page signs the revision and the new configuration");
        check(await HostServiceTests.WaitFor(() => rig.Store.Entries(mount.Id).Count == 1), "provider-config: the namespace of the instance's mounts is refreshed after the change");
        check(rig.Events().Any(item => item.Outcome == "provider-config-changed" && item.Arguments.Contains("vault-one") && !Rig.Text(item).Contains("two", StringComparison.Ordinal)), "provider-config: a provider-config-changed event without configuration values");

        // A stale revision at the tap: planned at revision 2, changed to 3 before the tap.
        Asked stale = await rig.Ask("provider-config", false, ("id", id), ("revision", "2"), ("config", """{"label":"three"}"""));
        rig.Store.UpdateConfiguration(instance.Id, """{"label":"elsewhere"}""");
        Asked refused = stale.View is null ? stale : await rig.Tap(stale.View, stale.Start);
        check(refused.Settled?.Result is { Outcome: "failed" } && refused.Detail.Contains("changed", StringComparison.Ordinal) && rig.Store.Instance(instance.Id) is { Revision: 3, Configuration: """{"label":"elsewhere"}""" },
            "provider-config: a revision that moved between page and tap is refused at apply (" + refused.Detail + ")");
    }

    private static async Task MaxStale(Action<bool, string> check, string root)
    {
        using Rig rig = new(root);
        await rig.Ask("provider-add", true, ("name", "vault-one"), ("type", "test"), ("config", Config), ("max-stale-seconds", "3600"));
        ProviderInstance instance = rig.Store.Instances().Single();
        string id = instance.Id.ToString("D");
        rig.Cache(instance.Id, "ext-kept");

        check((await rig.Ask("provider-max-stale", false, ("id", id), ("revision", "1"), ("max-stale-seconds", "86401"))).Start is { Link: null, Status: 400 }, "provider-max-stale: above 24 hours is refused");
        check((await rig.Ask("provider-max-stale", false, ("id", id), ("revision", "1"), ("max-stale-seconds", "3600"))).Start is { Link: null, Status: 409 }, "provider-max-stale: an unchanged value is refused");
        check((await rig.Ask("provider-max-stale", false, ("id", id), ("revision", "2"), ("max-stale-seconds", "60"))).Start is { Link: null, Status: 409 }, "provider-max-stale: a stale revision is refused");
        Asked set = await rig.Ask("provider-max-stale", true, ("id", id), ("revision", "1"), ("max-stale-seconds", "600"));
        check(set.Applied && rig.Store.Instance(instance.Id) is { Revision: 1 } after && after.MaxStale == TimeSpan.FromSeconds(600) && rig.Count("SELECT COUNT(*) FROM provider_cache") == 1 && rig.Running(instance.Id).Calls.Count(call => call == "update") == 0,
            "provider-max-stale: policy only: the revision stays, the cache rows stay, the adapter is not touched (" + set.Detail + ")");
        check(rig.Events().Any(item => item.Outcome == "provider-max-stale-changed" && item.Arguments.Contains("vault-one")), "provider-max-stale: a provider-max-stale-changed event");
        check((await rig.Ask("provider-max-stale", true, ("id", id), ("revision", "1"), ("max-stale-seconds", "0"))).Applied
            && rig.Store.Instance(instance.Id)!.MaxStale == TimeSpan.Zero && rig.Count("SELECT COUNT(*) FROM provider_cache") == 0,
            "provider-max-stale: approving live only purges the provider's cached rows");

        // Changed out of band between page and tap (the revision stays: the policy is not part of it): the signed "before" no longer holds.
        Asked planned = await rig.Ask("provider-max-stale", false, ("id", id), ("revision", "1"), ("max-stale-seconds", "120"));
        rig.Store.SetMaxStale(instance.Id, TimeSpan.FromSeconds(900));
        Asked late = planned.View is null ? planned : await rig.Tap(planned.View, planned.Start);
        check(planned.View is not null && late.Settled?.Result is { Outcome: "failed" } && late.Detail.Contains("maximum staleness changed", StringComparison.Ordinal)
            && rig.Store.Instance(instance.Id) is { Revision: 1 } kept && kept.MaxStale == TimeSpan.FromSeconds(900),
            "provider-max-stale: a value changed out of band at the same revision between page and tap is refused at apply (" + late.Detail + ")");
    }

    private static async Task WarningDrift(Action<bool, string> check, string root)
    {
        using Rig rig = new(root);
        await rig.Ask("provider-add", true, ("name", "vault-one"), ("type", "test"), ("config", Config), ("max-stale-seconds", "3600"));
        ProviderInstance instance = rig.Store.Instances().Single();
        string id = instance.Id.ToString("D");

        // One warning on the page, confirmed; two at the tap: the confirmation was for something else.
        rig.ValidateConfiguration = _ => Task.FromResult(Issues(("first warning", ValidationSeverity.Warning)));
        Asked planned = await rig.Ask("provider-config", false, ("id", id), ("revision", "1"), ("config", """{"label":"two"}"""), ("confirm-warnings", "yes"));
        rig.ValidateConfiguration = _ => Task.FromResult(Issues(("first warning", ValidationSeverity.Warning), ("second warning", ValidationSeverity.Warning)));
        Asked late = planned.View is null ? planned : await rig.Tap(planned.View, planned.Start);
        check(planned.View is not null && late.Settled?.Result is { Outcome: "failed" } && late.Detail.Contains("2 warnings", StringComparison.Ordinal)
            && rig.Store.Instance(instance.Id) is { Revision: 1, Configuration: Config } && rig.Running(instance.Id).CurrentLabel == "one",
            "confirm-warnings: a warning count that changed between page and tap refuses the change at apply (" + late.Detail + ")");

        // And fewer: none at the tap is also not what was confirmed.
        rig.ValidateConfiguration = null;
        rig.ValidateMount = (_, _) => Task.FromResult(Issues(("first warning", ValidationSeverity.Warning)));
        Asked again = await rig.Ask("mount-add", false, ("instance", id), ("kind", "tree"), ("path", "team"), ("base", "kv"), ("confirm-warnings", "yes"));
        rig.ValidateMount = (_, _) => Task.FromResult(Issues());
        Asked none = again.View is null ? again : await rig.Tap(again.View, again.Start);
        check(again.View is not null && none.Settled?.Result is { Outcome: "failed" } && rig.Store.Mounts().Count == 0,
            "confirm-warnings: a mount whose warnings went away between page and tap is refused too (" + none.Detail + ")");
    }

    private static async Task RemoveProvider(Action<bool, string> check, string root)
    {
        using Rig rig = new(root);
        await rig.Ask("provider-add", true, ("name", "vault-one"), ("type", "test"), ("config", Config), ("max-stale-seconds", "3600"));
        ProviderInstance instance = rig.Store.Instances().Single();
        string id = instance.Id.ToString("D");
        Mount mount = rig.Store.AddMount(instance.Id, MountKind.Tree, "team", "kv");
        Asked blocked = await rig.Ask("provider-remove", false, ("id", id), ("revision", "1"));
        check(blocked.Start is { Link: null, Status: 409, Error: { } mounts } && mounts.Contains("mount", StringComparison.Ordinal), "provider-remove: refused while mounts exist");

        // Mounts removed between the plan and the tap would be fine; one added in between is refused at apply.
        rig.Store.RemoveMount(mount.Id);
        rig.Cache(instance.Id, "ext-1");
        rig.Cache(instance.Id, "ext-2");
        Asked planned = await rig.Ask("provider-remove", false, ("id", id), ("revision", "1"));
        Mount again = rig.Store.AddMount(instance.Id, MountKind.Tree, "team", "kv");
        Asked late = planned.View is null ? planned : await rig.Tap(planned.View, planned.Start);
        check(late.Settled?.Result is { Outcome: "failed" } && rig.Store.Instance(instance.Id) is not null && rig.Count("SELECT COUNT(*) FROM provider_cache") == 2, "provider-remove: a mount added after the plan refuses it at apply; nothing is removed (" + late.Detail + ")");
        rig.Store.RemoveMount(again.Id);

        Asked removed = await rig.Ask("provider-remove", true, ("id", id), ("revision", "1"));
        check(removed.View is { } page && page.Sentence.Contains("2 cached", StringComparison.Ordinal), "provider-remove: the page names the number of cache rows to be deleted (" + removed.View?.Sentence + ")");
        check(removed.Applied && rig.Store.Instance(instance.Id) is null && rig.Count("SELECT COUNT(*) FROM provider_cache") == 0 && !rig.Registered(instance.Id),
            "provider-remove: the tap removes the instance and its cache rows and unregisters the adapter (" + removed.Detail + ")");
        check(rig.Events().Any(item => item.Outcome == "provider-removed" && item.Arguments.Contains("vault-one")), "provider-remove: a provider-removed event");
    }

    private static async Task Mounts(Action<bool, string> check, string root)
    {
        using Rig rig = new(root);
        await rig.Ask("provider-add", true, ("name", "vault-one"), ("type", "test"), ("config", Config), ("max-stale-seconds", "3600"));
        ProviderInstance instance = rig.Store.Instances().Single();
        string id = instance.Id.ToString("D");
        rig.Grant("g-shadowed", "team/dev/GITHUB");
        rig.Grant("g-shadowed-2", "team/ops/X, NATIVE");
        rig.Grant("g-other", "other/A");

        check((await rig.Ask("mount-add", false, ("instance", id), ("kind", "folder"), ("path", "team"), ("base", "kv"))).Start is { Link: null, Status: 400 }, "mount-add: an unknown kind is refused");
        check((await rig.Ask("mount-add", false, ("instance", id), ("kind", "tree"), ("path", "team/"), ("base", "kv"))).Start is { Link: null, Status: 400 }, "mount-add: an invalid path is refused");
        check((await rig.Ask("mount-add", false, ("instance", Guid.NewGuid().ToString("D")), ("kind", "tree"), ("path", "team"), ("base", "kv"))).Start is { Link: null, Status: 404 }, "mount-add: an unknown instance is refused (404)");

        string? validated = null;
        rig.ValidateMount = (_, path) =>
        {
            validated = path;

            return Task.FromResult(path == "bad" ? Issues(("no such path", ValidationSeverity.Error)) : Issues(("MOUNT-WARNING-canary", ValidationSeverity.Warning)));
        };
        check((await rig.Ask("mount-add", false, ("instance", id), ("kind", "tree"), ("path", "team"), ("base", "bad"))).Start is { Link: null, Status: 409 } && validated == "bad", "mount-add: validated through the adapter; an error refuses it");
        check((await rig.Ask("mount-add", false, ("instance", id), ("kind", "tree"), ("path", "team"), ("base", "kv"))).Start is { Link: null } unconfirmed && unconfirmed.Error!.Contains("confirm-warnings", StringComparison.Ordinal), "mount-add: a warning needs confirm-warnings=yes");

        rig.List = (_, _) => Task.FromResult(new ListSecretsResult([new ProviderSecretInfo("dev/GITHUB", "ext-gh", null), new ProviderSecretInfo("ops/X", "ext-x", null)], null, true));
        Asked added = await rig.Ask("mount-add", true, ("instance", id), ("kind", "tree"), ("path", "team"), ("base", "kv"), ("confirm-warnings", "yes"));
        Mount? mount = rig.Store.Mounts().SingleOrDefault();
        check(added.View is { } page && page.Sentence.Contains("2 active grants will end", StringComparison.Ordinal) && !page.Sentence.Contains("canary", StringComparison.Ordinal),
            "mount-add: the page names the number of active grants that will end (" + added.View?.Sentence + ")");
        check(added.Applied && mount is { Kind: MountKind.Tree, LogicalPath: "team", BasePath: "kv" } && rig.GrantStatus("g-shadowed") == "invalidated" && rig.GrantStatus("g-shadowed-2") == "invalidated" && rig.GrantStatus("g-other") == "active",
            "mount-add: the tap adds the mount and ends exactly those grants (" + added.Detail + ")");
        check(mount is not null && added.Detail.Length == 0 && rig.Store.Entries(mount.Id).Count == 2, "mount-add: the namespace is listed by the time the tap outcome settles");
        check(rig.Events().Any(item => item.Outcome == "mount-added" && item.Arguments.Contains("team")), "mount-add: a mount-added event");
        check((await rig.Ask("mount-add", false, ("instance", id), ("kind", "tree"), ("path", "team"), ("base", "kv"), ("confirm-warnings", "yes"))).Start is { Link: null, Status: 409 }, "mount-add: a duplicate mount is refused");

        // Remove: the entries go and the grants naming the mount's names end.
        rig.Grant("g-mounted", "team/dev/GITHUB");
        check((await rig.Ask("mount-remove", false, ("id", Guid.NewGuid().ToString("D")))).Start is { Link: null, Status: 404 }, "mount-remove: an unknown mount is refused (404)");
        string mountId = mount!.Id.ToString("D");
        Asked beforeNewGrant = await rig.Ask("mount-remove", false, ("id", mountId));
        rig.Grant("g-after-plan", "team/ops/X");
        Asked refused = await rig.Tap(beforeNewGrant.View!, beforeNewGrant.Start);
        check(!refused.Applied && refused.Detail.Contains("active grants", StringComparison.Ordinal) && rig.Store.Mounts().Count == 1
            && rig.GrantStatus("g-mounted") == "active" && rig.GrantStatus("g-after-plan") == "active"
            && rig.Events().All(item => item.Outcome != "mount-removed"), "mount-remove: a grant approved after planning rolls back the mount, both grants and the audit event");

        Asked removed = await rig.Ask("mount-remove", true, ("id", mountId));
        check(removed.View is { } removePage && removePage.Sentence.Contains("2 active grants will end", StringComparison.Ordinal) && removePage.Sentence.Contains("2 namespace entries", StringComparison.Ordinal),
            "mount-remove: the page names the grants that will end and the entries dropped (" + removed.View?.Sentence + ")");
        check(removed.Applied && rig.Store.Mounts().Count == 0 && rig.Store.Entries().Count == 0 && rig.GrantStatus("g-mounted") == "invalidated" && rig.GrantStatus("g-other") == "active",
            "mount-remove: the tap removes the mount, drops its entries and ends its grants (" + removed.Detail + ")");
        check(rig.Events().Any(item => item.Outcome == "mount-removed" && item.Arguments.Contains("team")), "mount-remove: a mount-removed event");
    }

    private static async Task Binding(Action<bool, string> check, string root)
    {
        using Rig rig = new(root);
        Dictionary<string, string> args = new() { ["name"] = "vault-one", ["type"] = "test", ["config"] = Config, ["max-stale-seconds"] = "3600" };
        Asked added = await rig.Ask("provider-add", true, [.. args.Select(item => (item.Key, item.Value))]);
        check(added.Applied, "binding: setup");

        // The mutation must name exactly what was signed: a changed configuration finds nothing; the same one is a repeat that applies nothing again.
        Dictionary<string, string> other = new(args) { ["config"] = """{"label":"swapped"}""" };
        MutationResult swapped = await rig.Service.MutateAsync(rig.Session, "provider-add", other, added.View!.Id, CancellationToken.None);
        check(swapped is { Status: 403, Code: "authorization-mismatch" } && rig.Store.Instances().Single().Configuration == Config, "binding: changing the configuration text after planning is refused");
        MutationResult first = await rig.Service.MutateAsync(rig.Session, "provider-add", args, added.View.Id, CancellationToken.None);
        MutationResult second = await rig.Service.MutateAsync(rig.Session, "provider-add", args, added.View.Id, CancellationToken.None);
        check(first.Applied && second is { Applied: true, Repeat: true } && rig.Store.Instances().Count == 1, "binding: the tap is single use (a retry is a repeat; nothing is applied twice)");

        // A config that differs from the planned one cannot be tapped into existence: a new authorization is planned and screened on its own.
        Asked again = await rig.Ask("provider-add", false, ("name", "vault-two"), ("type", "test"), ("config", Config), ("max-stale-seconds", "3600"));
        MutationResult untapped = again.View is null ? new MutationResult(0, null, null) : await rig.Service.MutateAsync(rig.Session, "provider-add", new Dictionary<string, string> { ["name"] = "vault-two", ["type"] = "test", ["config"] = Config, ["max-stale-seconds"] = "3600" }, again.View.Id, CancellationToken.None);
        check(untapped is { Status: 403, Code: "authorization-pending" } && rig.Store.Instances().Count == 1, "binding: without the tap nothing is added");
        rig.Service.CancelAuthorization(rig.Session, again.View?.Id ?? "");

        // Over HTTP: the configuration may be up to 2000 characters; every other parameter keeps the 300-character cap.
        AdminBrowser browser = await rig.App.SignedIn();
        string Request(string name, string config) => System.Text.Json.JsonSerializer.Serialize(new { operation = "provider-add", parameters = new Dictionary<string, string> { ["name"] = name, ["type"] = "test", ["config"] = config, ["max-stale-seconds"] = "60" } });
        string Long(int length) => "{\"label\":\"long\",\"note\":\"" + new string('n', length - 26) + "\"}";
        (int longStatus, string longBody) = await browser.PostAsync("/api/v1/authorizations", Request("vault-long", Long(1500)));
        check(longStatus == 201 && Long(1500).Length == 1500, "binding: a 1500-character configuration is accepted by the authorization request (" + longStatus + " " + longBody[..Math.Min(160, longBody.Length)] + ")");
        if (longStatus == 201)
        {
            using System.Text.Json.JsonDocument made = System.Text.Json.JsonDocument.Parse(longBody);
            await browser.SendAsync(HttpMethod.Delete, "/api/v1/authorizations/" + made.RootElement.GetProperty("id").GetString(), null);
        }

        (int tooLong, _) = await browser.PostAsync("/api/v1/authorizations", Request("vault-long", Long(2001)));
        (int longName, _) = await browser.PostAsync("/api/v1/authorizations", Request(new string('v', 301), Config));
        check(tooLong == 400 && longName == 400, "binding: a configuration over 2000 characters, or another parameter over 300, is refused (" + tooLong + " " + longName + ")");
    }

    private static async Task RegistryFailure(Action<bool, string> check, string root)
    {
        using Rig rig = new(root);
        await rig.Ask("provider-add", true, ("name", "vault-one"), ("type", "test"), ("config", Config), ("max-stale-seconds", "3600"));
        ProviderInstance instance = rig.Store.Instances().Single();
        rig.Update = () => throw new ProviderAdapterException(ProviderErrorKind.Unavailable, "upstream said hunter2-canary");
        Asked changed = await rig.Ask("provider-config", true, ("id", instance.Id.ToString("D")), ("revision", "1"), ("config", """{"label":"two"}"""));
        check(changed.Applied && rig.Store.Instance(instance.Id) is { Revision: 2, Configuration: """{"label":"two"}""" }, "registry failure: the configuration stays committed (" + changed.Detail + ")");
        check(changed.Detail.Contains("running", StringComparison.Ordinal) && !changed.Detail.Contains("hunter2", StringComparison.Ordinal), "registry failure: the outcome text says the running provider did not take it, without the adapter's text");
        check(rig.Service.Providers!.Provider(instance.Id)?.Status is { Lifecycle: "unavailable" }, "registry failure: visible as the instance's status");

        rig.Update = null;
        Asked recovered = await rig.Ask("provider-config", true, ("id", instance.Id.ToString("D")), ("revision", "2"), ("config", """{"label":"three"}"""));
        check(recovered.Applied && recovered.Detail.Length == 0 && rig.Service.Providers.Provider(instance.Id)?.Status is { Lifecycle: "ready" },
            "registry failure: the next successful update restores Ready");

        rig.App.Service.Providers!.ChangeDeadline = TimeSpan.FromMilliseconds(120);
        TaskCompletionSource release = new(TaskCreationOptions.RunContinuationsAsynchronously);
        rig.Update = () => release.Task;
        try
        {
            Asked timedOut = await rig.Ask("provider-config", true, ("id", instance.Id.ToString("D")), ("revision", "3"), ("config", """{"label":"four"}"""));
            check(timedOut.Applied && timedOut.Detail.Contains("running", StringComparison.Ordinal)
                && rig.Service.Providers.Provider(instance.Id)?.Status is { Lifecycle: "unavailable" },
                "registry timeout: an uncooperative update leaves the committed configuration and returns an unavailable status");
        }
        finally
        {
            release.TrySetResult();
        }

        rig.Service.Providers.RefreshDeadline = TimeSpan.FromMilliseconds(120);
        TaskCompletionSource<ListSecretsResult> listing = new(TaskCreationOptions.RunContinuationsAsynchronously);
        rig.List = (_, _) => listing.Task;
        try
        {
            Asked mounted = await rig.Ask("mount-add", true, ("instance", instance.Id.ToString("D")), ("kind", "tree"), ("path", "team"), ("base", "kv"));
            check(mounted.Applied && mounted.Detail.Contains("could not be listed", StringComparison.Ordinal) && rig.Store.Mounts().Count == 1 && rig.Store.Entries().Count == 0,
                "listing timeout: the tap leaves the mount committed and reports that its namespace still needs refreshing");
        }
        finally
        {
            listing.TrySetResult(new ListSecretsResult([], null, true));
        }
    }

    private static async Task Remote(Action<bool, string> check, string root)
    {
        using Rig rig = new(root, providers: false);
        foreach ((string op, (string, string)[] args) in new (string, (string, string)[])[]
        {
            ("provider-add", [("name", "v"), ("type", "test"), ("config", Config), ("max-stale-seconds", "60")]),
            ("provider-config", [("id", Guid.NewGuid().ToString("D")), ("revision", "1"), ("config", Config)]),
            ("provider-max-stale", [("id", Guid.NewGuid().ToString("D")), ("revision", "1"), ("max-stale-seconds", "60")]),
            ("provider-remove", [("id", Guid.NewGuid().ToString("D")), ("revision", "1")]),
            ("mount-add", [("instance", Guid.NewGuid().ToString("D")), ("kind", "tree"), ("path", "team"), ("base", "kv")]),
            ("mount-remove", [("id", Guid.NewGuid().ToString("D"))]),
        })
        {
            Asked refused = await rig.Ask(op, false, args);
            check(refused.Start is { Link: null, Status: 503, Error: { } why } && why.Contains("cannot be changed from this service", StringComparison.Ordinal), "remote: " + op + " is refused where there is no provider authority (" + refused.Start.Status + ")");
        }
    }
}
