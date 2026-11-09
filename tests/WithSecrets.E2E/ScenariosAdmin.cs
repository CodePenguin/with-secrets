using System.Text;
using System.Text.Json;

namespace WithSecrets.E2E;

/// <summary>
/// Phase 6b-1: the administration JSON API driven by a program (the single-page application is the next task, 6b-2) and the passkey in a real browser. The admin passkey is the browser's virtual
/// authenticator. A session starts with one tap and reads only; every change is its own authorization (POST /api/v1/authorizations), the tap on the one-use passkey page in the browser, and then
/// the one mutation that carries the authorization id. Until the single-page application exists these scenarios keep the coverage of the Phase 6a browser flows i1 to i4 (login, approve a machine,
/// revoke a grant, audit search) at the API; the page-level checks of those flows (what the buttons and views show) move to 6b-2.
/// </summary>
internal static class ScenariosAdmin
{
    private sealed class App : IDisposable
    {
        public App(Rig rig)
        {
            Service = HostService.Start(new HostServiceOptions { Lock = AuthorityLock.UnlockedForTests(), State = rig.State, Store = rig.Store, Grants = rig.Grants, Deployment = rig.Machine.Deployment, Port = 0 });
            Api = new ApiClient(Service.Port);
        }

        public HostService Service { get; }

        public ApiClient Api { get; }

        public void Dispose()
        {
            Api.Dispose();
            Service.Dispose();
        }
    }

    /// <summary>A program that talks to the API as the page's script would: cookies kept by hand, the anti-forgery value of GET /session and the Origin of the page on every request.</summary>
    private sealed class ApiClient(int port) : IDisposable
    {
        private readonly HttpClient _http = new(new SocketsHttpHandler { UseProxy = false, UseCookies = false, AllowAutoRedirect = false }) { Timeout = TimeSpan.FromSeconds(60) };
        private readonly Dictionary<string, string> _cookies = [];

        public string? Csrf { get; private set; }

        public string LastSetCookie { get; private set; } = "";

        public bool HasSession => _cookies.ContainsKey(AdminSessions.SessionCookie);

        public string Token => _cookies.GetValueOrDefault(AdminSessions.SessionCookie, "");

        public async Task<(int Status, JsonElement Body)> Send(HttpMethod method, string path, object? body = null)
        {
            using HttpRequestMessage request = new(method, $"http://127.0.0.1:{port}{path}");
            if (body is not null)
            {
                request.Content = new StringContent(JsonSerializer.Serialize(body), Encoding.UTF8, "application/json");
            }

            if (method != HttpMethod.Get)
            {
                request.Headers.Add("Origin", $"http://localhost:{port}");
                if (Csrf is not null)
                {
                    request.Headers.Add(AdminApi.TokenHeader, Csrf);
                }
            }

            if (_cookies.Count > 0)
            {
                request.Headers.Add("Cookie", string.Join("; ", _cookies.Select(item => item.Key + "=" + item.Value)));
            }

            using HttpResponseMessage response = await _http.SendAsync(request);
            StringBuilder all = new();
            if (response.Headers.TryGetValues("Set-Cookie", out IEnumerable<string>? values))
            {
                foreach (string line in values)
                {
                    all.Append(line).Append('\n');
                    string[] parts = line.Split(';');
                    int equals = parts[0].IndexOf('=', StringComparison.Ordinal);
                    string name = parts[0][..equals].Trim();
                    string value = parts[0][(equals + 1)..];
                    if (value.Length == 0 || parts.Any(part => part.Trim().StartsWith("max-age=0", StringComparison.OrdinalIgnoreCase)))
                    {
                        _cookies.Remove(name);
                    }
                    else
                    {
                        _cookies[name] = value;
                    }
                }
            }

            LastSetCookie = all.ToString();
            string text = await response.Content.ReadAsStringAsync();
            JsonElement json = JsonDocument.Parse(text.Length == 0 ? "{}" : text).RootElement.Clone();
            if (path == "/api/v1/session" && method == HttpMethod.Get && response.IsSuccessStatusCode)
            {
                Csrf = json.GetProperty("antiForgery").GetString();
            }

            return ((int)response.StatusCode, json);
        }

        public Task<(int Status, JsonElement Body)> Get(string path) => Send(HttpMethod.Get, path);

        public void Dispose() => _http.Dispose();
    }

    /// <summary>The sign-in: the login request, the passkey page of this login (one tap in the browser), and the return to the API, which claims the session.</summary>
    private static async Task SignIn(Ctx c, App app, S s)
    {
        (int before, JsonElement whoBefore) = await app.Api.Get("/api/v1/session");
        s.Check(before == 200 && !whoBefore.GetProperty("authenticated").GetBoolean() && (await app.Api.Get("/api/v1/machines")).Status == 401, "before the sign-in there is no session and no view is served");
        (int started, JsonElement login) = await app.Api.Send(HttpMethod.Post, "/api/v1/session", new { });
        s.Check(started == 202 && login.TryGetProperty("link", out _), "the sign-in answers the link of its one-use passkey page");
        await c.Page.GotoAsync(login.GetProperty("link").GetString()!);
        string request = await c.TextAppears("#request");
        s.Check(request.Contains("start an administrator session") && request.Contains("login:"), "the sign-in page says what the tap does and carries this login's code (" + request.Split('\n')[0] + ")");
        s.Check(await c.PasskeyCalls() == 0, "tap rule: no passkey prompt on load of the sign-in page");
        await c.Click("#approve");
        await c.StatusContains("Approved");
        (_, JsonElement who) = await app.Api.Get("/api/v1/session");
        s.Check(who.GetProperty("authenticated").GetBoolean() && app.Api.HasSession, "after the tap the next call to the session resource claims the session");
    }

    /// <summary>One change as a person makes it: ask for the authorization, tap on its page in the browser, then send the mutation that carries it. Returns the mutation's status and body and the text the page showed.</summary>
    private static async Task<(int Status, JsonElement Body, string Request)> Change(Ctx c, App app, S s, string operation, Dictionary<string, object> parameters, HttpMethod method, string path, Dictionary<string, object> mutation, Func<Task>? beforeTap = null)
    {
        (int status, JsonElement made) = await app.Api.Send(HttpMethod.Post, "/api/v1/authorizations", new { operation, parameters });
        s.Check(status == 201 && made.GetProperty("state").GetString() == "pending", "the authorization is asked for first (" + operation + ")");
        await c.Page.GotoAsync(made.GetProperty("link").GetString()!);
        string request = await c.TextAppears("#request");
        if (beforeTap is not null)
        {
            await beforeTap();
        }

        await c.Click("#approve");
        await c.StatusContains("Approved");
        string id = made.GetProperty("id").GetString()!;
        string state = "pending";
        for (int i = 0; i < 100 && state == "pending"; i++)
        {
            (_, JsonElement look) = await app.Api.Get("/api/v1/authorizations/" + id);
            state = look.GetProperty("state").GetString()!;
            if (state == "pending")
            {
                await Task.Delay(50);
            }
        }

        s.Check(state == "verified", "the tap makes the authorization verified (" + state + ")");
        Dictionary<string, object> body = new(mutation) { ["authorization"] = id };
        (int mutated, JsonElement answer) = await app.Api.Send(method, path, body);

        return (mutated, answer, request);
    }

    public static async Task Login(Host host, S s)
    {
        using Rig rig = new();
        await using Ctx c = await Ctx.NewAsync(host);
        await Flows.Configure(rig, c);
        using App app = new(rig);
        await SignIn(c, app, s);
        (_, JsonElement who) = await app.Api.Get("/api/v1/session");
        s.Check(who.GetProperty("admin").GetString() is { Length: > 0 } && who.GetProperty("idleExpires").GetString() is { Length: > 10 }, "signed in: whoami names the key and says when the session ends");
        string cookie = string.Join("\n", app.Api.LastSetCookie.Split('\n').Where(line => line.Length > 0));
        s.Check(app.Api.HasSession && app.Api.Token.Length > 20, "the session cookie is held by the client");
        (int machinesStatus, JsonElement machines) = await app.Api.Get("/api/v1/machines");
        s.Check(machinesStatus == 200 && machines.GetProperty("items")[0].GetProperty("fingerprint").GetString() == rig.Machine.Deployment.Fingerprint && machines.GetProperty("items")[0].GetProperty("status").GetString() == "trusted", "the machines resource shows the machine and its status");
        s.Check(rig.Machine.Deployment.Store.Audit(100).Any(entry => entry.Event == "admin-operation" && entry.Detail.StartsWith("admin-session; started", StringComparison.Ordinal)), "the session start is in the authority's audit history");
        _ = cookie;

        // The browser's own jar never sees the API session: the cookie is HttpOnly and scoped to /api/v1 (checked at the HTTP level in the unit suite); here the page cannot read it.
        string visible = await c.Page.EvaluateAsync<string>("() => document.cookie");
        s.Check(!visible.Contains(AdminSessions.SessionCookie, StringComparison.Ordinal), "script in the passkey page cannot read the session cookie");

        // A session alone changes nothing: a change without its authorization is refused.
        (int bare, JsonElement bareBody) = await app.Api.Send(HttpMethod.Post, "/api/v1/lock", new { authorization = "AAAAAAAAAAAA" });
        s.Check(bare == 403 && bareBody.GetProperty("code").GetString() == "authorization-invalid" && !app.Service.Lock.IsLocked, "a session alone cannot change anything (403 authorization-invalid)");

        // Sign out ends it: the views need a new sign-in.
        (int outStatus, _) = await app.Api.Send(HttpMethod.Delete, "/api/v1/session");
        (int after, JsonElement afterBody) = await app.Api.Get("/api/v1/machines");
        s.Check(outStatus == 200 && after == 401 && afterBody.GetProperty("code").GetString() == "session-required", "after sign out the machines resource is refused (401)");
        s.NoProblems(c);
    }

    public static async Task ApproveMachine(Host host, S s)
    {
        using Rig rig = new();
        await using Ctx c = await Ctx.NewAsync(host);
        await Flows.Configure(rig, c);
        using App app = new(rig);
        using SoftwareSigningKey other = new();
        string fp = KeyIdentity.Fingerprint(other.PublicKey);
        byte[] challenge = await rig.Machine.Deployment.Authority.BeginEnrollmentAsync();
        await rig.Machine.Deployment.Authority.EnrollAsync(EnrollmentRequest.Create("other-host", challenge, other));
        AuthorityStore store = rig.Machine.Deployment.Store;
        s.Check(store.Find(fp) is { Status: MachineStatus.Pending }, "fixture: a second machine is waiting as Pending");
        await SignIn(c, app, s);
        (_, JsonElement list) = await app.Api.Get("/api/v1/machines");
        JsonElement row = list.GetProperty("items").EnumerateArray().First(item => item.GetProperty("fingerprint").GetString() == fp);
        s.Check(row.GetProperty("status").GetString() == "pending" && row.GetProperty("actions").EnumerateArray().Any(item => item.GetString() == "approve"), "the machines resource lists the Pending machine and offers approve");
        (int status, JsonElement answer, string request) = await Change(c, app, s, "machine-approve", new() { ["fingerprint"] = fp[..20], ["name"] = "e2e second" }, HttpMethod.Post, "/api/v1/machines/" + fp[..20] + "/approve", new() { ["name"] = "e2e second" },
            async () =>
            {
                s.Check(await c.PasskeyCalls() == 0 && store.Find(fp)!.Status == MachineStatus.Pending, "tap rule: nothing is asked or changed before the tap");
            });
        s.Check(request.Contains("approve this machine") && request.Contains(KeyIdentity.Display(fp)) && request.Contains("e2e second") && request.Contains("Operation: approve-machine"), "its own passkey page shows the action, the full fingerprint and the name");
        s.Check(status == 200 && answer.GetProperty("outcome").GetString() == "applied" && store.Find(fp) is { Status: MachineStatus.Trusted, FriendlyName: "e2e second" }, "the tap and its mutation approve the machine");
        (_, JsonElement detail) = await app.Api.Get("/api/v1/machines/" + fp[..20]);
        s.Check(detail.GetProperty("status").GetString() == "trusted", "the machine resource now shows it Trusted");
        s.Check(store.Audit(100).Any(entry => entry.Event == "machine-approve" && entry.Actor.StartsWith("admin passkey", StringComparison.Ordinal)), "the audit history names the admin passkey that tapped");

        // The same authorization cannot approve it again or anything else.
        s.NoProblems(c);
    }

    private static async Task<string> MakeGrant(Ctx c, Rig rig, App app, S s)
    {
        await Scenarios3.SeedSecret(rig, c);
        File.WriteAllLines(Path.Combine(rig.Work, "check.cmd"), ["@echo off", "echo script-value=%E2E_SECRET%"]);
        CliCommand.Run run = (CliCommand.Run)Cmds.Parse(["--secrets", "E2E_SECRET", "--reason", "e2e grant", "--", "cmd", "/d", "/c", "check.cmd"]);
        using Cmd<int> approve = new((port, o, e) => LaunchClient.RunAsync(run.Args, rig.Work, app.Service.Port, port, o, e, rig.Machine.Trust, approve: true).GetAwaiter().GetResult());
        await c.Page.GotoAsync(await approve.LinkAsync());
        await c.TextAppears("#request");
        await c.Page.Locator("#reuse").SelectOptionAsync(new Microsoft.Playwright.SelectOptionValue { Index = 1 });
        await c.Click("#approve-for");
        await c.StatusContains("Approved");
        s.Check(await approve.Result.WaitAsync(TimeSpan.FromSeconds(30)) == 0, "fixture: a grant was made from the approval page");
        GrantRecord grant = rig.Machine.Deployment.Store.Grants().Single();

        return grant.Id;
    }

    public static async Task GrantRevoke(Host host, S s)
    {
        using Rig rig = new();
        await using Ctx c = await Ctx.NewAsync(host);
        await Flows.Configure(rig, c);
        using App app = new(rig);
        string id = await MakeGrant(c, rig, app, s);
        AuthorityStore store = rig.Machine.Deployment.Store;
        await SignIn(c, app, s);
        (_, JsonElement list) = await app.Api.Get("/api/v1/grants");
        JsonElement row = list.GetProperty("items").EnumerateArray().First(item => item.GetProperty("id").GetString() == id);
        s.Check(row.GetProperty("state").GetString() == "active" && row.GetProperty("secretNames").GetString()!.Contains("E2E_SECRET") && row.GetProperty("program").GetString()!.Contains("cmd") && row.GetProperty("actions").EnumerateArray().Any(item => item.GetString() == "revoke"), "the grants resource lists the grant with its state, secret names and program, and offers revoke");
        (int status, JsonElement answer, string request) = await Change(c, app, s, "grant-revoke", new() { ["id"] = id }, HttpMethod.Post, "/api/v1/grants/" + id + "/revoke", [],
            () =>
            {
                s.Check(store.FindGrant(id) is { Status: "active" }, "nothing changed before the tap");

                return Task.CompletedTask;
            });
        s.Check(request.Contains("revoke this grant") && request.Contains(id) && request.Contains("Operation: revoke-grant"), "its own passkey page names the revocation and the grant");
        s.Check(status == 200 && answer.GetProperty("outcome").GetString() == "applied" && store.FindGrant(id) is { Status: "revoked" }, "the tap and its mutation revoke the grant");
        (_, JsonElement after) = await app.Api.Get("/api/v1/grants/" + id);
        s.Check(after.GetProperty("status").GetString() == "revoked" && after.GetProperty("actions").GetArrayLength() == 0, "the grant resource shows it revoked, with no further action");
        s.NoProblems(c);
    }

    public static async Task AuditSearch(Host host, S s)
    {
        using Rig rig = new();
        await using Ctx c = await Ctx.NewAsync(host);
        await Flows.Configure(rig, c);
        await Scenarios3.SeedSecret(rig, c);
        File.WriteAllLines(Path.Combine(rig.Work, "check.cmd"), ["@echo off", "echo script-value=%E2E_SECRET%"]);
        using App app = new(rig);
        CliCommand.Run run = (CliCommand.Run)Cmds.Parse(["--secrets", "E2E_SECRET", "--reason", "e2e audit", "--", "cmd", "/d", "/c", "check.cmd"]);
        using (Cmd<int> cmd = new((port, o, e) => LaunchClient.RunAsync(run.Args, rig.Work, app.Service.Port, port, o, e, rig.Machine.Trust).GetAwaiter().GetResult()))
        {
            await c.Page.GotoAsync(await cmd.LinkAsync());
            await c.TextAppears("#request");
            await c.Click("#approve");
            s.Check(await cmd.Result.WaitAsync(TimeSpan.FromSeconds(30)) == 0, "fixture: a run was approved and ran");
        }

        await SignIn(c, app, s);
        bool found = false;
        string all = "";
        for (int i = 0; i < 30 && !found; i++)
        {
            (_, JsonElement events) = await app.Api.Get("/api/v1/audit/events");
            all = events.GetRawText();
            found = all.Contains("check.cmd", StringComparison.Ordinal);
            if (!found)
            {
                await Task.Delay(1000);
            }
        }

        s.Check(found, "the audit events resource shows the run's events once the host has uploaded them");
        s.Check(all.Contains("approved") && all.Contains("started") && !all.Contains("s3cr3t-e2e-value-1"), "it shows the authorization and launch outcomes and no secret value");
        (_, JsonElement filtered) = await app.Api.Get("/api/v1/audit/events?text=check.cmd&type=launch");
        string narrowed = filtered.GetRawText();
        s.Check(narrowed.Contains("launch") && !narrowed.Contains("\"type\":\"authorization\""), "the type and text filters narrow the events to the launch");
        (_, JsonElement none) = await app.Api.Get("/api/v1/audit/events?text=nothing-like-this");
        s.Check(none.GetProperty("items").GetArrayLength() == 0, "a search with no match returns no items");
        (int gapsStatus, JsonElement gaps) = await app.Api.Get("/api/v1/audit/gaps");
        s.Check(gapsStatus == 200 && gaps.GetProperty("items").ValueKind == JsonValueKind.Array, "the gap list is available");
        s.NoProblems(c);
    }
}
