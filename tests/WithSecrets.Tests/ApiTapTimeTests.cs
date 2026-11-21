using System.Text.Json;

namespace WithSecrets.Tests;

/// <summary>
/// Task M8 group B: a completed passkey tap is never lost. The service applies the plan the tap authorized when the tap is verified (the tap is already fresh, bound to the operation and its parameters, single use
/// and user verified), so a browser tab that was backgrounded, discarded or idled out between the tap and the apply loses nothing; the page reads the outcome by authorization id (also after a reload) and
/// every retry is answered with the same outcome and applies nothing again. The bundle of a new invitation is held by the service for the one browser that asked, given once, and then gone.
/// </summary>
internal static class ApiTapTimeTests
{
    public static async Task Run(Action<bool, string> check, string root)
    {
        await AppliedAtTheTap(check, root);
        await ResultStates(check, root);
        await Cancelling(check, root);
        await BundleOnce(check, root);
        await Delegated(check, root);
    }

    private static string? Member(string body, string name)
    {
        using JsonDocument doc = JsonDocument.Parse(body);

        return doc.RootElement.TryGetProperty(name, out JsonElement value) ? (value.ValueKind == JsonValueKind.String ? value.GetString() : value.GetRawText()) : null;
    }

    private static string? Inner(string body, string outer, string name)
    {
        using JsonDocument doc = JsonDocument.Parse(body);

        return doc.RootElement.TryGetProperty(outer, out JsonElement value) && value.ValueKind == JsonValueKind.Object && value.TryGetProperty(name, out JsonElement inner)
            ? (inner.ValueKind == JsonValueKind.String ? inner.GetString() : inner.GetRawText())
            : null;
    }

    private static int Tap(AdminApp app, Tapped tapped, TestAuthenticator signer) => TestState.Approve(app.Http, tapped.PageUrl, "http://localhost:" + new Uri(tapped.Link!).Port, "localhost", signer).Item1;

    private static string AuditText(AuthorityStore store) => string.Join("\n", store.Audit(5000).Select(entry => entry.Event + "|" + entry.Actor + "|" + entry.Detail));

    private static async Task<string> Read(AdminBrowser b, string id, bool collect = false) => (await b.SendAsync(HttpMethod.Get, "/api/v1/authorizations/" + id + (collect ? "?collect=invitation" : ""), null)).Body;

    // ---- the change is made at the tap, with no browser involved afterwards ----

    private static async Task AppliedAtTheTap(Action<bool, string> check, string root)
    {
        using AdminApp app = new(root);
        string fp = app.Fingerprint[..20];
        AdminBrowser b = await app.SignedIn();
        await b.LoadAsync();

        // The browser asks for the authorization and then goes away: it never sends a mutation request and never polls.
        Tapped made = await b.OpAsyncWithoutMutation("machine-rename", null, ("fingerprint", fp), ("name", "while away"));
        check(made.Link is not null && app.Store.Find(app.Fingerprint)!.FriendlyName != "while away", "tap time: before the tap nothing is changed");
        app.Clock.Advance(TimeSpan.FromSeconds(31));
        int tap = Tap(app, made, app.Laptop);
        check(tap == 200 && await HostServiceTests.WaitFor(() => app.Store.Find(app.Fingerprint)!.FriendlyName == "while away"), "tap time: the verified tap makes the change by itself, with no request from the browser after it");
        await HostServiceTests.WaitFor(() => AuditText(app.Store).Contains("rename-machine; applied", StringComparison.Ordinal));
        string applied = AuditText(app.Store).Split('\n').Count(line => line.Contains("rename-machine", StringComparison.Ordinal) && line.Contains("applied", StringComparison.Ordinal)).ToString();
        check(applied == "1", "tap time: the change is audited as applied once (" + applied + ")");

        // A reload (a new page of the same session) reads the outcome by the authorization id; reading it again says the same.
        AdminBrowser reloaded = app.Browser();
        foreach ((string name, string value) in b.Cookies)
        {
            reloaded.SetCookie(name, value);
        }

        reloaded.SessionToken = b.SessionToken;
        string first = await Read(reloaded, made.AuthorizationId!);
        string second = await Read(reloaded, made.AuthorizationId!);
        check(Member(first, "state") == "consumed" && Inner(first, "result", "outcome") == "applied" && Inner(second, "result", "outcome") == "applied", "tap time: after a reload the page reads the outcome (applied) by the authorization id, again and again");

        // Retrying the mutation request (a client that did not see the answer) applies nothing again.
        (HttpMethod method, string path, string json) = reloaded.MutationRequest("machine-rename", made.AuthorizationId, ("fingerprint", fp), ("name", "while away"));
        (int again, string againBody) = await reloaded.SendAsync(method, path, json);
        (int third, string thirdBody) = await reloaded.SendAsync(method, path, json);
        check(again == 200 && Member(againBody, "outcome") == "applied" && third == 200 && Member(thirdBody, "outcome") == "already-applied" && AuditText(app.Store).Split('\n').Count(line => line.Contains("rename-machine", StringComparison.Ordinal) && line.Contains("applied", StringComparison.Ordinal)) == 1,
            "tap time: a retry is answered with the same outcome (applied, then already-applied) and applies nothing again");

        // Another operation with the same authorization still changes nothing.
        (HttpMethod dm, string dp, string dj) = reloaded.MutationRequest("machine-disable", made.AuthorizationId, ("fingerprint", fp));
        (int other, string otherBody) = await reloaded.SendAsync(dm, dp, dj);
        check(other == 403 && Member(otherBody, "code") == "authorization-mismatch" && app.Store.Find(app.Fingerprint)!.Status == MachineStatus.Trusted, "tap time: the authorization is bound to its operation: another one is refused and changes nothing");

        // The session ending between the tap and the read (an idle-out) does not undo or repeat it: the change was made at the tap.
        AdminBrowser idler = await app.SignedIn();
        Tapped lost = await idler.OpAsyncWithoutMutation("set-audit-retention", null, ("days", "21"));
        app.Clock.Advance(TimeSpan.FromSeconds(31));
        Tap(app, lost, app.Laptop);
        await HostServiceTests.WaitFor(() => app.Store.AuditRetentionDays() == 21 && AuditText(app.Store).Contains("set-audit-retention; applied", StringComparison.Ordinal));
        app.Clock.Advance(TimeSpan.FromMinutes(16));
        (int expiredRead, _) = await idler.SendAsync(HttpMethod.Get, "/api/v1/authorizations/" + lost.AuthorizationId, null);
        check(app.Store.AuditRetentionDays() == 21 && expiredRead == 404 && AuditText(app.Store).Contains("set-audit-retention; applied", StringComparison.Ordinal), "tap time: a session that idled out after the tap keeps the change (it was made and audited at the tap); the ended session can read nothing more (404)");
    }

    // ---- the result states ----

    private static async Task ResultStates(Action<bool, string> check, string root)
    {
        using AdminApp app = new(root);
        string fp = app.Fingerprint[..20];
        AdminBrowser b = await app.SignedIn();

        // refused: a tap that is not accepted never becomes a change, and says why.
        Tapped refused = await b.OpAsync("machine-rename", app.Phone, true, null, true, ("fingerprint", fp), ("name", "refused"));
        string state = await b.WaitAuthorizationAsync(refused.AuthorizationId!);
        string view = await Read(b, refused.AuthorizationId!);
        check(state == "refused" && Member(view, "detail") is { Length: > 0 } && Inner(view, "result", "outcome") is null && app.Store.Find(app.Fingerprint)!.FriendlyName != "refused", "results: a refused tap reads as refused with a reason and changes nothing");

        // failed: the tap was good but the change cannot be made (the machine changed in between).
        Tapped waiting = await b.OpAsyncWithoutMutation("machine-disable", null, ("fingerprint", fp));
        app.Store.Disable(app.Fingerprint, "someone else");
        app.Clock.Advance(TimeSpan.FromSeconds(31));
        Tap(app, waiting, app.Laptop);
        await b.WaitAuthorizationAsync(waiting.AuthorizationId!);
        string failed = await Read(b, waiting.AuthorizationId!);
        check(Member(failed, "state") == "consumed" && Inner(failed, "result", "outcome") == "failed" && Inner(failed, "result", "code") == "operation-failed" && Inner(failed, "result", "detail") is { Length: > 0 }, "results: a good tap whose change cannot be made reads as failed, with a safe sentence");
        app.Store.Enable(app.Fingerprint, "test");

        // already applied and expired are in the binding suite (a retry is answered as already applied; a tap that never came expires).
        string pendingView = (await b.PostAsync("/api/v1/authorizations", AdminBrowser.AuthorizationBody("machine-rename", ("fingerprint", fp), ("name", "pending")))).Body;
        string pendingRead = await Read(b, Member(pendingView, "id")!);
        check(Member(pendingRead, "state") == "pending" && Inner(pendingRead, "result", "outcome") is null && Member(pendingRead, "result") is null or "null", "results: before the tap the authorization is pending and has no result");
    }

    // ---- cancelling ----

    private static async Task Cancelling(Action<bool, string> check, string root)
    {
        using AdminApp app = new(root);
        string fp = app.Fingerprint[..20];
        AdminBrowser b = await app.SignedIn();
        AdminBrowser thief = await app.SignedIn();

        Tapped waiting = await b.OpAsyncWithoutMutation("machine-rename", null, ("fingerprint", fp), ("name", "cancelled"));
        (int stolen, _) = await thief.SendAsync(HttpMethod.Delete, "/api/v1/authorizations/" + waiting.AuthorizationId, null);
        (int noOrigin, string noOriginBody) = await b.SendAsync(HttpMethod.Delete, "/api/v1/authorizations/" + waiting.AuthorizationId, null, origin: null);
        check(stolen == 404 && noOrigin == 403 && Member(noOriginBody, "code") == "origin-required" && Member(await Read(b, waiting.AuthorizationId!), "state") == "pending", "cancel: another session cannot cancel it (404) and a request without the page's Origin is refused (403)");
        (int cancelled, _) = await b.SendAsync(HttpMethod.Delete, "/api/v1/authorizations/" + waiting.AuthorizationId, null);
        string view = await Read(b, waiting.AuthorizationId!);
        check(cancelled == 200 && Member(view, "state") == "refused" && Member(view, "detail")!.Contains("cancelled", StringComparison.Ordinal), "cancel: the owner cancels an authorization whose tap has not been made; it reads as refused (cancelled)");
        app.Clock.Advance(TimeSpan.FromSeconds(31));
        Tap(app, waiting, app.Laptop);
        await Task.Delay(300);
        check(app.Store.Find(app.Fingerprint)!.FriendlyName != "cancelled" && Member(await Read(b, waiting.AuthorizationId!), "state") == "refused", "cancel: a tap on the page of a cancelled authorization changes nothing");
        (int again, _) = await b.SendAsync(HttpMethod.Delete, "/api/v1/authorizations/" + waiting.AuthorizationId, null);
        check(again == 200, "cancel: cancelling again is harmless");

        Tapped done = await b.OpAsyncWithoutMutation("machine-rename", app.Laptop, ("fingerprint", fp), ("name", "done"));
        await b.WaitAuthorizationAsync(done.AuthorizationId!);
        (int late, string lateBody) = await b.SendAsync(HttpMethod.Delete, "/api/v1/authorizations/" + done.AuthorizationId, null);
        check(late == 409 && Member(lateBody, "code") == "already-judged" && app.Store.Find(app.Fingerprint)!.FriendlyName == "done", "cancel: after the tap was judged the change cannot be taken back (409)");
    }

    // ---- the bundle of a new invitation: held for the browser that asked, given once ----

    private static async Task BundleOnce(Action<bool, string> check, string root)
    {
        using AdminApp app = new(root, machineEndpoint: true);
        AdminBrowser b = await app.SignedIn();
        Tapped created = await b.OpAsyncWithoutMutation("pairing-create", app.Laptop);
        await b.WaitAuthorizationAsync(created.AuthorizationId!);
        string plain = await Read(b, created.AuthorizationId!);
        check(Inner(plain, "result", "outcome") == "applied" && Inner(plain, "result", "invitation") is null or "null" && !plain.Contains("wsp", StringComparison.Ordinal) && app.Store.Invitations().Count == 1, "bundle: an invitation made at the tap is not in an ordinary read of its authorization");
        AdminBrowser stranger = await app.SignedIn();
        (int strangerStatus, _) = await stranger.SendAsync(HttpMethod.Get, "/api/v1/authorizations/" + created.AuthorizationId + "?collect=invitation", null);
        string taken = await Read(b, created.AuthorizationId!, collect: true);
        string bundle = Inner(taken, "result", "invitation") is { } text ? (Inner("{\"x\":" + text + "}", "x", "bundle") ?? "") : "";
        string gone = await Read(b, created.AuthorizationId!, collect: true);
        (HttpMethod method, string path, string json) = b.MutationRequest("pairing-create", created.AuthorizationId);
        (int replay, string replayBody) = await b.SendAsync(method, path, json);
        check(strangerStatus == 404 && bundle.Length > 20 && PairingBundle.TryParse(bundle) is not null, "bundle: the browser that asked collects the bundle (another session cannot)");
        check(Inner(gone, "result", "invitation") is null or "null" && Inner(gone, "result", "invitationGone") == "true" && replay == 200 && !replayBody.Contains(bundle, StringComparison.Ordinal) && !gone.Contains(bundle, StringComparison.Ordinal), "bundle: it is given once; a second read or a retry never gives it again (invitationGone)");
        string listing = (await b.SendAsync(HttpMethod.Get, "/api/v1/pairing/invitations", null)).Body;
        check(!listing.Contains(bundle, StringComparison.Ordinal) && !AuditText(app.Store).Contains(bundle, StringComparison.Ordinal), "bundle: the list and the audit history never hold it");

        // Held too long: not collected within the hold, it is gone for good.
        Tapped second = await b.OpAsyncWithoutMutation("pairing-create", app.Laptop);
        await b.WaitAuthorizationAsync(second.AuthorizationId!);
        app.Clock.Advance(AdminService.BundleHold + TimeSpan.FromSeconds(10));
        await b.GetAsync("/api/v1/machines");
        string late = await Read(b, second.AuthorizationId!, collect: true);
        check(Inner(late, "result", "outcome") == "applied" && Inner(late, "result", "invitation") is null or "null" && Inner(late, "result", "invitationGone") == "true", "bundle: one that was not collected within " + AdminService.BundleHold.TotalMinutes + " minutes is gone (the invitation can be revoked and made again) (" + late + ")");
        (int badQuery, _) = await b.SendAsync(HttpMethod.Get, "/api/v1/authorizations/" + created.AuthorizationId + "?collect=other", null);
        check(badQuery == 400, "bundle: an unknown value of collect is refused (400)");
    }

    // ---- operations with passkey pages of their own ----

    private static async Task Delegated(Action<bool, string> check, string root)
    {
        FakePasskeys fake = new();
        using AdminApp app = new(root, passkeys: fake);
        AdminBrowser b = await app.SignedIn();
        Tapped enroll = await b.OpAsyncWithoutMutation("passkey-enroll", app.Laptop);
        await b.WaitAuthorizationAsync(enroll.AuthorizationId!);
        string view = await Read(b, enroll.AuthorizationId!);
        check(Inner(view, "result", "outcome") == "started" && Inner(view, "result", "link") is { Length: > 8 } && await HostServiceTests.WaitFor(() => fake.Calls.Contains("enroll")), "delegated: the tap starts the operation's own passkey pages by itself, and the first page's link is in the result (started)");
        (HttpMethod method, string path, string json) = b.MutationRequest("passkey-enroll", enroll.AuthorizationId);
        (int retry, string retryBody) = await b.SendAsync(method, path, json);
        int calls = fake.Calls.Count(call => call == "enroll");
        (int retry2, string retry2Body) = await b.SendAsync(method, path, json);
        check(retry == 202 && Member(retryBody, "outcome") == "started" && retry2 == 202 && Member(retry2Body, "outcome") == "already-started" && fake.Calls.Count(call => call == "enroll") == calls && calls == 1, "delegated: a retry is answered with the same link and starts nothing again");
    }
}
