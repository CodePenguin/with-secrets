using System.Text.Json;

namespace WithSecrets.Tests;

/// <summary>The administrator's side of pairing (task M2): the invitation is made, listed and revoked through the admin API, each change with its own operation-bound passkey tap; the bundle is shown once.</summary>
internal static class PairingAdminTests
{
    private static string Code(string body) => JsonDocument.Parse(body).RootElement.TryGetProperty("code", out JsonElement code) ? code.GetString() ?? "" : "";

    /// <summary>The operation was turned away: at the authorization (a plan that cannot be made) or at the mutation.</summary>
    private static bool Refused(Tapped tapped) => tapped.AuthorizationId is null ? tapped.PostStatus >= 400 : tapped.MutationStatus >= 400;

    public static async Task Run(Action<bool, string> check, string root)
    {
        using AdminApp app = new(root, machineEndpoint: true);
        AdminBrowser b = await app.SignedIn();

        // The list starts empty and holds statuses only.
        (int emptyStatus, string emptyBody) = await b.SendAsync(HttpMethod.Get, "/api/v1/pairing/invitations", null);
        check(emptyStatus == 200 && JsonDocument.Parse(emptyBody).RootElement.GetProperty("items").GetArrayLength() == 0, "pairing api: the list of invitations starts empty");

        // A session alone makes no invitation: it needs the operation's own tap.
        Tapped untapped = await b.OpAsync("pairing-create", null, true, null, true);
        (HttpMethod um, string up, string uj) = b.MutationRequest("pairing-create", untapped.AuthorizationId);
        (int untappedStatus, string untappedBody) = await b.SendAsync(um, up, uj);
        check(untappedStatus == 403 && Code(untappedBody) == "authorization-pending" && app.Store.Invitations().Count == 0, "pairing api: creating an invitation without the operation's passkey tap is refused and makes nothing");
        check(untapped.Link is not null, "pairing api: the authorization names a passkey page for the creation");

        // With the tap the bundle is returned ONCE.
        Tapped created = await b.OpAsync("pairing-create", app.Laptop, true, null, true);
        using JsonDocument doc = JsonDocument.Parse(created.MutationBody);
        JsonElement invitation = doc.RootElement.GetProperty("invitation");
        string bundleText = invitation.GetProperty("bundle").GetString()!;
        PairingBundle? bundle = PairingBundle.TryParse(bundleText);
        string id = invitation.GetProperty("id").GetString()!;
        string codeText = bundleText.Split(';')[3];
        check(created.MutationStatus == 200 && bundle is not null && bundle.InvitationId == id && bundle.Authority.StartsWith("https://127.0.0.1:", StringComparison.Ordinal) && invitation.TryGetProperty("expires", out _), "pairing api: with the tap the invitation is created and its bundle (address, identifier, code) is returned");
        (int listStatus, string listBody) = await b.SendAsync(HttpMethod.Get, "/api/v1/pairing/invitations", null);
        check(listStatus == 200 && !listBody.Contains(bundleText, StringComparison.Ordinal) && !listBody.Contains("bundle", StringComparison.OrdinalIgnoreCase) && !listBody.Contains(codeText, StringComparison.Ordinal) && JsonDocument.Parse(listBody).RootElement.GetProperty("items")[0].GetProperty("status").GetString() == "pending",
            "pairing api: the list shows the invitation's status only; the bundle and the code can never be fetched again");
        (HttpMethod rm, string rp, string rj) = b.MutationRequest("pairing-create", created.AuthorizationId);
        (int replay, string replayBody) = await b.SendAsync(rm, rp, rj);
        check(replay == 200 && replayBody.Contains("\"already-applied\"", StringComparison.Ordinal) && !replayBody.Contains(codeText, StringComparison.Ordinal) && app.Store.Invitations().Count == 1, "pairing api: repeating the creation does not return the bundle again and makes no second invitation");

        // The authority holds no code: scan its files and its audit.
        byte[] code = System.Buffers.Text.Base64Url.DecodeFromChars(codeText);
        bool leaked = Directory.EnumerateFiles(app.Machine.Folder, "*", SearchOption.AllDirectories).Any(file =>
        {
            using FileStream stream = new(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            using MemoryStream memory = new();
            stream.CopyTo(memory);
            string text = System.Text.Encoding.Latin1.GetString(memory.ToArray());

            return text.Contains(codeText, StringComparison.Ordinal) || text.Contains(Convert.ToHexString(code), StringComparison.OrdinalIgnoreCase) || text.Contains(Convert.ToBase64String(code), StringComparison.Ordinal);
        });
        string audit = string.Join('\n', app.Store.Audit(1000).Select(entry => entry.Event + entry.Detail + entry.Actor));
        check(!leaked && !audit.Contains(codeText, StringComparison.Ordinal) && audit.Contains("pairing-invitation-created", StringComparison.Ordinal), "pairing api: the code is in no file of the authority and not in its audit; the creation is audited");

        // Revoke needs its own tap and works only on a pending invitation.
        Tapped revokeUntapped = await b.OpAsync("pairing-revoke", null, true, null, true, ("id", id));
        (HttpMethod vm, string vp, string vj) = b.MutationRequest("pairing-revoke", revokeUntapped.AuthorizationId, ("id", id));
        (int revokePending, _) = await b.SendAsync(vm, vp, vj);
        check(revokePending == 403 && app.Store.Invitation(id)!.Status == "pending", "pairing api: revoking without the tap changes nothing");
        Tapped revoked = await b.OpAsync("pairing-revoke", app.Laptop, true, null, true, ("id", id));
        check(revoked.MutationStatus is 200 or 204 && app.Store.Invitation(id) is { Status: "revoked" } && app.Store.Audit(1000).Any(entry => entry.Event == "pairing-invitation-revoked"), "pairing api: with the tap the invitation is revoked (verifier wiped) and the revocation is audited");
        Tapped again = await b.OpAsync("pairing-revoke", app.Laptop, true, null, true, ("id", id));
        Tapped unknown = await b.OpAsync("pairing-revoke", app.Laptop, true, null, true, ("id", PairingProtocol.NewToken(16)));
        check(Refused(again) && Refused(unknown) && app.Store.Invitation(id)!.Status == "revoked", "pairing api: a revoked or unknown invitation cannot be revoked");

        if (PlatformSkip.NoServerTls13("an invitation made through the API pairing a machine"))
        {
            return;
        }

        // The whole way: the invitation made through the API pairs a machine, which then shows as Pending in the machine list.
        Tapped second = await b.OpAsync("pairing-create", app.Laptop, true, null, true);
        PairingBundle real = PairingBundle.TryParse(JsonDocument.Parse(second.MutationBody).RootElement.GetProperty("invitation").GetProperty("bundle").GetString()!)!;
        using TestMachine hostMachine = new(Path.Combine(root, "pair-host-" + Guid.NewGuid().ToString("N")[..6]), trusted: false, hostName: "api-paired", clock: app.Clock);
        PairingResult paired = await PairingClient.RunAsync(new PairingClientOptions
        {
            Bundle = real,
            MachineKey = hostMachine.MachineKey,
            IdentityCertificate = hostMachine.Deployment.IdentityCertificate,
            HostName = "api-paired",
            HostConfig = hostMachine.Deployment.HostConfig,
            Clock = app.Clock,
            MachineTls = hostMachine.Deployment.Tls,
        });
        (int machinesStatus, string machinesBody) = await b.SendAsync(HttpMethod.Get, "/api/v1/machines", null);
        check(paired.Ok && machinesStatus == 200 && machinesBody.Contains(hostMachine.Fingerprint, StringComparison.Ordinal) && machinesBody.Contains("api-paired", StringComparison.Ordinal) && !machinesBody.Contains(real.Format().Split(';')[3], StringComparison.Ordinal), "pairing api: an invitation made through the admin API pairs a machine, which the administrator then sees as Pending with its fingerprint and host name");
        (int afterStatus, string afterBody) = await b.SendAsync(HttpMethod.Get, "/api/v1/pairing/invitations", null);
        check(afterStatus == 200 && JsonDocument.Parse(afterBody).RootElement.GetProperty("items").EnumerateArray().Any(item => item.GetProperty("status").GetString() == "consumed"), "pairing api: the used invitation shows as consumed");
    }

    public static async Task Refusals(Action<bool, string> check, string root)
    {
        // A service with no machine endpoint has no address to put in an invitation: creation is refused and nothing is made.
        using AdminApp noEndpoint = new(root);
        AdminBrowser b = await noEndpoint.SignedIn();
        Tapped made = await b.OpAsync("pairing-create", noEndpoint.Laptop, true, null, true);
        check(Refused(made) && noEndpoint.Store.Invitations().Count == 0 && !made.MutationBody.Contains("wsp1;", StringComparison.Ordinal), "pairing api: with no machine endpoint configured an invitation cannot be made (no address to give), and nothing is stored");

        // Without a session the invitation routes refuse and make nothing.
        using AdminApp locked = new(root, unlocked: false, machineEndpoint: true);
        AdminBrowser lb = locked.Browser();
        await lb.LoadAsync();
        (int lockedList, _) = await lb.SendAsync(HttpMethod.Get, "/api/v1/pairing/invitations", null);
        (int lockedCreate, _) = await lb.SendAsync(HttpMethod.Post, "/api/v1/pairing/invitations", "{}");
        check(lockedList is 401 or 403 or 423 && lockedCreate is 401 or 403 or 423 && locked.Store.Invitations().Count == 0, "pairing api: without a session (a locked authority) the invitation routes refuse and nothing is made");
    }
}
