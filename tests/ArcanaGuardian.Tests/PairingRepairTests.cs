using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;

namespace ArcanaGuardian.Tests;

/// <summary>Fix round 1, M1: pairing again. The same authority keeps its pin; a different authority is refused unless a person confirms at a terminal, and then the stale signing-key pin is dropped so the host can pin the new authority.</summary>
internal static partial class PairingTests
{
    private static async Task Repairing(Action<bool, string> check, string root)
    {
        using Rig a = new(root);
        using Rig b = new(root);
        using Host host = a.NewHost("moving-host");
        HostConfigFile config = host.Machine.Deployment.HostConfig;

        // Paired with A, approved, pinned.
        (CreatedInvitation inviteA, PairingBundle bundleA) = a.NewInvitation();
        (PairingResult first, _) = await a.Pair(host, bundleA);
        MachineRecord pending = a.Store.Find(host.Fingerprint)!;
        AdminActions.ApproveMachine(a.Store, a.Authority.Deployment.Keys, a.Authority.Deployment.HostConfig, null, host.Fingerprint, "moving box", "admin passkey test", pending.SecurityRevision);
        using (RemoteAuthority remoteA = new(config.Load().Config!.Remote!, host.Machine.Deployment.Tls, config, a.Clock) { Retries = 0 })
        {
            check(first.Ok && await remoteA.EnsureAuthorityKeyPinnedAsync(CancellationToken.None) && config.Load().Config?.Authority is { } pinA && pinA.Fingerprint == a.Authority.Deployment.Keys.CurrentRecord().Fingerprint, "re-pair: fixture: paired with authority A, approved and A's signing key pinned");
        }

        string before = File.ReadAllText(config.FilePath);

        // Same authority again: allowed without a question, and the pin is kept.
        (CreatedInvitation again, PairingBundle againBundle) = a.NewInvitation();
        int asked = 0;
        (PairingResult same, _) = await a.Pair(host, againBundle, question => { asked++; return false; });
        check(!same.Ok && asked == 0 && config.Load().Config is { Authority: not null, Remote: { } sameRemote } && sameRemote.AuthorityIdentityFingerprint == a.AuthorityFingerprint, "re-pair: pairing again with the SAME authority asks nothing and keeps the pinned signing key (the authority itself refuses to touch the Trusted machine)");
        config.SetRemote(host.Fingerprint, config.Load().Config!.Remote);
        check(config.Load().Config?.Authority is not null, "re-pair: saving the same authority again keeps the pin (only a confirmed replacement drops it)");
        _ = inviteA;
        _ = again;
        before = File.ReadAllText(config.FilePath);

        // A different authority, nobody confirms: explicit refusal, nothing sent, nothing changed, the invitation is not spent.
        (CreatedInvitation inviteB, PairingBundle bundleB) = b.NewInvitation();
        List<string> audited = [];
        (PairingResult refused, List<(string Step, byte[] Body, string Client)> refusedRequests) = await b.Pair(host, bundleB, null, (name, detail) => audited.Add(name));
        check(!refused.Ok && refused.Message.Contains("already trusts", StringComparison.Ordinal) && refused.Message.Contains(KeyIdentity.Display(a.AuthorityFingerprint), StringComparison.Ordinal) && refused.Message.Contains(KeyIdentity.Display(b.AuthorityFingerprint), StringComparison.Ordinal)
            && refusedRequests.Count == 1 && File.ReadAllText(config.FilePath) == before && b.Store.Find(host.Fingerprint) is null && b.Store.Invitation(inviteB.Id) is { Status: "pending" } && audited.Count == 0, "re-pair: a different authority is refused with both identities named when nobody confirms: only the bootstrap was sent, host.json is unchanged, the new authority learned nothing and the invitation is unspent");
        string questionAsked = "";
        (PairingResult declined, _) = await b.Pair(host, bundleB, question => { questionAsked = question; return false; });
        check(!declined.Ok && questionAsked.Contains("replaces the trusted authority", StringComparison.Ordinal) && File.ReadAllText(config.FilePath) == before && b.Store.Find(host.Fingerprint) is null, "re-pair: a person who declines the question changes nothing");

        // The person confirms: audited, remote replaced, stale pin dropped, and the host can then pin the NEW authority.
        (PairingResult replaced, _) = await b.Pair(host, bundleB, _ => true, (name, detail) => audited.Add(name + ": " + detail));
        HostConfig? after = config.Load().Config;
        check(replaced.Ok && after?.Remote?.AuthorityIdentityFingerprint == b.AuthorityFingerprint && after.Authority is null && audited.Count == 1 && audited[0].StartsWith("pairing-authority-replaced", StringComparison.Ordinal) && !audited[0].Contains(bundleB.Format().Split(';')[3], StringComparison.Ordinal),
            "re-pair: with the person's confirmation the remote authority is replaced, the old signing-key pin is dropped and the replacement is audited (no code in it)");
        MachineRecord pendingB = b.Store.Find(host.Fingerprint)!;
        AdminActions.ApproveMachine(b.Store, b.Authority.Deployment.Keys, b.Authority.Deployment.HostConfig, null, host.Fingerprint, "moved box", "admin passkey test", pendingB.SecurityRevision);
        using (RemoteAuthority remoteB = new(config.Load().Config!.Remote!, host.Machine.Deployment.Tls, config, b.Clock) { Retries = 0 })
        {
            check(await remoteB.EnsureAuthorityKeyPinnedAsync(CancellationToken.None) && config.Load().Config?.Authority is { } pinB && pinB.Fingerprint == b.Authority.Deployment.Keys.CurrentRecord().Fingerprint, "re-pair: after the replacement and B's approval the host pins B's signing key (no stale pin is left to fail every answer)");
        }

        // A signing key pinned in local mode (no remote authority) is also a trusted identity: replacing it needs the confirmation.
        using Host local = a.NewHost("local-host");
        using SoftwareSigningKey localKey = new();
        local.Machine.Deployment.HostConfig.Pin(local.Fingerprint, new PinnedAuthorityKey(KeyIdentity.Fingerprint(localKey.PublicKey), localKey.PublicKey, DateTimeOffset.UtcNow));
        (CreatedInvitation inviteLocal, PairingBundle bundleLocal) = a.NewInvitation();
        (PairingResult localRefused, _) = await a.Pair(local, bundleLocal);
        check(!localRefused.Ok && local.Machine.Deployment.HostConfig.Load().Config is { Authority: not null, Remote: null } && a.Store.Find(local.Fingerprint) is null && a.Store.Invitation(inviteLocal.Id) is { Status: "pending" }, "re-pair: a host with a signing key pinned in local mode is refused too, unchanged, unless a person confirms");
        (PairingResult localReplaced, _) = await a.Pair(local, bundleLocal, _ => true);
        check(localReplaced.Ok && local.Machine.Deployment.HostConfig.Load().Config is { Authority: null, Remote: not null }, "re-pair: confirmed, the local-mode pin is dropped and the host is remote");

        // The command: an unattended run (no terminal) can never confirm.
        using Host cli = a.NewHost("cli-moving");
        (CreatedInvitation i1, PairingBundle b1) = a.NewInvitation();
        await a.Pair(cli, b1);
        (CreatedInvitation i2, PairingBundle b2) = b.NewInvitation();
        StringWriter output = new();
        StringWriter error = new();
        int exit = await AuthorityPairing.RunAsync(new PairingEnvironment
        {
            Console = new FakeConsole(null, interactive: false),
            Variable = name => name == PairingInput.ValueVariable ? b2.Format() : null,
            ClearVariable = _ => { },
            ReadFile = _ => null,
            FileExists = _ => false,
            OpenMachine = () => new PairingMachine(new NoDispose(cli.Machine.MachineKey), cli.Machine.Deployment.IdentityCertificate, "cli-moving", cli.Machine.Deployment.HostConfig),
            Clock = b.Clock,
        }, output, error);
        check(exit == RunCommand.Denied && error.ToString().Contains("already trusts", StringComparison.Ordinal) && cli.Machine.Deployment.HostConfig.Load().Config?.Remote?.AuthorityIdentityFingerprint == a.AuthorityFingerprint && !Holds(error.ToString() + output, [ExtractCode(b2)]) && b.Store.Invitation(i2.Id) is { Status: "pending" },
            "re-pair command: an unattended run (invitation from a file or variable, no terminal) is refused, exit 3, nothing changed");
        _ = i1;
    }
    /// <summary>Fix round 1, L5: a pairing secret file that other accounts can read is refused, before it is read.</summary>
    private static async Task SecretFiles(Action<bool, string> check, string root)
    {
        string folder = Path.Combine(root, "secret-files-" + Guid.NewGuid().ToString("N")[..6]);
        Directory.CreateDirectory(folder);
        string path = Path.Combine(folder, "invitation.secret");
        File.WriteAllText(path, "wsp1;not-a-real-invitation");
        if (OperatingSystem.IsWindows())
        {
            FileInfo info = new(path);
            FileSecurity security = info.GetAccessControl();
            security.SetAccessRuleProtection(true, false);
            security.AddAccessRule(new FileSystemAccessRule(WindowsIdentity.GetCurrent().User!, FileSystemRights.FullControl, AccessControlType.Allow));
            info.SetAccessControl(security);
        }
        else
        {
            File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite);
        }

        check(PairingInput.OthersCanRead(path) is null, "secret file: a file only its owner can read is accepted");
        if (OperatingSystem.IsWindows())
        {
            FileInfo info = new(path);
            FileSecurity security = info.GetAccessControl();
            security.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(WellKnownSidType.WorldSid, null), FileSystemRights.Read, AccessControlType.Allow));
            info.SetAccessControl(security);
        }
        else
        {
            File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.OtherRead);
        }

        string? problem = PairingInput.OthersCanRead(path);
        check(problem is not null, "secret file: a file that other accounts can read is detected (" + problem + ")");
        int reads = 0;
        PairingInput.Found refused = PairingInput.Obtain(new FakeConsole(null, false), name => name == PairingInput.FileVariable ? path : null, _ => { reads++; return "never"; }, _ => false, PairingInput.OthersCanRead);
        check(refused.Bundle is null && refused.Source == PairingSource.File && refused.Problem!.Contains("not protected", StringComparison.Ordinal) && refused.Problem.Contains("left in place", StringComparison.Ordinal) && reads == 0, "secret file: the pairing input refuses such a file without reading it, says the file is left in place, and does not fall back to another source");
        await Task.CompletedTask;
    }
}
