using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace WithSecrets.Tests;

/// <summary>
/// The machine key store: owner-only key files where there is no CNG (Linux, WSL), CNG on Windows (covered by IdentityTests). The file key is tested on every system for what does not depend on Unix
/// permissions (creation, reload, wrong content, no key material in messages); the permission refusals need Unix modes and run only on Linux, and are skipped on Windows.
/// </summary>
internal static class KeyStoreTests
{
    private const UnixFileMode Owner = UnixFileMode.UserRead | UnixFileMode.UserWrite;

    public static Task Run(Action<bool, string> check)
    {
        string parent = Path.Combine(Path.GetTempPath(), "ws-keystore-" + Guid.NewGuid().ToString("N")[..8]);
        Directory.CreateDirectory(parent);
        TextWriter? before = TerminalPrompt.Output;
        StringWriter terminal = new();
        TerminalPrompt.Output = terminal;
        try
        {
            Choice(check, parent);
            Everywhere(check, parent);
            if (!OperatingSystem.IsWindows())
            {
                UnixModes(check, parent);
                TlsKeyIsNotPersisted(check, parent);
            }

            check(!terminal.ToString().Contains("PRIVATE", StringComparison.Ordinal), "key store: nothing key-like reached the terminal");
        }
        finally
        {
            TerminalPrompt.Output = before;
            Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
            try
            {
                Directory.Delete(parent, true);
            }
            catch (IOException)
            {
                // A stray file in the temp folder is harmless.
            }
        }

        return Task.CompletedTask;
    }

    private static void Choice(Action<bool, string> check, string parent)
    {
        string folder = Path.Combine(parent, "choice");
        if (OperatingSystem.IsWindows())
        {
            check(MachineKeyStore.TryOpen(folder, "with-secrets test absent " + Guid.NewGuid().ToString("N")) is null && !Directory.Exists(MachineKeyStore.KeyFolder(folder)), "key store: on Windows the choice is CNG (no key file, no key folder is made); the Linux file tests are skipped");

            return;
        }

        using ISigningKey key = MachineKeyStore.OpenOrCreate(folder, KeyNames.Machine, out bool created);
        check(created && key is FileSigningKey, "key store: without CNG the choice is the owner-only key file");
    }

    private static void Everywhere(Action<bool, string> check, string parent)
    {
        string folder = Path.Combine(parent, "keys-a");
        string path = FileSigningKey.FileOf(folder, KeyNames.Machine);
        check(Path.GetDirectoryName(FileSigningKey.FileOf(folder, "../../x y")) == folder, "file key: a name cannot leave the key folder");

        string fingerprint;
        using (FileSigningKey first = FileSigningKey.OpenOrCreate(path, out bool created))
        {
            fingerprint = KeyIdentity.Fingerprint(first.PublicKey);
            byte[] data = Encoding.UTF8.GetBytes("signed by the file key");
            check(created && File.Exists(path) && KeyIdentity.IsCanonicalP256(first.PublicKey) && KeyIdentity.Verify(first.PublicKey, data, first.Sign(data)), "file key: created, a canonical P-256 key, signs with the fixed-size form");
        }

        using (FileSigningKey second = FileSigningKey.OpenOrCreate(path, out bool createdAgain))
        {
            check(!createdAgain && KeyIdentity.Fingerprint(second.PublicKey) == fingerprint, "file key: reload gives the same fingerprint and makes no new key");
        }

        check(Directory.GetFiles(folder).Length == 1, "file key: no temporary file is left behind");

        // Wrong content: refused, the file is left as it was, and the message does not repeat the content.
        string canary = "CANARY-NOT-A-KEY-" + Guid.NewGuid().ToString("N");
        string bad = FileSigningKey.FileOf(folder, "bad content");
        File.WriteAllText(bad, canary);
        Protect(bad);
        string? message = Refusal(() => FileSigningKey.OpenOrCreate(bad, out _));
        check(message is not null && !message.Contains(canary, StringComparison.Ordinal) && File.ReadAllText(bad) == canary, "file key: a file with other content is refused, not replaced, and the message does not repeat the content");

        // A real private key of another curve is refused too.
        string other = FileSigningKey.FileOf(folder, "p384");
        string p384Hex;
        using (ECDsa p384 = ECDsa.Create(ECCurve.NamedCurves.nistP384))
        {
            byte[] pkcs8 = p384.ExportPkcs8PrivateKey();
            p384Hex = Convert.ToHexString(pkcs8[^24..]);
            File.WriteAllBytes(other, pkcs8);
        }

        Protect(other);
        check(Refusal(() => FileSigningKey.TryOpen(other)) is { } curve && !curve.Contains(p384Hex, StringComparison.OrdinalIgnoreCase), "file key: a private key of another curve is refused, without key material in the message");

        // Trailing bytes after a valid key are refused (the file is exactly what this program writes).
        string trailing = FileSigningKey.FileOf(folder, "trailing");
        using (ECDsa p256 = ECDsa.Create(ECCurve.NamedCurves.nistP256))
        {
            File.WriteAllBytes(trailing, [.. p256.ExportPkcs8PrivateKey(), 0]);
        }

        Protect(trailing);
        check(Refusal(() => FileSigningKey.TryOpen(trailing)) is not null, "file key: bytes after the key are refused");
        check(FileSigningKey.TryOpen(Path.Combine(folder, "absent.key")) is null, "file key: no file is no key (TryOpen creates nothing)");

        // CreateFresh replaces what is there.
        using (FileSigningKey fresh = FileSigningKey.CreateFresh(bad))
        {
            check(KeyIdentity.IsCanonicalP256(fresh.PublicKey) && File.ReadAllBytes(bad).Length > 40, "file key: CreateFresh replaces a leftover with a new key");
        }

        if (!OperatingSystem.IsWindows())
        {
            // A deployment over the file key keeps its machine fingerprint across a restart.
            string deployFolder = Path.Combine(parent, "deploy");
            string one;
            using (LocalDeployment first = LocalDeployment.OpenProduction(deployFolder))
            {
                one = first.Fingerprint;
            }

            Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
            using LocalDeployment second = LocalDeployment.OpenProduction(deployFolder);
            check(one == second.Fingerprint && File.Exists(FileSigningKey.FileOf(MachineKeyStore.KeyFolder(deployFolder), KeyNames.Machine)), "file key: a restarted deployment has the same machine fingerprint");
        }
    }

    [System.Runtime.Versioning.UnsupportedOSPlatform("windows")]
    private static void UnixModes(Action<bool, string> check, string parent)
    {
        string folder = Path.Combine(parent, "modes", "keys");
        string path = FileSigningKey.FileOf(folder, KeyNames.Machine);
        using FileSigningKey made = FileSigningKey.OpenOrCreate(path, out _);
        check(File.GetUnixFileMode(path) == Owner, "file key (unix): the file is created with mode 0600");
        check(File.GetUnixFileMode(folder) == (Owner | UnixFileMode.UserExecute), "file key (unix): the key folder is created with mode 0700");

        string tail = Convert.ToHexString(File.ReadAllBytes(path)[^24..]);
        foreach ((UnixFileMode mode, string what) in new[]
        {
            (Owner | UnixFileMode.GroupRead, "group-readable"),
            (Owner | UnixFileMode.OtherRead, "other-readable"),
            (Owner | UnixFileMode.GroupWrite, "group-writable"),
        })
        {
            File.SetUnixFileMode(path, mode);
            string? message = Refusal(() => FileSigningKey.TryOpen(path));
            check(message is not null && message.Contains("chmod", StringComparison.Ordinal) && !message.Contains(tail, StringComparison.OrdinalIgnoreCase), $"file key (unix): a {what} key file is refused, with the fix, and no key material in the message");
            check(Refusal(() => FileSigningKey.OpenOrCreate(path, out _)) is not null, $"file key (unix): OpenOrCreate does not adopt or replace a {what} key file");
        }

        File.SetUnixFileMode(path, Owner);
        using (FileSigningKey? reopened = FileSigningKey.TryOpen(path))
        {
            check(reopened is not null && KeyIdentity.Fingerprint(reopened.PublicKey) == KeyIdentity.Fingerprint(made.PublicKey), "file key (unix): back to 0600 it opens again with the same fingerprint");
        }

        File.SetUnixFileMode(folder, Owner | UnixFileMode.UserExecute | UnixFileMode.GroupRead | UnixFileMode.GroupExecute);
        check(Refusal(() => FileSigningKey.TryOpen(path)) is { } folderMessage && folderMessage.Contains("chmod 700", StringComparison.Ordinal), "file key (unix): a key folder that others can enter is refused");
        File.SetUnixFileMode(folder, Owner | UnixFileMode.UserExecute);

        string link = FileSigningKey.FileOf(folder, "linked");
        File.CreateSymbolicLink(link, path);
        check(Refusal(() => FileSigningKey.TryOpen(link)) is { } linkMessage && linkMessage.Contains("link", StringComparison.Ordinal), "file key (unix): a link in place of the key file is refused");
    }

    private static void TlsKeyIsNotPersisted(Action<bool, string> check, string parent)
    {
        string root = Path.Combine(parent, "tls");
        string path = FileSigningKey.FileOf(Path.Combine(root, "keys"), KeyNames.Machine);
        using FileSigningKey identity = FileSigningKey.OpenOrCreate(path, out _);
        byte[] certificate = MachineIdentityFile.LoadOrCreate(root, identity, TimeProvider.System);
        string[] before = Directory.GetFileSystemEntries(root, "*", SearchOption.AllDirectories);
        using (TemporaryCertificate tls = new(identity, certificate))
        {
            X509Certificate2 current = tls.Current;
            using ECDsa? key = current.GetECDsaPrivateKey();
            check(key is not null && !current.PublicKey.ExportSubjectPublicKeyInfo().AsSpan().SequenceEqual(identity.PublicKey), "tls key (unix): the TLS key is a separate in-memory key, not the identity key");
        }

        string[] after = Directory.GetFileSystemEntries(root, "*", SearchOption.AllDirectories);
        check(before.Order(StringComparer.Ordinal).SequenceEqual(after.Order(StringComparer.Ordinal), StringComparer.Ordinal), "tls key (unix): making and disposing a temporary TLS certificate writes no file (the TLS key is never persisted)");
    }

    private static void Protect(string file)
    {
        if (!OperatingSystem.IsWindows())
        {
            File.SetUnixFileMode(file, Owner);
        }
    }

    private static string? Refusal(Func<IDisposable?> action)
    {
        try
        {
            action()?.Dispose();
        }
        catch (CryptographicException error)
        {
            return error.Message;
        }

        return null;
    }
}
