using System.Globalization;
using System.Security.Cryptography;

namespace WithSecrets;

/// <summary>A key file or key folder that was not used (a protection problem, never a program fault). The message is one line: the path and the fix, never key material. The command line prints it without a stack trace.</summary>
public sealed class KeyFileException(string message) : CryptographicException(message);

/// <summary>
/// An ECDSA P-256 key kept in a FILE that only its owner can read (mode 0600, in a directory with mode 0700): the key store of a Linux machine. This is WEAKER than Windows CNG: the private part is an
/// ordinary file, so anything running as the same user (or as root) can copy it, and a copy is a full copy of the machine identity. It exists because Linux has no non-exportable key store that is
/// available everywhere (no TPM, keyring or secret service is assumed). What is checked before a key is used (Unix): the key file and the key folder are not links; both are owned by the user this process runs as;
/// the file has no group or other access (0600) and the folder none (0700); the file is a regular file holding exactly one P-256 private key; and no folder from the key folder up to the store folder can be
/// written by group or other (a sticky-bit folder, which is how a shared temporary folder is made safe, is accepted). A new key is made exclusively (a temporary file made with O_EXCL, flushed, then linked
/// into place only when the name is free, so two processes never replace each other's key and a crash leaves no half-written key). Nothing here ever puts key material in an error message, a log line or the terminal.
/// </summary>
public sealed class FileSigningKey : ISigningKey
{
    private const UnixFileMode OwnerOnly = UnixFileMode.UserRead | UnixFileMode.UserWrite;
    private const UnixFileMode OwnerDirectory = UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute;
    private const UnixFileMode Others = UnixFileMode.GroupRead | UnixFileMode.GroupWrite | UnixFileMode.GroupExecute | UnixFileMode.OtherRead | UnixFileMode.OtherWrite | UnixFileMode.OtherExecute;
    private const UnixFileMode OthersWrite = UnixFileMode.GroupWrite | UnixFileMode.OtherWrite;
    private const int MaxKeyFileBytes = 1024;
    private static readonly Oid P256 = new("1.2.840.10045.3.1.7");

    private readonly ECDsa _key;
    private readonly Lock _lock = new();

    private FileSigningKey(ECDsa key, string path)
    {
        _key = key;
        Path = path;
    }

    /// <summary>The key file (public information).</summary>
    public string Path { get; }

    public byte[] PublicKey => _key.ExportSubjectPublicKeyInfo();

    public byte[] Sign(byte[] data)
    {
        lock (_lock)
        {
            return _key.SignData(data, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
        }
    }

    public void Dispose() => _key.Dispose();

    /// <summary>The key file for <paramref name="name" /> under <paramref name="keyFolder" />: only letters, digits and dashes are kept, so a name cannot reach another folder.</summary>
    public static string FileOf(string keyFolder, string name)
    {
        char[] safe = [.. name.Select(letter => char.IsAsciiLetterOrDigit(letter) ? char.ToLowerInvariant(letter) : '-')];

        return System.IO.Path.Combine(keyFolder, new string(safe).Trim('-') + ".key");
    }

    /// <summary>
    /// The key in <paramref name="path" />, made when the file does not exist. An existing file is used only when it is protected and is a P-256 private key; otherwise this throws and nothing is changed.
    /// <paramref name="storeRoot" /> is the highest folder whose protection is checked (default: the key folder's parent).
    /// </summary>
    public static FileSigningKey OpenOrCreate(string path, out bool created, string? storeRoot = null)
    {
        created = false;
        if (TryOpen(path, storeRoot) is { } existing)
        {
            return existing;
        }

        FileSigningKey made = Create(path, replace: false, storeRoot, out bool won);
        created = won;

        return made;
    }

    /// <summary>A new key in <paramref name="path" />, replacing a file that is there atomically (used for a key generation that nothing records yet).</summary>
    public static FileSigningKey CreateFresh(string path, string? storeRoot = null) => Create(path, replace: true, storeRoot, out _);

    /// <summary>The existing key, or null when there is no file. Throws <see cref="KeyFileException" /> (without any key material in the message) when the file or its folder is not acceptable.</summary>
    public static FileSigningKey? TryOpen(string path, string? storeRoot = null)
    {
        if (!OperatingSystem.IsWindows())
        {
            CheckDirectory(System.IO.Path.GetDirectoryName(path)!, mustExist: false, storeRoot);
            if (!CheckFile(path))
            {
                return null;
            }
        }
        else
        {
            FileInfo info = new(path);
            if (info.LinkTarget is not null)
            {
                throw Refused(path, "it is a link");
            }

            if (!info.Exists)
            {
                return null;
            }
        }

        byte[] bytes;
        IDisposable? pages = null;
        try
        {
            using FileStream stream = new(path, FileMode.Open, FileAccess.Read, FileShare.Read);
            if (stream.Length is 0 or > MaxKeyFileBytes)
            {
                throw Refused(path, "it does not hold a private key this program made");
            }

            bytes = new byte[(int)stream.Length];
            pages = LinuxHardening.TryLock(bytes);
            stream.ReadExactly(bytes);
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException)
        {
            pages?.Dispose();

            throw Refused(path, "it cannot be read");
        }

        ECDsa key = ECDsa.Create();
        try
        {
            int read;
            try
            {
                key.ImportPkcs8PrivateKey(bytes, out read);
            }
            catch (CryptographicException)
            {
                throw Refused(path, "it does not hold a private key this program made");
            }

            if (read != bytes.Length || key.ExportParameters(false).Curve.Oid?.Value != P256.Value)
            {
                throw Refused(path, "it is not an ECDSA P-256 private key");
            }

            return new FileSigningKey(key, path);
        }
        catch
        {
            key.Dispose();

            throw;
        }
        finally
        {
            LinuxHardening.Wipe(bytes, pages);
        }
    }

    private static FileSigningKey Create(string path, bool replace, string? storeRoot, out bool won)
    {
        won = true;
        string folder = System.IO.Path.GetDirectoryName(path)!;
        if (!OperatingSystem.IsWindows())
        {
            CheckDirectory(folder, mustExist: true, storeRoot);
        }
        else
        {
            Directory.CreateDirectory(folder);
        }

        ECDsa key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        byte[] pkcs8 = key.ExportPkcs8PrivateKey();
        IDisposable pages = LinuxHardening.TryLock(pkcs8);
        string temp = path + "." + Guid.NewGuid().ToString("N")[..8] + ".tmp";
        try
        {
            // The temporary file is made exclusively (O_EXCL: never an existing file or a link planted under the name), with mode 0600 from the first byte, and flushed to disk before it is put in place.
            FileStreamOptions options = new() { Mode = FileMode.CreateNew, Access = FileAccess.Write, Share = FileShare.None };
            if (!OperatingSystem.IsWindows())
            {
                options.UnixCreateMode = OwnerOnly;
            }

            using (FileStream stream = new(temp, options))
            {
                stream.Write(pkcs8);
                stream.Flush(flushToDisk: true);
            }

            if (replace)
            {
                File.Move(temp, path, overwrite: true);
            }
            else if (!Publish(temp, path))
            {
                // A file that exists already is never replaced here: a second process that made the key first wins, this one reads it.
                key.Dispose();
                File.Delete(temp);
                won = false;

                return TryOpen(path, storeRoot) ?? throw Refused(path, "it could not be created");
            }

            if (OperatingSystem.IsLinux())
            {
                LinuxHardening.SyncDirectory(folder);
            }

            return new FileSigningKey(key, path);
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException)
        {
            key.Dispose();
            TryDelete(temp);

            throw Refused(path, $"this user cannot create it here ({error.GetType().Name}); the key folder must belong to user {UserText()} with mode 700: run chown {UserText()} {folder} and chmod 700 {folder}");
        }
        catch
        {
            key.Dispose();
            TryDelete(temp);

            throw;
        }
        finally
        {
            LinuxHardening.Wipe(pkcs8, pages);
        }
    }

    /// <summary>Puts the finished temporary file under its final name only when the name is free. False when something has the name.</summary>
    private static bool Publish(string temp, string path)
    {
        if (OperatingSystem.IsLinux())
        {
            return LinuxHardening.LinkExclusive(temp, path);
        }

        try
        {
            File.Move(temp, path, overwrite: false);

            return true;
        }
        catch (IOException) when (File.Exists(path))
        {
            return false;
        }
    }

    private static void TryDelete(string file)
    {
        try
        {
            File.Delete(file);
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException)
        {
            // A stray temporary file is harmless (it is never read as a key).
        }
    }

    private static string UserText() => LinuxHardening.CurrentUserId()?.ToString(CultureInfo.InvariantCulture) ?? "the current user";

    /// <summary>The checks of the key file (Unix): a link, anything but a regular file, a file of another owner, and one that group or other can reach are refused. False when there is no file.</summary>
    [System.Runtime.Versioning.UnsupportedOSPlatform("windows")]
    private static bool CheckFile(string path)
    {
        if (Inspect(path) is not { } facts)
        {
            return false;
        }

        if (facts.IsLink)
        {
            throw Refused(path, "it is a link");
        }

        if (!facts.IsFile)
        {
            throw Refused(path, "it is not a regular file");
        }

        if (OwnerProblem(facts.Owner) is { } owner)
        {
            throw Refused(path, $"it is owned by user {owner.Actual}, not by user {owner.Expected} who runs this program; run chown {owner.Expected} on it (and keep mode 600), or delete it to make a new identity");
        }

        if ((facts.Mode & Others) != 0)
        {
            throw Refused(path, "other users can read or write it (its mode allows group or other access); run chmod 600 on it, or delete it to make a new identity");
        }

        return true;
    }

    [System.Runtime.Versioning.UnsupportedOSPlatform("windows")]
    private static LinuxHardening.Facts? Inspect(string path)
    {
        try
        {
            return LinuxHardening.Inspect(path);
        }
        catch (Exception error) when (error is PlatformNotSupportedException or IOException)
        {
            throw Refused(path, error.Message);
        }
    }

    private static (string Actual, string Expected)? OwnerProblem(uint? owner)
    {
        if (owner is not { } actual || LinuxHardening.CurrentUserId() is not { } expected || actual == expected)
        {
            return null;
        }

        return (actual.ToString(CultureInfo.InvariantCulture), expected.ToString(CultureInfo.InvariantCulture));
    }

    /// <summary>
    /// Makes the key folder with mode 0700 when it is missing (when <paramref name="mustExist" />); refuses one that is a link, is owned by another user, or that others can enter, and refuses a folder from its parent up
    /// to <paramref name="storeRoot" /> (default: the key folder's parent) that group or other can write, unless it has the sticky bit (then only the owner of an entry can remove or rename it: how a shared temporary folder is made safe).
    /// </summary>
    [System.Runtime.Versioning.UnsupportedOSPlatform("windows")]
    private static void CheckDirectory(string folder, bool mustExist, string? storeRoot)
    {
        string root = System.IO.Path.GetFullPath(storeRoot ?? System.IO.Path.GetDirectoryName(System.IO.Path.GetFullPath(folder)) ?? folder);
        if (Inspect(folder) is not { } facts)
        {
            if (!mustExist)
            {
                return;
            }

            try
            {
                Directory.CreateDirectory(folder, OwnerDirectory);
            }
            catch (Exception error) when (error is IOException or UnauthorizedAccessException)
            {
                throw new KeyFileException($"the key folder {folder} cannot be created by user {UserText()}: its parent folder is not writable by that user. Give that user write access to the parent (for example chown {UserText()} on it), or create {folder} with mode 700 as that user. No key was used");
            }

            CheckAncestors(folder, root);

            return;
        }

        if (facts.IsLink)
        {
            throw new KeyFileException($"the key folder {folder} is a link, which is not followed; replace it with a real folder owned by user {UserText()} (mode 700). No key was used");
        }

        if (!facts.IsDirectory)
        {
            throw new KeyFileException($"the key folder {folder} is not a folder. No key was used");
        }

        if (OwnerProblem(facts.Owner) is { } owner)
        {
            throw new KeyFileException($"the key folder {folder} is owned by user {owner.Actual}, not by user {owner.Expected} who runs this program; run chown {owner.Expected} {folder} and chmod 700 {folder}, or run the program as its owner. No key was used");
        }

        if ((facts.Mode & Others) != 0)
        {
            throw new KeyFileException($"the key folder {folder} is not protected: other users can enter it (its mode allows group or other access); run chmod 700 on it. No key was used");
        }

        CheckAncestors(folder, root);
    }

    [System.Runtime.Versioning.UnsupportedOSPlatform("windows")]
    private static void CheckAncestors(string folder, string root)
    {
        string? current = System.IO.Path.GetDirectoryName(System.IO.Path.GetFullPath(folder));
        while (current is not null)
        {
            if (Directory.Exists(current))
            {
                UnixFileMode mode = File.GetUnixFileMode(current);
                if ((mode & OthersWrite) != 0 && (mode & UnixFileMode.StickyBit) == 0)
                {
                    throw new KeyFileException($"the folder {current} above the key folder can be changed by group or other users (its mode allows group or other write), so they could replace the key folder; run chmod go-w {current}. No key was used");
                }
            }

            if (string.Equals(System.IO.Path.TrimEndingDirectorySeparator(current), System.IO.Path.TrimEndingDirectorySeparator(root), StringComparison.Ordinal))
            {
                return;
            }

            current = System.IO.Path.GetDirectoryName(current);
        }
    }

    private static KeyFileException Refused(string path, string reason) => new($"the key file {path} was not used: {reason}");
}

/// <summary>
/// The one place that chooses where this program's persistent signing keys live. Windows: CNG, non-exportable (<see cref="CngSigningKey" />, unchanged). Every other system: an owner-only file under
/// <c>keys</c> in the store folder (<see cref="FileSigningKey" />), weaker, see there.
/// </summary>
public static class MachineKeyStore
{
    /// <summary>The folder (under the store folder) that holds key files on a system without CNG.</summary>
    public static string KeyFolder(string storeFolder) => System.IO.Path.Combine(storeFolder, "keys");

    /// <summary>The key named <paramref name="name" />, made when it does not exist.</summary>
    public static ISigningKey OpenOrCreate(string storeFolder, string name, out bool created)
        => OperatingSystem.IsWindows() ? CngSigningKey.OpenOrCreate(TestIsolation.KeyNameFor(storeFolder, name), out created) : FileSigningKey.OpenOrCreate(FileSigningKey.FileOf(KeyFolder(storeFolder), name), out created, storeFolder);

    /// <summary>A new key under the name; whatever held the name is replaced.</summary>
    public static ISigningKey CreateFresh(string storeFolder, string name)
        => OperatingSystem.IsWindows() ? CngSigningKey.CreateFresh(TestIsolation.KeyNameFor(storeFolder, name)) : FileSigningKey.CreateFresh(FileSigningKey.FileOf(KeyFolder(storeFolder), name), storeFolder);

    /// <summary>The existing key, or null. Creates nothing.</summary>
    public static ISigningKey? TryOpen(string storeFolder, string name)
        => OperatingSystem.IsWindows() ? CngSigningKey.TryOpen(TestIsolation.KeyNameFor(storeFolder, name)) : FileSigningKey.TryOpen(FileSigningKey.FileOf(KeyFolder(storeFolder), name), storeFolder);
}
