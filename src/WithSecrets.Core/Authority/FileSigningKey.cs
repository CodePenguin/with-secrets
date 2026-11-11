using System.Security.Cryptography;

namespace WithSecrets;

/// <summary>
/// An ECDSA P-256 key kept in a FILE that only its owner can read (mode 0600, in a directory with mode 0700): the key store of a Linux machine. This is WEAKER than Windows CNG: the private part is an
/// ordinary file, so anything running as the same user (or as root) can copy it, and a copy is a full copy of the machine identity. It exists because Linux has no non-exportable key store that is
/// available everywhere (no TPM, keyring or secret service is assumed). A file that is readable (or writable) by group or other, a link, a file that is not a P-256 private key, or a directory that
/// others can enter is refused, never used. Nothing here ever puts key material in an error message, a log line or the terminal.
/// </summary>
public sealed class FileSigningKey : ISigningKey
{
    private const UnixFileMode OwnerOnly = UnixFileMode.UserRead | UnixFileMode.UserWrite;
    private const UnixFileMode OwnerDirectory = UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute;
    private const UnixFileMode Others = UnixFileMode.GroupRead | UnixFileMode.GroupWrite | UnixFileMode.GroupExecute | UnixFileMode.OtherRead | UnixFileMode.OtherWrite | UnixFileMode.OtherExecute;
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

    /// <summary>The key in <paramref name="path" />, made when the file does not exist. An existing file is used only when it is protected and is a P-256 private key; otherwise this throws and nothing is changed.</summary>
    public static FileSigningKey OpenOrCreate(string path, out bool created)
    {
        created = false;
        if (TryOpen(path) is { } existing)
        {
            return existing;
        }

        FileSigningKey made = Create(path);
        created = true;

        return made;
    }

    /// <summary>A new key in <paramref name="path" />; a file that is there is replaced (used for a key generation that nothing records yet).</summary>
    public static FileSigningKey CreateFresh(string path)
    {
        if (File.Exists(path))
        {
            File.Delete(path);
        }

        return Create(path);
    }

    /// <summary>The existing key, or null when there is no file. Throws <see cref="CryptographicException" /> (without any key material in the message) when the file or its directory is not acceptable.</summary>
    public static FileSigningKey? TryOpen(string path)
    {
        if (!OperatingSystem.IsWindows())
        {
            CheckDirectory(System.IO.Path.GetDirectoryName(path)!, mustExist: false);
        }

        FileInfo info = new(path);
        if (!info.Exists && info.LinkTarget is null)
        {
            return null;
        }

        if (info.LinkTarget is not null)
        {
            throw Refused(path, "it is a link");
        }

        if (!OperatingSystem.IsWindows() && (File.GetUnixFileMode(path) & Others) != 0)
        {
            throw Refused(path, "other users can read or write it (its mode allows group or other access); run chmod 600 on it, or delete it to make a new identity");
        }

        byte[] bytes;
        try
        {
            bytes = File.ReadAllBytes(path);
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException)
        {
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
            CryptographicOperations.ZeroMemory(bytes);
        }
    }

    private static FileSigningKey Create(string path)
    {
        string folder = System.IO.Path.GetDirectoryName(path)!;
        if (!OperatingSystem.IsWindows())
        {
            CheckDirectory(folder, mustExist: true);
        }
        else
        {
            Directory.CreateDirectory(folder);
        }

        ECDsa key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        byte[] pkcs8 = key.ExportPkcs8PrivateKey();
        string temp = path + "." + Guid.NewGuid().ToString("N")[..8] + ".tmp";
        try
        {
            FileStreamOptions options = new() { Mode = FileMode.CreateNew, Access = FileAccess.Write, Share = FileShare.None };
            if (!OperatingSystem.IsWindows())
            {
                options.UnixCreateMode = OwnerOnly;
            }

            using (FileStream stream = new(temp, options))
            {
                stream.Write(pkcs8);
            }

            // A file that exists already is never replaced here: a second process that made the key first wins, this one reads it.
            File.Move(temp, path, overwrite: false);

            return new FileSigningKey(key, path);
        }
        catch (IOException) when (File.Exists(path))
        {
            key.Dispose();
            if (File.Exists(temp))
            {
                File.Delete(temp);
            }

            return TryOpen(path) ?? throw Refused(path, "it could not be created");
        }
        catch
        {
            key.Dispose();
            if (File.Exists(temp))
            {
                File.Delete(temp);
            }

            throw;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(pkcs8);
        }
    }

    /// <summary>Makes the key directory with mode 0700 when it is missing (when <paramref name="mustExist" />); refuses one that others can enter.</summary>
    [System.Runtime.Versioning.UnsupportedOSPlatform("windows")]
    private static void CheckDirectory(string folder, bool mustExist)
    {
        if (!Directory.Exists(folder))
        {
            if (mustExist)
            {
                Directory.CreateDirectory(folder, OwnerDirectory);
            }

            return;
        }

        if ((File.GetUnixFileMode(folder) & Others) != 0)
        {
            throw new CryptographicException($"the key folder {folder} is not protected: other users can enter it (its mode allows group or other access); run chmod 700 on it. No key was used");
        }
    }

    private static CryptographicException Refused(string path, string reason) => new($"the key file {path} was not used: {reason}");
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
        => OperatingSystem.IsWindows() ? CngSigningKey.OpenOrCreate(name, out created) : FileSigningKey.OpenOrCreate(FileSigningKey.FileOf(KeyFolder(storeFolder), name), out created);

    /// <summary>A new key under the name; whatever held the name is replaced.</summary>
    public static ISigningKey CreateFresh(string storeFolder, string name)
        => OperatingSystem.IsWindows() ? CngSigningKey.CreateFresh(name) : FileSigningKey.CreateFresh(FileSigningKey.FileOf(KeyFolder(storeFolder), name));

    /// <summary>The existing key, or null. Creates nothing.</summary>
    public static ISigningKey? TryOpen(string storeFolder, string name)
        => OperatingSystem.IsWindows() ? CngSigningKey.TryOpen(name) : FileSigningKey.TryOpen(FileSigningKey.FileOf(KeyFolder(storeFolder), name));
}
