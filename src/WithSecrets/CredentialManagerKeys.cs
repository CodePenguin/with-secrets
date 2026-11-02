using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;

using Dotenvx.Providers;

namespace WithSecrets;

/// <summary>
/// Custody of the secret store's private key, as Dotenvx keeps it: a generic Windows Credential Manager entry with the target
/// <c>dotenvx:PUBLIC_KEY</c> (local machine persistence, the key as UTF-16 text). Reads go through Dotenvx.Providers'
/// native provider, keyed by the public key. Dotenvx.Providers has no public write, and Dotenvx.Core's is internal, so the
/// write is this minimal CredWriteW wrapper, made like Dotenvx's own; it is read back through the provider at once. Windows only
/// for now. Task 18 replaces this custody with keys wrapped by passkey PRF.
/// <para>
/// The private key is a .NET string here and in Dotenvx (the provider returns strings), so it cannot be wiped from memory.
/// </para>
/// </summary>
internal sealed class CredentialManagerKeys : IStoreKeys
{
    private const string TargetPrefix = "dotenvx:";
    private const uint CredTypeGeneric = 1;
    private const uint CredPersistLocalMachine = 2;
    private const int ErrorNotFound = 1168;

    public string? Unavailable => OperatingSystem.IsWindows() ? null
        : "the secret store's key custody is Windows-only for now (Windows Credential Manager); other systems wait for passkey-wrapped keys";

    /// <summary>When the lookup itself fails, the answer is "exists", so a key that may have been there is never deleted.</summary>
    public bool Exists(string publicKey)
    {
        try
        {
            return OperatingSystem.IsWindows() && Read(publicKey) is not null;
        }
        catch (Exception)
        {
            return true;
        }
    }

    public void Delete(string publicKey)
    {
        if (OperatingSystem.IsWindows() && !CredDelete(TargetPrefix + publicKey, CredTypeGeneric, 0))
        {
            int error = Marshal.GetLastWin32Error();
            if (error != ErrorNotFound)
            {
                throw new Win32Exception(error);
            }
        }
    }

    public void Save(string publicKey, string privateKey)
    {
        if (Unavailable is { } why)
        {
            throw new PlatformNotSupportedException(why);
        }

        Write(TargetPrefix + publicKey, privateKey);
        if (!string.Equals(Read(publicKey), privateKey, StringComparison.Ordinal))
        {
            throw new InvalidOperationException("the secret store key was written to Windows Credential Manager but cannot be read back");
        }
    }

    public string PrivateKey(string publicKey) => Read(publicKey) ?? throw new KeyNotFoundException("the private key of the secret store is not in Windows Credential Manager");

    /// <summary>The private key through Dotenvx's native provider (no 1Password, Bitwarden or Armor), or null.</summary>
    private static string? Read(string publicKey)
    {
        IDictionary<string, string> found = new NativeProvider(new ProviderOptions { NoOnePassword = true, NoBitwarden = true, NoArmor = true, ArmorOff = true }).GetSync(publicKey);

        return found.TryGetValue(publicKey, out string? key) && key.Length > 0 ? key : null;
    }

    private static void Write(string target, string secret)
    {
        IntPtr blob = Marshal.StringToCoTaskMemUni(secret);
        try
        {
            Credential credential = new()
            {
                Type = CredTypeGeneric,
                TargetName = target,
                CredentialBlobSize = (uint)Encoding.Unicode.GetByteCount(secret),
                CredentialBlob = blob,
                Persist = CredPersistLocalMachine,
                UserName = "dotenvx",
            };
            if (!CredWrite(ref credential, 0))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }
        }
        finally
        {
            Marshal.ZeroFreeCoTaskMemUnicode(blob);
        }
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct Credential
    {
        public uint Flags;
        public uint Type;
        public string TargetName;
        public string? Comment;
        public long LastWritten;
        public uint CredentialBlobSize;
        public IntPtr CredentialBlob;
        public uint Persist;
        public uint AttributeCount;
        public IntPtr Attributes;
        public string? TargetAlias;
        public string UserName;
    }

    [DllImport("Advapi32.dll", EntryPoint = "CredWriteW", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CredWrite(ref Credential credential, uint flags);

    [DllImport("Advapi32.dll", EntryPoint = "CredDeleteW", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CredDelete(string target, uint type, uint flags);
}
