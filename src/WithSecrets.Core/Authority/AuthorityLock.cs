using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text;

namespace WithSecrets;

/// <summary>How the authority became unlocked. <see cref="Seam" /> exists for tests and tools that build a service in code; no command line, setting or environment variable can choose it.</summary>
public enum UnlockMethod
{
    Manual,
    Unattended,
    Seam,
}

/// <summary>Thrown by anything that needs the authority's protected keys while the authority is locked.</summary>
public sealed class AuthorityLockedException() : InvalidOperationException(AuthorityLock.LockedMessage);

/// <summary>
/// Whether the authority may use its protected keys and serve anything secret-related. The service starts LOCKED. While locked, the authority signing key is not
/// used (<see cref="AuthorityKeyRing" /> refuses), the authority decides and grants nothing, the host serves no run, and the memory the host held for a grant
/// (store key, the vouching state, synchronized grants) is discarded and zeroed. This is a gate in the authority process, not a second encryption layer: the signing key stays
/// protected by the operating system (CNG), the lock decides when this process may ask the system to use it. Unlocking is an administrator ceremony
/// (a fresh, operation-bound passkey tap on the authority's own admin page) or, only when the administrator chose that, the platform-protected unattended mechanism;
/// neither creates or widens a grant.
/// </summary>
public sealed class AuthorityLock
{
    public const string LockedMessage = "the authority is locked; it serves nothing secret-related until an administrator unlocks it";

    private readonly Lock _gate = new();
    private readonly List<Action<string>> _onLock = [];
    private bool _locked = true;
    private UnlockMethod? _how;

    /// <summary>A lock that starts locked, as every service does.</summary>
    public AuthorityLock()
    {
    }

    /// <summary>The test seam: an already unlocked lock, passed in <see cref="HostServiceOptions.Lock" />. The program never makes one.</summary>
    internal static AuthorityLock UnlockedForTests()
    {
        AuthorityLock made = new();
        made.Unlock(UnlockMethod.Seam);

        return made;
    }

    public bool IsLocked
    {
        get
        {
            lock (_gate)
            {
                return _locked;
            }
        }
    }

    public UnlockMethod? How
    {
        get
        {
            lock (_gate)
            {
                return _how;
            }
        }
    }

    /// <summary>Registers what must be discarded when the authority locks (the host's held keys and vouching state).</summary>
    public void OnLock(Action<string> discard)
    {
        lock (_gate)
        {
            _onLock.Add(discard);
        }
    }

    public void EnsureUnlocked()
    {
        if (IsLocked)
        {
            throw new AuthorityLockedException();
        }
    }

    internal void Unlock(UnlockMethod how)
    {
        lock (_gate)
        {
            _locked = false;
            _how = how;
        }
    }

    internal bool WhileUnlocked(Func<bool> use)
    {
        lock (_gate)
        {
            return !_locked && use();
        }
    }

    /// <summary>Locks at once and runs every registered discard (key material zeroed as far as the runtime permits). Idempotent.</summary>
    public void Lock(string reason)
    {
        Action<string>[] discards;
        lock (_gate)
        {
            _locked = true;
            _how = null;
            discards = [.. _onLock];
        }

        foreach (Action<string> discard in discards)
        {
            discard(reason);
        }
    }
}

/// <summary>The unlock-protection mechanism of this platform.</summary>
public static class UnlockProtections
{
    /// <summary>DPAPI on Windows, else none (unattended unlock is then refused with a message). No other platform is assumed to have an equivalent.</summary>
    public static IUnlockProtection ForThisPlatform() => OperatingSystem.IsWindows() ? new DpapiUnlockProtection() : new NoUnlockProtection("unattended unlock has no platform-protection adapter on this operating system; use manual unlock");
}

/// <summary>When the authority becomes unlocked after it starts. Manual is the default; unattended is an explicit, weaker opt-in.</summary>
public enum UnlockPolicy
{
    Manual,
    Unattended,
}

public static class UnlockPolicies
{
    public const string Manual = "manual";
    public const string Unattended = "unattended";

    public static string Name(UnlockPolicy policy) => policy == UnlockPolicy.Unattended ? Unattended : Manual;

    public static bool TryParse(string? text, out UnlockPolicy policy)
    {
        policy = UnlockPolicy.Manual;
        switch (text)
        {
            case Manual:
                return true;
            case Unattended:
                policy = UnlockPolicy.Unattended;

                return true;
            default:
                return false;
        }
    }

    /// <summary>The line the service, the admin page and <c>admin status</c> show, so the weaker mode is never silent.</summary>
    public static string Describe(UnlockPolicy policy) => policy == UnlockPolicy.Unattended
        ? "Unattended (weaker). The service unlocks itself at start, and anything that can run as this user can do the same. Sensitive changes still need a fresh passkey."
        : "Manual. An administrator unlocks it with a passkey.";
}

/// <summary>
/// Protection of the unattended-unlock material by the platform. <see cref="Seal" /> returns a blob that only this platform mechanism can open again;
/// <see cref="Open" /> returns null when it cannot (another user, another machine, damaged). Implementations exist only where the platform has a mechanism; no
/// platform is assumed to have one.
/// </summary>
public interface IUnlockProtection
{
    string Name { get; }

    /// <summary>Null when the mechanism works here, else why not (shown to the administrator who asked for unattended unlock).</summary>
    string? Unavailable { get; }

    byte[] Seal(byte[] material);

    byte[]? Open(byte[] sealedBlob);
}

/// <summary>No mechanism on this platform: unattended unlock is refused with a clear message.</summary>
public sealed class NoUnlockProtection(string reason) : IUnlockProtection
{
    public string Name => "none";

    public string? Unavailable => reason;

    public byte[] Seal(byte[] material) => throw new InvalidOperationException(reason);

    public byte[]? Open(byte[] sealedBlob) => null;
}

/// <summary>
/// Windows data protection (DPAPI) for the current user. Anything running as the same user can open the blob, which is exactly why unattended unlock is documented
/// as the weaker mode. The blob is not exportable to another user or machine.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class DpapiUnlockProtection : IUnlockProtection
{
    private static readonly byte[] Entropy = Encoding.UTF8.GetBytes("with-secrets authority unattended unlock v1");

    public string Name => "Windows DPAPI (current user)";

    public string? Unavailable => null;

    public byte[] Seal(byte[] material) => Transform(material, protect: true) ?? throw new CryptographicException("the platform could not protect the unlock material");

    public byte[]? Open(byte[] sealedBlob) => Transform(sealedBlob, protect: false);

    [StructLayout(LayoutKind.Sequential)]
    private struct DataBlob
    {
        public int Size;
        public IntPtr Data;
    }

    [DllImport("crypt32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool CryptProtectData(ref DataBlob input, string? description, ref DataBlob entropy, IntPtr reserved, IntPtr prompt, int flags, out DataBlob output);

    [DllImport("crypt32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool CryptUnprotectData(ref DataBlob input, IntPtr description, ref DataBlob entropy, IntPtr reserved, IntPtr prompt, int flags, out DataBlob output);

    [DllImport("kernel32.dll")]
    private static extern IntPtr LocalFree(IntPtr memory);

    private const int UiForbidden = 0x1;

    private static byte[]? Transform(byte[] input, bool protect)
    {
        GCHandle inHandle = GCHandle.Alloc(input, GCHandleType.Pinned);
        GCHandle entropyHandle = GCHandle.Alloc(Entropy, GCHandleType.Pinned);
        DataBlob output = default;
        try
        {
            DataBlob data = new() { Size = input.Length, Data = inHandle.AddrOfPinnedObject() };
            DataBlob entropy = new() { Size = Entropy.Length, Data = entropyHandle.AddrOfPinnedObject() };
            bool done = protect
                ? CryptProtectData(ref data, null, ref entropy, IntPtr.Zero, IntPtr.Zero, UiForbidden, out output)
                : CryptUnprotectData(ref data, IntPtr.Zero, ref entropy, IntPtr.Zero, IntPtr.Zero, UiForbidden, out output);
            if (!done)
            {
                return null;
            }

            byte[] result = new byte[output.Size];
            Marshal.Copy(output.Data, result, 0, output.Size);

            return result;
        }
        finally
        {
            if (output.Data != IntPtr.Zero)
            {
                LocalFree(output.Data);
            }

            inHandle.Free();
            entropyHandle.Free();
        }
    }
}

/// <summary>
/// The unattended start: when (and only when) the administrator set the unattended policy, open the platform-sealed material and, if it is the material the policy
/// recorded, unlock. It decides nothing else: it makes no grant, widens none, and leaves every sensitive operation to its own passkey tap. Any doubt (no material, a
/// blob the platform will not open, a different hash, a platform without a mechanism) leaves the authority locked and says so.
/// </summary>
public static class UnattendedUnlock
{
    /// <summary>Null when nothing was asked (manual policy); otherwise a one-line outcome, and the lock is unlocked only on success.</summary>
    public static string? TryUnlock(AuthorityStore store, AuthorityKeyRing keys, AuthorityLock lockState, IUnlockProtection protection)
    {
        UnlockPolicy policy;
        (byte[] Sealed, string Verifier, byte[]? Signature)? stored;
        try
        {
            policy = store.GetUnlockPolicy();
            stored = policy == UnlockPolicy.Unattended ? store.UnattendedMaterial() : null;
        }
        catch (AuthorityDatabaseException failure)
        {
            return "the unlock policy could not be read (" + failure.Message + "); the authority stays locked";
        }

        if (policy != UnlockPolicy.Unattended)
        {
            return null;
        }

        if (protection.Unavailable is { } unavailable)
        {
            return "unattended unlock is configured but " + unavailable + "; the authority stays locked";
        }

        if (stored is not { } material)
        {
            return "unattended unlock is configured but its material is missing; the authority stays locked";
        }

        // The policy row must be one the authority key signed when an administrator tapped for it; a row planted by a plain write to with-secrets.db has no such signature.
        try
        {
            byte[]? publicKey = keys.ActivePublicKey();
            if (publicKey is null || material.Signature is null || !KeyIdentity.Verify(publicKey, AuthorityStore.PolicySigningBytes(UnlockPolicy.Unattended, material.Sealed, material.Verifier), material.Signature))
            {
                return "unattended unlock is configured but the authority key did not sign the policy (a change made outside the admin app); the authority stays locked";
            }
        }
        catch (Exception error) when (error is AuthorityDatabaseException or CryptographicException)
        {
            return "unattended unlock is configured but the policy signature could not be checked; the authority stays locked";
        }

        byte[]? opened;
        try
        {
            opened = protection.Open(material.Sealed);
        }
        catch (Exception error) when (error is CryptographicException or InvalidOperationException)
        {
            opened = null;
        }

        if (opened is null)
        {
            return "unattended unlock is configured but the platform would not open its material (another user or machine, or damaged); the authority stays locked";
        }

        try
        {
            bool same = CryptographicOperations.FixedTimeEquals(Encoding.ASCII.GetBytes(Convert.ToHexString(SHA256.HashData(opened))), Encoding.ASCII.GetBytes(material.Verifier));
            if (!same)
            {
                return "unattended unlock is configured but its material does not match the recorded one; the authority stays locked";
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(opened);
        }

        lockState.Unlock(UnlockMethod.Unattended);

        return "unlocked at start by the unattended-unlock policy (the weaker mode)";
    }
}
