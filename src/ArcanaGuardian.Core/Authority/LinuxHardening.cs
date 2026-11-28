using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Cryptography;

namespace ArcanaGuardian;

/// <summary>
/// What Linux offers to protect a process that holds a key FILE (see <see cref="FileSigningKey" />): no core dump or ptrace by another process of the same user (non-dumpable), key and PRF material kept out of swap
/// (best-effort mlock), and the file facts (owner, type) that .NET does not expose. libc only, no package; everything here is a no-op or "unknown" on Windows. Nothing here puts a key, a code or any
/// secret in a message: only paths, numbers and error numbers.
/// </summary>
public static class LinuxHardening
{
    private const int PrSetDumpable = 4;
    private const int PrGetDumpable = 3;
    private const int AtFdCwd = -100;
    private const int AtSymlinkNofollow = 0x100;
    private const uint StatxBasicStats = 0x7ff;
    private const int StatxSize = 256;
    private const int StatxUidOffset = 20;
    private const int StatxModeOffset = 28;
    private const int OpenReadOnly = 0;
    private const int OpenDirectory = 0x10000;

    private const ushort FileTypeMask = 0xF000;
    private const ushort SymbolicLinkType = 0xA000;
    private const ushort DirectoryType = 0x4000;
    private const ushort RegularFileType = 0x8000;

    /// <summary>For tests: the owner to report for a path (null: the real one), so the refusal of a file or folder that belongs to another user can be tested by a user who cannot chown. Null in production.</summary>
    internal static Func<string, uint?>? OwnerOverride { get; set; }

    /// <summary>The user id this process runs as; null where it is not known (not Linux).</summary>
    public static uint? CurrentUserId() => OperatingSystem.IsLinux() ? GetUid() : null;

    /// <summary>Owner (null where the system does not say), type and mode of a path (the path itself, never what a link points to).</summary>
    public readonly record struct Facts(uint? Owner, bool IsLink, bool IsDirectory, bool IsFile, UnixFileMode Mode);

    /// <summary>The facts of <paramref name="path" /> (not following a link), or null when the path does not exist. Throws <see cref="PlatformNotSupportedException" /> when Linux cannot say who owns it.</summary>
    [UnsupportedOSPlatform("windows")]
    public static Facts? Inspect(string path)
    {
        if (!OperatingSystem.IsLinux())
        {
            FileSystemInfo info = Directory.Exists(path) ? new DirectoryInfo(path) : new FileInfo(path);
            if (!info.Exists && info.LinkTarget is null)
            {
                return null;
            }

            bool link = info.LinkTarget is not null;

            return new Facts(null, link, !link && info is DirectoryInfo, !link && info is FileInfo, link ? default : info.UnixFileMode);
        }

        byte[] buffer = new byte[StatxSize];
        int result;
        try
        {
            result = Statx(AtFdCwd, path, AtSymlinkNofollow, StatxBasicStats, buffer);
        }
        catch (Exception error) when (error is DllNotFoundException or EntryPointNotFoundException)
        {
            throw new PlatformNotSupportedException("this system cannot report who owns a file (statx is missing)", error);
        }

        if (result != 0)
        {
            int errno = Marshal.GetLastPInvokeError();
            if (errno is 2 or 20)
            {
                return null;
            }

            throw new IOException($"{path} could not be inspected (error {errno})");
        }

        uint owner = OwnerOverride?.Invoke(path) ?? BitConverter.ToUInt32(buffer, StatxUidOffset);
        ushort mode = BitConverter.ToUInt16(buffer, StatxModeOffset);
        ushort type = (ushort)(mode & FileTypeMask);

        // The permission bits and the sticky, setuid and setgid bits are the low twelve bits; they are exactly what UnixFileMode names.
        return new Facts(owner, type == SymbolicLinkType, type == DirectoryType, type == RegularFileType, (UnixFileMode)(mode & 0xFFF));
    }

    /// <summary>
    /// Makes this process non-dumpable (prctl PR_SET_DUMPABLE 0): no core file, and no ptrace or /proc/PID/mem reading by another process of the same user. Returns null when done (or on Windows,
    /// where it is skipped), else one line to log (no secret in it). Never throws.
    /// </summary>
    public static string? MakeNonDumpable()
    {
        if (!OperatingSystem.IsLinux())
        {
            return null;
        }

        try
        {
            if (Prctl(PrSetDumpable, 0, 0, 0, 0) == 0)
            {
                return null;
            }

            return $"the process could not be made non-dumpable (error {Marshal.GetLastPInvokeError()}); a core dump or a debugger of the same user could read its memory";
        }
        catch (Exception error) when (error is DllNotFoundException or EntryPointNotFoundException)
        {
            return "the process could not be made non-dumpable (prctl is missing); a core dump or a debugger of the same user could read its memory";
        }
    }

    /// <summary>The process hardening of a command that loads a key: non-dumpable, with the one-line warning (no secret in it) in the log when it could not be done. Skipped on Windows.</summary>
    public static void HardenProcess()
    {
        if (MakeNonDumpable() is { } problem)
        {
            AppLog.Warn("{Problem}", problem);
        }
    }

    /// <summary>True when the process is dumpable (so something is wrong or it was never hardened); false when it is not, or on Windows.</summary>
    public static bool IsDumpable()
    {
        if (!OperatingSystem.IsLinux())
        {
            return false;
        }

        try
        {
            return Prctl(PrGetDumpable, 0, 0, 0, 0) == 1;
        }
        catch (Exception error) when (error is DllNotFoundException or EntryPointNotFoundException)
        {
            return false;
        }
    }

    /// <summary>
    /// Keeps <paramref name="data" /> in RAM (mlock; never swapped) until the result is disposed, which also unlocks it. Best effort: when the system refuses (RLIMIT_MEMLOCK, a container without the
    /// capability) a one-line warning without secrets goes to the log and the result is a lock that holds nothing, never an exception. Skipped on Windows. The array stays pinned while it is locked.
    /// This covers the array the caller gives; copies the runtime or a crypto library makes elsewhere are not covered (see the operations guide).
    /// </summary>
    public static IDisposable TryLock(byte[] data)
    {
        if (!OperatingSystem.IsLinux() || data.Length == 0)
        {
            return NoLock.Instance;
        }

        GCHandle handle = GCHandle.Alloc(data, GCHandleType.Pinned);
        try
        {
            if (Mlock(handle.AddrOfPinnedObject(), (nuint)data.Length) == 0)
            {
                return new PageLock(handle, data.Length);
            }

            AppLog.Warn("memory holding key material could not be locked against swapping (error {Errno}); it may be written to swap", Marshal.GetLastPInvokeError());
        }
        catch (Exception error) when (error is DllNotFoundException or EntryPointNotFoundException)
        {
            AppLog.Warn("memory holding key material could not be locked against swapping (mlock is missing); it may be written to swap");
        }

        handle.Free();

        return NoLock.Instance;
    }

    /// <summary>Flushes the directory entry (a new or renamed file in it) to disk. Best effort; never throws.</summary>
    [SupportedOSPlatform("linux")]
    internal static void SyncDirectory(string folder)
    {
        try
        {
            int descriptor = Open(folder, OpenReadOnly | OpenDirectory);
            if (descriptor < 0)
            {
                return;
            }

            try
            {
                _ = Fsync(descriptor);
            }
            finally
            {
                _ = Close(descriptor);
            }
        }
        catch (Exception error) when (error is DllNotFoundException or EntryPointNotFoundException)
        {
            // Without libc there is nothing to flush with.
        }
    }

    /// <summary>
    /// Makes <paramref name="target" /> a new name of the file <paramref name="temp" /> only when nothing has that name (link(2): atomic, and it fails when the name exists, which a plain rename does not), then removes
    /// <paramref name="temp" />. False when the name was taken. Linux only.
    /// </summary>
    [SupportedOSPlatform("linux")]
    internal static bool LinkExclusive(string temp, string target)
    {
        if (Link(temp, target) == 0)
        {
            File.Delete(temp);

            return true;
        }

        int errno = Marshal.GetLastPInvokeError();
        if (errno == 17)
        {
            return false;
        }

        throw new IOException($"{target} could not be created (error {errno})");
    }

    private sealed class NoLock : IDisposable
    {
        public static readonly NoLock Instance = new();

        public void Dispose()
        {
        }
    }

    private sealed class PageLock(GCHandle handle, int length) : IDisposable
    {
        private int _done;

        public void Dispose()
        {
            if (Interlocked.Exchange(ref _done, 1) != 0)
            {
                return;
            }

            try
            {
                // The memory is cleared by its owner before this; the unlock only returns the pages to the system.
                _ = Munlock(handle.AddrOfPinnedObject(), (nuint)length);
            }
            finally
            {
                handle.Free();
            }
        }
    }

    [DllImport("libc", EntryPoint = "getuid")]
    private static extern uint GetUid();

    [DllImport("libc", EntryPoint = "prctl", SetLastError = true)]
    private static extern int Prctl(int option, nuint arg2, nuint arg3, nuint arg4, nuint arg5);

    [DllImport("libc", EntryPoint = "mlock", SetLastError = true)]
    private static extern int Mlock(IntPtr address, nuint length);

    [DllImport("libc", EntryPoint = "munlock", SetLastError = true)]
    private static extern int Munlock(IntPtr address, nuint length);

    [DllImport("libc", EntryPoint = "statx", SetLastError = true, CharSet = CharSet.Ansi)]
    private static extern int Statx(int directory, string path, int flags, uint mask, byte[] buffer);

    [DllImport("libc", EntryPoint = "link", SetLastError = true, CharSet = CharSet.Ansi)]
    private static extern int Link(string existing, string created);

    [DllImport("libc", EntryPoint = "open", SetLastError = true, CharSet = CharSet.Ansi)]
    private static extern int Open(string path, int flags);

    [DllImport("libc", EntryPoint = "fsync", SetLastError = true)]
    private static extern int Fsync(int descriptor);

    [DllImport("libc", EntryPoint = "close", SetLastError = true)]
    private static extern int Close(int descriptor);

    /// <summary>Zeroes <paramref name="data" /> and then lets go of its lock.</summary>
    internal static void Wipe(byte[] data, IDisposable? pageLock)
    {
        CryptographicOperations.ZeroMemory(data);
        pageLock?.Dispose();
    }
}
