using System.ComponentModel;
using System.Diagnostics;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Win32.SafeHandles;
using WithSecrets.LastPass;

namespace WithSecrets;

internal sealed class LastPassRefreshLauncher : IInteractiveProviderRefresh
{
    private const string Title = "WithSecrets | LastPass refresh";
    internal const string PipePrefix = "with-secrets-lp-";
    private readonly NamedPipeServerStream _pipe;
    private readonly LastPassRefreshHandoff _handoff;

    private LastPassRefreshLauncher(NamedPipeServerStream pipe, LastPassRefreshHandoff handoff)
    {
        _pipe = pipe;
        _handoff = handoff;
    }

    public string MatchingCode => _handoff.MatchingCode;

    public Task<IReadOnlyDictionary<string, string>> ReceiveAsync(CancellationToken cancel)
        => _handoff.ReceiveStageAsync(_pipe, cancel);

    public void Dispose()
    {
        _pipe.Dispose();
        _handoff.Dispose();
    }

    public static async Task<IInteractiveProviderRefresh> StartAsync(InteractiveProviderRefreshRequest request, ISigningKey authority, CancellationToken cancel)
    {
        using CancellationTokenSource deadline = CancellationTokenSource.CreateLinkedTokenSource(cancel);
        deadline.CancelAfter(TimeSpan.FromSeconds(15));
        string channel = Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(16));
        NamedPipeServerStream pipe = new(PipePrefix + channel, PipeDirection.InOut, 1, PipeTransmissionMode.Byte,
            PipeOptions.CurrentUserOnly | PipeOptions.Asynchronous);
        try
        {
            (string executable, int? process) = OpenTerminal(channel);
            await pipe.WaitForConnectionAsync(deadline.Token).ConfigureAwait(false);
            VerifyHelper(pipe, executable, process);
            LastPassRefreshRequest handoff = new(request.Id, request.InstanceId, request.RequestedBy, request.ProviderName,
                request.Account, request.European, request.Expires, request.StorePublicKey,
                [.. request.Mappings.Select(mapping => new LastPassRefreshMapping(mapping.Path, mapping.LocalName))]);
            return new LastPassRefreshLauncher(pipe, await LastPassRefreshHandoff.SendAsync(pipe, pipe, handoff,
                authority, deadline.Token).ConfigureAwait(false));
        }
        catch
        {
            pipe.Dispose();
            throw;
        }
    }

    private static (string Executable, int? Process) OpenTerminal(string channel)
    {
        string? executable = Environment.ProcessPath;
        if (executable is null || !Path.IsPathFullyQualified(executable) || !File.Exists(executable))
            throw TerminalUnavailable();

        List<string> command = [executable];
        if (string.Equals(Path.GetFileNameWithoutExtension(executable), "dotnet", StringComparison.OrdinalIgnoreCase))
        {
            // Unix terminal applications may spawn through a desktop daemon. Only a dedicated executable
            // identifies the resulting helper independently of an attacker-controlled command line.
            if (!OperatingSystem.IsWindows()) throw TerminalUnavailable();
            string assembly = Path.GetFullPath(Environment.GetCommandLineArgs()[0]);
            if (!Path.IsPathFullyQualified(assembly) || !File.Exists(assembly)) throw TerminalUnavailable();
            command.Add(assembly);
        }
        command.AddRange(["--lastpass-refresh-helper", channel]);

        if (OperatingSystem.IsWindows()) return (executable, OpenWindowsConsole(command));
        if (OperatingSystem.IsMacOS())
        {
            const string script = """
                on run argv
                  set commandText to "exec"
                  repeat with part in argv
                    set commandText to commandText & " " & quoted form of (contents of part)
                  end repeat
                  tell application id "com.apple.Terminal"
                    do script commandText
                    activate
                  end tell
                end run
                """;
            Start("/usr/bin/osascript", ["-e", script, "--", .. command]);
            return (executable, null);
        }
        if (OperatingSystem.IsLinux() && (Environment.GetEnvironmentVariable("DISPLAY") is { Length: > 0 }
            || Environment.GetEnvironmentVariable("WAYLAND_DISPLAY") is { Length: > 0 }))
        {
            (string Path, string[] Options)[] terminals =
            [
                ("/usr/bin/gnome-terminal", ["--title", Title, "--"]),
                ("/usr/bin/konsole", ["-p", "tabtitle=" + Title, "-e"]),
                ("/usr/bin/xterm", ["-T", Title, "-e"]),
            ];
            foreach ((string path, string[] options) in terminals)
            {
                if (!File.Exists(path)) continue;
                Start(path, [.. options, .. command]);
                return (executable, null);
            }
        }
        throw TerminalUnavailable();
    }

    private static void Start(string executable, IReadOnlyList<string> arguments)
    {
        ProcessStartInfo info = new(executable) { UseShellExecute = false };
        foreach (string argument in arguments) info.ArgumentList.Add(argument);
        using Process process = Process.Start(info) ?? throw TerminalUnavailable();
    }

    private static ProviderAdapterException TerminalUnavailable() => new(ProviderErrorKind.Unavailable,
        "An interactive desktop terminal was not available on the WithSecrets host.");

    private static int OpenWindowsConsole(IReadOnlyList<string> command)
    {
        // Windows executable and assembly filenames cannot contain double quotes. These are files, so there is no trailing path separator.
        StringBuilder line = new(string.Join(' ', command.Select(argument => "\"" + argument + "\"")));
        StartupInfo startup = new() { Size = Marshal.SizeOf<StartupInfo>(), Title = Title };
        if (!CreateProcess(command[0], line, IntPtr.Zero, IntPtr.Zero, false, 0x10, IntPtr.Zero, null, ref startup, out ProcessInfo created))
            throw new Win32Exception(Marshal.GetLastPInvokeError());
        CloseHandle(created.Process);
        CloseHandle(created.Thread);
        return created.ProcessId;
    }

    private static void VerifyHelper(NamedPipeServerStream pipe, string executable, int? launchedProcess)
    {
        if (OperatingSystem.IsWindows())
        {
            if (!GetNamedPipeClientProcessId(pipe.SafePipeHandle, out int peer) || peer != launchedProcess)
                throw TerminalUnavailable();
            return;
        }

        int descriptor = pipe.SafePipeHandle.DangerousGetHandle().ToInt32();
        int client;
        string? actual;
        if (OperatingSystem.IsLinux())
        {
            uint size = (uint)Marshal.SizeOf<PeerCredentials>();
            const int socketLevel = 1, peerCredentials = 17;
            if (GetLinuxPeer(descriptor, socketLevel, peerCredentials, out PeerCredentials credentials, ref size) != 0
                || size != Marshal.SizeOf<PeerCredentials>() || credentials.Process <= 0)
                throw TerminalUnavailable();
            client = credentials.Process;
            actual = File.ResolveLinkTarget($"/proc/{client}/exe", returnFinalTarget: false)?.FullName;
        }
        else if (OperatingSystem.IsMacOS())
        {
            uint size = sizeof(int);
            const int localLevel = 0, peerProcess = 2;
            if (GetMacPeer(descriptor, localLevel, peerProcess, out client, ref size) != 0 || size != sizeof(int) || client <= 0)
                throw TerminalUnavailable();
            byte[] path = new byte[4096];
            int length = ReadMacProcessPath(client, path, (uint)path.Length);
            actual = length <= 0 || length >= path.Length ? null : Encoding.UTF8.GetString(path, 0, length).TrimEnd('\0');
        }
        else throw TerminalUnavailable();

        if (!string.Equals(actual, executable, StringComparison.Ordinal)) throw TerminalUnavailable();
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct StartupInfo
    {
        public int Size;
        public string? Reserved, Desktop, Title;
        public int X, Y, XSize, YSize, XCountChars, YCountChars, FillAttribute, Flags;
        public short ShowWindow, ReservedBytes;
        public IntPtr ReservedData, StandardInput, StandardOutput, StandardError;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct ProcessInfo
    {
        public IntPtr Process, Thread;
        public int ProcessId, ThreadId;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct PeerCredentials
    {
        public int Process;
        public uint User, Group;
    }

    [DllImport("kernel32.dll", EntryPoint = "CreateProcessW", CharSet = CharSet.Unicode, ExactSpelling = true, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CreateProcess(string application, StringBuilder commandLine, IntPtr processAttributes, IntPtr threadAttributes,
        [MarshalAs(UnmanagedType.Bool)] bool inheritHandles, uint flags, IntPtr environment, string? directory, ref StartupInfo startup, out ProcessInfo process);

    [DllImport("kernel32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseHandle(IntPtr handle);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetNamedPipeClientProcessId(SafePipeHandle pipe, out int process);

    [DllImport("libc", EntryPoint = "getsockopt")]
    private static extern int GetLinuxPeer(int socket, int level, int option, out PeerCredentials credentials, ref uint length);

    [DllImport("libc", EntryPoint = "getsockopt")]
    private static extern int GetMacPeer(int socket, int level, int option, out int process, ref uint length);

    [DllImport("libproc.dylib", EntryPoint = "proc_pidpath")]
    private static extern int ReadMacProcessPath(int process, [Out] byte[] buffer, uint length);
}
