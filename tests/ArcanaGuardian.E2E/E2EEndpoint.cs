namespace ArcanaGuardian.E2E;

/// <summary>The command line's endpoint of a service the browser tests start: a named pipe of its own on Windows, a socket in a private directory of its own elsewhere.</summary>
internal static class E2EEndpoint
{
    public static LocalEndpoint Make()
    {
        if (OperatingSystem.IsWindows())
        {
            return LocalEndpoint.NamedPipe("ws-e2e-" + Guid.NewGuid().ToString("N"));
        }

        string directory = Path.Combine(Path.GetTempPath(), "ws-" + Guid.NewGuid().ToString("N")[..8]);
        Directory.CreateDirectory(directory);
        File.SetUnixFileMode(directory, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);

        return LocalEndpoint.UnixSocket(directory);
    }
}
