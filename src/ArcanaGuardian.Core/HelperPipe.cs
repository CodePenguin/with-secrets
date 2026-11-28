namespace ArcanaGuardian;

/// <summary>Names for same-user pipes shared by a host and its local helper.</summary>
public static class HelperPipe
{
    public static string GetName(string name)
        // .NET places relative pipe names under TMPDIR on Unix. The default macOS TMPDIR
        // can push a random pipe name beyond the Unix-domain socket path limit.
        => OperatingSystem.IsWindows() ? name : Path.Combine("/tmp", name);
}
