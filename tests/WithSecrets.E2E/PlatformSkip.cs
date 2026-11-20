namespace WithSecrets.E2E;

/// <summary>
/// Machine transport is TLS 1.3 only, and .NET has no server-side TLS 1.3 on macOS (see <see cref="PlatformTls" />), so a test that needs a machine listener to answer a real handshake cannot run there: it says so and is skipped.
/// Nothing is weakened to make it run (no older protocol, no certificate callback that accepts everything). The same tests run on Windows and Linux.
/// </summary>
internal static class PlatformSkip
{
    public static bool NoServerTls13(string what)
    {
        if (PlatformTls.ListenerUnsupported is null)
        {
            return false;
        }

        Console.WriteLine("  SKIP " + what + ": .NET has no server-side TLS 1.3 on macOS, so no machine listener can answer a handshake here; run on Windows and Linux");

        return true;
    }
}
