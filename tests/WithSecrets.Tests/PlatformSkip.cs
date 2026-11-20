namespace WithSecrets.Tests;

/// <summary>
/// Machine transport is TLS 1.3 only, and macOS takes no part in it (see <see cref="PlatformTls" />: no server-side TLS 1.3 in .NET, and the opt-in client side can abort the process), so a test that needs a machine listener to answer a real handshake
/// is skipped there and says so. Nothing is weakened to make it run (no older protocol, no certificate callback that accepts everything). The same tests run on Windows and Linux; the macOS refusal itself is tested in ClientTlsProbeTests.
/// </summary>
internal static class PlatformSkip
{
    public static bool NoServerTls13(string what)
    {
        if (PlatformTls.MachineTransportUnsupported is null)
        {
            return false;
        }

        Console.WriteLine("  SKIP " + what + ": macOS takes no part in machine transport (see PlatformTls); run on Windows and Linux");

        return true;
    }
}
