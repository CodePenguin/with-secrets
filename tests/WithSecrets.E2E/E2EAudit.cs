using System.Collections.Concurrent;
using System.Runtime.CompilerServices;

namespace WithSecrets.E2E;

/// <summary>
/// Software machine keys for the browser tests, one per store folder, so that the events a command writes and the ones the service writes are signed by the same
/// machine key (and no real key store is touched).
/// </summary>
internal static class E2EAudit
{
    private static readonly ConcurrentDictionary<string, SoftwareSigningKey> Keys = new(StringComparer.OrdinalIgnoreCase);

    [ModuleInitializer]
    internal static void Use() => AdminAudit.KeyFactory = folder => new Shared(KeyFor(folder));

    public static SoftwareSigningKey KeyFor(string folder) => Keys.GetOrAdd(Path.GetFullPath(folder), _ => new SoftwareSigningKey());

    private sealed class Shared(ISigningKey inner) : ISigningKey
    {
        public byte[] PublicKey => inner.PublicKey;

        public byte[] Sign(byte[] data) => inner.Sign(data);

        public void Dispose()
        {
        }
    }
}
