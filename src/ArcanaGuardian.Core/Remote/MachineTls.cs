using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace ArcanaGuardian;

/// <summary>
/// The TLS private key of one running host-service instance: ECDSA P-256, never written by this program, distinct from the identity key, gone when the instance ends.
/// <para>
/// Windows SChannel does not accept a key that exists only in process memory ("the platform does not support ephemeral keys": the TLS provider runs in another process and has to open the key by name),
/// so on Windows the key is a NON-EXPORTABLE CNG key with a random one-use name in the user's key store (the software provider), created when the instance starts and DELETED when it is disposed. It is not a
/// file this program writes or reads, it is never exported, and it is not reused by a later instance. What cannot be prevented is a crash or kill that skips disposal: the key then stays in the user's own key
/// store (protected like every key of that store) until it is deleted by hand; it can only sign TLS handshakes for a certificate that has expired by then. Elsewhere the key is an ordinary in-memory ECDSA key.
/// </para>
/// </summary>
internal sealed class TlsKey : IDisposable
{
    private readonly CngKey? _cng;
    private int _disposed;

    public TlsKey()
    {
        if (OperatingSystem.IsWindows())
        {
            (Key, _cng) = CreateWindows();
        }
        else
        {
            Key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        }
    }

    public ECDsa Key { get; }

    public byte[] PublicKey => Key.ExportSubjectPublicKeyInfo();

    [SupportedOSPlatform("windows")]
    private static (ECDsa, CngKey) CreateWindows()
    {
        CngKey key = CngKey.Create(CngAlgorithm.ECDsaP256, TestIsolation.KeyName("arcana-guardian tls " + Guid.NewGuid().ToString("N")), new CngKeyCreationParameters
        {
            Provider = CngProvider.MicrosoftSoftwareKeyStorageProvider,
            ExportPolicy = CngExportPolicies.None,
            KeyUsage = CngKeyUsages.Signing,
        });

        return (new ECDsaCng(key), key);
    }

    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) == 1)
        {
            return;
        }

        Key.Dispose();
        if (_cng is not null && OperatingSystem.IsWindows())
        {
            try
            {
                _cng.Delete();
            }
            catch (CryptographicException)
            {
                // Already gone.
            }

            _cng.Dispose();
        }
    }
}

/// <summary>
/// The temporary TLS certificate of this running instance (architecture 10.2): a fresh in-memory key and a 24-hour leaf signed by the persistent machine identity key, with the machine's SAN URI and both
/// <c>serverAuth</c> and <c>clientAuth</c> (the same certificate serves as the TLS server certificate of an authority and the client certificate of a host). It is replaced one hour before it expires: new
/// handshakes use the replacement at once (the listener asks <see cref="Current" /> for each handshake, a client for each connection pool), and connections made with the old one are not touched. The previous
/// certificate and its key are kept until the next rotation so a handshake that started with it can finish. Time comes from the <see cref="TimeProvider" /> (a test moves it).
/// </summary>
public sealed class TemporaryCertificate : IDisposable
{
    private readonly ISigningKey _identityKey;
    private readonly byte[] _identityCertificate;
    private readonly TimeProvider _clock;
    private readonly Lock _lock = new();
    private Generation _current;
    private Generation? _previous;
    private int _rotations;
    private int _disposed;

    public TemporaryCertificate(ISigningKey identityKey, byte[] identityCertificate, TimeProvider? clock = null)
    {
        _identityKey = identityKey;
        _identityCertificate = identityCertificate;
        _clock = clock ?? TimeProvider.System;
        _current = Make();
    }

    private sealed class Generation(TlsKey key, X509Certificate2 publicPart, X509Certificate2 withKey, DateTimeOffset rotateAt)
    {
        public TlsKey Key { get; } = key;

        public X509Certificate2 Public { get; } = publicPart;

        public X509Certificate2 WithKey { get; } = withKey;

        public DateTimeOffset RotateAt { get; } = rotateAt;

        public void Dispose()
        {
            WithKey.Dispose();
            Public.Dispose();
            Key.Dispose();
        }
    }

    /// <summary>Raised after a replacement was made (the host's client builds a new connection pool when it happens).</summary>
    public event Action? Rotated;

    /// <summary>How many replacements have been made since this instance started.</summary>
    public int Rotations => Volatile.Read(ref _rotations);

    /// <summary>The fingerprint of the machine identity this certificate speaks for.</summary>
    public string IdentityFingerprint => KeyIdentity.Fingerprint(_identityKey.PublicKey);

    public TimeProvider Clock => _clock;

    private Generation Make()
    {
        DateTimeOffset now = _clock.GetUtcNow();
        TlsKey key = new();
        try
        {
            byte[] der = MachineCertificates.CreateTemporary(_identityKey, _identityCertificate, key.PublicKey, now);
            X509Certificate2 publicPart = MachineCertificates.Load(der);
            X509Certificate2 withKey = publicPart.CopyWithPrivateKey(key.Key);

            return new Generation(key, publicPart, withKey, publicPart.NotAfter.ToUniversalTime() - MachineCertificates.RotateBefore);
        }
        catch
        {
            key.Dispose();

            throw;
        }
    }

    /// <summary>The certificate to present now (with its private key); a replacement is made first when it is time.</summary>
    public X509Certificate2 Current
    {
        get
        {
            ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) == 1, this);
            bool rotated = false;
            X509Certificate2 current;
            lock (_lock)
            {
                if (_clock.GetUtcNow() >= _current.RotateAt)
                {
                    Generation next = Make();
                    _previous?.Dispose();
                    _previous = _current;
                    _current = next;
                    Interlocked.Increment(ref _rotations);
                    rotated = true;
                }

                current = _current.WithKey;
            }

            if (rotated)
            {
                Rotated?.Invoke();
            }

            return current;
        }
    }

    /// <summary>The public part (DER) of the current certificate.</summary>
    public byte[] CurrentPublic
    {
        get
        {
            _ = Current;
            lock (_lock)
            {
                return _current.Public.RawData;
            }
        }
    }

    /// <summary>When the current certificate will be replaced.</summary>
    public DateTimeOffset NextRotation
    {
        get
        {
            lock (_lock)
            {
                return _current.RotateAt;
            }
        }
    }

    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) == 1)
        {
            return;
        }

        lock (_lock)
        {
            _previous?.Dispose();
            _current.Dispose();
        }
    }
}
