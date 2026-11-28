using System.Security.Cryptography;
using System.Text;

namespace WithSecrets;

/// <summary>
/// The keys an unlock makes usable in the authority's memory: the secret store key K and the review key R. Opening them takes the PRF output of an enrolled admin passkey; both open
/// together or neither does. They are held in pinned arrays (kept out of swap on Linux) until <see cref="Close" />, which zeroes them; the authority's lock calls it. A state without a
/// secret store yet opens with nothing held, still only for an admin key.
/// </summary>
public sealed class UnlockedKeys(ISecretCipher? cipher = null) : IDisposable
{
    private const string NotOpen = "the secret store key is not open: an administrator unlocks the authority with an admin passkey";
    private const string Stale = "the secret store key that is open is not the current one: an administrator unlocks the authority again";

    private readonly Lock _gate = new();
    private readonly ISecretCipher _cipher = cipher ?? JweCipher.Instance;
    private Held? _store;
    private Held? _review;
    private VerifiedCredential? _openedBy;
    private bool _disposed;

    private sealed record Held(byte[] Key, IDisposable Pages, string PublicKey)
    {
        public static Held Pin(byte[] key, string publicKey)
        {
            byte[] pinned = GC.AllocateArray<byte>(key.Length, pinned: true);
            IDisposable pages = LinuxHardening.TryLock(pinned);
            key.CopyTo(pinned, 0);

            return new Held(pinned, pages, publicKey);
        }

        public void Wipe() => LinuxHardening.Wipe(Key, Pages);
    }

    public bool IsOpen
    {
        get
        {
            lock (_gate)
            {
                return _openedBy is not null;
            }
        }
    }

    /// <summary>The admin passkey whose unlock opened the keys; null while closed.</summary>
    public VerifiedCredential? OpenedBy
    {
        get
        {
            lock (_gate)
            {
                return _openedBy;
            }
        }
    }

    /// <summary>For tests: the arrays held now (the same arrays <see cref="Close" /> zeroes).</summary>
    internal (byte[]? Store, byte[]? Review) HeldForTests
    {
        get
        {
            lock (_gate)
            {
                return (_store?.Key, _review?.Key);
            }
        }
    }

    /// <summary>Closes what was open, then opens K and R with what <paramref name="unlock" /> released. False, with nothing held, unless it is an admin key of <paramref name="manifest" /> whose PRF output opens both.</summary>
    public bool TryOpen(Manifest manifest, Unlock unlock)
    {
        lock (_gate)
        {
            Close();
            if (_disposed || manifest.Keys.FirstOrDefault(key => key.Id == unlock.CredentialId && key.Admin) is not { } opener)
            {
                return false;
            }

            if (manifest.Store.Length == 0)
            {
                _openedBy = VerifiedCredential.From(opener);

                return true;
            }

            if (manifest.Review is not { } review)
            {
                return false;
            }

            byte[]? master = null;
            byte[]? store = null;
            byte[]? reviewKey = null;
            Held? heldStore = null;
            Held? heldReview = null;
            try
            {
                master = KeyVault.OpenMaster(manifest, unlock);
                store = KeyVault.UnwrapVault(manifest.Vault, master, manifest.Store);
                reviewKey = KeyVault.UnwrapReview(review.Vault, master, review.PublicKey);
                if (JweCipher.Instance.Derive(Encoding.UTF8.GetString(store)) != manifest.Store || JweCipher.Instance.Derive(Encoding.UTF8.GetString(reviewKey)) != review.PublicKey)
                {
                    return false;
                }

                heldStore = Held.Pin(store, manifest.Store);
                heldReview = Held.Pin(reviewKey, review.PublicKey);
                _store = heldStore;
                _review = heldReview;
                _openedBy = VerifiedCredential.From(opener);
                heldStore = null;
                heldReview = null;

                return true;
            }
            catch (Exception error) when (error is not OutOfMemoryException)
            {
                return false;
            }
            finally
            {
                heldStore?.Wipe();
                heldReview?.Wipe();
                SecretValues.Clear(master);
                SecretValues.Clear(store);
                SecretValues.Clear(reviewKey);
            }
        }
    }

    /// <summary>
    /// Runs <paramref name="use" /> with the store key's text while it is held. Throws <see cref="SecretStoreException" /> when it is closed, when <paramref name="current" /> has another store key, or when the
    /// passkey that opened it is no longer an admin key of <paramref name="current" />.
    /// </summary>
    internal T UseStoreKey<T>(Manifest current, Func<string, T> use)
    {
        lock (_gate)
        {
            if (_store is not { } store || _openedBy is not { } opener)
            {
                throw new SecretStoreException(NotOpen);
            }

            if (current.Store != store.PublicKey || !current.IsAdmin(opener.Id))
            {
                throw new SecretStoreException(Stale);
            }

            return use(Encoding.UTF8.GetString(store.Key));
        }
    }

    /// <summary>Whether <see cref="UseStoreKey" /> would run for <paramref name="current" /> now. Makes no copy of the key.</summary>
    internal bool CanUseStoreKey(Manifest current)
    {
        lock (_gate)
        {
            return _store is { } store && _openedBy is { } opener && current.Store == store.PublicKey && current.IsAdmin(opener.Id);
        }
    }

    private static ReadOnlySpan<byte> AuthenticatorPurpose => "with-secrets authenticator credential v1"u8;

    internal string? SealAuthenticatorSeed(string reviewKey, string id, string name, ReadOnlySpan<byte> seed)
    {
        lock (_gate)
        {
            if (_review is not { } review || review.PublicKey != reviewKey || seed.Length != AuthenticatorCode.SeedSize) return null;
            Span<byte> key = stackalloc byte[32];
            Span<byte> sealedSeed = stackalloc byte[12 + AuthenticatorCode.SeedSize + 16];
            RandomNumberGenerator.Fill(sealedSeed[..12]);
            try
            {
                HMACSHA256.HashData(review.Key, AuthenticatorPurpose, key);
                using AesGcm cipher = new(key, 16);
                cipher.Encrypt(sealedSeed[..12], seed, sealedSeed.Slice(12, AuthenticatorCode.SeedSize), sealedSeed[^16..], Encoding.UTF8.GetBytes(id + "\n" + name));
                return Convert.ToBase64String(sealedSeed);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(key);
            }
        }
    }

    internal long? MatchAuthenticatorCode(AuthenticatorCredential credential, string code, DateTimeOffset now)
    {
        lock (_gate)
        {
            if (_review is not { } review || review.PublicKey != credential.ReviewKey) return null;
            Span<byte> sealedSeed = stackalloc byte[12 + AuthenticatorCode.SeedSize + 16];
            if (string.IsNullOrEmpty(credential.SealedSeed) || !Convert.TryFromBase64String(credential.SealedSeed, sealedSeed, out int length) || length != sealedSeed.Length) return null;
            Span<byte> key = stackalloc byte[32];
            Span<byte> seed = stackalloc byte[AuthenticatorCode.SeedSize];
            try
            {
                HMACSHA256.HashData(review.Key, AuthenticatorPurpose, key);
                using AesGcm cipher = new(key, 16);
                cipher.Decrypt(sealedSeed[..12], sealedSeed.Slice(12, AuthenticatorCode.SeedSize), sealedSeed[^16..], seed,
                    Encoding.UTF8.GetBytes(credential.Id + "\n" + credential.Name));
                return AuthenticatorCode.Match(seed, code, now);
            }
            catch (CryptographicException)
            {
                return null;
            }
            finally
            {
                CryptographicOperations.ZeroMemory(key);
                CryptographicOperations.ZeroMemory(seed);
            }
        }
    }

    /// <summary>Decrypts review text sealed to <paramref name="reviewPublicKey" />; null unless that is the review key held now.</summary>
    public string? TryDecryptReview(string ciphertext, string reviewPublicKey)
    {
        lock (_gate)
        {
            if (_review is not { } review || review.PublicKey != reviewPublicKey)
            {
                return null;
            }

            try
            {
                return _cipher.Decrypt(Encoding.UTF8.GetString(review.Key), ciphertext);
            }
            catch (Exception error) when (error is not OutOfMemoryException)
            {
                return null;
            }
        }
    }

    /// <summary>Decrypts data sealed to the review key held now (a provider's configuration); null while closed.</summary>
    public string? TryDecryptCurrentReview(string ciphertext)
    {
        lock (_gate)
        {
            return _review is { } review ? TryDecryptReview(ciphertext, review.PublicKey) : null;
        }
    }

    /// <summary>Zeroes and drops K and R. Idempotent.</summary>
    public void Close()
    {
        lock (_gate)
        {
            _store?.Wipe();
            _review?.Wipe();
            _store = null;
            _review = null;
            _openedBy = null;
        }
    }

    public void Dispose()
    {
        lock (_gate)
        {
            _disposed = true;
            Close();
        }
    }
}
