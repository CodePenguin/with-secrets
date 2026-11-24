using System.Security.Cryptography;
using System.Text;

namespace WithSecrets;

/// <summary>The authority's in-memory private review key. Opening it requires the PRF output of an enrolled admin passkey.</summary>
public sealed class ReviewKeys(ISecretCipher? cipher = null) : IDisposable
{
    private readonly Lock _gate = new();
    private readonly ISecretCipher _cipher = cipher ?? DotenvxCipher.Instance;
    private byte[]? _privateKey;
    private IDisposable? _pages;
    private string? _publicKey;
    private bool _disposed;

    public bool IsOpen
    {
        get
        {
            lock (_gate)
            {
                return _privateKey is not null;
            }
        }
    }

    public bool TryOpen(Manifest manifest, Unlock unlock)
    {
        lock (_gate)
        {
            Close();
            if (_disposed || manifest.Review is not { } review || !manifest.Keys.Any(key => key.Id == unlock.CredentialId && key.Admin))
            {
                return false;
            }

            byte[]? master = null;
            byte[]? unwrapped = null;
            try
            {
                master = KeyVault.OpenMaster(manifest, unlock);
                unwrapped = KeyVault.UnwrapReview(review.Vault, master, review.PublicKey);
                if (DotenvxCipher.Instance.Derive(Encoding.UTF8.GetString(unwrapped)) != review.PublicKey)
                {
                    return false;
                }

                byte[] pinned = GC.AllocateArray<byte>(unwrapped.Length, pinned: true);
                _pages = LinuxHardening.TryLock(pinned);
                unwrapped.CopyTo(pinned, 0);
                _privateKey = pinned;
                _publicKey = review.PublicKey;
                return true;
            }
            catch (Exception error) when (error is not OutOfMemoryException)
            {
                return false;
            }
            finally
            {
                if (master is not null) CryptographicOperations.ZeroMemory(master);
                if (unwrapped is not null) CryptographicOperations.ZeroMemory(unwrapped);
            }
        }
    }

    public string? TryDecrypt(string ciphertext, string reviewPublicKey)
    {
        lock (_gate)
        {
            if (_privateKey is not { } key || _publicKey != reviewPublicKey)
            {
                return null;
            }

            try
            {
                return _cipher.Decrypt(Encoding.UTF8.GetString(key), ciphertext);
            }
            catch (Exception error) when (error is not OutOfMemoryException)
            {
                return null;
            }
        }
    }

    /// <summary>Decrypts data sealed to the current open review key.</summary>
    public string? TryDecryptCurrent(string ciphertext)
    {
        lock (_gate)
        {
            return _publicKey is { } publicKey ? TryDecrypt(ciphertext, publicKey) : null;
        }
    }


    public void Close()
    {
        lock (_gate)
        {
            if (_privateKey is { } key && _pages is { } pages)
            {
                LinuxHardening.Wipe(key, pages);
            }

            _privateKey = null;
            _pages = null;
            _publicKey = null;
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
