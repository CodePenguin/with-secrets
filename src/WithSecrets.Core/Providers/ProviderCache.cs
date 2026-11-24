using System.Globalization;
using System.Text;

namespace WithSecrets;

/// <summary>A verified provider cache row: the ciphertext of the value for <see cref="StorePublicKey" /> and when a successful retrieval last proved it current.</summary>
public sealed record CachedSecret(Guid InstanceId, string ExternalId, string Ciphertext, DateTimeOffset LastVerified, string StorePublicKey);

/// <summary>
/// The provider cache (10.3.3): one row per (instance, external id), the value encrypted to the native store's PUBLIC key (no tap needed to write) and sealed by
/// the active authority signing key over the instance, the external id, lastVerified, the SHA-256 of the ciphertext, the store public key and the key's
/// fingerprint. A row is used only through <see cref="TryGet" />: anything that does not verify against the ACTIVE authority key (ruling 7), names another store
/// key, or is read while the authority is locked is a miss. Reading or decrypting never changes a row.
/// </summary>
public sealed class ProviderCache(ProviderStore store, AuthorityKeyRing keys, ISecretCipher? cipher = null)
{
    private const string SealContext = "with-secrets provider cache v1";

    private readonly ISecretCipher _cipher = cipher ?? DotenvxCipher.Instance;

    /// <summary>
    /// Encrypts each value (strict UTF-8, else <see cref="ArgumentException" /> before anything is signed) of one instance to <paramref name="storePublicKey" />, seals
    /// it with the active authority key (<see cref="AuthorityLockedException" /> while locked, before anything is written) and replaces the rows in ONE transaction,
    /// keeping a stored row with a NEWER lastVerified (<see cref="CacheWrite.Superseded" />). With <paramref name="expectedGeneration" />, nothing is written
    /// (<see cref="CacheWrite.Invalidated" />) when the instance generation moved (checked inside that transaction).
    /// </summary>
    public CacheWrite PutAll(Guid instanceId, IReadOnlyList<(string ExternalId, byte[] Value)> values, DateTimeOffset verifiedAt, string storePublicKey, long? expectedGeneration = null)
    {
        if (string.IsNullOrEmpty(storePublicKey))
        {
            throw new ArgumentException("A cache row needs the store public key.", nameof(storePublicKey));
        }

        // Every value is checked before anything is signed; the message names no byte.
        if (values.Any(item => !ProviderBatch.IsStrictUtf8(item.Value)))
        {
            throw new ArgumentException("A cached value must be well-formed UTF-8.");
        }

        ISigningKey key = keys.Current();
        string fingerprint = KeyIdentity.Fingerprint(key.PublicKey);
        List<(string, CacheRow)> rows = [];
        foreach ((string externalId, byte[] value) in values)
        {
            string ciphertext = _cipher.Encrypt(Encoding.UTF8.GetString(value), storePublicKey);
            byte[] signature = key.Sign(Seal(instanceId, externalId, verifiedAt, SecretStore.Hash(ciphertext), storePublicKey, fingerprint));
            rows.Add((externalId, new CacheRow(ciphertext, verifiedAt.UtcTicks, storePublicKey, fingerprint, signature)));
        }

        return store.WriteCache(instanceId, rows, expectedGeneration);
    }

    /// <summary>True while the authority is locked: nothing is signed, served or refreshed then.</summary>
    public bool IsLocked => keys.LockState?.IsLocked == true;

    /// <summary>
    /// The row of (instance, external id) when it verifies: sealed by the active authority key as the key store holds it, the ciphertext matching its sealed hash, and for
    /// <paramref name="currentStorePublicKey" />. Null for a missing row, a bad or non-active-key seal, a hash mismatch, another store key, an unreadable row,
    /// or while the authority is locked (nothing is served then). Never changes the row.
    /// </summary>
    public CachedSecret? TryGet(Guid instanceId, string externalId, string currentStorePublicKey)
    {
        if (keys.LockState?.IsLocked == true || string.IsNullOrEmpty(currentStorePublicKey))
        {
            return null;
        }

        CacheRow? row = store.ReadCache(instanceId, externalId);
        if (row is null || !string.Equals(row.StorePublicKey, currentStorePublicKey, StringComparison.Ordinal))
        {
            return null;
        }

        // The key store's active key, not the public key with-secrets.db names: a row planted with a planted authority_keys row has nothing to verify against.
        byte[]? activeKey;
        try
        {
            activeKey = keys.ActivePublicKey();
        }
        catch (Exception error) when (error is AuthorityDatabaseException or System.Security.Cryptography.CryptographicException)
        {
            return null;
        }

        if (activeKey is null)
        {
            return null;
        }

        string fingerprint = KeyIdentity.Fingerprint(activeKey);
        if (!string.Equals(row.AuthorityKey, fingerprint, StringComparison.Ordinal) || row.LastVerified < DateTimeOffset.MinValue.UtcTicks || row.LastVerified > DateTimeOffset.MaxValue.UtcTicks)
        {
            return null;
        }

        DateTimeOffset verified = new(row.LastVerified, TimeSpan.Zero);
        byte[] sealedText = Seal(instanceId, externalId, verified, SecretStore.Hash(row.Ciphertext), row.StorePublicKey, fingerprint);

        return KeyIdentity.Verify(activeKey, sealedText, row.Signature) ? new CachedSecret(instanceId, externalId, row.Ciphertext, verified, row.StorePublicKey) : null;
    }

    /// <summary>The value's UTF-8 bytes (the caller owns and zeroes them). Throws <see cref="SecretStoreException" /> without detail when it cannot be decrypted.</summary>
    public byte[] Decrypt(CachedSecret row, string storePrivateKey)
    {
        try
        {
            return Encoding.UTF8.GetBytes(_cipher.Decrypt(storePrivateKey, row.Ciphertext));
        }
        catch (Exception failure) when (failure is not OutOfMemoryException)
        {
            throw new SecretStoreException("a cached provider value cannot be decrypted (" + failure.GetType().Name + ")");
        }
    }

    /// <summary>The exact bytes the authority key signs for a cache row.</summary>
    internal static byte[] Seal(Guid instanceId, string externalId, DateTimeOffset lastVerified, string ciphertextHash, string storePublicKey, string authorityFingerprint)
    {
        string text = SealContext + "\n" + instanceId.ToString("D") + "\n" + externalId + "\n" + lastVerified.UtcTicks.ToString(CultureInfo.InvariantCulture) + "\n" + ciphertextHash + "\n"
            + storePublicKey + "\n" + authorityFingerprint;

        return Encoding.UTF8.GetBytes(text);
    }
}

/// <summary>What a cache write did: wrote every row, wrote all but rows that a NEWER retrieval had already written (kept), or wrote nothing because the instance generation moved.</summary>
public enum CacheWrite
{
    Written,
    Superseded,
    Invalidated,
}
