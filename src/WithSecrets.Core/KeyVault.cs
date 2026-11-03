using System.Buffers.Text;
using System.Security.Cryptography;
using System.Text;

namespace WithSecrets;

/// <summary>
/// A key's slot in the signed manifest: <see cref="Salt" /> (32 random bytes, the input of the passkey's PRF for this key) and
/// <see cref="Wrap" /> (the master key sealed under a key derived from that PRF output). Both are base64url, and neither is
/// secret by itself: opening <see cref="Wrap" /> needs the passkey.
/// </summary>
public sealed record KeySlot(string Salt, string Wrap);

/// <summary>
/// What a passkey released by WebAuthn PRF at one approval: the credential's id (base64url) and the 32-byte output for that
/// key's slot salt. It is the one thing that opens a slot. Dispose zeroes the output; <see cref="ToString" /> says nothing about it.
/// </summary>
public sealed class Unlock(string credentialId, byte[] output) : IDisposable
{
    public string CredentialId { get; } = credentialId;

    /// <summary>The PRF output. Valid until <see cref="Dispose" />.</summary>
    public byte[] Output { get; } = output;

    public void Dispose() => CryptographicOperations.ZeroMemory(Output);

    public override string ToString() => "Unlock(" + CredentialId + ")";
}

/// <summary>
/// The crypto of the key slots, in two layers. Each PRF-capable passkey has a slot that wraps a stable master key MK; one vault
/// wraps the secret store's private key K (the Dotenvx key, as UTF-8 hex text) under MK.
/// <list type="bullet">
/// <item>Slot: <c>KEK = HKDF-SHA256(ikm: PRF output, salt: slot salt, info: "with-secrets/v1 slot")</c>, then AES-256-GCM of MK under
/// KEK with a random 12-byte nonce and the associated data <c>credential id || slot salt</c>. Stored as base64url of
/// <c>nonce || ciphertext || tag</c> (60 bytes).</item>
/// <item>Vault: AES-256-GCM of K under MK, random nonce, associated data <c>"with-secrets/v1 vault" || store public key</c>.
/// Stored as base64url of <c>nonce || ciphertext || tag</c>.</item>
/// </list>
/// Every failure is a <see cref="CryptographicException" /> that says nothing about which input was wrong. Callers zero the
/// arrays they get and hand in. (.NET strings, such as the hex of K, cannot be wiped.)
/// </summary>
internal static class KeyVault
{
    public const string SlotInfo = "with-secrets/v1 slot";
    public const string VaultContext = "with-secrets/v1 vault";
    public const string RecoveryContext = "with-secrets/v1 recovery";

    /// <summary>The recovery code is 20 random bytes: 160 bits, 32 base32 characters.</summary>
    public const int RecoveryCodeBytes = 20;

    public const int KeyBytes = 32;
    public const int SaltBytes = 32;
    public const int NonceBytes = 12;
    public const int TagBytes = 16;

    /// <summary>The stored size of a slot's wrap: nonce, the 32-byte master key, tag.</summary>
    public const int SlotWrapBytes = NonceBytes + KeyBytes + TagBytes;

    private const int MaxVaultKeyBytes = 256;

    public static byte[] NewMasterKey() => RandomNumberGenerator.GetBytes(KeyBytes);

    public static byte[] NewSalt() => RandomNumberGenerator.GetBytes(SaltBytes);

    /// <summary>Wraps <paramref name="masterKey" /> for one passkey: its credential id, its slot salt and the PRF output for that salt.</summary>
    public static string WrapSlot(byte[] masterKey, byte[] prfOutput, byte[] credentialId, byte[] salt)
    {
        Require(masterKey.Length == KeyBytes && prfOutput.Length == KeyBytes && salt.Length == SaltBytes && credentialId.Length > 0);
        byte[] kek = Kek(prfOutput, salt);
        try
        {
            return Seal(masterKey, kek, [.. credentialId, .. salt]);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(kek);
        }
    }

    /// <summary>The master key in <paramref name="wrap" />. Throws <see cref="CryptographicException" /> when anything is wrong.</summary>
    public static byte[] UnwrapSlot(string wrap, byte[] prfOutput, byte[] credentialId, byte[] salt)
    {
        Require(prfOutput.Length == KeyBytes && salt.Length == SaltBytes && credentialId.Length > 0);
        byte[] kek = Kek(prfOutput, salt);
        try
        {
            byte[] master = Open(wrap, kek, [.. credentialId, .. salt], SlotWrapBytes, SlotWrapBytes);
            if (master.Length != KeyBytes)
            {
                CryptographicOperations.ZeroMemory(master);

                throw Failed();
            }

            return master;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(kek);
        }
    }

    /// <summary>Wraps the store's private key (UTF-8 hex text) under <paramref name="masterKey" />, for the store key with this public key.</summary>
    public static string WrapVault(byte[] storePrivateKey, byte[] masterKey, string storePublicKey)
    {
        Require(masterKey.Length == KeyBytes && storePrivateKey.Length is > 0 and <= MaxVaultKeyBytes);

        return Seal(storePrivateKey, masterKey, VaultAad(storePublicKey));
    }

    /// <summary>The store's private key bytes in <paramref name="vault" />. Throws <see cref="CryptographicException" /> when anything is wrong.</summary>
    public static byte[] UnwrapVault(string vault, byte[] masterKey, string storePublicKey)
    {
        Require(masterKey.Length == KeyBytes);

        return Open(vault, masterKey, VaultAad(storePublicKey), NonceBytes + 1 + TagBytes, NonceBytes + MaxVaultKeyBytes + TagBytes);
    }

    /// <summary>A new recovery code: 20 random bytes (shown to the person as 8 groups of 4 base32 characters, see <see cref="RecoveryCode" />).</summary>
    public static byte[] NewRecoveryCode() => RandomNumberGenerator.GetBytes(RecoveryCodeBytes);

    /// <summary>
    /// The recovery slot of the master key: a new random salt, and the master key sealed under
    /// <c>RK = HKDF-SHA256(ikm: code bytes, salt: recovery salt, info: "with-secrets/v1 recovery")</c> with AES-256-GCM, a random
    /// 12-byte nonce and the associated data <c>"with-secrets/v1 recovery" || store public key</c>. Stored like a slot wrap.
    /// </summary>
    public static KeySlot NewRecoverySlot(byte[] masterKey, byte[] code, string storePublicKey)
    {
        byte[] salt = NewSalt();

        return new KeySlot(Base64Url.EncodeToString(salt), WrapRecovery(masterKey, code, salt, storePublicKey));
    }

    /// <summary>Seals <paramref name="masterKey" /> for the recovery code (see <see cref="NewRecoverySlot" />).</summary>
    public static string WrapRecovery(byte[] masterKey, byte[] code, byte[] salt, string storePublicKey)
    {
        Require(masterKey.Length == KeyBytes && code.Length == RecoveryCodeBytes && salt.Length == SaltBytes);
        byte[] recoveryKey = RecoveryKey(code, salt);
        try
        {
            return Seal(masterKey, recoveryKey, RecoveryAad(storePublicKey));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(recoveryKey);
        }
    }

    /// <summary>The master key in <paramref name="wrap" />. Throws <see cref="CryptographicException" /> when anything is wrong.</summary>
    public static byte[] UnwrapRecovery(string wrap, byte[] code, byte[] salt, string storePublicKey)
    {
        Require(code.Length == RecoveryCodeBytes && salt.Length == SaltBytes);
        byte[] recoveryKey = RecoveryKey(code, salt);
        try
        {
            byte[] master = Open(wrap, recoveryKey, RecoveryAad(storePublicKey), SlotWrapBytes, SlotWrapBytes);
            if (master.Length != KeyBytes)
            {
                CryptographicOperations.ZeroMemory(master);

                throw Failed();
            }

            return master;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(recoveryKey);
        }
    }

    /// <summary>The master key of <paramref name="manifest" />, opened with the recovery code. Throws <see cref="CryptographicException" /> when there is no recovery slot or the code is wrong.</summary>
    public static byte[] OpenRecovery(Manifest manifest, byte[] code)
    {
        if (manifest.Recovery is not { } slot || manifest.Store.Length == 0)
        {
            throw Failed();
        }

        try
        {
            return UnwrapRecovery(slot.Wrap, code, Base64Url.DecodeFromChars(slot.Salt), manifest.Store);
        }
        catch (FormatException)
        {
            throw Failed();
        }
    }

    /// <summary>
    /// The master key, opened with what a passkey released at an approval: the slot of the key with that credential id in
    /// <paramref name="manifest" />. The caller zeroes the result. Throws <see cref="CryptographicException" /> when the key has
    /// no slot or the output does not open it.
    /// </summary>
    public static byte[] OpenMaster(Manifest manifest, Unlock unlock)
    {
        if (manifest.Keys.FirstOrDefault(key => key.Id == unlock.CredentialId)?.Slot is not { } slot)
        {
            throw Failed();
        }

        try
        {
            return UnwrapSlot(slot.Wrap, unlock.Output, Base64Url.DecodeFromChars(unlock.CredentialId), Base64Url.DecodeFromChars(slot.Salt));
        }
        catch (FormatException)
        {
            throw Failed();
        }
    }

    /// <summary>True when <paramref name="text" /> is base64url of a slot wrap's exact size (the manifest's shape check; it opens nothing).</summary>
    public static bool IsSlotWrap(string text) => Decodes(text, SlotWrapBytes, SlotWrapBytes);

    /// <summary>True when <paramref name="text" /> is base64url of a salt's exact size.</summary>
    public static bool IsSalt(string text) => Decodes(text, SaltBytes, SaltBytes);

    /// <summary>True when <paramref name="text" /> is base64url of a plausible vault (the manifest's shape check; it opens nothing).</summary>
    public static bool IsVault(string text) => Decodes(text, NonceBytes + 1 + TagBytes, NonceBytes + MaxVaultKeyBytes + TagBytes);

    /// <summary>KEK = HKDF-SHA256(ikm: PRF output, salt: slot salt, info: "with-secrets/v1 slot"), 32 bytes.</summary>
    private static byte[] Kek(byte[] prfOutput, byte[] salt) => HKDF.DeriveKey(HashAlgorithmName.SHA256, prfOutput, KeyBytes, salt, Encoding.UTF8.GetBytes(SlotInfo));

    /// <summary>RK = HKDF-SHA256(ikm: recovery code bytes, salt: recovery salt, info: "with-secrets/v1 recovery"), 32 bytes.</summary>
    private static byte[] RecoveryKey(byte[] code, byte[] salt) => HKDF.DeriveKey(HashAlgorithmName.SHA256, code, KeyBytes, salt, Encoding.UTF8.GetBytes(RecoveryContext));

    private static byte[] RecoveryAad(string storePublicKey) => [.. Encoding.UTF8.GetBytes(RecoveryContext), .. Encoding.UTF8.GetBytes(storePublicKey)];

    private static byte[] VaultAad(string storePublicKey) => [.. Encoding.UTF8.GetBytes(VaultContext), .. Encoding.UTF8.GetBytes(storePublicKey)];

    private static string Seal(byte[] plain, byte[] key, byte[] associated)
    {
        byte[] nonce = RandomNumberGenerator.GetBytes(NonceBytes);
        byte[] sealedBytes = new byte[plain.Length];
        byte[] tag = new byte[TagBytes];
        using AesGcm aes = new(key, TagBytes);
        aes.Encrypt(nonce, plain, sealedBytes, tag, associated);

        return Base64Url.EncodeToString([.. nonce, .. sealedBytes, .. tag]);
    }

    private static byte[] Open(string text, byte[] key, byte[] associated, int minimum, int maximum)
    {
        byte[] raw;
        try
        {
            raw = Base64Url.DecodeFromChars(text);
        }
        catch (FormatException)
        {
            throw Failed();
        }

        if (raw.Length < minimum || raw.Length > maximum)
        {
            throw Failed();
        }

        byte[] plain = new byte[raw.Length - NonceBytes - TagBytes];
        try
        {
            using AesGcm aes = new(key, TagBytes);
            aes.Decrypt(raw.AsSpan(0, NonceBytes), raw.AsSpan(NonceBytes, plain.Length), raw.AsSpan(NonceBytes + plain.Length), plain, associated);

            return plain;
        }
        catch (CryptographicException)
        {
            CryptographicOperations.ZeroMemory(plain);

            throw Failed();
        }
    }

    private static bool Decodes(string text, int minimum, int maximum)
    {
        try
        {
            int length = Base64Url.DecodeFromChars(text).Length;

            return length >= minimum && length <= maximum;
        }
        catch (FormatException)
        {
            return false;
        }
    }

    private static void Require(bool condition)
    {
        if (!condition)
        {
            throw Failed();
        }
    }

    /// <summary>One message for every failure: it must not say whether the key, the id, the salt or the bytes were wrong.</summary>
    private static CryptographicException Failed() => new("The key could not be opened.");
}
