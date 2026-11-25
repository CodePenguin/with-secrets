using System.Buffers.Text;
using System.Security.Cryptography;
using System.Text;

namespace WithSecrets.Tests;

/// <summary>
/// The key slots' crypto: a slot wraps the stable master key MK under a key derived from a passkey's PRF output
/// (HKDF-SHA-256, AES-256-GCM, the credential id and the slot salt as associated data), and one vault wraps the secret store's
/// private key under MK. Every wrong input must fail, and none of them may leak why.
/// </summary>
internal static class KeyVaultTests
{
    public static Task Run(Action<bool, string> check)
    {
        Slots(check);
        Vaults(check);
        Authenticator(check);
        Transport(check);
        ManifestSlots(check);

        return Task.CompletedTask;
    }

    /// <summary>Changes one character of a base64url text to another valid one, so the text keeps its shape but not its meaning.</summary>
    private static string Alter(string text, string field)
    {
        int at = text.IndexOf(field, StringComparison.Ordinal) + field.Length + 3;
        char changed = text[at] == 'A' ? 'B' : 'A';

        return text[..at] + changed + text[(at + 1)..];
    }

    private static void ManifestSlots(Action<bool, string> check)
    {
        using TestAuthenticator laptop = TestAuthenticator.ES256();
        using TestAuthenticator phone = TestAuthenticator.ES256();
        byte[] mk = KeyVault.NewMasterKey();
        PasskeyRecord record = laptop.Record("localhost", "laptop", mk);
        KeySlot slot = record.Slot!;
        Manifest first = Manifest.First(record, ToolSettings.Defaults);
        string text = first.Canonical();
        check(text.Contains("\"admin\":true,\"slot\":{\"salt\":\"" + slot.Salt + "\",\"wrap\":\"" + slot.Wrap + "\"}}],\"store\":\"\",\"vault\":\"\",\"secrets\":{},\"settings\":", StringComparison.Ordinal),
            "slot manifest: a key carries its slot after admin, and the vault follows the store key (" + text + ")");
        Manifest? parsed = Manifest.Parse(text, out string? error);
        check(parsed is not null && error is null && parsed.Keys.Single().Slot == slot && parsed.Vault == "" && parsed.Canonical() == text, "slot manifest: round trip keeps the slot (" + error + ")");
        check(first.Problem() is null, "slot manifest: a key with a slot is valid (" + first.Problem() + ")");

        (string publicKey, string privateKey) = JweCipher.Instance.NewKeyPair();
        string vault = KeyVault.WrapVault(Encoding.UTF8.GetBytes(privateKey), mk, publicKey);
        ReviewKey review = KeyVault.NewReviewKey(mk);
        Manifest withStore = first.WithSecrets(publicKey, new Dictionary<string, string> { ["A_NAME"] = new string('a', 64) }, vault, review);
        string storeText = withStore.Canonical();
        check(storeText.Contains(",\"store\":\"" + publicKey + "\",\"vault\":\"" + vault + "\",\"review\":{\"pub\":\"" + review.PublicKey + "\",\"vault\":\"" + review.Vault + "\"}", StringComparison.Ordinal)
            && Manifest.Parse(storeText, out error) is { } back && back.Vault == vault && back.Review == review && back.Canonical() == storeText, "slot manifest: the review key and vault are signed alongside the store key");
        byte[] reviewPrivate = KeyVault.UnwrapReview(review.Vault, mk, review.PublicKey);
        try
        {
            check(JweCipher.Instance.Derive(Encoding.UTF8.GetString(reviewPrivate)) == review.PublicKey && review.PublicKey != publicKey
                && Fails(() => KeyVault.UnwrapReview(review.Vault, mk, publicKey)) && Fails(() => KeyVault.UnwrapVault(review.Vault, mk, review.PublicKey))
                && Fails(() => KeyVault.UnwrapReview(vault, mk, publicKey)), "review key: the wrap is bound to its public key and its own context");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(reviewPrivate);
        }
        Manifest more = withStore.WithKey(phone.Record("localhost", "phone", mk));
        check(more.Vault == vault && more.Keys.Count == 2 && more.Keys.All(key => key.Slot is not null) && more.WithSettings(ToolSettings.Defaults).Vault == vault && more.WithoutKey(more.Keys[0].Id).Vault == vault && more.WithSecrets(publicKey, new Dictionary<string, string>()).Vault == vault,
            "slot manifest: key, settings and secret changes keep the vault and the slots");
        check(more.Review == review && more.WithSettings(ToolSettings.Defaults).Review == review
            && more.WithoutKey(more.Keys[0].Id).Review == review && more.WithSecrets(publicKey, new Dictionary<string, string>()).Review == review,
            "review key: ordinary manifest changes carry the review key");

        // A manifest is not valid when a key has no slot, a slot is not the right shape, or the vault does not go with the store key.
        (string Name, Manifest Value)[] invalid =
        [
            ("a key without a slot", Manifest.First(record with { Slot = null }, ToolSettings.Defaults)),
            ("a salt of 16 bytes", Manifest.First(record with { Slot = slot with { Salt = Base64Url.EncodeToString(new byte[16]) } }, ToolSettings.Defaults)),
            ("a salt that is not base64url", Manifest.First(record with { Slot = slot with { Salt = "%%%" } }, ToolSettings.Defaults)),
            ("a wrap of 59 bytes", Manifest.First(record with { Slot = slot with { Wrap = Base64Url.EncodeToString(new byte[59]) } }, ToolSettings.Defaults)),
            ("an empty wrap", Manifest.First(record with { Slot = slot with { Wrap = "" } }, ToolSettings.Defaults)),
            ("a store key without a vault", first.WithSecrets(publicKey, new Dictionary<string, string>())),
            ("a vault without a store key", first with { Vault = vault }),
            ("a vault that is not base64url", withStore with { Vault = "***" }),
            ("a vault that is too short", withStore with { Vault = Base64Url.EncodeToString(new byte[20]) }),
            ("a missing review key", withStore with { Review = null }),
            ("a review key without a store", first with { Review = review }),
            ("the store key reused for review", withStore with { Review = review with { PublicKey = publicKey } }),
            ("a malformed review vault", withStore with { Review = review with { Vault = "***" } }),
        ];
        foreach ((string name, Manifest value) in invalid)
        {
            check(value.Problem() is not null && Manifest.Parse(value.Canonical(), out string? why) is null && why is not null, "slot manifest: " + name + " is not valid (" + value.Problem() + ")");
        }

        // The slots and the vault are signed text: changing one character keeps the shape but not the signature.
        SignedManifest signed = TestState.Sign(laptop, text);
        check(signed.Verify(out error) is not null && error is null, "slot manifest: the signed manifest verifies (" + error + ")");
        SignedManifest slotEdit = signed with { Text = Alter(text, "\"wrap\":") };
        check(Manifest.Parse(slotEdit.Text, out _) is not null && slotEdit.Verify(out error) is null && error is not null && error.Contains("signature", StringComparison.Ordinal), "slot manifest: an edited wrap passes the shape check but fails the signature (" + error + ")");
        SignedManifest saltEdit = signed with { Text = Alter(text, "\"salt\":") };
        check(Manifest.Parse(saltEdit.Text, out _) is not null && saltEdit.Verify(out error) is null && error is not null, "slot manifest: an edited salt fails verification (" + error + ")");
        SignedManifest withVault = TestState.Sign(laptop, storeText);
        check(withVault.Verify(out error) is not null, "slot manifest: a signed manifest with a vault verifies (" + error + ")");
        SignedManifest vaultEdit = withVault with { Text = Alter(storeText, "\"vault\":") };
        check(Manifest.Parse(vaultEdit.Text, out _) is not null && vaultEdit.Verify(out error) is null && error is not null && error.Contains("signature", StringComparison.Ordinal), "slot manifest: an edited vault passes the shape check but fails the signature (" + error + ")");
        SignedManifest swapped = withVault with { Text = storeText.Replace(vault, KeyVault.WrapVault(Encoding.UTF8.GetBytes(privateKey), mk, publicKey), StringComparison.Ordinal) };
        check(swapped.Verify(out _) is null, "slot manifest: another valid vault for the same key (a replay swap) fails the signature too");
        SignedManifest reviewEdit = withVault with { Text = storeText.Replace(review.Vault, KeyVault.NewReviewKey(mk).Vault, StringComparison.Ordinal) };
        check(Manifest.Parse(reviewEdit.Text, out _) is not null && reviewEdit.Verify(out _) is null, "review key: replacing the review vault invalidates the signature");

        // The first manifest of a first setup has the store key and the vault and no secrets: editing the vault there fails too.
        Manifest firstWithStore = first with { Store = publicKey, Vault = vault, Review = review };
        string firstText = firstWithStore.Canonical();
        SignedManifest firstSigned = TestState.Sign(laptop, firstText);
        check(firstWithStore.Problem() is null && Manifest.Parse(firstText, out _) is { Version: 1 } && firstSigned.Verify(out error) is not null, "slot manifest: a first manifest with the store key and vault (no secrets) is valid and verifies (" + error + ")");
        SignedManifest firstVaultEdit = firstSigned with { Text = Alter(firstText, "\"vault\":") };
        check(Manifest.Parse(firstVaultEdit.Text, out _) is not null && firstVaultEdit.Verify(out error) is null && error is not null && error.Contains("signature", StringComparison.Ordinal), "slot manifest: an edited vault in the first manifest passes the shape check but fails the signature (" + error + ")");
        SignedManifest firstSwap = firstSigned with { Text = firstText.Replace(vault, KeyVault.WrapVault(Encoding.UTF8.GetBytes(privateKey), mk, publicKey), StringComparison.Ordinal) };
        check(firstSwap.Verify(out _) is null, "slot manifest: another valid vault in the first manifest fails the signature too");
    }

    /// <summary>True when the call fails with a CryptographicException (the only failure the vault code may show).</summary>
    private static bool Fails(Func<object?> call)
    {
        try
        {
            call();

            return false;
        }
        catch (CryptographicException)
        {
            return true;
        }
    }

    private static string Flip(string wrap, int index)
    {
        byte[] bytes = Base64Url.DecodeFromChars(wrap);
        bytes[index] ^= 0x01;

        return Base64Url.EncodeToString(bytes);
    }

    private static void Slots(Action<bool, string> check)
    {
        byte[] mk = KeyVault.NewMasterKey();
        byte[] salt = KeyVault.NewSalt();
        byte[] prf = RandomNumberGenerator.GetBytes(32);
        byte[] credential = RandomNumberGenerator.GetBytes(16);
        check(mk.Length == 32 && salt.Length == 32 && !mk.AsSpan().SequenceEqual(KeyVault.NewMasterKey()) && !salt.AsSpan().SequenceEqual(KeyVault.NewSalt()), "key vault: a master key and a salt are 32 random bytes");

        string wrap = KeyVault.WrapSlot(mk, prf, credential, salt);
        check(wrap.Length > 0 && Base64Url.DecodeFromChars(wrap).Length == KeyVault.SlotWrapBytes && KeyVault.SlotWrapBytes == 12 + 32 + 16, "key vault: a slot is nonce (12) + master key (32) + tag (16), base64url");
        check(KeyVault.UnwrapSlot(wrap, prf, credential, salt).AsSpan().SequenceEqual(mk), "key vault: slot round trip returns the master key");
        check(KeyVault.WrapSlot(mk, prf, credential, salt) != wrap, "key vault: the nonce is fresh, so two wraps of the same key differ");

        check(Fails(() => KeyVault.UnwrapSlot(wrap, RandomNumberGenerator.GetBytes(32), credential, salt)), "key vault: a slot does not open with another PRF output (wrong KEK)");
        byte[] nearly = (byte[])prf.Clone();
        nearly[31] ^= 0x01;
        check(Fails(() => KeyVault.UnwrapSlot(wrap, nearly, credential, salt)), "key vault: a slot does not open with a PRF output that differs in one bit");
        byte[] otherCredential = (byte[])credential.Clone();
        otherCredential[0] ^= 0x01;
        check(Fails(() => KeyVault.UnwrapSlot(wrap, prf, otherCredential, salt)), "key vault: a slot does not open for another credential id (the id is associated data)");
        byte[] otherSalt = (byte[])salt.Clone();
        otherSalt[5] ^= 0x01;
        check(Fails(() => KeyVault.UnwrapSlot(wrap, prf, credential, otherSalt)), "key vault: a slot does not open with another salt");
        foreach ((int index, string where) in new[] { (0, "nonce"), (12, "ciphertext"), (43, "ciphertext end"), (44, "tag"), (59, "tag end") })
        {
            check(Fails(() => KeyVault.UnwrapSlot(Flip(wrap, index), prf, credential, salt)), "key vault: a tampered slot (" + where + ") does not open");
        }

        byte[] raw = Base64Url.DecodeFromChars(wrap);
        check(Fails(() => KeyVault.UnwrapSlot(Base64Url.EncodeToString(raw[..^1]), prf, credential, salt)), "key vault: a truncated slot does not open");
        check(Fails(() => KeyVault.UnwrapSlot(Base64Url.EncodeToString([.. raw, 0]), prf, credential, salt)), "key vault: a slot with a byte added does not open");
        check(Fails(() => KeyVault.UnwrapSlot("", prf, credential, salt)) && Fails(() => KeyVault.UnwrapSlot("%%%not base64url", prf, credential, salt)), "key vault: an empty or malformed slot does not open (as a CryptographicException)");
        check(Fails(() => KeyVault.UnwrapSlot(wrap, prf[..31], credential, salt)) && Fails(() => KeyVault.WrapSlot(mk[..31], prf, credential, salt)) && Fails(() => KeyVault.WrapSlot(mk, [], credential, salt)),
            "key vault: a PRF output or master key of the wrong length is refused");
        check(Fails(() => KeyVault.WrapSlot(mk, prf, credential, salt[..16])), "key vault: a salt of the wrong length is refused");
    }

    private static void Vaults(Action<bool, string> check)
    {
        byte[] mk = KeyVault.NewMasterKey();
        (string publicKey, string privateKey) = JweCipher.Instance.NewKeyPair();
        byte[] key = Encoding.UTF8.GetBytes(privateKey);
        string vault = KeyVault.WrapVault(key, mk, publicKey);

        check(vault.Length > 0 && Base64Url.DecodeFromChars(vault).Length == 12 + key.Length + 16, "key vault: a vault is nonce + the private key text + tag");
        check(KeyVault.UnwrapVault(vault, mk, publicKey).AsSpan().SequenceEqual(key), "key vault: vault round trip returns the private key bytes");
        check(!vault.Contains(privateKey, StringComparison.Ordinal) && !Convert.ToHexStringLower(Base64Url.DecodeFromChars(vault)).Contains(privateKey, StringComparison.Ordinal), "key vault: the private key is not in the vault in the clear");
        check(Fails(() => KeyVault.UnwrapVault(vault, KeyVault.NewMasterKey(), publicKey)), "key vault: a vault does not open with another master key");
        check(Fails(() => KeyVault.UnwrapVault(vault, mk, JweCipher.Instance.NewKeyPair().PublicKey)), "key vault: a vault does not open for another store public key (it is associated data)");
        foreach (int index in new[] { 0, 12, 12 + 63, 12 + 64 })
        {
            check(Fails(() => KeyVault.UnwrapVault(Flip(vault, index), mk, publicKey)), $"key vault: a tampered vault (byte {index}) does not open");
        }

        check(Fails(() => KeyVault.UnwrapVault("", mk, publicKey)) && Fails(() => KeyVault.UnwrapVault("!", mk, publicKey)), "key vault: an empty or malformed vault does not open");
        check(Fails(() => KeyVault.UnwrapVault(vault, mk[..16], publicKey)), "key vault: a master key of the wrong length is refused");
    }

    private static void Authenticator(Action<bool, string> check)
    {
        // The test authenticator plays the PRF extension: PRF(salt) = HMAC-SHA256(secret, "WebAuthn PRF" || 0x00 || salt).
        using TestAuthenticator a = TestAuthenticator.ES256();
        using TestAuthenticator b = TestAuthenticator.ES256();
        byte[] salt = RandomNumberGenerator.GetBytes(32);
        byte[] first = a.Prf(salt)!;
        check(first.Length == 32 && first.AsSpan().SequenceEqual(a.Prf(salt)!) && !first.AsSpan().SequenceEqual(a.Prf(RandomNumberGenerator.GetBytes(32))!) && !first.AsSpan().SequenceEqual(b.Prf(salt)!), "test authenticator: PRF is 32 bytes, stable for a salt, different for another salt and another credential");
        check(first.AsSpan().SequenceEqual(HMACSHA256.HashData(a.PrfSecret, (byte[])[.. Encoding.ASCII.GetBytes("WebAuthn PRF"), 0, .. salt])), "test authenticator: PRF is HMAC-SHA256(secret, \"WebAuthn PRF\" || 0x00 || salt)");
        using TestAuthenticator none = TestAuthenticator.ES256(prf: false);
        check(none.Prf(salt) is null, "test authenticator: a no-PRF authenticator returns nothing");
    }

    private static void Transport(Action<bool, string> check)
    {
        // The PRF output crosses the page's localhost HTTP encrypted to a per-page server key (ECDH P-256, HKDF-SHA-256 with the
        // bind as salt and "with-secrets/v1 prf" as info, AES-256-GCM with the bind as associated data).
        byte[] bind = RandomNumberGenerator.GetBytes(32);
        byte[] prf = RandomNumberGenerator.GetBytes(32);
        (byte[] privateState, string publicKey) = SecretCrypto.NewServerKey();
        (string epk, string iv, string ct) = PrfBrowser.Seal(publicKey, bind, prf);
        check(SecretCrypto.DecryptBytes(privateState, bind, epk, iv, ct, SecretCrypto.PrfInfo).AsSpan().SequenceEqual(prf), "prf transport: the server opens what the page sealed");
        check(Fails(() => SecretCrypto.DecryptBytes(privateState, RandomNumberGenerator.GetBytes(32), epk, iv, ct, SecretCrypto.PrfInfo)), "prf transport: another bind (another page) does not open it");
        check(Fails(() => SecretCrypto.DecryptBytes(privateState, bind, epk, iv, ct, SecretCrypto.Info)), "prf transport: the --set key info does not open it (domain separation)");
        check(Fails(() => SecretCrypto.DecryptBytes(SecretCrypto.NewServerKey().PrivateState, bind, epk, iv, ct, SecretCrypto.PrfInfo)), "prf transport: another page's server key does not open it");
        (string epk2, string iv2, string ct2) = PrfBrowser.Seal(publicKey, bind, prf);
        check(ct2 != ct && epk2 != epk && iv2 != iv, "prf transport: every seal is fresh");
        check(!ct.Contains(Base64Url.EncodeToString(prf), StringComparison.Ordinal), "prf transport: the PRF output is not in the sealed text");
        CryptographicOperations.ZeroMemory(privateState);
    }
}

/// <summary>The page's side of the PRF transport, in .NET: what <c>sealPrf</c> in the page scripts does.</summary>
internal static class PrfBrowser
{
    public static (string Epk, string Iv, string Ct) Seal(string serverPublicKey, byte[] bind, byte[] plaintext)
    {
        byte[] point = Base64Url.DecodeFromChars(serverPublicKey);
        using ECDiffieHellman mine = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
        using ECDiffieHellman server = ECDiffieHellman.Create(new ECParameters
        {
            Curve = ECCurve.NamedCurves.nistP256,
            Q = new ECPoint { X = point[1..33], Y = point[33..] },
        });
        byte[] secret = mine.DeriveRawSecretAgreement(server.PublicKey);
        byte[] key = HKDF.DeriveKey(HashAlgorithmName.SHA256, secret, 32, bind, Encoding.UTF8.GetBytes(SecretCrypto.PrfInfo));
        byte[] iv = RandomNumberGenerator.GetBytes(12);
        byte[] sealedBytes = new byte[plaintext.Length];
        byte[] tag = new byte[16];
        using AesGcm aes = new(key, 16);
        aes.Encrypt(iv, plaintext, sealedBytes, tag, bind);
        ECParameters open = mine.ExportParameters(false);

        return (Base64Url.EncodeToString([0x04, .. open.Q.X!, .. open.Q.Y!]), Base64Url.EncodeToString(iv), Base64Url.EncodeToString([.. sealedBytes, .. tag]));
    }
}
