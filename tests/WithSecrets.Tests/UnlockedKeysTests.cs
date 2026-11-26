using Microsoft.Data.Sqlite;

namespace WithSecrets.Tests;

/// <summary>
/// The keys an admin unlock opens: the secret store key and the review key, together or not at all, only with the PRF output of an enrolled admin passkey, held in pinned arrays
/// that are zeroed when they are closed. The store key is used only for the manifest it was opened for.
/// </summary>
internal static class UnlockedKeysTests
{
    public static Task Run(Action<bool, string> check)
    {
        string root = Path.Combine(Path.GetTempPath(), "ws-unlocked-" + Guid.NewGuid().ToString("N")[..8]);
        Directory.CreateDirectory(root);
        try
        {
            Opens(check, root);
            Refuses(check, root);
            NoStore(check, root);
        }
        finally
        {
            SqliteConnection.ClearAllPools();
            try
            {
                Directory.Delete(root, true);
            }
            catch (IOException)
            {
                // A stray temp file is harmless.
            }
        }

        return Task.CompletedTask;
    }

    private static (StateDatabase Db, TestAuthenticator Admin, TestAuthenticator Convenience) State(string root, string name)
    {
        StateDatabase db = new(Path.Combine(root, name, WithSecretsDatabase.FileName));
        TestAuthenticator admin = TestAuthenticator.ES256();
        TestAuthenticator convenience = TestAuthenticator.ES256();
        TestState.Add(db, admin.Record("localhost", "laptop"), withStore: true);
        TestState.Add(db, convenience.Record("localhost", "phone"));

        return (db, admin, convenience);
    }

    private static bool Throws(Action action)
    {
        try
        {
            action();
        }
        catch (SecretStoreException)
        {
            return true;
        }

        return false;
    }

    private static void Opens(Action<bool, string> check, string root)
    {
        (StateDatabase db, TestAuthenticator admin, _) = State(root, "opens");
        Manifest manifest = TestState.Current(db)!;
        string ciphertext = JweCipher.Instance.Encrypt("unlocked-canary", manifest.Store);
        string reviewText = JweCipher.Instance.Encrypt("review-canary", manifest.Review!.PublicKey);
        using UnlockedKeys keys = new();
        check(!keys.IsOpen && keys.OpenedBy is null && Throws(() => keys.UseStoreKey(manifest, key => key)), "unlocked keys: a new object holds nothing and refuses the store key");

        using (Unlock unlock = TestVault.Unlock(db, admin)!)
        {
            check(keys.TryOpen(manifest, unlock) && keys.IsOpen && keys.OpenedBy?.Id == TestAuthenticator.Encode(admin.CredentialId), "unlocked keys: an admin passkey's PRF output opens them and they name that key");
        }

        check(keys.UseStoreKey(manifest, key => JweCipher.Instance.Decrypt(key, ciphertext)) == "unlocked-canary", "unlocked keys: the store key decrypts a stored value, after the PRF output was disposed");
        check(keys.TryDecryptReview(reviewText, manifest.Review.PublicKey) == "review-canary" && keys.TryDecryptReview(reviewText, "other") is null, "unlocked keys: the review key decrypts review text sealed to its own public key only");

        (string otherStore, _) = JweCipher.Instance.NewKeyPair();
        check(Throws(() => keys.UseStoreKey(manifest with { Store = otherStore }, key => key)), "unlocked keys: a manifest with another store key gets nothing");
        check(Throws(() => keys.UseStoreKey(manifest.WithoutKey(keys.OpenedBy!.Id), key => key)), "unlocked keys: a manifest in which the unlocking key is no longer an admin gets nothing");

        (byte[]? store, byte[]? review) = keys.HeldForTests;
        check(store is { Length: > 0 } && review is { Length: > 0 } && store.Any(item => item != 0) && review.Any(item => item != 0), "unlocked keys: both keys are held while open");
        keys.Close();
        check(!keys.IsOpen && keys.OpenedBy is null && Throws(() => keys.UseStoreKey(manifest, key => key)) && keys.TryDecryptReview(reviewText, manifest.Review.PublicKey) is null,
            "unlocked keys: after Close nothing is open and the store key is refused");
        check(store!.All(item => item == 0) && review!.All(item => item == 0) && keys.HeldForTests == (null, null), "unlocked keys: Close zeroes both held arrays and drops them");
    }

    private static void Refuses(Action<bool, string> check, string root)
    {
        (StateDatabase db, TestAuthenticator admin, TestAuthenticator convenience) = State(root, "refuses");
        Manifest manifest = TestState.Current(db)!;
        using UnlockedKeys keys = new();

        byte[] salt = TestVault.Salt(db);
        string phoneId = TestAuthenticator.Encode(convenience.CredentialId);
        KeySlot phoneSlot = convenience.Slot(TestVault.Master(db), salt)!;
        Manifest forged = manifest with { Keys = [.. manifest.Keys.Select(key => key.Id == phoneId ? key with { Slot = phoneSlot } : key)] };
        using (Unlock phone = new(phoneId, convenience.Prf(salt)!))
        {
            check(!keys.TryOpen(manifest, phone) && !keys.TryOpen(forged, phone) && !keys.IsOpen && keys.HeldForTests == (null, null),
                "unlocked keys: a passkey that is not an admin opens nothing, even with a key slot");
        }

        using TestAuthenticator stranger = TestAuthenticator.ES256();
        using (Unlock good = TestVault.Unlock(db, admin)!)
        using (Unlock unenrolled = new(TestAuthenticator.Encode(stranger.CredentialId), [.. good.Output]))
        {
            check(!keys.TryOpen(manifest, unenrolled) && !keys.IsOpen, "unlocked keys: an unenrolled credential id opens nothing");
        }

        using (Unlock good = TestVault.Unlock(db, admin)!)
        {
            byte[] flipped = [.. good.Output];
            flipped[0] ^= 1;
            using Unlock wrong = new(good.CredentialId, flipped);
            check(!keys.TryOpen(manifest, wrong) && !keys.IsOpen && keys.OpenedBy is null && keys.HeldForTests == (null, null), "unlocked keys: a PRF output with one flipped byte opens nothing and holds nothing");
            check(keys.TryOpen(manifest, good) && keys.IsOpen, "unlocked keys: the right output still opens them afterwards");
            check(!keys.TryOpen(manifest, wrong) && !keys.IsOpen && keys.HeldForTests == (null, null), "unlocked keys: a failed open closes what was open before");
        }

        using (Unlock good = TestVault.Unlock(db, admin)!)
        {
            keys.Dispose();
            check(!keys.TryOpen(manifest, good) && !keys.IsOpen, "unlocked keys: a disposed object opens nothing");
        }
    }

    private static void NoStore(Action<bool, string> check, string root)
    {
        StateDatabase db = new(Path.Combine(root, "nostore", WithSecretsDatabase.FileName));
        using TestAuthenticator admin = TestAuthenticator.ES256();
        using TestAuthenticator convenience = TestAuthenticator.ES256();
        TestState.Add(db, admin.Record("localhost", "laptop"));
        TestState.Add(db, convenience.Record("localhost", "phone"));
        Manifest manifest = TestState.Current(db)!;
        using UnlockedKeys keys = new();
        using (Unlock phone = new(TestAuthenticator.Encode(convenience.CredentialId), convenience.Prf(TestVault.Salt(db))!))
        {
            check(!keys.TryOpen(manifest, phone) && !keys.IsOpen, "unlocked keys without a store: a passkey that is not an admin still opens nothing");
        }

        using (Unlock unlock = TestVault.Unlock(db, admin)!)
        {
            check(keys.TryOpen(manifest, unlock) && keys.IsOpen && keys.HeldForTests == (null, null) && Throws(() => keys.UseStoreKey(manifest, key => key)),
                "unlocked keys without a store: an admin passkey opens them with nothing held, and there is no store key to use");
        }
    }
}
