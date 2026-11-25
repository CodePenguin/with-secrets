using System.Text;

using Microsoft.Data.Sqlite;

namespace WithSecrets.Tests;

/// <summary>The provider cache: rows encrypted to the store public key and sealed by the active authority key (10.3.3, ruling 7). A row that does not verify is never served.</summary>
internal static class ProviderCacheTests
{
    private const string Value = "Provider-Cache-Value-1";

    internal sealed class Rig : IDisposable
    {
        private readonly string _folder = Path.Combine(Path.GetTempPath(), "ws-providercache-" + Guid.NewGuid().ToString("N"));
        private readonly Dictionary<int, SoftwareSigningKey> _signing = [];

        public Rig()
        {
            Authority = AuthorityStore.InFolder(_folder);
            Store = new ProviderStore(Authority);
            Lock = AuthorityLock.UnlockedForTests();
            Keys = new AuthorityKeyRing(Authority, generation =>
            {
                lock (_signing)
                {
                    return _signing.TryGetValue(generation, out SoftwareSigningKey? known) ? known : _signing[generation] = new SoftwareSigningKey();
                }
            })
            { LockState = Lock };
            Cache = new ProviderCache(Store, Keys);
            (PublicKey, PrivateKey) = JweCipher.Instance.NewKeyPair();
        }

        public AuthorityStore Authority { get; }

        public ProviderStore Store { get; }

        public AuthorityLock Lock { get; }

        public AuthorityKeyRing Keys { get; }

        public ProviderCache Cache { get; }

        public string PublicKey { get; }

        public string PrivateKey { get; }

        public void Exec(string sql, params (string Name, object Value)[] parameters)
        {
            using SqliteConnection connection = new("Data Source=" + Authority.FilePath + ";Pooling=False");
            connection.Open();
            using SqliteCommand command = connection.CreateCommand();
            command.CommandText = sql;
            foreach ((string name, object value) in parameters)
            {
                command.Parameters.AddWithValue(name, value);
            }

            command.ExecuteNonQuery();
        }

        public object? Scalar(string sql)
        {
            if (!File.Exists(Authority.FilePath))
            {
                return null;
            }

            using SqliteConnection connection = new("Data Source=" + Authority.FilePath + ";Pooling=False");
            connection.Open();
            using SqliteCommand command = connection.CreateCommand();
            command.CommandText = sql;

            return command.ExecuteScalar();
        }

        public long Rows() => Scalar("SELECT COUNT(*) FROM provider_cache") is long count ? count : 0;

        public void Dispose()
        {
            SqliteConnection.ClearAllPools();
            foreach (SoftwareSigningKey key in _signing.Values)
            {
                key.Dispose();
            }

            try
            {
                Directory.Delete(_folder, true);
            }
            catch (IOException)
            {
            }
        }
    }

    private static readonly DateTimeOffset T0 = new(2026, 11, 22, 8, 0, 0, TimeSpan.Zero);

    public static Task Run(Action<bool, string> check)
    {
        RoundTrip(check);
        Tampering(check);
        Locked(check);
        Replacing(check);
        Generations(check);
        UpgradeAndDisable(check);
        PlantedKey(check);

        return Task.CompletedTask;
    }

    private static void UpgradeAndDisable(Action<bool, string> check)
    {
        using Rig rig = new();
        TimeSpan hour = TimeSpan.FromHours(1);
        Guid id = rig.Store.AddInstance("legacy", "fake", "{}", hour).Id;
        rig.Cache.PutAll(id, [("old", Bytes(Value))], T0, rig.PublicKey);
        rig.Exec("PRAGMA user_version = 0");

        ProviderStore reopened = new(new AuthorityStore(new WithSecretsDatabase(rig.Authority.FilePath)));
        check(reopened.Instance(id)?.MaxStale == TimeSpan.Zero && rig.Rows() == 0, "cache: upgrade disables previous defaults and purges existing rows");

        reopened.SetMaxStale(id, hour);
        ProviderStore restarted = new(new AuthorityStore(new WithSecretsDatabase(rig.Authority.FilePath)));
        check(restarted.Instance(id)?.MaxStale == hour, "cache: a post-upgrade opt-in survives restart");

        ProviderCache cache = new(restarted, rig.Keys);
        long generation = restarted.Generation(id);
        cache.PutAll(id, [("opted-in", Bytes(Value))], T0, rig.PublicKey, generation);
        restarted.SetMaxStale(id, TimeSpan.Zero);
        check(rig.Rows() == 0
            && cache.PutAll(id, [("in-flight", Bytes(Value))], T0, rig.PublicKey, generation) == CacheWrite.Invalidated
            && cache.PutAll(id, [("disabled", Bytes(Value))], T0, rig.PublicKey) == CacheWrite.Invalidated
            && rig.Rows() == 0, "cache: disabling purges rows and blocks both in-flight and later writes");
    }

    /// <summary>Final review I2: a seal verifies against the key store's active key, never against the public key a plain with-secrets.db write names.</summary>
    private static void PlantedKey(Action<bool, string> check)
    {
        using Rig rig = new();
        Guid instance = rig.Store.AddInstance("cache-test", "fake", "{}", TimeSpan.FromHours(1)).Id;
        rig.Cache.PutAll(instance, [("ext-1", Bytes(Value))], T0, rig.PublicKey);
        check(rig.Cache.TryGet(instance, "ext-1", rig.PublicKey) is not null, "cache: planted key: the genuine row verifies first");

        using SoftwareSigningKey attacker = new();
        string fingerprint = KeyIdentity.Fingerprint(attacker.PublicKey);
        rig.Exec("UPDATE authority_keys SET public_key = $k, fingerprint = $f WHERE status = 'Active'", ("$k", Convert.ToBase64String(attacker.PublicKey)), ("$f", fingerprint));
        string planted = JweCipher.Instance.Encrypt("Attacker-Chosen-Value", rig.PublicKey);
        byte[] signature = attacker.Sign(ProviderCache.Seal(instance, "ext-1", T0, SecretStore.Hash(planted), rig.PublicKey, fingerprint));
        rig.Exec("UPDATE provider_cache SET ciphertext = $c, authority_key = $f, signature = $s", ("$c", planted), ("$f", fingerprint), ("$s", signature));

        CachedSecret? served = null;
        bool threw = false;
        try
        {
            served = rig.Cache.TryGet(instance, "ext-1", rig.PublicKey);
        }
        catch (Exception)
        {
            threw = true;
        }

        check(!threw && served is null, "cache: a row sealed by a key planted in authority_keys is never served (the key store's key decides)");
    }

    private static string Text(byte[] bytes) => Encoding.UTF8.GetString(bytes);

    private static byte[] Bytes(string text) => Encoding.UTF8.GetBytes(text);

    private static void RoundTrip(Action<bool, string> check)
    {
        using Rig rig = new();
        Guid instance = rig.Store.AddInstance("cache-test", "fake", "{}", TimeSpan.FromHours(1)).Id;
        rig.Cache.PutAll(instance, [("ext-1", Bytes(Value))], T0, rig.PublicKey);
        CachedSecret? row = rig.Cache.TryGet(instance, "ext-1", rig.PublicKey);
        check(row is not null && Text(rig.Cache.Decrypt(row, rig.PrivateKey)) == Value && row.LastVerified == T0 && row.InstanceId == instance && row.ExternalId == "ext-1"
            && row.StorePublicKey == rig.PublicKey, "cache: put then get round trips (decrypts to the value, lastVerified kept)");

        string ciphertext = rig.Scalar("SELECT ciphertext FROM provider_cache") as string ?? "";
        check(ciphertext.StartsWith(JweCipher.Prefix, StringComparison.Ordinal) && !ciphertext.Contains(Value, StringComparison.Ordinal)
            && !ciphertext.Contains(Convert.ToBase64String(Bytes(Value)), StringComparison.Ordinal), "cache: ciphertext at rest does not contain the plaintext");
        check(rig.Cache.TryGet(instance, "ext-other", rig.PublicKey) is null && rig.Cache.TryGet(Guid.NewGuid(), "ext-1", rig.PublicKey) is null, "cache: a missing row is null");

        long before = (long)rig.Scalar("SELECT last_verified FROM provider_cache")!;
        for (int i = 0; i < 3; i++)
        {
            CachedSecret? again = rig.Cache.TryGet(instance, "ext-1", rig.PublicKey);
            byte[] opened = rig.Cache.Decrypt(again!, rig.PrivateKey);
            SecretValues.Clear(opened);
        }

        check((long)rig.Scalar("SELECT last_verified FROM provider_cache")! == before && before == T0.UtcTicks, "cache: TryGet and Decrypt never change last_verified");

        bool threw = false;
        try
        {
            (_, string otherPrivate) = JweCipher.Instance.NewKeyPair();
            rig.Cache.Decrypt(row!, otherPrivate);
        }
        catch (SecretStoreException failure)
        {
            threw = !failure.Message.Contains(Value, StringComparison.Ordinal);
        }

        check(threw, "cache: decrypt with the wrong store key throws without the value");
    }

    private static void Tampering(Action<bool, string> check)
    {
        using Rig rig = new();
        Guid instance = rig.Store.AddInstance("cache-test", "fake", "{}", TimeSpan.FromHours(1)).Id;
        rig.Cache.PutAll(instance, [("ext-1", Bytes(Value))], T0, rig.PublicKey);

        // A valid ciphertext of another value for the same store key (anyone with the public key can make one).
        string original = (string)rig.Scalar("SELECT ciphertext FROM provider_cache")!;
        rig.Exec("UPDATE provider_cache SET ciphertext = $c", ("$c", JweCipher.Instance.Encrypt("Attacker-Value-1", rig.PublicKey)));
        check(rig.Cache.TryGet(instance, "ext-1", rig.PublicKey) is null, "cache: tampered ciphertext (valid encryption of another value) -> null");
        rig.Exec("UPDATE provider_cache SET ciphertext = $c", ("$c", "garbage"));
        check(rig.Cache.TryGet(instance, "ext-1", rig.PublicKey) is null, "cache: garbled ciphertext -> null");
        rig.Exec("UPDATE provider_cache SET ciphertext = $c", ("$c", original));
        check(rig.Cache.TryGet(instance, "ext-1", rig.PublicKey) is not null, "cache: the restored row verifies again");

        rig.Exec("UPDATE provider_cache SET last_verified = last_verified + 1");
        check(rig.Cache.TryGet(instance, "ext-1", rig.PublicKey) is null, "cache: tampered last_verified -> null");
        rig.Exec("UPDATE provider_cache SET last_verified = 9223372036854775807");
        check(rig.Cache.TryGet(instance, "ext-1", rig.PublicKey) is null, "cache: an out-of-range last_verified -> null, no throw");
        rig.Exec("UPDATE provider_cache SET last_verified = $t", ("$t", T0.UtcTicks));
        check(rig.Cache.TryGet(instance, "ext-1", rig.PublicKey) is not null, "cache: the restored last_verified verifies again");

        rig.Exec("UPDATE provider_cache SET external_id = 'ext-2'");
        check(rig.Cache.TryGet(instance, "ext-2", rig.PublicKey) is null, "cache: a row moved to another external id -> null");
        rig.Exec("UPDATE provider_cache SET external_id = 'ext-1'");
        Guid other = Guid.NewGuid();
        rig.Exec("UPDATE provider_cache SET instance_id = $i", ("$i", other.ToString("D")));
        check(rig.Cache.TryGet(other, "ext-1", rig.PublicKey) is null, "cache: a row moved to another instance -> null");
        rig.Exec("UPDATE provider_cache SET instance_id = $i", ("$i", instance.ToString("D")));

        (string otherPublic, _) = JweCipher.Instance.NewKeyPair();
        check(rig.Cache.TryGet(instance, "ext-1", otherPublic) is null, "cache: row for another store public key -> null");
        rig.Exec("UPDATE provider_cache SET store_public_key = $k", ("$k", otherPublic));
        check(rig.Cache.TryGet(instance, "ext-1", otherPublic) is null && rig.Cache.TryGet(instance, "ext-1", rig.PublicKey) is null, "cache: a rewritten store_public_key -> null");
        rig.Exec("UPDATE provider_cache SET store_public_key = $k", ("$k", rig.PublicKey));
        check(rig.Cache.TryGet(instance, "ext-1", "") is null, "cache: no current store key -> null");

        // A signature by a key that is not the authority's, under the authority's fingerprint.
        byte[] good = (byte[])rig.Scalar("SELECT signature FROM provider_cache")!;
        string fingerprint = (string)rig.Scalar("SELECT authority_key FROM provider_cache")!;
        using (SoftwareSigningKey stranger = new())
        {
            byte[] forged = stranger.Sign(ProviderCache.Seal(instance, "ext-1", T0, SecretStore.Hash(original), rig.PublicKey, fingerprint));
            rig.Exec("UPDATE provider_cache SET signature = $s", ("$s", forged));
            check(rig.Cache.TryGet(instance, "ext-1", rig.PublicKey) is null, "cache: row sealed by another key -> null");

            rig.Exec("UPDATE provider_cache SET signature = $s, authority_key = $f", ("$s", forged), ("$f", KeyIdentity.Fingerprint(stranger.PublicKey)));
            check(rig.Cache.TryGet(instance, "ext-1", rig.PublicKey) is null, "cache: row naming a foreign key fingerprint -> null");
        }

        rig.Exec("UPDATE provider_cache SET signature = $s, authority_key = $f", ("$s", good[..10]), ("$f", fingerprint));
        check(rig.Cache.TryGet(instance, "ext-1", rig.PublicKey) is null, "cache: a truncated signature -> null");
        rig.Exec("UPDATE provider_cache SET signature = $s", ("$s", good));
        check(rig.Cache.TryGet(instance, "ext-1", rig.PublicKey) is not null, "cache: the restored signature verifies again");

        // Ruling 7: rotation of the authority key turns every sealed row into a miss.
        rig.Keys.Rotate("test");
        check(rig.Cache.TryGet(instance, "ext-1", rig.PublicKey) is null, "cache: a row sealed by a retired (rotated-out) authority key -> null");
        rig.Cache.PutAll(instance, [("ext-1", Bytes(Value))], T0, rig.PublicKey);
        check(rig.Cache.TryGet(instance, "ext-1", rig.PublicKey) is not null, "cache: a row sealed after rotation verifies with the new active key");

        rig.Exec("DELETE FROM provider_cache");
        check(rig.Cache.TryGet(instance, "ext-1", rig.PublicKey) is null, "cache: a deleted row -> null");
    }

    private static void Locked(Action<bool, string> check)
    {
        using Rig rig = new();
        Guid instance = rig.Store.AddInstance("cache-test", "fake", "{}", TimeSpan.FromHours(1)).Id;
        rig.Cache.PutAll(instance, [("ext-1", Bytes(Value))], T0, rig.PublicKey);
        rig.Lock.Lock("test");

        bool threw = false;
        try
        {
            rig.Cache.PutAll(instance, [("ext-2", Bytes(Value))], T0, rig.PublicKey);
        }
        catch (AuthorityLockedException)
        {
            threw = true;
        }

        check(threw && rig.Rows() == 1, "cache: locked authority: Put throws AuthorityLockedException and writes nothing");

        threw = false;
        try
        {
            rig.Cache.PutAll(instance, [("ext-1", Bytes("Replaced-Value-2"))], T0.AddHours(1), rig.PublicKey);
        }
        catch (AuthorityLockedException)
        {
            threw = true;
        }

        check(threw && (long)rig.Scalar("SELECT last_verified FROM provider_cache")! == T0.UtcTicks, "cache: locked authority: Put does not replace an existing row");
        check(rig.Cache.TryGet(instance, "ext-1", rig.PublicKey) is null, "cache: locked authority: TryGet serves no row");

        rig.Lock.Unlock(UnlockMethod.Seam);
        check(rig.Cache.TryGet(instance, "ext-1", rig.PublicKey) is not null, "cache: unlocked again: the row verifies");
    }

    private static void Replacing(Action<bool, string> check)
    {
        using Rig rig = new();
        Guid instance = rig.Store.AddInstance("cache-test", "fake", "{}", TimeSpan.FromHours(1)).Id;
        rig.Cache.PutAll(instance, [("ext-1", Bytes(Value))], T0, rig.PublicKey);
        rig.Cache.PutAll(instance, [("ext-1", Bytes("Rotated-Value-2"))], T0.AddMinutes(5), rig.PublicKey);
        CachedSecret? row = rig.Cache.TryGet(instance, "ext-1", rig.PublicKey);
        check(rig.Rows() == 1 && row is not null && Text(rig.Cache.Decrypt(row, rig.PrivateKey)) == "Rotated-Value-2" && row.LastVerified == T0.AddMinutes(5),
            "cache: Put replaces, lastVerified updated");

        rig.Cache.PutAll(instance, [("ext-2", Bytes(Value))], T0, rig.PublicKey);
        Guid other = rig.Store.AddInstance("other-cache-test", "fake", "{}", TimeSpan.FromHours(1)).Id;
        rig.Cache.PutAll(other, [("ext-1", Bytes(Value))], T0, rig.PublicKey);
        check(rig.Rows() == 3, "cache: rows are keyed by (instance, external id)");

        // An older retrieval that commits after a newer one never replaces the newer row.
        check(rig.Cache.PutAll(instance, [("ext-1", Bytes("Older-Value-0"))], T0, rig.PublicKey) == CacheWrite.Superseded, "cache: Put with an older lastVerified reports Superseded");
        row = rig.Cache.TryGet(instance, "ext-1", rig.PublicKey);
        check(row is not null && Text(rig.Cache.Decrypt(row, rig.PrivateKey)) == "Rotated-Value-2" && row.LastVerified == T0.AddMinutes(5),
            "cache: an older Put keeps the newer row's value and lastVerified");
        check(rig.Cache.PutAll(instance, [("ext-1", Bytes("Older-Value-0")), ("ext-4", Bytes(Value))], T0, rig.PublicKey) == CacheWrite.Superseded && rig.Rows() == 4
            && rig.Cache.TryGet(instance, "ext-4", rig.PublicKey) is not null, "cache: PutAll writes the rows that are not older and reports Superseded");
        check(rig.Cache.PutAll(instance, [("ext-1", Bytes("Same-Time-Value"))], T0.AddMinutes(5), rig.PublicKey) == CacheWrite.Written, "cache: an equal lastVerified replaces");

        bool threw = false;
        string message = "";
        try
        {
            rig.Cache.PutAll(instance, [("ext-3", [.. Bytes("Secret-Prefix"), 0xC3, 0x28])], T0, rig.PublicKey);
        }
        catch (ArgumentException failure)
        {
            threw = true;
            message = failure.Message;
        }

        check(threw && rig.Rows() == 4, "cache: Put refuses bytes that are not strict UTF-8 and writes nothing");
        check(!message.Contains("Secret", StringComparison.Ordinal) && !message.Contains("C3", StringComparison.OrdinalIgnoreCase) && !message.Contains("28", StringComparison.Ordinal),
            "cache: the UTF-8 refusal carries none of the bytes (" + message + ")");
    }

    private static void Generations(Action<bool, string> check)
    {
        using Rig rig = new();
        Guid instance = rig.Store.AddInstance("cache-test", "fake", "{}", TimeSpan.FromHours(1)).Id;
        long generation = rig.Store.Generation(instance);
        check(rig.Cache.PutAll(instance, [("ext-1", Bytes(Value))], T0, rig.PublicKey, generation) == CacheWrite.Written && rig.Rows() == 1, "cache: Put with the current generation writes");

        // A real writer moves it (an invalidation of an id no row has deletes nothing).
        rig.Store.ApplyInvalidation(instance, new InvalidateProviderDataEvent(ExternalSecretIds: ["unrelated"]));
        check(rig.Cache.PutAll(instance, [("ext-2", Bytes(Value))], T0, rig.PublicKey, generation) == CacheWrite.Invalidated && rig.Rows() == 1, "cache: Put with a moved generation writes nothing");
        check(rig.Cache.PutAll(instance, [("ext-1", Bytes("Rotated-Value-2"))], T0.AddHours(1), rig.PublicKey, generation) == CacheWrite.Invalidated
            && (long)rig.Scalar("SELECT last_verified FROM provider_cache")! == T0.UtcTicks, "cache: Put with a moved generation does not replace a row");
    }
}
