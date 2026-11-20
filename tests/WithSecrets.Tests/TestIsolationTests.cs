using System.Security.Cryptography;

namespace WithSecrets.Tests;

/// <summary>
/// The test-only isolation (WITH_SECRETS_TEST_STORE and WITH_SECRETS_TEST_KEY_PREFIX): both together or neither, a short safe prefix, never the default store, and on Windows the CNG key names
/// carry the prefix so a test run never touches the production-named keys.
/// </summary>
internal static class TestIsolationTests
{
    public static Task Run(Action<bool, string> check)
    {
        string parent = Path.Combine(Path.GetTempPath(), "ws-isolation-" + Guid.NewGuid().ToString("N")[..8]);
        string defaultStore = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".with-secrets");
        try
        {
            Dictionary<string, string?> env = [];
            string? Problem(string? store, string? prefix)
            {
                env[TestIsolation.StoreVariable] = store;
                env[TestIsolation.KeyPrefixVariable] = prefix;

                return TestIsolation.Parse(name => env.GetValueOrDefault(name), out _);
            }

            check(Problem(null, null) is null && TestIsolation.Parse(_ => null, out TestIsolation.Settings? none) is null && none is null, "isolation: neither variable set means no isolation and no problem");
            check(Problem(parent, "wstest") is null && TestIsolation.Parse(name => env.GetValueOrDefault(name), out TestIsolation.Settings? ok) is null && ok is { KeyPrefix: "wstest" } && ok.StoreFolder == Path.GetFullPath(parent), "isolation: a store folder with a prefix is accepted");
            check(Problem(parent, null) is not null, "isolation: a store folder without a prefix is refused (it would use the production key names)");
            check(Problem(null, "wstest") is not null, "isolation: a prefix without a store folder is refused");
            check(Problem(defaultStore, "wstest") is not null, "isolation: the default store folder is refused");
            check(Problem(defaultStore + Path.DirectorySeparatorChar, "wstest") is not null, "isolation: the default store folder with a trailing separator is refused");
            check(Problem(Path.Combine(defaultStore, "..", ".with-secrets"), "wstest") is not null, "isolation: a path that resolves to the default store is refused");
            check(Problem(defaultStore.ToUpperInvariant(), "wstest") is not null || !OperatingSystem.IsWindows(), "isolation: the default store folder in another case is refused (Windows)");
            check(Problem(Path.Combine(defaultStore, "nested"), "wstest") is not null, "isolation: a folder inside the default store is refused");
            check(Problem("relative-folder", "wstest") is not null, "isolation: a relative store folder is refused");
            foreach (string bad in new[] { "", "ab", "UPPER", "has space", "a/b", "..\\x", "with-secrets", "toolongprefix123", "wstest\"", "wstest%" })
            {
                check(Problem(parent, bad) is not null || (bad.Length == 0), $"isolation: the prefix \"{bad}\" is refused");
            }

            check(Problem(parent, "wstest") is null && Problem(parent, "ab12cd") is null, "isolation: short lower-case letters and digits are accepted");

            // Names: the prefix goes in front, the production name is what it was.
            TestIsolation.Settings? before = TestIsolation.Current;
            try
            {
                TestIsolation.Set(null);
                check(TestIsolation.KeyName(KeyNames.Machine) == KeyNames.Machine, "isolation: without a prefix the key name is the production name");
                TestIsolation.Set(new TestIsolation.Settings(parent, "wstest"));
                check(TestIsolation.KeyName(KeyNames.Machine) == "wstest " + KeyNames.Machine && TestIsolation.KeyName(LocalDeployment.AuthorityKeyNameOf(2)) == "wstest " + KeyNames.Authority + " g2", "isolation: with a prefix the machine and authority key names carry it");
                check(AppLog.DefaultFolder == Path.Combine(parent, "logs"), "isolation: the log folder moves into the test store");

                if (OperatingSystem.IsWindows())
                {
                    Cng(check, parent, defaultStore);
                }
            }
            finally
            {
                TestIsolation.Set(before);
            }
        }
        finally
        {
            try
            {
                Directory.Delete(parent, true);
            }
            catch (IOException)
            {
                // Harmless.
            }
            catch (UnauthorizedAccessException)
            {
                // Harmless.
            }
        }

        return Task.CompletedTask;
    }

    [System.Runtime.Versioning.SupportedOSPlatform("windows")]
    private static void Cng(Action<bool, string> check, string parent, string defaultStore)
    {
        string prefix = "wstest" + Guid.NewGuid().ToString("N")[..4];
        string folder = Path.Combine(parent, "cng");
        bool productionBefore = ProductionNamesExist();
        TestIsolation.Set(new TestIsolation.Settings(folder, prefix));
        try
        {
            using (ISigningKey key = MachineKeyStore.OpenOrCreate(folder, KeyNames.Machine, out bool created))
            {
                check(created && key is CngSigningKey { Exportable: false }, "isolation: the machine key is a real non-exportable CNG key");
            }

            using (CngSigningKey? named = CngSigningKey.TryOpen(prefix + " " + KeyNames.Machine))
            {
                check(named is not null, "isolation: the CNG key exists under the prefixed name");
            }

            using (ISigningKey authority = MachineKeyStore.OpenOrCreate(folder, LocalDeployment.AuthorityKeyNameOf(1), out _))
            {
                check(authority is CngSigningKey, "isolation: the authority key is made under the prefix too");
            }

            check(ProductionNamesExist() == productionBefore, "isolation: the production-named keys were neither created nor removed");
            check(Refusal(() => MachineKeyStore.OpenOrCreate(defaultStore, KeyNames.Machine, out _)), "isolation: a prefix with the default store folder is refused by the key store (no key is made)");
            check(ProductionNamesExist() == productionBefore, "isolation: the refusal made no production-named key");
        }
        finally
        {
            foreach (string name in new[] { KeyNames.Machine, LocalDeployment.AuthorityKeyNameOf(1) })
            {
                using CngSigningKey? leftover = CngSigningKey.TryOpen(prefix + " " + name);
                leftover?.Delete();
            }
        }

        using CngSigningKey? gone = CngSigningKey.TryOpen(prefix + " " + KeyNames.Machine);
        check(gone is null, "isolation: the test keys are deleted");
    }

    [System.Runtime.Versioning.SupportedOSPlatform("windows")]
    private static bool ProductionNamesExist()
    {
        using CngSigningKey? machine = CngSigningKey.TryOpen(KeyNames.Machine);
        using CngSigningKey? authority = CngSigningKey.TryOpen(KeyNames.Authority);

        return machine is not null || authority is not null;
    }

    private static bool Refusal(Action action)
    {
        try
        {
            action();

            return false;
        }
        catch (CryptographicException)
        {
            return true;
        }
    }
}
