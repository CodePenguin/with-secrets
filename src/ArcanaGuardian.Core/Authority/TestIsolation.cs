using System.Security.Cryptography;
using System.Text.RegularExpressions;

namespace ArcanaGuardian;

/// <summary>
/// TEST ONLY. Lets an end-to-end test run a real authority (Windows CNG keys) without touching the user's own keys or store. Two environment variables, which must be set together:
/// <c>ARCANA_GUARDIAN_TEST_STORE</c> (an absolute folder used instead of <c>~/.ArcanaGuardian</c>) and <c>ARCANA_GUARDIAN_TEST_KEY_PREFIX</c> (3 to 12 lower-case letters or digits, put in front of every CNG key name: the machine
/// identity key, the authority signing keys and the temporary TLS key). The keys stay real, non-exportable CNG keys. Refused (the program does not start) when only one variable is set, the prefix is not that charset,
/// or the store folder is, or is inside, the default <c>~/.ArcanaGuardian</c>; the key store refuses a prefix with the default folder again on its own. Never used in production and never logs key material.
/// </summary>
public static partial class TestIsolation
{
    public const string StoreVariable = "ARCANA_GUARDIAN_TEST_STORE";
    public const string KeyPrefixVariable = "ARCANA_GUARDIAN_TEST_KEY_PREFIX";

    /// <summary>The isolation in force: the absolute store folder and the key-name prefix.</summary>
    public sealed record Settings(string StoreFolder, string KeyPrefix);

    private static readonly Lock Gate = new();
    private static bool _loaded;
    private static Settings? _current;
    private static string? _problem;

    /// <summary>The settings from the environment, or null when there is no isolation (or a problem: see <see cref="Problem" />).</summary>
    public static Settings? Current
    {
        get
        {
            Load();

            return _current;
        }
    }

    /// <summary>Why the environment's isolation settings are refused, or null.</summary>
    public static string? Problem
    {
        get
        {
            Load();

            return _problem;
        }
    }

    internal static string DefaultStore => Path.GetFullPath(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".ArcanaGuardian"));

    /// <summary>The store folder: the test store when isolated, else the default.</summary>
    public static string StoreFolder => Current?.StoreFolder ?? DefaultStore;

    /// <summary>For tests: replaces what the environment said (null: no isolation).</summary>
    internal static void Set(Settings? settings)
    {
        lock (Gate)
        {
            _loaded = true;
            _current = settings;
            _problem = null;
        }
    }

    /// <summary>The CNG name of a key under the active prefix (the name itself without isolation).</summary>
    public static string KeyName(string name) => Current is { } settings ? settings.KeyPrefix + " " + name : name;

    /// <summary>The CNG name for a key of the store <paramref name="folder" />: with a prefix active, the default store is refused.</summary>
    internal static string KeyNameFor(string folder, string name)
    {
        if (Current is not null && IsDefaultStoreOrInside(folder))
        {
            throw new CryptographicException("the test key prefix is set but the store folder is the default one; no key was used");
        }

        return KeyName(name);
    }

    /// <summary>Reads the two variables. Returns the problem (null when fine); <paramref name="settings" /> is null without isolation.</summary>
    public static string? Parse(Func<string, string?> environment, out Settings? settings)
    {
        settings = null;
        string? store = Empty(environment(StoreVariable));
        string? prefix = Empty(environment(KeyPrefixVariable));
        if (store is null && prefix is null)
        {
            return null;
        }

        if (store is null || prefix is null)
        {
            return $"{StoreVariable} and {KeyPrefixVariable} must be set together (a test store with production key names, or test key names in the real store, is refused)";
        }

        if (!PrefixPattern().IsMatch(prefix))
        {
            return $"{KeyPrefixVariable} must be 3 to 12 lower-case letters or digits";
        }

        if (!Path.IsPathFullyQualified(store))
        {
            return $"{StoreVariable} must be an absolute folder";
        }

        string full = Path.GetFullPath(store);
        if (IsDefaultStoreOrInside(full))
        {
            return $"{StoreVariable} is the default store folder (or inside it); a test never uses the real store";
        }

        settings = new Settings(full, prefix);

        return null;
    }

    private static string? Empty(string? value) => string.IsNullOrEmpty(value) ? null : value;

    private static bool IsDefaultStoreOrInside(string folder)
    {
        string full = Path.TrimEndingDirectorySeparator(Path.GetFullPath(folder));
        string home = Path.TrimEndingDirectorySeparator(DefaultStore);
        StringComparison comparison = OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal;

        return full.Equals(home, comparison) || full.StartsWith(home + Path.DirectorySeparatorChar, comparison);
    }

    private static void Load()
    {
        lock (Gate)
        {
            if (_loaded)
            {
                return;
            }

            _loaded = true;
            _problem = Parse(Environment.GetEnvironmentVariable, out _current);
        }
    }

    [GeneratedRegex("^[a-z0-9]{3,12}$")]
    private static partial Regex PrefixPattern();
}
