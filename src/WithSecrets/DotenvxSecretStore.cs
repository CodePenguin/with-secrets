using System.Text.RegularExpressions;

namespace WithSecrets;

/// <summary>
/// The secret store: one dotenvx file with a separately encrypted value per secret. Dotenvx does the encryption and the key
/// lookup. With native custody the private key sits in Windows Credential Manager and no .env.keys file is written.
/// </summary>
public sealed partial class DotenvxSecretStore : ISecretStore
{
    private static readonly object Gate = new();

    private readonly string _directory;
    private readonly string _fileName;

    public DotenvxSecretStore(string storeFile)
    {
        string full = Path.GetFullPath(storeFile);
        _directory = Path.GetDirectoryName(full)!;
        _fileName = Path.GetFileName(full);
    }

    [GeneratedRegex(@"^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$")]
    private static partial Regex EntryLine();

    private string FilePath => Path.Combine(_directory, _fileName);

    public IReadOnlyList<string> ListNames()
    {
        if (!File.Exists(FilePath))
        {
            return [];
        }

        List<string> names = [];
        foreach (string line in File.ReadAllLines(FilePath))
        {
            Match match = EntryLine().Match(line);
            if (match.Success && match.Groups[2].Value.Trim().Trim('"', '\'').StartsWith("encrypted:", StringComparison.Ordinal))
            {
                names.Add(match.Groups[1].Value);
            }
        }

        return names;
    }

    public IReadOnlyDictionary<string, string> GetValues(IReadOnlyCollection<string> names)
    {
        return InStoreDirectory(() =>
        {
            // Strict makes a wrong or missing key an exception instead of a log line. Only native custody and a keys
            // file next to the store can supply the key: the password managers and Armor are switched off.
            object? result = global::Dotenvx.Dotenvx.Get(null, new global::Dotenvx.GetOptions
            {
                Path = [_fileName],
                Strict = true,
                Quiet = true,
                NoArmor = true,
                No1Password = true,
                NoBitwarden = true,
                ProcessEnv = new Dictionary<string, string>()
            });

            if (result is not IReadOnlyDictionary<string, string> all)
            {
                throw new InvalidOperationException("dotenvx returned no values.");
            }

            Dictionary<string, string> picked = [];
            foreach (string name in names)
            {
                picked[name] = all.TryGetValue(name, out string? value)
                    ? value
                    : throw new KeyNotFoundException($"{name} is not in the store.");
            }

            return (IReadOnlyDictionary<string, string>)picked;
        });
    }

    public void Set(string name, string value)
    {
        Directory.CreateDirectory(_directory);
        InStoreDirectory(() =>
        {
            // The first write creates the key pair. On a terminal, dotenvx asks where the private key should live:
            // choose Windows Credential Manager.
            global::Dotenvx.Dotenvx.Set(name, value, new global::Dotenvx.SetsOptions
            {
                Path = [_fileName],
                Quiet = true,
                NoArmor = true,
                No1Password = true,
                NoBitwarden = true
            });

            return 0;
        });
    }

    public bool Remove(string name)
    {
        if (!File.Exists(FilePath))
        {
            return false;
        }

        string[] lines = File.ReadAllLines(FilePath);
        string[] kept = [.. lines.Where(line =>
        {
            Match match = EntryLine().Match(line);

            return !(match.Success && match.Groups[1].Value == name);
        })];

        if (kept.Length == lines.Length)
        {
            return false;
        }

        string temp = FilePath + ".tmp";
        File.WriteAllLines(temp, kept);
        File.Move(temp, FilePath, true);

        return true;
    }

    /// <summary>
    /// Dotenvx finds key files relative to the working directory, so each call runs from the store's folder. The program the
    /// agent asked for keeps its own working directory: it is passed to the child explicitly.
    /// </summary>
    private T InStoreDirectory<T>(Func<T> action)
    {
        lock (Gate)
        {
            string previous = Environment.CurrentDirectory;
            Environment.CurrentDirectory = _directory;
            try
            {
                return action();
            }
            finally
            {
                Environment.CurrentDirectory = previous;
            }
        }
    }
}
