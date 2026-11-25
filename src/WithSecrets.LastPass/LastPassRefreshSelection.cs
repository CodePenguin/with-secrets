namespace WithSecrets.LastPass;

internal sealed class LastPassRefreshSelection
{
    private const int MaxFields = 100;

    private readonly Dictionary<string, List<Field>> _byAccount = new(StringComparer.Ordinal);

    internal sealed record Field(string Path, string Name);

    public LastPassRefreshSelection(IReadOnlyCollection<string> paths)
    {
        if (paths.Count is < 1 or > MaxFields || paths.Distinct(StringComparer.Ordinal).Count() != paths.Count)
            throw InvalidSelection();

        foreach (string path in paths)
        {
            if (path is null || path.Split('/') is not [string id, string leaf] || !IsItemId(id)
                || FieldName(leaf) is not { } field)
                throw InvalidSelection();

            if (!_byAccount.TryGetValue(id, out List<Field>? fields))
            {
                fields = [];
                _byAccount.Add(id, fields);
            }
            fields.Add(new Field(path, field));
        }
        Count = paths.Count;
    }

    public int Count { get; }

    public IReadOnlyList<Field>? Find(string id) => _byAccount.GetValueOrDefault(id);

    internal static bool IsPath(string path) => path.Split('/') is [string id, string leaf]
        && IsItemId(id) && FieldName(leaf) is not null;

    internal static bool IsAccount(string? username) => username is { Length: > 0 and <= 256 }
        && username.All(character => character is >= '!' and <= '~')
        && username.Split('@') is [{ Length: > 0 }, { Length: > 0 }];

    private static bool IsItemId(string id) => id.Length is > 0 and <= 32
        && id[0] is >= '1' and <= '9' && id.All(char.IsAsciiDigit);

    internal static string? FieldName(string leaf) => leaf switch
    {
        "F_70617373776F7264" => "password",
        "F_757365726E616D65" => "username",
        "F_6E6F7465" => "note",
        "F_75726C" => "url",
        _ => null,
    };

    private static ProviderAdapterException InvalidSelection()
        => new(ProviderErrorKind.InvalidConfiguration, "Select distinct LastPass item IDs and explicit fields for the refresh.");
}
