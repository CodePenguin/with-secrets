namespace ArcanaGuardian;

/// <summary>
/// Turns the paths in a command into full paths, so the prompt shows exactly which file runs and a relative path such as
/// <c>./check.sh</c> or <c>..\tools\run.ps1</c> cannot be mistaken for another file.
/// </summary>
public static class PathExpander
{
    /// <summary>A full path with no <c>.</c> or <c>..</c> segments, relative to the working folder.</summary>
    public static string Full(string path, string workingDirectory)
    {
        return Path.GetFullPath(path, workingDirectory);
    }

    /// <summary>
    /// The index of the script in the arguments: the first one that names an existing file of a size that is hashed, or -1.
    /// This is the file an interpreter runs (<c>pwsh -File run.ps1</c>, <c>node app.js</c>). It is the same file the approval
    /// reuse key hashes.
    /// </summary>
    public static int ScriptArgumentIndex(IReadOnlyList<string> arguments, string workingDirectory)
    {
        for (int index = 0; index < arguments.Count; index++)
        {
            try
            {
                FileInfo info = new(Full(arguments[index], workingDirectory));
                if (info.Exists && info.Length <= RequestFingerprint.MaxHashedFileBytes)
                {
                    return index;
                }
            }
            catch (Exception error) when (error is ArgumentException or IOException or UnauthorizedAccessException or NotSupportedException)
            {
                // Not a usable path: it is an ordinary argument.
            }
        }

        return -1;
    }

    /// <summary>
    /// The one index of the script: for a known interpreter the exact operand it will run as its script (see
    /// <see cref="Policy.ScriptIndex" />), when that names an existing file of a size that is hashed, else -1; for any other
    /// program only the guess of <see cref="ScriptArgumentIndex(IReadOnlyList{string}, string)" /> (see <see cref="IsGuess" />).
    /// The page, the fingerprint and the file lock all use this index.
    /// </summary>
    public static int ScriptArgumentIndex(string program, IReadOnlyList<string> arguments, string workingDirectory)
    {
        if (Policy.ScriptIndex(program, arguments) is not { } operand)
        {
            return ScriptArgumentIndex(arguments, workingDirectory);
        }

        if (operand < 0)
        {
            return -1;
        }

        try
        {
            FileInfo info = new(Full(arguments[operand], workingDirectory));

            return info.Exists && info.Length <= RequestFingerprint.MaxHashedFileBytes ? operand : -1;
        }
        catch (Exception error) when (error is ArgumentException or IOException or UnauthorizedAccessException or NotSupportedException)
        {
            return -1;
        }
    }

    /// <summary>True when the script of this program is only guessed from the arguments (the program has no analyzer).</summary>
    public static bool IsGuess(string program, IReadOnlyList<string> arguments) => Policy.ScriptIndex(program, arguments) is null;

    /// <summary>The arguments with the script of <see cref="ScriptArgumentIndex(string, IReadOnlyList{string}, string)" /> written as a full path.</summary>
    public static IReadOnlyList<string> ExpandScript(string program, IReadOnlyList<string> arguments, string workingDirectory)
    {
        int index = ScriptArgumentIndex(program, arguments, workingDirectory);
        if (index < 0)
        {
            return arguments;
        }

        List<string> expanded = [.. arguments];
        expanded[index] = Full(arguments[index], workingDirectory);

        return expanded;
    }

    /// <summary>The arguments with the guessed script (if there is one) written as a full path. Other arguments are left as typed.</summary>
    public static IReadOnlyList<string> ExpandScript(IReadOnlyList<string> arguments, string workingDirectory)
    {
        int index = ScriptArgumentIndex(arguments, workingDirectory);
        if (index < 0)
        {
            return arguments;
        }

        List<string> expanded = [.. arguments];
        expanded[index] = Full(arguments[index], workingDirectory);

        return expanded;
    }

    /// <summary>"link -> target" when the file is a symbolic link, otherwise null. The person should see where a link really leads.</summary>
    public static string? LinkNote(string fullPath)
    {
        try
        {
            FileSystemInfo? target = new FileInfo(fullPath).ResolveLinkTarget(true);

            return target is null ? null : $"{fullPath} -> {target.FullName}";
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException or NotSupportedException or ArgumentException)
        {
            return null;
        }
    }
}
