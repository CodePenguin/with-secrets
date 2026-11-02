namespace WithSecrets;

/// <summary>
/// Refuses commands that cannot be reviewed from the prompt. The prompt shows the whole command line, however long, but never
/// the contents of a script file, so approve commands you recognize.
/// </summary>
public static class Policy
{
    /// <summary>
    /// A technical limit, not a review limit. A command longer than this is refused, never cut short.
    /// </summary>
    public const int MaxCommandLength = 16000;

    private static readonly HashSet<string> PosixShells = new(StringComparer.Ordinal) { "bash", "sh", "zsh", "dash", "ksh", "fish" };

    private static readonly HashSet<string> EnvironmentDumpers = new(StringComparer.Ordinal) { "env", "printenv", "set" };

    /// <summary>Returns the reason to refuse, or null when the command may go to the person.</summary>
    public static string? Check(string program, IReadOnlyList<string> arguments)
    {
        string name = Path.GetFileNameWithoutExtension(program).ToLowerInvariant();

        if (EnvironmentDumpers.Contains(name))
        {
            return $"'{name}' prints the environment. Run a program that needs the secrets instead.";
        }

        if (PosixShells.Contains(name) && arguments.Any(IsShortFlagWithC))
        {
            return "Inline shell commands are refused. Put the logic in a script file and run that.";
        }

        if (name == "cmd" && arguments.Any(argument => argument.Equals("/c", StringComparison.OrdinalIgnoreCase)
                                                      || argument.Equals("/k", StringComparison.OrdinalIgnoreCase)))
        {
            return "Inline cmd commands are refused. Put the logic in a script file and run that.";
        }

        if (name is "powershell" or "pwsh" && !arguments.Any(IsFileFlag))
        {
            return "PowerShell is allowed only with -File. Put the logic in a script file and run that.";
        }

        return CheckLength(program, arguments);
    }

    private static readonly char[] BatchUnsafe = ['"', '%', '^', '&', '|', '<', '>', '!', '\r', '\n', '\0'];

    /// <summary>
    /// Windows starts a .cmd or .bat file through cmd.exe. .NET quotes arguments for normal programs, not for cmd.exe, so a
    /// quote or one of these characters lets an argument end the quoting and run another command with the secrets in its
    /// environment, and %NAME% is expanded to the value. Run this on the resolved program. Returns the reason to refuse, or null.
    /// </summary>
    public static string? CheckBatchFile(string resolvedProgram, IReadOnlyList<string> arguments)
    {
        string extension = Path.GetExtension(resolvedProgram);
        bool batch = extension.Equals(".cmd", StringComparison.OrdinalIgnoreCase) || extension.Equals(".bat", StringComparison.OrdinalIgnoreCase);

        return batch && arguments.Any(argument => argument.IndexOfAny(BatchUnsafe) >= 0)
            ? "A .cmd or .bat file runs through cmd.exe, which reads quotes and the characters & | < > ^ % ! in arguments as commands. Remove them from the arguments, or put the logic in a script file."
            : null;
    }

    /// <summary>The prompt must show the whole command, never part of it. Run this after the paths are written in full.</summary>
    public static string? CheckLength(string program, IReadOnlyList<string> arguments)
    {
        return ApprovalSummary.CommandLine(program, arguments).Length > MaxCommandLength
            ? $"The command line is longer than {MaxCommandLength} characters, which is more than the prompt can carry. The prompt must show the whole command."
            : null;
    }

    // -c, -lc, -ec ... but not --long-options
    private static bool IsShortFlagWithC(string argument)
    {
        return argument.Length > 1 && argument[0] == '-' && argument[1] != '-' && argument.Contains('c', StringComparison.Ordinal);
    }

    private static bool IsFileFlag(string argument)
    {
        return argument.Equals("-File", StringComparison.OrdinalIgnoreCase) || argument.Equals("-f", StringComparison.OrdinalIgnoreCase);
    }
}
