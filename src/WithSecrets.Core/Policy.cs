namespace WithSecrets;

/// <summary>
/// Refuses commands that cannot be reviewed from the prompt. The prompt shows the whole command line, however long, the inline
/// code of a shell (<see cref="InlineCode" />, first 4000 characters) and the start of a script file (first 200 lines, at most
/// 16 KB, see <see cref="ApprovalSummary" />). Limits: a long or obfuscated script can still be hard to judge, and only the
/// script file named in the command is shown, not the files it runs in turn. Base64 code (-EncodedCommand) and code read from
/// standard input cannot be read on the page and are refused.
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

        if (name is "powershell" or "pwsh")
        {
            if (arguments.Any(IsEncodedFlag))
            {
                return "-EncodedCommand is refused: the code is base64 and not readable on the approval page. Use -Command with the code itself, or -File.";
            }

            if (arguments.Any(argument => argument == "-"))
            {
                return "PowerShell reading its code from standard input is refused: the approval page cannot show it. Use -Command or -File.";
            }

            if (InlineCode(program, arguments) is null && !arguments.Any(IsFileFlag))
            {
                return "PowerShell needs -File or code (-Command). Without either there is nothing for the approval page to show.";
            }
        }

        return CheckLength(program, arguments);
    }

    /// <summary>
    /// The code a shell would run that is written in the arguments themselves: the argument after <c>-c</c> for a POSIX shell,
    /// the rest of the line after <c>/c</c>, <c>/k</c> or <c>/r</c> for cmd, and the rest of the line after <c>-Command</c> (or,
    /// without <c>-File</c>, from the first argument that is not a flag) for PowerShell. Null when the command runs no inline
    /// code. The approval page shows this text, so what it returns must cover everything the shell will read as code.
    /// </summary>
    public static string? InlineCode(string program, IReadOnlyList<string> arguments)
    {
        string name = Path.GetFileNameWithoutExtension(program).ToLowerInvariant();
        string? code = null;
        if (PosixShells.Contains(name))
        {
            int flag = arguments.ToList().FindIndex(IsShortFlagWithC);
            code = flag >= 0 && flag + 1 < arguments.Count ? arguments[flag + 1] : null;
        }
        else if (name == "cmd")
        {
            for (int index = 0; index < arguments.Count && code is null; index++)
            {
                string argument = arguments[index];
                if (argument.Length >= 2 && argument[0] == '/' && "ckr".Contains(char.ToLowerInvariant(argument[1]), StringComparison.Ordinal))
                {
                    code = string.Join(' ', new[] { argument[2..] }.Concat(arguments.Skip(index + 1)).Where(part => part.Length > 0));
                }
            }
        }
        else if (name is "powershell" or "pwsh")
        {
            // The first of -File and -Command decides; a flag's own value (-ExecutionPolicy Bypass) must not look like code.
            int file = arguments.ToList().FindIndex(IsFileFlag);
            int command = arguments.ToList().FindIndex(argument => FlagName(argument) is { Length: > 0 } flag
                && ("command".StartsWith(flag, StringComparison.Ordinal) || flag is "commandwithargs" or "cwa"));
            if (file >= 0 && (command < 0 || file < command))
            {
                return null;
            }

            int start = command >= 0 ? command + 1 : arguments.ToList().FindIndex(argument => argument.Length > 0 && argument[0] is not ('-' or '/'));
            code = start >= 0 ? string.Join(' ', arguments.Skip(start)) : null;
        }

        return string.IsNullOrEmpty(code) ? null : code;
    }

    private static string FlagName(string argument)
    {
        return argument.Length > 1 && argument[0] is '-' or '/' ? argument.TrimStart('-', '/').ToLowerInvariant() : "";
    }

    // -e, -ec, -enc ... -encodedcommand, and the encoded arguments that go with it.
    private static bool IsEncodedFlag(string argument)
    {
        string flag = FlagName(argument);

        return flag.Length > 0 && (flag == "ec" || "encodedcommand".StartsWith(flag, StringComparison.Ordinal) || (flag.Length >= 2 && "encodedarguments".StartsWith(flag, StringComparison.Ordinal)));
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
        string flag = FlagName(argument);

        return flag.Length > 0 && "file".StartsWith(flag, StringComparison.Ordinal);
    }
}
