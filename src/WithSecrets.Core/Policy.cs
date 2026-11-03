using System.Globalization;
using System.Text.RegularExpressions;

namespace WithSecrets;

/// <summary>
/// Refuses commands that cannot be reviewed from the prompt. The prompt shows the whole command line, however long, the inline
/// code of an interpreter (<see cref="InlineCode" />, first 4000 characters), the start of every script file the command runs
/// (first 200 lines, at most 16 KB, see <see cref="ApprovalSummary" />) and a program that is itself a text file.
/// <para>
/// Interpreters are not parsed option by option. Each known one (sh, bash, zsh, dash, ksh, fish, python, py, node, perl, ruby,
/// cmd, powershell, pwsh) is allowed only in one strict form, and everything else is refused with "put options inside the
/// script file": a script as the first argument, or one inline code argument (<c>-c</c> or <c>-e</c>); PowerShell with a few
/// fixed switches and then exactly <c>-File</c> or <c>-Command</c>; cmd <c>/c</c> with a tail of plain words that starts with a
/// .cmd or .bat file or echo, dir, type or ver. Limits: a long or obfuscated script can still be hard to judge; only the files
/// named in the command are shown, not the files they load in turn (<c>source</c>, <c>import</c>); a renamed or copied
/// interpreter skips the analysis (the Run line still shows the real path); the child's standard input is closed.
/// </para>
/// </summary>
public static partial class Policy
{
    /// <summary>
    /// A technical limit, not a review limit. A command longer than this is refused, never cut short.
    /// </summary>
    public const int MaxCommandLength = 16000;

    private static readonly HashSet<string> PosixShells = new(StringComparer.Ordinal) { "bash", "sh", "zsh", "dash", "ksh", "fish" };

    private static readonly HashSet<string> EnvironmentDumpers = new(StringComparer.Ordinal) { "env", "printenv", "set" };

    private static readonly HashSet<string> PolicyValues = new(StringComparer.OrdinalIgnoreCase) { "Bypass", "RemoteSigned", "Unrestricted", "AllSigned", "Restricted", "Default", "Undefined" };

    private static readonly HashSet<string> CmdBuiltins = new(StringComparer.OrdinalIgnoreCase) { "echo", "dir", "type", "ver" };

    private const string Bare = "An interpreter with nothing to run reads code from outside the approval. Give it a script file or inline code.";

    private const string EncodedRefusal = "An encoded command is refused: its code is base64 and not readable on the approval page. Use -Command with the code itself, or -File.";

    /// <summary>Returns the reason to refuse, or null when the command may go to the person.</summary>
    public static string? Check(string program, IReadOnlyList<string> arguments)
    {
        string name = Path.GetFileNameWithoutExtension(program).ToLowerInvariant();

        if (EnvironmentDumpers.Contains(name))
        {
            return $"'{name}' prints the environment. Run a program that needs the secrets instead.";
        }

        return Analyze(program, arguments, false).Refusal ?? CheckLength(program, arguments);
    }

    /// <summary>
    /// Run after the script operand was written as a full path. The expanded arguments must still be an allowed form, and the
    /// script operand and the inline code must be the same ones as in the typed arguments, so that what the page shows, the
    /// fingerprint hashes and the lock holds is what runs. Returns the reason to refuse, or null.
    /// </summary>
    public static string? CheckExpanded(string program, IReadOnlyList<string> typed, IReadOnlyList<string> expanded)
    {
        if (!IsInterpreter(program))
        {
            return CheckLength(program, expanded);
        }

        Analysis before = Analyze(program, typed, false);
        Analysis after = Analyze(program, expanded, true);
        if (after.Refusal is not null)
        {
            return after.Refusal;
        }

        if (before.Refusal is not null || before.Script != after.Script || (before.Script < 0 && before.Code != after.Code))
        {
            return "The full path of the script changes how the command is read, so the approval page could not show what runs. Nothing was run. Run from another folder.";
        }

        return CheckLength(program, expanded);
    }

    /// <summary>
    /// The code an interpreter would run that is written in the arguments themselves, as the approval page shows it: the code
    /// argument of <c>-c</c> or <c>-e</c>, the code of <c>-Command</c>, or the tail of <c>cmd /c</c>. Null when there is none or the
    /// form is refused (see <see cref="Check" />).
    /// </summary>
    public static string? InlineCode(string program, IReadOnlyList<string> arguments) => Analyze(program, arguments, true).Code;

    /// <summary>
    /// The index in <paramref name="arguments" /> of the operand a known interpreter will run as its script file, or -1 when it
    /// runs none. Null when the program has no analyzer, so nothing is known. The page, the fingerprint and the file lock all use
    /// this one index.
    /// </summary>
    public static int? ScriptIndex(string program, IReadOnlyList<string> arguments)
    {
        return IsInterpreter(program) ? Math.Max(-1, Analyze(program, arguments, true).Script) : null;
    }

    /// <summary>True for programs that run code given to them (a shell, python, node, perl, ruby, cmd, PowerShell).</summary>
    public static bool IsInterpreter(string program)
    {
        string name = Path.GetFileNameWithoutExtension(program).ToLowerInvariant();

        return PosixShells.Contains(name) || name is "cmd" or "powershell" or "pwsh" or "node" or "nodejs" or "perl" or "ruby" or "py"
            || name.StartsWith("python", StringComparison.Ordinal);
    }

    private sealed record Analysis(string? Code = null, string? Refusal = null, bool HasTarget = false, int Script = -1);

    private static Analysis Refuse(string reason) => new(Refusal: reason);

    private static Analysis NotAllowed(string argument) =>
        Refuse($"The argument '{ApprovalSummary.Clean(argument)}' is not allowed here: put options inside the script file. Allowed: a script file first, or one inline code argument (-c or -e).");

    // Strict is for the arguments as typed. Relaxed is for arguments whose script operand was written as a full path: that one
    // word may have spaces and so on (cmd still refuses its special characters), and nothing else is relaxed.
    private static Analysis Analyze(string program, IReadOnlyList<string> arguments, bool relaxed)
    {
        string name = Path.GetFileNameWithoutExtension(program).ToLowerInvariant();
        bool powerShell = name is "powershell" or "pwsh";
        Analysis result;
        if (PosixShells.Contains(name))
        {
            result = Simple(arguments, "-c");
        }
        else if (name.StartsWith("python", StringComparison.Ordinal) || name == "py")
        {
            result = Simple(arguments, "-c");
        }
        else if (name is "node" or "nodejs" or "perl" or "ruby")
        {
            result = Simple(arguments, "-e");
        }
        else if (name == "cmd")
        {
            result = Cmd(arguments, relaxed);
        }
        else if (powerShell)
        {
            result = PowerShell(arguments);
        }
        else
        {
            return new Analysis();
        }

        if (result.Refusal is not null)
        {
            return result;
        }

        // Another PowerShell started inside inline text with an encoded flag hides its code from the page.
        if (!powerShell && result.Code is { } code && NestedPowerShell().IsMatch(code)
            && code.Split([' ', '\t', '\r', '\n'], StringSplitOptions.RemoveEmptyEntries).Any(IsEncodedFlag))
        {
            return Refuse(EncodedRefusal);
        }

        return result;
    }

    [GeneratedRegex("(powershell|pwsh)", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex NestedPowerShell();

    [GeneratedRegex("^[A-Za-z0-9._:\\\\/-]+$", RegexOptions.CultureInvariant)]
    private static partial Regex PlainWord();

    // An argument that an interpreter would trim, or that starts with a dash that is not the ASCII one (PowerShell reads the
    // en dash, em dash, horizontal bar and minus sign as a dash).
    private static bool Padded(string argument)
    {
        return argument.Length > 0 && (char.IsWhiteSpace(argument[0]) || char.IsWhiteSpace(argument[^1]));
    }

    private static bool UnicodeDash(string argument)
    {
        string trimmed = argument.TrimStart();

        return trimmed.Length > 0 && trimmed[0] > '\u007f' && (char.GetUnicodeCategory(trimmed[0]) == UnicodeCategory.DashPunctuation || trimmed[0] == '−');
    }

    // sh, bash, zsh, dash, ksh, fish, python, py, node, perl, ruby: `PROG script [args]` (the first argument does not start with a
    // dash) or `PROG -c CODE [args]` / `PROG -e CODE [args]` (the first argument is exactly the code flag).
    private static Analysis Simple(IReadOnlyList<string> arguments, string codeFlag)
    {
        if (arguments.Count == 0)
        {
            return Refuse(Bare);
        }

        string first = arguments[0];
        if (first == codeFlag)
        {
            if (arguments.Count < 2 || arguments[1].Length == 0)
            {
                return Refuse(codeFlag + " has no code after it.");
            }

            return arguments[1][0] is '-' or '+'
                ? Refuse("Code that starts with a dash can be read as an option: " + codeFlag + " " + ApprovalSummary.Clean(arguments[1][..Math.Min(20, arguments[1].Length)]) + "...")
                : new Analysis(arguments[1], HasTarget: true);
        }

        if (first.Length == 0 || first[0] is '-' or '+' || Padded(first) || UnicodeDash(first))
        {
            return NotAllowed(first);
        }

        return new Analysis(HasTarget: true, Script: 0);
    }

    // `cmd [/d] /c TAIL` (or /k, /r): every tail word is plain, and the first is a .cmd or .bat file or echo, dir, type or ver.
    private static Analysis Cmd(IReadOnlyList<string> arguments, bool relaxed)
    {
        if (arguments.Count == 0)
        {
            return Refuse(Bare);
        }

        if (!arguments[0].Equals("/d", StringComparison.OrdinalIgnoreCase))
        {
            return arguments[0] is "/c" or "/C" or "/k" or "/K" or "/r" or "/R"
                ? Refuse("Use cmd /d /c: without /d cmd runs the AutoRun commands from the registry, which the approval page cannot show.")
                : NotAllowed(arguments[0]);
        }

        int index = 1;
        if (index >= arguments.Count)
        {
            return Refuse(Bare);
        }

        if (arguments[index] is not ("/c" or "/C" or "/k" or "/K" or "/r" or "/R"))
        {
            return NotAllowed(arguments[index]);
        }

        string[] tail = [.. arguments.Skip(index + 1)];
        if (tail.Length == 0)
        {
            return Refuse("cmd " + arguments[index] + " has no command after it.");
        }

        string firstExtension = Path.GetExtension(tail[0]);
        bool fullPath = relaxed && (firstExtension.Equals(".cmd", StringComparison.OrdinalIgnoreCase) || firstExtension.Equals(".bat", StringComparison.OrdinalIgnoreCase));
        if (fullPath && tail[0].IndexOfAny(BatchUnsafe) >= 0)
        {
            return Refuse("The folder name has characters cmd cannot take safely (a quote or one of % ^ & | < > !): run from another folder.");
        }

        if (tail.Where((word, position) => !(fullPath && position == 0) && !PlainWord().IsMatch(word)).Any())
        {
            return Refuse("cmd /c arguments with special characters (only letters, digits and . _ : \\ / - are allowed): put the logic in a script file.");
        }

        string extension = Path.GetExtension(tail[0]);
        bool file = extension.Equals(".cmd", StringComparison.OrdinalIgnoreCase) || extension.Equals(".bat", StringComparison.OrdinalIgnoreCase);
        if (!file && !CmdBuiltins.Contains(tail[0]))
        {
            return Refuse("cmd /c runs a .cmd or .bat file written with its extension, or echo, dir, type or ver. A name without an extension is looked up through PATHEXT and cannot be shown: put the logic in a script file.");
        }

        return new Analysis(string.Join(' ', tail), HasTarget: true, Script: file ? index + 1 : -1);
    }

    // powershell, pwsh: -NoProfile, -NonInteractive, -NoLogo and -ExecutionPolicy VALUE (each once, any order), then exactly
    // `-File path [args]` or `-Command CODE`, written in full. Anything else is refused.
    private static Analysis PowerShell(IReadOnlyList<string> arguments)
    {
        if (arguments.Count == 0)
        {
            return Refuse(Bare);
        }

        HashSet<string> seen = new(StringComparer.Ordinal);
        int index = 0;
        for (; index < arguments.Count; index++)
        {
            string argument = arguments[index];
            if (Padded(argument) || UnicodeDash(argument))
            {
                return IsEncodedFlag(argument.Trim()) ? Refuse(EncodedRefusal) : NotAllowed(argument);
            }

            string lower = argument.ToLowerInvariant();
            if (lower is "-noprofile" or "-noninteractive" or "-nologo")
            {
                if (!seen.Add(lower))
                {
                    return NotAllowed(argument);
                }

                continue;
            }

            if (lower == "-executionpolicy")
            {
                if (index + 1 >= arguments.Count || !PolicyValues.Contains(arguments[index + 1]) || !seen.Add(lower))
                {
                    return NotAllowed(argument);
                }

                index++;
                continue;
            }

            break;
        }

        if (index >= arguments.Count)
        {
            return Refuse(Bare);
        }

        string flag = arguments[index];
        if ((flag.Equals("-File", StringComparison.OrdinalIgnoreCase) || flag.Equals("-Command", StringComparison.OrdinalIgnoreCase)) && !seen.Contains("-noprofile"))
        {
            return Refuse("Use -NoProfile: a PowerShell profile is code the approval page cannot show.");
        }

        if (flag.Equals("-File", StringComparison.OrdinalIgnoreCase))
        {
            if (index + 1 >= arguments.Count || arguments[index + 1].Length == 0 || arguments[index + 1][0] == '-' || Padded(arguments[index + 1]) || UnicodeDash(arguments[index + 1]))
            {
                return Refuse("-File needs the path of a script file right after it.");
            }

            if (arguments[index + 1].IndexOfAny(['[', ']', '`']) >= 0)
            {
                return Refuse("PowerShell reads -File paths as wildcards: no [ ] or backtick in the script path or its folder; run from another folder.");
            }

            return new Analysis(HasTarget: true, Script: index + 1);
        }

        if (flag.Equals("-Command", StringComparison.OrdinalIgnoreCase))
        {
            return arguments.Count - index != 2 || arguments[index + 1].Length == 0
                ? Refuse("-Command takes exactly one code argument.")
                : new Analysis(arguments[index + 1], HasTarget: true);
        }

        return IsEncodedFlag(flag) ? Refuse(EncodedRefusal) : NotAllowed(flag);
    }

    // The en dash, em dash, horizontal bar and minus sign are read as a dash by PowerShell, so they start a flag too.
    private static readonly char[] Dashes = ['-', '/', '–', '—', '―', '−'];

    private static string FlagName(string argument)
    {
        return argument.Length > 1 && Dashes.Contains(argument[0]) ? argument[1..].TrimStart(Dashes).ToLowerInvariant() : "";
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
}
