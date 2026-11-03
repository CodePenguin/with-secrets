namespace WithSecrets;

public sealed record RunArgs(IReadOnlyList<string> Secrets, string Reason, string Program, IReadOnlyList<string> Arguments);

/// <summary>
/// Exit codes: 2 usage, 3 denied, 4 store error, 5 audit error, 127 program not found. Anything else is the program's own.
/// <paramref name="reuse" /> is what the approval page may offer besides "Approve once" (from the settings); without
/// <paramref name="grants" /> nothing is offered. A saved approval is made only when the person chose a time on the page and
/// signed it, for exactly that time, keeps that signature, and is used only while it verifies and its lifetime is within the
/// current ceiling. One that does not verify is reported once on stderr and ignored: the person is asked again.
/// </summary>
public sealed class RunCommand(ISecretSource store, IApprover approver, AuditLog audit, TextWriter stdout, TextWriter stderr, GrantStore? grants = null, ReuseOffer? reuse = null)
{
    public const int Usage = 2;
    public const int Denied = 3;
    public const int StoreError = 4;
    public const int AuditError = 5;
    public const int NotFound = 127;

    public async Task<int> ExecuteAsync(RunArgs args, string workingDirectory)
    {
        IReadOnlyList<string> available;
        try
        {
            available = store.ListNames();
        }
        catch (Exception error)
        {
            return await Fail(StoreError, $"cannot read the secret store: {error.Message}");
        }

        IReadOnlyList<string> names = args.Secrets;
        string[] invalid = [.. names.Where(name => !SecretNames.IsValid(name))];
        if (invalid.Length > 0)
        {
            return await Fail(Usage, $"Invalid secret name: {string.Join(", ", invalid.Select(ApprovalSummary.Clean))}.");
        }

        string[] missing = [.. names.Where(name => !available.Contains(name, StringComparer.Ordinal))];
        if (missing.Length > 0 || names.Count == 0)
        {
            string have = available.Count == 0 ? "(none)" : string.Join(", ", available);

            return await Fail(Usage, $"Unknown secret: {string.Join(", ", missing)}. Names in the store: {have}. Ask the user to add a missing name.");
        }

        string? refusal = Policy.Check(args.Program, args.Arguments);
        if (refusal is not null)
        {
            return await Fail(Usage, refusal);
        }

        string? resolved = ProgramResolver.Resolve(args.Program, workingDirectory);
        if (resolved is null)
        {
            return await Fail(NotFound, $"Program not found on PATH: {ApprovalSummary.Clean(args.Program)}. The working directory is not searched. Use ./name to run a file there.");
        }

        string? alias = AppExecutionAlias(args.Program, resolved);
        if (alias is not null)
        {
            return await Fail(Usage, alias);
        }

        // Write the program and the script as full paths. The prompt shows them, and they are what runs. What is checked and shown
        // is the expanded command, and it must read the same as the typed one.
        resolved = PathExpander.Full(resolved, workingDirectory);
        IReadOnlyList<string> arguments = PathExpander.ExpandScript(args.Program, args.Arguments, workingDirectory);
        string? expandedRefusal = Policy.CheckExpanded(args.Program, args.Arguments, arguments) ?? Policy.CheckBatchFile(resolved, arguments);
        if (expandedRefusal is not null)
        {
            return await Fail(Usage, expandedRefusal);
        }

        string? tooLong = Policy.CheckLength(resolved, arguments);
        if (tooLong is not null)
        {
            return await Fail(Usage, tooLong);
        }

        // The index is the same in the typed and the expanded arguments (checked above).
        int scriptIndex = PathExpander.ScriptArgumentIndex(args.Program, args.Arguments, workingDirectory);

        // A script that is too big to be hashed and shown is never run unseen.
        string? oversized = OversizedScript(args.Program, resolved, args.Arguments, workingDirectory);
        if (oversized is not null)
        {
            return await Fail(Usage, $"The script {ApprovalSummary.Clean(oversized)} is larger than 1 MB, which is more than the approval page can show. Split it into smaller files, or run a program that loads it. Nothing was run.");
        }

        // The script an interpreter is told to run must exist, so that the page can show it.
        if (Policy.ScriptIndex(args.Program, args.Arguments) is { } named && named >= 0 && scriptIndex < 0)
        {
            return await Fail(Usage, $"The script {ApprovalSummary.Clean(arguments[named])} does not exist, so the approval page cannot show it. Nothing was run.");
        }

        // Every file that will be read as code is shown on the approval page: the script argument, and the program itself when it
        // is a text file (evil.cmd, check.sh). If one cannot be read, the person would approve unseen content: refuse.
        string? scriptPath = scriptIndex >= 0 ? arguments[scriptIndex] : null;
        foreach (string? batch in new[] { resolved, scriptPath })
        {
            if (batch is not null && NonAsciiBatch(batch))
            {
                return await Fail(Usage, $"The batch file {ApprovalSummary.Clean(batch)} has characters outside ASCII: batch files must be ASCII, because cmd reads them in another code page than the page shows. Nothing was run.");
            }
        }

        string? programPath = HashedFileOrNull(resolved);
        ScriptView? script = null;
        ScriptView? programFile = null;
        try
        {
            script = scriptPath is null ? null : ScriptView.Read(scriptPath) with { Guessed = PathExpander.IsGuess(args.Program, args.Arguments) };
            programFile = programPath is null ? null : ScriptView.Read(programPath) is { Text: not null } text ? text : null;
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException)
        {
            return await Fail(Usage, $"Cannot read the script {ApprovalSummary.Clean(scriptPath ?? resolved)} ({error.Message}), so the approval page could not show it. Nothing was run.");
        }

        if (script is not null && !script.Guessed)
        {
            if (script.Text is null)
            {
                return await Fail(Usage, $"The script {ApprovalSummary.Clean(script.Path)} is not text, so the approval page cannot show it. Binary scripts, zipapps and .pyc files are not allowed.");
            }

            if (Path.GetFileNameWithoutExtension(args.Program).Equals("powershell", StringComparison.OrdinalIgnoreCase) && script.NonAscii && !script.Bom)
            {
                return await Fail(Usage, $"Windows PowerShell 5.1 reads the script {ApprovalSummary.Clean(script.Path)} in the ANSI code page when it has no byte order mark, so it would run other characters than the page shows. Save the script with a UTF-8 BOM or use only ASCII.");
            }
        }

        AfterScriptRead?.Invoke();

        List<string> links = [];
        foreach (string? note in new[] { PathExpander.LinkNote(resolved), scriptIndex >= 0 ? PathExpander.LinkNote(arguments[scriptIndex]) : null })
        {
            if (note is not null)
            {
                links.Add(note);
            }
        }

        // A store whose key is released by the approving passkey (PRF) gets that release at every run, and a saved approval has none:
        // such a store never offers or uses saved approvals.
        ReuseOffer offer = !store.NeedsUnlock && grants is not null && reuse is { IsOn: true } ? reuse : ReuseOffer.Off;
        Dictionary<string, string> sources = names.ToDictionary(name => name, _ => store.Label, StringComparer.Ordinal);
        ApprovalRequest request = new(args.Program, resolved, arguments, workingDirectory, args.Reason, names, offer.IsOn ? offer : null, args.Arguments, links, Sources: sources, Unlock: store.NeedsUnlock, Script: script, ProgramFile: programFile);
        Fingerprint fingerprint = RequestFingerprint.Compute(request);

        // What the page shows must be the file the fingerprint covers; a file that changed in between is not approved unseen.
        foreach (ScriptView shown in new[] { script, programFile }.OfType<ScriptView>())
        {
            if (!fingerprint.Files.TryGetValue(shown.Path, out string? hashed) || hashed != shown.Sha256)
            {
                return await Fail(Usage, "The script changed while the request was being made, so nothing was run. Ask again.");
            }
        }

        // The request id goes into the text the person signs, so a saved approval names the request it covers.
        request = request with { RequestId = fingerprint.Key };

        // A saved approval that does not verify is never used; the person is asked again.
        GrantLookup saved = offer.IsOn ? grants!.Find(fingerprint.Key, offer.MaxMinutes) : GrantLookup.None;

        // What the approving passkey released (PRF) on the approval page: the only thing that opens the store key. It is zeroed
        // when the values were read, and on every way out.
        Unlock? unlock = null;
        try
        {
            if (saved.Rejected is not null)
            {
                await stderr.WriteLineAsync($"with-secrets: {GrantStore.RejectedMessage} ({saved.Rejected}).");
            }

            if (saved.Grant is { } grant)
            {
                DateTimeOffset now = DateTimeOffset.UtcNow;
                string detail = $"approval by passkey {grant.KeyName} from {grant.Approved:O}, ends {grant.Expires:O}";
                await stderr.WriteLineAsync($"with-secrets: reusing the approval for this exact request ({Math.Max(0, (int)(grant.Expires - now).TotalMinutes)} min left).");
                if (!audit.TryWrite("reused", request, detail, files: fingerprint.Files, keyName: grant.KeyName))
                {
                    return await Fail(AuditError, "cannot write the audit log, so nothing was run.");
                }
            }
            else
            {
                await stderr.WriteLineAsync("with-secrets: waiting for the user to approve this request...");
                await stderr.WriteLineAsync(ApprovalSummary.BuildMessage(request));

                ApprovalDecision decision = approver.Request(request);
                unlock = decision.Unlock;
                if (decision.Approved && !offer.Allows(decision.ReuseMinutes))
                {
                    decision = ApprovalDecision.Deny("the approval named a reuse time that was not offered");
                }

                if (!audit.TryWrite(decision.Approved ? "approved" : "denied", request, decision.Detail, files: fingerprint.Files, reuseMinutes: decision.Approved ? decision.ReuseMinutes : null))
                {
                    return await Fail(AuditError, "cannot write the audit log, so nothing was run.");
                }

                if (!decision.Approved)
                {
                    return await Fail(Denied, $"The user did not approve ({decision.Detail}). Do not retry. Ask the user.");
                }

                // A script can change while the prompt is open. The person approved what they saw, so run only that.
                if (RequestFingerprint.Compute(request).Key != fingerprint.Key)
                {
                    return await Fail(Denied, "A file named in the command changed while the prompt was open, so nothing was run. Ask again.");
                }

                // Only the time the person signed, never longer than the ceiling now (Allows checked it), and only with what they
                // signed: the grant keeps the assertion and is checked again at every use.
                if (decision.ReuseMinutes > 0 && decision.Evidence is { } evidence && grants!.Add(fingerprint.Key, decision.ReuseMinutes, evidence))
                {
                    await stderr.WriteLineAsync($"with-secrets: the user approved this for {decision.ReuseMinutes} min; the same request runs again without asking until then.");
                }
            }

            // The files the person saw are held open (on Windows: nobody can write or delete them) from now until the program ends,
            // and checked once more against what was shown. If that cannot be done, nothing runs.
            using HeldFiles held = new();
            string? holdFailure = held.Hold(new[] { script, programFile }.OfType<ScriptView>().ToList());
            if (holdFailure is not null)
            {
                return await Fail(Denied, holdFailure);
            }

            // Only the approved names are decrypted. The bytes are zeroed when the program ends; the strings the redactor and the
            // child's environment need cannot be wiped (see SecretValues). The store key itself is opened inside, from what the
            // passkey released, and zeroed there.
            SecretValues secrets;
            try
            {
                secrets = store.GetValues(names, unlock);
            }
            catch (Exception error)
            {
                return await Fail(StoreError, $"cannot decrypt the secret store: {error.Message}");
            }
            finally
            {
                unlock?.Dispose();
            }

            int exitCode;
            using (secrets)
            {
                exitCode = await ChildRunner.RunAsync(new ChildSpec(resolved, arguments, workingDirectory, secrets.Texts()), stdout, stderr);
            }

            audit.TryWrite("finished", request, "", exitCode, fingerprint.Files);

            return exitCode;
        }
        finally
        {
            unlock?.Dispose();
        }
    }

    /// <summary>
    /// A Windows App Execution Alias (python3.exe in WindowsApps) is a stub with no content: it opens the Store, not Python.
    /// Returns the message, or null.
    /// </summary>
    private static string? AppExecutionAlias(string typedProgram, string resolved)
    {
        if (!OperatingSystem.IsWindows())
        {
            return null;
        }

        try
        {
            FileInfo info = new(resolved);

            return info.Exists && IsAlias(resolved, info.Attributes, info.Length) ? AliasMessage(typedProgram) : null;
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException)
        {
            return null;
        }
    }

    /// <summary>An App Execution Alias: a zero-length reparse point in a WindowsApps folder.</summary>
    internal static bool IsAlias(string path, FileAttributes attributes, long length)
    {
        return length == 0 && attributes.HasFlag(FileAttributes.ReparsePoint) && path.Contains(@"\WindowsApps\", StringComparison.OrdinalIgnoreCase);
    }

    internal static string AliasMessage(string typedProgram)
    {
        string name = Path.GetFileNameWithoutExtension(typedProgram);
        string real = name.StartsWith("python", StringComparison.OrdinalIgnoreCase) || name.StartsWith("py", StringComparison.OrdinalIgnoreCase) ? " (for Python, the real python.exe)" : "";

        return $"{ApprovalSummary.Clean(name)} resolves to an App Execution Alias: use the full path to the real program{real}. Nothing was run.";
    }

    /// <summary>A batch file is read in the console code page, so a byte above 127 can be read as another character than the page shows.</summary>
    private static bool NonAsciiBatch(string path)
    {
        string extension = Path.GetExtension(path);
        if (!extension.Equals(".cmd", StringComparison.OrdinalIgnoreCase) && !extension.Equals(".bat", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        try
        {
            return File.ReadAllBytes(path).Any(value => value > 127);
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException)
        {
            return false;
        }
    }

    /// <summary>The path when it is an existing file small enough to be hashed (the same rule as the approval fingerprint), else null.</summary>
    private static string? HashedFileOrNull(string path)
    {
        try
        {
            FileInfo info = new(path);

            return info.Exists && info.Length <= RequestFingerprint.MaxHashedFileBytes ? path : null;
        }
        catch (Exception error) when (error is ArgumentException or IOException or UnauthorizedAccessException or NotSupportedException)
        {
            return null;
        }
    }

    /// <summary>Test hook: runs after the shown files were read and before the fingerprint is made.</summary>
    internal static Action? AfterScriptRead { get; set; }

    private static readonly string[] ScriptExtensions = [".sh", ".bash", ".cmd", ".bat", ".ps1", ".py", ".js", ".mjs", ".pl", ".rb", ".vbs"];

    /// <summary>
    /// The path of a script too big to hash and show (over 1 MB), or null: the program itself when it has a script extension, or,
    /// for an interpreter, an argument that names an existing file that big.
    /// </summary>
    private static string? OversizedScript(string typedProgram, string resolved, IReadOnlyList<string> arguments, string workingDirectory)
    {
        if (IsBig(resolved) && ScriptExtensions.Contains(Path.GetExtension(resolved), StringComparer.OrdinalIgnoreCase))
        {
            return resolved;
        }

        // The exact script operand of a known interpreter, whatever it is called; for other programs, a big file with a script extension.
        if (Policy.ScriptIndex(typedProgram, arguments) is { } operand)
        {
            string named = operand >= 0 ? SafeFull(arguments[operand], workingDirectory) : "";

            return named.Length > 0 && IsBig(named) ? named : null;
        }

        foreach (string argument in arguments)
        {
            string full = SafeFull(argument, workingDirectory);
            if (full.Length > 0 && ScriptExtensions.Contains(Path.GetExtension(full), StringComparer.OrdinalIgnoreCase) && IsBig(full))
            {
                return full;
            }
        }

        return null;
    }

    private static string SafeFull(string argument, string workingDirectory)
    {
        try
        {
            return Path.GetFullPath(argument, workingDirectory);
        }
        catch (Exception error) when (error is ArgumentException or NotSupportedException or PathTooLongException)
        {
            return "";
        }
    }

    private static bool IsBig(string path)
    {
        try
        {
            FileInfo info = new(path);

            return info.Exists && info.Length > RequestFingerprint.MaxHashedFileBytes;
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException)
        {
            return false;
        }
    }

    private async Task<int> Fail(int code, string message)
    {
        await stderr.WriteLineAsync("with-secrets: " + message);

        return code;
    }
}

/// <summary>
/// The shown script files, open for reading until disposed. On Windows they are opened so that nobody can write or delete them
/// meanwhile (FileShare.Read); elsewhere the operating system gives no such lock, so the check is only a last comparison before
/// launch and an interpreter may read the file again later. Each file's bytes must still hash to what was shown.
/// </summary>
internal sealed class HeldFiles : IDisposable
{
    private readonly List<FileStream> _streams = [];

    /// <summary>Opens and checks every file. Returns why not, or null.</summary>
    public string? Hold(IReadOnlyList<ScriptView> files)
    {
        foreach (ScriptView file in files)
        {
            try
            {
                FileStream stream = new(file.Path, FileMode.Open, FileAccess.Read, FileShare.Read);
                _streams.Add(stream);
                using MemoryStream copy = new();
                stream.CopyTo(copy);
                if (Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(copy.ToArray())) != file.Sha256)
                {
                    return "A file named in the command changed after it was shown, so nothing was run. Ask again.";
                }
            }
            catch (Exception error) when (error is IOException or UnauthorizedAccessException)
            {
                return $"Cannot hold {ApprovalSummary.Clean(file.Path)} against changes ({error.Message}), so nothing was run.";
            }
        }

        return null;
    }

    public void Dispose()
    {
        foreach (FileStream stream in _streams)
        {
            stream.Dispose();
        }
    }
}
