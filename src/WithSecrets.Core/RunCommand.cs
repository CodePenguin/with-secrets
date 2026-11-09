namespace WithSecrets;

/// <summary><paramref name="EnvFiles" /> are the -f files; null or empty means the default .env in the working directory.</summary>
public sealed record RunArgs(IReadOnlyList<string> Secrets, string Reason, string Program, IReadOnlyList<string> Arguments, IReadOnlyList<string>? EnvFiles = null);

/// <summary>
/// Exit codes: 2 usage, 3 denied, 4 store error, 5 audit error, 127 program not found. Anything else is the program's own.
/// <paramref name="reuse" /> is what the approval page may offer besides "Approve once" (from the settings); without
/// <paramref name="grants" /> nothing is offered. A saved approval is made only when the person chose a time on the page and
/// signed it, for exactly that time, keeps that signature, and is used only while it verifies and its lifetime is within the
/// current ceiling. One that does not verify is reported once on stderr and ignored: the person is asked again.
/// </summary>
public sealed class RunCommand(ISecretSource store, IApprover approver, AuditLog audit, TextWriter stdout, TextWriter stderr, GrantStore? grants = null, ReuseOffer? reuse = null, Func<string, string?>? environment = null)
{
    public const int Usage = 2;
    public const int Denied = 3;
    public const int StoreError = 4;
    public const int AuditError = 5;
    public const int NotFound = 127;

    /// <summary>The outcome of the last run, for the service to report (a child may exit with any code, so the code alone does not say).</summary>
    public LaunchOutcome Outcome { get; private set; } = LaunchOutcome.Failed;

    /// <summary>
    /// The run as the host service does it: the request (already parsed and checked for its digest, version and expiry) is
    /// validated again here, the .env plan in it is checked with the same rules that built it, and the run goes on exactly as
    /// <see cref="ExecuteAsync(RunArgs, string)" /> does it, except that the program starts only through the gate in
    /// <paramref name="context" /> and the child gets the environment the request carries.
    /// </summary>
    public async Task<int> ExecuteAsync(LaunchRequest launch, LaunchContext context)
    {
        // A request over the API is never launched on the host's own say-so: it needs an authority to answer for it.
        if (context.Authorization is null)
        {
            return await Fail(Denied, "no authority is configured for this host service. Nothing was run.");
        }

        string? invalid = launch.Validate(DateTimeOffset.UtcNow);
        if (invalid is not null)
        {
            return await Fail(Usage, "invalid request: " + invalid);
        }

        // The folder is where the program runs and where scripts are read: a full path to a folder that exists.
        if (!Path.IsPathFullyQualified(launch.WorkingDirectory) || !Directory.Exists(launch.WorkingDirectory))
        {
            return await Fail(Usage, "the working directory must be a full path to an existing folder: " + ApprovalSummary.Clean(launch.WorkingDirectory));
        }

        // Two names that differ only in case are one variable on Windows, and the two readers of the block would disagree on which counts.
        if (launch.InheritedEnvironment.Keys.GroupBy(name => name, OperatingSystem.IsWindows() ? StringComparer.OrdinalIgnoreCase : StringComparer.Ordinal).FirstOrDefault(group => group.Count() > 1) is { } twice)
        {
            return await Fail(Usage, "the inherited environment names " + ApprovalSummary.Clean(twice.Key) + " more than once (names are compared without regard to case)");
        }

        IReadOnlyList<string> available;
        try
        {
            available = store.ListNames();
        }
        catch (Exception error)
        {
            return await Fail(StoreError, $"cannot read the secret store: {error.Message}");
        }

        EnvResult composed = EnvDeclarations.FromRequest(launch);
        if (composed.Plan is not { } plan)
        {
            return await Fail(Usage, composed.Error!);
        }

        context.Request = launch;

        return await RunPlan(launch.Program, launch.Arguments, launch.Reason, launch.WorkingDirectory, plan, available, context);
    }

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

        // The .env files are read once, here. This plan (pairs, files, ordinary values) goes to the page, the fingerprint, the audit
        // row and the launch unchanged: a file edited later changes nothing.
        EnvResult composed = EnvDeclarations.Compose(args.EnvFiles, workingDirectory, args.Secrets, environment ?? Environment.GetEnvironmentVariable);
        if (composed.Plan is not { } plan)
        {
            return await Fail(Usage, composed.Error!);
        }

        foreach (string note in plan.Notes)
        {
            await stderr.WriteLineAsync("with-secrets: " + note);
        }

        return await RunPlan(args.Program, args.Arguments, args.Reason, workingDirectory, plan, available, new LaunchContext());
    }

    private async Task<int> RunPlan(string program, IReadOnlyList<string> typedArguments, string reason, string workingDirectory, EnvPlan plan, IReadOnlyList<string> available, LaunchContext context)
    {
        if (plan.Mappings.Count == 0)
        {
            return await Fail(Usage, "Name the secrets with --secrets NAME[,NAME...]. There is no option for all secrets.");
        }

        IReadOnlyList<string> names = [.. plan.Mappings.Select(mapping => mapping.Secret).Distinct(StringComparer.Ordinal)];
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

        string? refusal = Policy.Check(program, typedArguments);
        if (refusal is not null)
        {
            return await Fail(Usage, refusal);
        }

        // A request that carries the sender's environment is resolved against that PATH, as the sender's own shell would.
        string? resolved = context.Environment is { } senderEnvironment
            ? ProgramResolver.Resolve(program, workingDirectory, EnvironmentValue(senderEnvironment, "PATH") ?? "", pathExt: EnvironmentValue(senderEnvironment, "PATHEXT") ?? "")
            : ProgramResolver.Resolve(program, workingDirectory);
        if (resolved is null)
        {
            return await Fail(NotFound, $"Program not found on PATH: {ApprovalSummary.Clean(program)}. The working directory is not searched. Use ./name to run a file there.");
        }

        string? alias = AppExecutionAlias(program, resolved);
        if (alias is not null)
        {
            return await Fail(Usage, alias);
        }

        // Write the program and the script as full paths. The prompt shows them, and they are what runs. What is checked and shown
        // is the expanded command, and it must read the same as the typed one.
        resolved = PathExpander.Full(resolved, workingDirectory);
        IReadOnlyList<string> arguments = PathExpander.ExpandScript(program, typedArguments, workingDirectory);
        string? expandedRefusal = Policy.CheckExpanded(program, typedArguments, arguments) ?? Policy.CheckBatchFile(resolved, arguments);
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
        int scriptIndex = PathExpander.ScriptArgumentIndex(program, typedArguments, workingDirectory);

        // A script that is too big to be hashed and shown is never run unseen.
        string? oversized = OversizedScript(program, resolved, typedArguments, workingDirectory);
        if (oversized is not null)
        {
            return await Fail(Usage, $"The script {ApprovalSummary.Clean(oversized)} is larger than 1 MB, which is more than the approval page can show. Split it into smaller files, or run a program that loads it. Nothing was run.");
        }

        // The script an interpreter is told to run must exist, so that the page can show it.
        if (Policy.ScriptIndex(program, typedArguments) is { } named && named >= 0 && scriptIndex < 0)
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
            script = scriptPath is null ? null : ScriptView.Read(scriptPath) with { Guessed = PathExpander.IsGuess(program, typedArguments) };
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

            if (Path.GetFileNameWithoutExtension(program).Equals("powershell", StringComparison.OrdinalIgnoreCase) && script.NonAscii && !script.Bom)
            {
                return await Fail(Usage, $"Windows PowerShell 5.1 reads the script {ApprovalSummary.Clean(script.Path)} in the ANSI code page when it has no byte order mark, so it would run other characters than the page shows. Save the script with a UTF-8 BOM or use only ASCII.");
            }
        }

        AfterScriptRead?.Invoke();

        List<string> links = [];
        links.AddRange(plan.Links ?? []);
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
        ApprovalRequest request = new(program, resolved, arguments, workingDirectory, reason, names, offer.IsOn ? offer : null, typedArguments, links, Sources: sources, Unlock: store.NeedsUnlock, Script: script, ProgramFile: programFile, Mappings: plan.Mappings, EnvFiles: plan.Files, EnvNames: [.. plan.Ordinary.Keys.Order(StringComparer.Ordinal)], EnvValues: plan.Ordinary, InheritedEnvironment: context.Environment);
        Fingerprint fingerprint = RequestFingerprint.Compute(request);

        // What the page shows must be the file the fingerprint covers; a file that changed in between is not approved unseen.
        foreach (ScriptView shown in new[] { script, programFile }.OfType<ScriptView>())
        {
            if (!fingerprint.Files.TryGetValue(shown.Path, out string? hashed) || hashed != shown.Sha256)
            {
                return await Fail(Usage, "The script changed while the request was being made, so nothing was run. Ask again.");
            }
        }

        // A request that came over the API must be the one that is approved and launched: nothing in it may differ from the page's data.
        if (context.Request is { } launch && LaunchRequestBinding.Mismatch(launch, request) is { } mismatch)
        {
            return await Fail(Usage, "the launch request is not the request that would be approved (" + mismatch + "). Nothing was run.");
        }

        // The request id goes into the text the person signs, so a saved approval names the request it covers.
        request = request with { RequestId = fingerprint.Key };

        // A saved approval that does not verify is never used; the person is asked again.
        GrantLookup saved = offer.IsOn ? grants!.Find(fingerprint.Key, offer.MaxMinutes) : GrantLookup.None;

        // Behind a host service, a saved approval is also tied to the machine's security revision: one made before the machine was
        // disabled or untrusted (or before this service started) is not honoured; the person is asked again.
        if (saved.Grant is not null && context.Authorization is { } revisionHost && !revisionHost.SavedStillValid(fingerprint.Key))
        {
            saved = GrantLookup.None;
        }

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
                // A saved approval stands in for the page, not for the authority: the machine must still be Trusted.
                if (context.Authorization is { } reusedHost && context.Request is { } reusedLaunch)
                {
                    AuthorizationOutcome reused = await reusedHost.AuthorizeAsync(reusedLaunch, () => ApprovalDecision.Allow("saved approval"), context.Cancel);
                    if (!reused.Decision.Approved)
                    {
                        audit.TryWrite("denied", request, reused.Decision.Detail, files: fingerprint.Files);

                        return context.Cancel.IsCancellationRequested ? await Cancelled() : await Fail(Denied, reused.AuthorityMessage ?? $"The user did not approve ({reused.Decision.Detail}). Do not retry. Ask the user.");
                    }
                }

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
                ApprovalDecision decision;
                string? authorityMessage = null;
                HostAuthorization? savedRevisionHost = null;
                if (context.Authorization is { } host && context.Request is { } launched)
                {
                    // The authority decides whether this machine may ask at all; only then is the person asked, for exactly this request.
                    AuthorizationOutcome outcome = await host.AuthorizeAsync(launched, () =>
                    {
                        stderr.WriteLine("with-secrets: waiting for the user to approve this request...");
                        stderr.WriteLine(ApprovalSummary.BuildMessage(request, showValues: false));

                        return approver.Request(request, context.Cancel);
                    }, context.Cancel);
                    decision = outcome.Decision;
                    authorityMessage = outcome.AuthorityMessage;
                    savedRevisionHost = host;
                }
                else
                {
                    await stderr.WriteLineAsync("with-secrets: waiting for the user to approve this request...");
                    await stderr.WriteLineAsync(ApprovalSummary.BuildMessage(request, showValues: false));
                    decision = approver.Request(request, context.Cancel);
                }

                unlock = decision.Unlock;
                if (!decision.Approved && context.Cancel.IsCancellationRequested)
                {
                    audit.TryWrite("denied", request, "cancelled by the client", files: fingerprint.Files);

                    return await Cancelled();
                }

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
                    return await Fail(Denied, authorityMessage ?? $"The user did not approve ({decision.Detail}). Do not retry. Ask the user.");
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
                    savedRevisionHost?.RememberSaved(fingerprint.Key);
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

            // A launch that was cancelled while the page was open (the client left, or the service is stopping) decrypts nothing.
            if (context.StaleReason() is { } stale)
            {
                audit.TryWrite("finished", request, "cancelled before the program started (" + stale + ")", Denied, fingerprint.Files);

                return await Cancelled();
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
                // The variable the program sees is the left side of the pair; the redactor gets every value.
                Dictionary<string, string> injected = request.Mappings!.ToDictionary(mapping => mapping.Variable, mapping => secrets.Text(mapping.Secret), StringComparer.Ordinal);

                // Prepare the child and its environment, then commit through the gate: the process starts only if the launch was not
                // cancelled and the local authorization did not change since it began. The loser of that race starts nothing and
                // its prepared environment is thrown away. Once started, nothing here touches the child.
                PreparedChild prepared = ChildRunner.Prepare(new ChildSpec(resolved, arguments, workingDirectory, injected, plan.Ordinary, context.Environment));
                System.Diagnostics.Process? process = null;
                string? startFailure = null;
                bool committed = false;
                try
                {
                    context.AfterPrepare?.Invoke(prepared);
                    committed = context.Gate.TryCommit(context.Revision, context.Cancel, () => process = prepared.Start(out startFailure), () => context.StaleReason() is null);
                }
                finally
                {
                    if (!committed)
                    {
                        prepared.Discard();
                    }
                }

                if (!committed)
                {
                    audit.TryWrite("finished", request, "cancelled before the program started", Denied, fingerprint.Files);

                    return await Cancelled();
                }

                if (process is null)
                {
                    await stderr.WriteLineAsync(startFailure);
                    Outcome = LaunchOutcome.Failed;
                    audit.TryWrite("finished", request, "the program could not be started", NotFound, fingerprint.Files);

                    return NotFound;
                }

                // The client's own cancel (Ctrl+C, a closed connection, the cancel route) ends the program and its children. An
                // invalidation of the authorization never does: it is not this token.
                System.Diagnostics.Process started = process;
                using CancellationTokenRegistration kill = context.Cancel.Register(() =>
                {
                    try
                    {
                        started.Kill(true);
                    }
                    catch (Exception error) when (error is InvalidOperationException or System.ComponentModel.Win32Exception or NotSupportedException)
                    {
                        // Already ended.
                    }
                });
                try
                {
                    context.AfterCommit?.Invoke();
                    exitCode = await prepared.WaitAsync(process, stdout, stderr);
                }
                catch (Exception error) when (error is not OutOfMemoryException)
                {
                    try
                    {
                        started.Kill(true);
                    }
                    catch (Exception killError) when (killError is InvalidOperationException or System.ComponentModel.Win32Exception or NotSupportedException)
                    {
                        // Already ended.
                    }

                    AppLog.Warn("launch failed after the program started: {Type}", error.GetType().Name);
                    Outcome = LaunchOutcome.Failed;
                    audit.TryWrite("finished", request, "internal error after the program started", StoreError, fingerprint.Files);
                    await stderr.WriteLineAsync("with-secrets: internal error after the program started; it may have run. Check its effects before retrying.");

                    return StoreError;
                }
            }

            Outcome = LaunchOutcome.Exited;

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
        Outcome = code == Denied ? LaunchOutcome.Denied : LaunchOutcome.Failed;
        await stderr.WriteLineAsync("with-secrets: " + message);

        return code;
    }

    /// <summary>The launch ended before the program started because it was cancelled or its authorization was invalidated.</summary>
    private async Task<int> Cancelled()
    {
        await stderr.WriteLineAsync("with-secrets: the launch was cancelled before the program started. Nothing was run.");
        Outcome = LaunchOutcome.Cancelled;

        return Denied;
    }

    private static string? EnvironmentValue(IReadOnlyDictionary<string, string> environment, string name)
    {
        StringComparison comparison = OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal;

        return environment.FirstOrDefault(item => string.Equals(item.Key, name, comparison)) is { Key: not null } found ? found.Value : null;
    }
}

/// <summary>
/// What a launch carries besides its request: the gate it commits through and the revision it began at, the token that cancels it,
/// the environment for the child, and (for tests) two hooks. A run with no context starts at once, with the
/// environment of this process.
/// </summary>
public sealed class LaunchContext
{
    public LaunchGate Gate { get; init; } = new();

    /// <summary>The <see cref="LaunchGate.Revision" /> read when the launch began.</summary>
    public int Revision { get; init; }

    public CancellationToken Cancel { get; init; }

    /// <summary>The environment the child inherits (null: the environment of this process).</summary>
    public IReadOnlyDictionary<string, string>? Environment { get; init; }

    /// <summary>The host's side of the authority protocol. A launch that came over the API asks the authority through it before anything is decrypted; null only for the in-process runs of tests.</summary>
    public HostAuthorization? Authorization { get; init; }

    /// <summary>The request that came over the API, when it did; the approval is checked against it.</summary>
    public LaunchRequest? Request { get; internal set; }

    /// <summary>
    /// Why the launch must not go on, or null: the client cancelled, the authorization was invalidated since it began, or the
    /// request expired while it waited.
    /// </summary>
    internal string? StaleReason()
    {
        if (Cancel.IsCancellationRequested)
        {
            return "cancelled";
        }

        if (Gate.Revision != Revision)
        {
            return "authorization invalidated";
        }

        return Request is { } request && DateTimeOffset.UtcNow >= request.Expires ? "request expired" : null;
    }

    /// <summary>Test hook: the child is prepared and not started, the gate is not yet taken.</summary>
    internal Action<PreparedChild>? AfterPrepare { get; init; }

    /// <summary>Test hook: the child was started (the gate is released).</summary>
    internal Action? AfterCommit { get; init; }
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
