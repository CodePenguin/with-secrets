using System.Security.Cryptography;

namespace WithSecrets;

/// <summary><paramref name="EnvFiles" /> are the -f files; null or empty means the default .env in the working directory.</summary>
public sealed record RunArgs(IReadOnlyList<string> Secrets, string Reason, string Program, IReadOnlyList<string> Arguments, IReadOnlyList<string>? EnvFiles = null);

/// <summary>
/// Exit codes: 2 usage, 3 denied, 4 store error, 5 audit error, 127 program not found. Anything else is the program's own.
/// Every run is asked: nothing an approval says is kept for a later run. <paramref name="reuse" /> is the times a grant may last (from the settings); it is used
/// only by <c>--approve</c>, which makes a grant.
/// </summary>
public sealed class RunCommand(ISecretSource store, IApprover approver, TextWriter stdout, TextWriter stderr, ReuseOffer? reuse = null, Func<string, string?>? environment = null)
{
    /// <summary>What the last <c>approve</c> came to, for its audit event: a reason code for a refusal, the grant's id for a grant.</summary>
    private string _approveReason = "";
    private string _approveGrant = "";
    private VerifiedCredential? _approveKey;

    private const string AuditEventMessage = "cannot commit the signed audit event, so nothing was run.";

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
    public async Task<int> ExecuteAsync(LaunchRequest launch, LaunchContext context, bool approveOnly = false)
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
            // A remote authority holds the store: this host reads none, and the authority refuses a name it does not have.
            available = context.Authorization is { IsRemote: true } ? launch.SecretNames : store.ListNames();
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

        return await RunPlan(launch.Program, launch.Arguments, launch.Reason, launch.WorkingDirectory, plan, available, context, approveOnly);
    }

    /// <summary>A run without the service (tests): <paramref name="audit" /> is where the signed events go, as the service gives them to a run (none: nothing is recorded).</summary>
    internal async Task<int> ExecuteAsync(RunArgs args, string workingDirectory, IHostAudit? audit = null)
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

        // The .env files are read once, here. This plan (pairs, files, ordinary values) goes to the page, the fingerprint
        // and the launch unchanged: a file edited later changes nothing.
        EnvResult composed = EnvDeclarations.Compose(args.EnvFiles, workingDirectory, args.Secrets, environment ?? Environment.GetEnvironmentVariable);
        if (composed.Plan is not { } plan)
        {
            return await Fail(Usage, composed.Error!);
        }

        foreach (string note in plan.Notes)
        {
            await stderr.WriteLineAsync("with-secrets: " + note);
        }

        return await RunPlan(args.Program, args.Arguments, args.Reason, workingDirectory, plan, available, new LaunchContext { Audit = audit });
    }

    private async Task<int> RunPlan(string program, IReadOnlyList<string> typedArguments, string reason, string workingDirectory, EnvPlan plan, IReadOnlyList<string> available, LaunchContext context, bool approveOnly = false)
    {
        IReadOnlyList<EncryptedValue> encrypted = plan.Encrypted ?? [];
        bool requiresDotenvx = encrypted.Count > 0 || context.Request?.DotenvxInputDigest is not null
            || DotenvxRun.HasPolicy(workingDirectory) || plan.HasDotenvxDeclarations;
        if (plan.Mappings.Count == 0 && !requiresDotenvx)
        {
            return await Fail(Usage, "Name the secrets with --secrets NAME[,NAME...]. There is no option for all secrets.");
        }

        IReadOnlyList<string> names = [.. plan.Mappings.Select(mapping => mapping.Secret).Distinct(StringComparer.Ordinal)];
        string[] invalid = [.. names.Where(name => !SecretNames.IsValid(name))];
        if (invalid.Length > 0)
        {
            return await Fail(Usage, $"Invalid secret name: {string.Join(", ", invalid.Select(ApprovalSummary.Clean))}.");
        }

        // Before any page: nothing the page cannot show (a secret, a decrypted value) goes to a variable that changes which code runs, where traffic goes or who a
        // commit is by. The requests that come over the API were checked the same way (EnvDeclarations.FromRequest); this is the same rule for every way in.
        if (plan.Mappings.Select(mapping => mapping.Variable).Concat(encrypted.Select(value => value.Variable)).FirstOrDefault(EnvDeclarations.IsProtectedVariable) is { } protectedVariable)
        {
            return await Fail(Usage, $"A secret cannot be given to {ApprovalSummary.Clean(protectedVariable)}, because it changes which code runs. Nothing was run.");
        }

        string? dotenvx = null;
        string? dotenvxInputs = context.Request?.DotenvxInputDigest;
        if (requiresDotenvx && context.Request is null)
        {
            if (plan.Files.Count == 0)
            {
                return await Fail(Usage, "The dotenvx project policy requires a selected .env file.");
            }

            string executable = Environment.GetEnvironmentVariable(DotenvxRun.ExecutableVariable) ?? "";
            if (!Path.IsPathFullyQualified(executable) || !File.Exists(executable))
            {
                return await Fail(Usage, $"Set {DotenvxRun.ExecutableVariable} to a trusted absolute dotenvx path to resolve {encrypted.FirstOrDefault()?.Variable ?? "the project environment"}.");
            }

            dotenvx = executable;
            try
            {
                dotenvxInputs = DotenvxRun.InputDigest(workingDirectory, plan.Files, plan.FileHashes);
            }
            catch (Exception error) when (error is IOException or UnauthorizedAccessException or DotenvxResolutionException)
            {
                return await Fail(Usage, "Cannot read the project inputs for dotenvx. Nothing was run.");
            }
        }

        if (requiresDotenvx && context.Request is not null && context.Request.DotenvxInputDigest is null)
        {
            return await Fail(Usage, "The requesting client must bind the dotenvx project inputs before approval.");
        }

        string[] missing = [.. names.Where(name => !available.Contains(name, StringComparer.Ordinal))];
        if (missing.Length > 0)
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

        // A remote authority approves and decrypts: the authority's grants stand in for a local decision.
        bool remote = context.Authorization is { IsRemote: true };
        Dictionary<string, string> sources = names.ToDictionary(name => name, store.LabelFor, StringComparer.Ordinal);
        var dynamicNames = context.Request?.DotenvxDynamicNames ?? (context.Request is null && dotenvxInputs is not null ? plan.DynamicNames : null);
        if (dynamicNames is { Count: 0 })
        {
            dynamicNames = null;
        }
        ApprovalRequest request = new(program, resolved, arguments, workingDirectory, reason, names, null, typedArguments, links, Sources: sources, Script: script, ProgramFile: programFile, Mappings: plan.Mappings, EnvFiles: plan.Files, EnvNames: [.. plan.Ordinary.Keys.Order(StringComparer.Ordinal)], EnvValues: plan.Ordinary, InheritedEnvironment: context.Environment, Decrypts: [.. encrypted.Select(value => value.ToItem())], DotenvxInputDigest: dotenvxInputs, DotenvxDynamicNames: dynamicNames);
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

        // The request id goes into the text the person signs, so the approval names the request it covers.
        request = request with { RequestId = fingerprint.Key };

        // A grant has its own scope key: the machine, the request fingerprint and the FULL argument list (inline code included), so a grant for one
        // command line never covers another.
        string? grantScope = context.Authorization is { } scopeHost ? GrantEvidence.Scope(scopeHost.Fingerprint, fingerprint.Key, arguments) : null;

        // The host's signed audit trail. Every run that gets here names secrets, so every one is
        // secret-bearing: its authorization event is committed durably BEFORE anything is decrypted, and a run whose event cannot be committed does not go on. The later
        // events (launch, execution) cannot be a condition of a launch that already happened, so a failure to record them is only logged. No value of any secret is
        // recorded: the arguments are redacted, and the reasons are codes.
        IHostAudit? hostAudit = context.Audit;
        string auditProgram = resolved;
        IReadOnlyList<string> auditArguments = hostAudit is null ? [] : AuditRedaction.Arguments(arguments, resolved);
        string auditRequestId = context.Request?.RequestId ?? "";
        // The metadata of every event of the run: what the person approved, by name and fingerprint only (secret names, the variable mapping, the .env files and the
        // fingerprints of the files the approval covers). Never a value. The approving key is added to the event that carries it.
        Dictionary<string, string> auditMetadata = new(StringComparer.Ordinal) { ["secrets"] = string.Join(",", request.SecretNames.OrderBy(name => name, StringComparer.Ordinal)) };
        if (request.Mappings is { Count: > 0 } mappings && mappings.Any(pair => pair.Variable != pair.Secret))
        {
            auditMetadata["variables"] = string.Join(",", mappings.Select(pair => pair.Variable + "=" + pair.Secret));
        }

        if (request.EnvFiles is { Count: > 0 } envFiles)
        {
            auditMetadata["envFiles"] = string.Join(",", envFiles);
        }

        if (request.Decrypts is { Count: > 0 } decrypts)
        {
            // Names and a short fingerprint of each ciphertext (the hash of a ciphertext is not a secret); never a value, a ciphertext or a key.
            auditMetadata["decrypts"] = string.Join(",", decrypts.Select(item => item.Variable + ":" + item.Short));
        }

        if (fingerprint.Files.Count > 0)
        {
            auditMetadata["files"] = string.Join(";", fingerprint.Files.Select(file => file.Key + "=" + file.Value));
        }

        bool Record(string type, string outcome, string reason, string grantId = "", int? exit = null, string key = "", AuditKeys? attribution = null)
        {
            if (hostAudit is null)
            {
                return true;
            }

            Dictionary<string, string> metadata = new(auditMetadata, StringComparer.Ordinal);
            if (key.Length > 0)
            {
                metadata["key"] = key;
            }

            attribution?.Metadata(metadata);
            return hostAudit.TryRecord(new AuditFacts(type, outcome, reason, auditRequestId, workingDirectory, auditProgram, auditArguments, grantId, exit, metadata));
        }

        // Remote authority: the page, the passkey tap and the decryption happen at the authority; what comes back is the verified, signed delivery. Nothing is decrypted here.
        async Task<(int? Exit, SecretValues? Values, string Grant)> RemoteAuthorizeAsync()
        {
            await stderr.WriteLineAsync("with-secrets: waiting for the authority to approve this request...");
            await stderr.WriteLineAsync(ApprovalSummary.BuildMessage(request, showValues: false));
            // The host's own record that it asked is committed before the authority is asked (and before any value can arrive); the outcome follows as its own event.
            if (!Record(AuditEventTypes.Authorization, "requested", "remote"))
            {
                return (await Fail(AuditError, AuditEventMessage), null, "");
            }

            RemoteAuthorization outcome = await context.Authorization!.AuthorizeRemoteAsync(context.Request!, GrantEvidence.Scope(context.Authorization.Fingerprint, fingerprint.Key, arguments), new PageContext(resolved, arguments, links, script, programFile, fingerprint.Key), link => context.OnApprovalLink?.Invoke(link), context.Cancel);
            if (!outcome.Ok)
            {
                Record(AuditEventTypes.Authorization, "denied", context.Cancel.IsCancellationRequested ? "cancelled" : outcome.Code, attribution: outcome.Keys);

                return (context.Cancel.IsCancellationRequested ? await Cancelled() : await Fail(outcome.Code == "authority-locked" ? LaunchClient.AuthorityLocked : Denied, outcome.Message), null, "");
            }

            SecretValues values = outcome.Values!;
            bool viaGrant = outcome.Via == SecretsDelivery.ViaGrant;
            string grant = viaGrant ? outcome.GrantId : "";
            // The authorization event is committed before the program starts (the values are only in memory until then); a run whose event cannot be committed does not go on.
            if (!Record(AuditEventTypes.Authorization, viaGrant ? "granted" : "approved", viaGrant ? "online" : ReasonCodes.Approved, grant, attribution: outcome.Keys))
            {
                values.Dispose();

                return (await Fail(AuditError, AuditEventMessage), null, "");
            }

            // A script can change while the prompt is open. The person approved what they saw, so run only that.
            if (RequestFingerprint.Compute(request).Key != fingerprint.Key)
            {
                values.Dispose();
                Record(AuditEventTypes.Launch, "failed", "files-changed", grant);

                return (await Fail(Denied, "A file named in the command changed while the prompt was open, so nothing was run. Ask again."), null, "");
            }

            return (null, values, grant);
        }

        // approve: the same validation and the human approval, but the result is a grant for this scope and nothing is launched.
        if (approveOnly)
        {
            if (remote)
            {
                return await Fail(Usage, "creating a grant from a host whose authority is remote is not built yet (a grant that exists for this machine at the authority is used by runs here). Nothing was saved.");
            }

            // The grant lets later runs decrypt without a tap, so the request for it is committed first, like the authorization of a run: without it, no tap is asked for.
            if (!Record(AuditEventTypes.Authorization, "approval-requested", "grant"))
            {
                return await Fail(AuditError, AuditEventMessage);
            }

            int approved = await ApproveGrantOnly(request, fingerprint, context, grantScope);
            Record(AuditEventTypes.Authorization, approved == 0 ? "grant-approved" : "denied", approved == 0 ? "" : _approveReason.Length > 0 ? _approveReason : "refused", _approveGrant, attribution: approved == 0 ? new AuditKeys(Key: _approveKey) : null);

            return approved;
        }

        // A grant for exactly this request (the authority answers; when it cannot be reached nothing is run) stands in for the
        // approval page's decision. A request that is not covered, or whose grant ended, goes through the page as before.
        GrantUse? grantUse = null;
        if (!remote && context.Authorization is { } grantHost && context.Request is { } grantLaunch)
        {
            grantUse = await grantHost.TryUseGrantAsync(grantLaunch, grantScope!, context.Cancel);
            if (grantUse.Kind == GrantUseKind.Denied)
            {
                Record(AuditEventTypes.Authorization, "denied", context.Cancel.IsCancellationRequested ? "cancelled" : "grant-check-failed");

                return context.Cancel.IsCancellationRequested ? await Cancelled() : await Fail(Denied, grantUse.Message);
            }
        }

        string runGrant = grantUse is { Kind: GrantUseKind.Granted } usedGrant ? usedGrant.GrantId : "";
        SecretValues? delivered = null;
        try
        {
            if (remote)
            {
                (int? exit, delivered, runGrant) = await RemoteAuthorizeAsync();
                if (exit is { } remoteExit)
                {
                    return remoteExit;
                }
            }
            else if (grantUse is { Kind: GrantUseKind.Granted } granted)
            {
                const string how = "checked with the authority";
                await stderr.WriteLineAsync($"with-secrets: a grant covers this request (grant {granted.GrantId}, {how}); no approval page decision is needed.");
                if (!Record(AuditEventTypes.Authorization, "granted", "online", granted.GrantId, attribution: granted.Keys))
                {
                    return await Fail(AuditError, AuditEventMessage);
                }
            }
            else
            {
                ApprovalDecision decision;
                string? authorityMessage = null;
                string? authorityCode = null;
                ApprovalRequest asked = OfferTime(request, context, grantScope);
                if (context.Authorization is { } host && context.Request is { } launched)
                {
                    // The authority decides whether this machine may ask at all; only then is the person asked, for exactly this request.
                    AuthorizationOutcome outcome = await host.AuthorizeAsync(launched, () =>
                    {
                        stderr.WriteLine("with-secrets: waiting for the user to approve this request...");
                        stderr.WriteLine(ApprovalSummary.BuildMessage(asked, showValues: false));

                        return approver.Request(asked, context.Cancel);
                    }, context.Cancel);
                    decision = outcome.Decision;
                    authorityMessage = outcome.AuthorityMessage;
                    authorityCode = outcome.Code;
                }
                else
                {
                    await stderr.WriteLineAsync("with-secrets: waiting for the user to approve this request...");
                    await stderr.WriteLineAsync(ApprovalSummary.BuildMessage(asked, showValues: false));
                    decision = approver.Request(asked, context.Cancel);
                }

                if (!decision.Approved && context.Cancel.IsCancellationRequested)
                {
                    Record(AuditEventTypes.Authorization, "denied", "cancelled");

                    return await Cancelled();
                }

                // The signed authorization event: for an approval it must be committed before anything is decrypted. A denial is recorded too (nothing runs either way).
                string authorizationCode = authorityCode ?? (decision.Approved ? ReasonCodes.Approved : ReasonCodes.UserDenied);
                if (!Record(AuditEventTypes.Authorization, decision.Approved ? "approved" : "denied", authorizationCode, key: decision.Credential?.Name ?? AdminAudit.KeyName(decision.Detail), attribution: new AuditKeys(Key: decision.Credential, SessionKey: decision.SessionKey)) && decision.Approved)
                {
                    return await Fail(AuditError, AuditEventMessage);
                }

                if (!decision.Approved)
                {
                    return await Fail(Denied, authorityMessage ?? (decision.TimedOut ? HostAuthorization.TimeoutMessage : $"The user did not approve ({decision.Detail}). Do not retry. Ask the user."));
                }

                // A script can change while the prompt is open. The person approved what they saw, so run only that.
                if (RequestFingerprint.Compute(request).Key != fingerprint.Key)
                {
                    Record(AuditEventTypes.Launch, "failed", "files-changed", runGrant);

                    return await Fail(Denied, "A file named in the command changed while the prompt was open, so nothing was run. Ask again.");
                }

                // A launch that was cancelled or expired while the page was open records nothing and decrypts nothing (the same check as below, before the record is asked for).
                if (decision.ReuseMinutes == 0 && context.StaleReason() is { } staleBeforeRecord)
                {
                    Record(AuditEventTypes.Launch, "cancelled", staleBeforeRecord.Replace(' ', '-'), runGrant);

                    return await Cancelled();
                }

                // Every approval is a grant. A time was chosen instead of once: the same approval (one passkey tap) also makes the grant. Once: it is recorded
                // as a consumed once-only grant (it covers no further run). If either cannot be made, nothing is run.
                string? grantProblem = decision.ReuseMinutes != 0 ? await GrantFromRun(decision, context, grantScope)
                    : context.Authorization is { IsRemote: false } ? await OnceGrantFromRun(decision, context, grantScope)
                    : null;
                if (grantProblem is not null)
                {
                    Record(AuditEventTypes.Launch, "failed", "grant-not-made");

                    return await Fail(Denied, grantProblem);
                }
            }

            // The files the person saw are held open (on Windows: nobody can write or delete them) from now until the program ends,
            // and checked once more against what was shown. If that cannot be done, nothing runs.
            using HeldFiles held = new();
            string? holdFailure = held.Hold(new[] { script, programFile }.OfType<ScriptView>().ToList());
            if (holdFailure is not null)
            {
                Record(AuditEventTypes.Launch, "failed", "files-not-held", runGrant);

                return await Fail(Denied, holdFailure);
            }

            // What the program is told to run: the files as they were shown (a private copy where the system cannot lock them, see HeldFiles).
            string runProgram = held.PathFor(resolved);
            string[] runArguments = [.. arguments.Select((argument, index) => index == scriptIndex ? held.PathFor(argument) : argument)];
            AfterHold?.Invoke();

            // A launch that was cancelled while the page was open (the client left, or the service is stopping) decrypts nothing.
            if (context.StaleReason() is { } stale)
            {
                Record(AuditEventTypes.Launch, "cancelled", stale.Replace(' ', '-'), runGrant);

                return await Cancelled();
            }

            // Resolve project ciphertext in a separate process before reading locally stored values.
            Dictionary<string, string> injected;
            try
            {
                injected = !requiresDotenvx ? new(StringComparer.Ordinal)
                    : context.DotenvxResolver is { } resolve ? await resolve()
                    : await DotenvxRun.ResolveAsync(dotenvx!, workingDirectory, plan.Files,
                        [.. encrypted.Select(value => value.Variable), .. dynamicNames ?? []], context.Cancel, dotenvxInputs);
                if (context.Request is null && (dynamicNames ?? []).Any(name => !injected.ContainsKey(name))
                    || encrypted.Any(item => !injected.TryGetValue(item.Variable, out string? value) || value == item.Ciphertext || !UsablePlaintext(value)))
                {
                    throw new DotenvxResolutionException();
                }
            }
            catch (OperationCanceledException) when (context.Cancel.IsCancellationRequested)
            {
                Record(AuditEventTypes.Launch, "cancelled", "dotenvx-cancelled", runGrant);
                return await Cancelled();
            }
            catch (DotenvxResolutionException error)
            {
                Record(AuditEventTypes.Launch, "failed", "dotenvx-failed", runGrant);
                return await Fail(Usage, error.ApprovalRequired ? DotenvxRun.ApprovalError : "Cannot resolve the approved project environment with dotenvx. Nothing was run.");
            }

            if (context.StaleReason() is { } staleAfterDotenvx)
            {
                Record(AuditEventTypes.Launch, "cancelled", staleAfterDotenvx.Replace(' ', '-'), runGrant);

                return await Cancelled();
            }

            BeforeGrantRecheck?.Invoke();

            // A run under a grant asks the authority about it again just before the decryption (recording no second use): a grant that ended or was revoked since the first check decrypts nothing.
            if (grantUse is { Kind: GrantUseKind.Granted } covering && context.Authorization is { } recheckHost && context.Request is { } recheckLaunch)
            {
                GrantUse again = await recheckHost.TryUseGrantAsync(recheckLaunch, grantScope!, context.Cancel, recheck: true);
                if (again.Kind != GrantUseKind.Granted || again.GrantId != covering.GrantId)
                {
                    Record(AuditEventTypes.Launch, context.Cancel.IsCancellationRequested ? "cancelled" : "failed", "grant-ended", runGrant);

                    return context.Cancel.IsCancellationRequested ? await Cancelled() : await Fail(Denied, again.Kind == GrantUseKind.Denied ? again.Message : "the grant that covered this request ended before anything was decrypted. Nothing was run.");
                }

                // The check above awaited the authority: a cancel, an invalidation, a lock or an expiry meanwhile decrypts nothing either.
                if (context.StaleReason() is { } staleAfterRecheck)
                {
                    Record(AuditEventTypes.Launch, "cancelled", staleAfterRecheck.Replace(' ', '-'), runGrant);

                    return await Cancelled();
                }
            }

            BeforeDecrypt?.Invoke();

            // Only the approved names are decrypted, with the store key the administrator's unlock opened, inside the authority's lock; the strings the child needs cannot be wiped (see SecretValues).
            SecretValues secrets;
            try
            {
                secrets = delivered ?? (names.Count == 0 ? new SecretValues(new Dictionary<string, byte[]>()) : store.GetValues(names));
            }
            catch (AuthorityLockedException)
            {
                Record(AuditEventTypes.Launch, "cancelled", "authority-locked", runGrant);

                return await Cancelled();
            }
            catch (Exception error)
            {
                Record(AuditEventTypes.Launch, "failed", "decrypt-failed", runGrant);

                return await Fail(StoreError, $"cannot decrypt the secret store: {error.Message}");
            }

            int exitCode;
            using (secrets)
            {
                secrets.OpenedBy?.AddTo(auditMetadata, "unlock");
                // The variable the program sees is the left side of the pair; the redactor gets every value.
                foreach (SecretMapping mapping in request.Mappings!)
                {
                    injected[mapping.Variable] = secrets.Text(mapping.Secret);
                }

                // Final filter, whatever the earlier checks said: nothing the page could not show goes to a variable that changes which code runs, where
                // traffic goes or who a commit is by. Nothing is run and nothing is decrypted.
                if (request.Mappings!.Select(mapping => mapping.Variable).Concat(encrypted.Select(value => value.Variable)).FirstOrDefault(EnvDeclarations.IsProtectedVariable) is { } protectedName)
                {
                    Record(AuditEventTypes.Launch, "failed", "protected-variable", runGrant);

                    return await Fail(Usage, $"A secret value cannot be given to {ApprovalSummary.Clean(protectedName)}, because it changes which code runs. Nothing was run.");
                }

                // Prepare the child and its environment, then commit through the gate: the process starts only if the launch was not
                // cancelled and the local authorization did not change since it began. The loser of that race starts nothing and
                // its prepared environment is thrown away. Once started, nothing here touches the child.
                PreparedChild prepared = ChildRunner.Prepare(new ChildSpec(runProgram, runArguments, workingDirectory, injected, plan.Ordinary, context.Environment));
                System.Diagnostics.Process? process = null;
                string? startFailure = null;
                string? copyProblem = null;
                bool committed = false;
                try
                {
                    context.AfterPrepare?.Invoke(prepared);

                    // The copies are checked in the same step as the start, the last point at which this process can look: nothing runs if one is not what was shown.
                    // The interpreter opens the file a moment later by its path, so this narrows the window and does not close it (see HeldFiles).
                    committed = context.Gate.TryCommit(context.Revision, context.Cancel, () => process = (copyProblem = held.Verify()) is null ? prepared.Start(out startFailure) : null, () => context.StaleReason() is null);
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
                    Record(AuditEventTypes.Launch, "cancelled", "not-committed", runGrant);

                    return await Cancelled();
                }

                if (copyProblem is not null)
                {
                    Record(AuditEventTypes.Launch, "failed", "files-not-held", runGrant);

                    return await Fail(Denied, copyProblem);
                }

                if (process is null)
                {
                    await stderr.WriteLineAsync(startFailure);
                    Outcome = LaunchOutcome.Failed;
                    Record(AuditEventTypes.Launch, "failed", "start-failed", runGrant);

                    return NotFound;
                }

                // The client's own cancel (Ctrl+C, a closed connection, the cancel route) ends the program and its children. An
                // invalidation of the authorization never does: it is not this token.
                System.Diagnostics.Process started = process;
                Record(AuditEventTypes.Launch, "started", "", runGrant);
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
                    Record(AuditEventTypes.Execution, "failed", "internal-error", runGrant);
                    await stderr.WriteLineAsync("with-secrets: internal error after the program started; it may have run. Check its effects before retrying.");

                    return StoreError;
                }
            }

            Outcome = LaunchOutcome.Exited;

            Record(AuditEventTypes.Execution, "exited", "", runGrant, exitCode);

            return exitCode;
        }
        finally
        {
            delivered?.Dispose();
        }
    }

    /// <summary>
    /// A decrypted value the child may get: at least the store's minimum length (so the redactor is not steered to blank short words), at most the value
    /// limit, and no NUL or other control character except a tab. A NUL ends or splits an environment entry (on Windows it can add a variable no name check sees).
    /// </summary>
    internal static bool UsablePlaintext(string plain)
    {
        return plain.Length >= SecretNames.MinValueLength && plain.Length <= EnvDeclarations.MaxValue && !plain.Any(letter => char.IsControl(letter) && letter != '\t');
    }

    /// <summary>
    /// The request as the person is asked. With a local authority whose revision is known it carries what the grant's evidence must name (scope, security revision,
    /// contents): every approval is a grant, once included. When they can also choose a time here (the administration web app) and the settings offer times,
    /// it offers them, so a time lets the agent run this exact command again.
    /// </summary>
    private ApprovalRequest OfferTime(ApprovalRequest request, LaunchContext context, string? grantScope)
    {
        if (grantScope is null || context.Authorization is not { IsRemote: false, KnownRevision: { } revision } || context.Request is not { } launch)
        {
            return request;
        }

        List<string> lines = [.. request.ExtraLines ?? []];
        lines.AddRange(GrantEvidence.ApproveLines(revision, grantScope, contents: GrantEvidence.ContentsKey(launch.SecretNames, launch.Program, launch.WorkingDirectory)));
        ApprovalRequest shown = request with { RequestId = grantScope, ExtraLines = lines };

        return approver.OffersTime && reuse is { IsOn: true } times ? shown with { Reuse = times } : shown;
    }

    /// <summary>Makes the grant from the approval of a run that chose a time (the passkey assertion already signed it). Null when it was made, else why not.</summary>
    private static async Task<string?> GrantFromRun(ApprovalDecision decision, LaunchContext context, string? grantScope)
    {
        if (context.Authorization is not { } host || context.Request is not { } launch || grantScope is null)
        {
            return "a grant cannot be made here. Nothing was run.";
        }

        LaunchRequest grantRequest = launch with { RequestId = "grant-" + Convert.ToHexString(RandomNumberGenerator.GetBytes(12)).ToLowerInvariant() };
        GrantApproval result = await host.ApproveGrantAsync(grantRequest, grantScope, () => decision, context.Cancel);

        return result.Granted ? null : result.Message + " Nothing was run.";
    }

    /// <summary>Records the consumed once-only grant of a run approved once (the passkey assertion already signed it). Null when it was recorded, else why not.</summary>
    private static async Task<string?> OnceGrantFromRun(ApprovalDecision decision, LaunchContext context, string? grantScope)
    {
        if (context.Authorization is not { } host || context.Request is not { } launch || grantScope is null)
        {
            return "the approval cannot be recorded here. Nothing was run.";
        }

        // As for a grant with a time: its own request id.
        LaunchRequest onceRequest = launch with { RequestId = "grant-" + Convert.ToHexString(RandomNumberGenerator.GetBytes(12)).ToLowerInvariant() };
        GrantApproval result = await host.RecordOnceGrantAsync(onceRequest, grantScope, decision, context.Cancel);

        return result.Granted ? null : result.Message + " Nothing was run.";
    }

    /// <summary>
    /// <c>approve</c>: the person approves this exact request on the page and picks how long (the times the page offers); the authority records a grant for
    /// the request's scope (secrets, program, folder, script and .env plan: the fingerprint of the request) for that time and nothing is launched. A new
    /// approval needs the authority, so it fails while the authority cannot be reached. Nothing is decrypted here.
    /// </summary>
    private async Task<int> ApproveGrantOnly(ApprovalRequest request, Fingerprint fingerprint, LaunchContext context, string? grantScope)
    {
        if (context.Authorization is not { } host || context.Request is not { } launch || grantScope is null)
        {
            return await Fail(Denied, "no authority is configured for this host service. Nothing was saved.");
        }

        if (host.KnownRevision is not { } revision)
        {
            return await Fail(Denied, "this service has not yet checked in with its authority, so a grant cannot be made now. Try again in a moment.");
        }

        ReuseOffer times = reuse is { IsOn: true } ? reuse : ReuseOffer.Off;
        if (!times.IsOn)
        {
            return await Fail(Usage, "a grant needs a time to choose on the approval page, and the settings offer none (reuseMaxMinutes is below 10). Raise it with: with-secrets admin");
        }

        // The page offers the times, and says plainly that this makes a grant (no program runs) and what it covers. What the person signs includes the grant's scope and the machine's security revision, so the authority can keep the assertion as the grant's proof.
        List<string> lines =
        [
            "This creates a grant: for the time you choose, the agent can re-run exactly this command (same program, arguments, folder, secrets and script) without asking, until it ends or you revoke it.",
        ];
        lines.AddRange(GrantEvidence.ApproveLines(revision, grantScope, contents: GrantEvidence.ContentsKey(launch.SecretNames, launch.Program, launch.WorkingDirectory)));
        ApprovalRequest shown = request with { RequestId = grantScope, Reuse = times, Heading = "Create a grant for this exact command. Nothing runs now.", ExtraLines = lines };
        GrantApproval result = await host.ApproveGrantAsync(launch, grantScope, () =>
        {
            stderr.WriteLine("with-secrets: waiting for the user to approve this request and choose how long the grant lasts...");
            stderr.WriteLine(ApprovalSummary.BuildMessage(shown, showValues: false));
            ApprovalDecision decision = approver.Request(shown, context.Cancel);
            if (decision.Approved && !times.Allows(decision.ReuseMinutes))
            {
                decision = ApprovalDecision.Deny("the approval named a time that was not offered");
            }

            // A script can change while the prompt is open. The person approved what they saw.
            if (decision.Approved && RequestFingerprint.Compute(request).Key != fingerprint.Key)
            {
                decision = ApprovalDecision.Deny("a file named in the command changed while the prompt was open");
            }

            _approveKey = decision.Approved ? decision.Credential : null;

            return decision;
        }, context.Cancel);

        if (!result.Granted)
        {
            _approveReason = context.Cancel.IsCancellationRequested ? "cancelled" : result.Code;

            return context.Cancel.IsCancellationRequested ? await Cancelled() : await Fail(Denied, result.Message);
        }

        _approveGrant = result.GrantId ?? "";
        string ends = result.Expires is { } at ? $"until {at.UtcDateTime:yyyy-MM-dd HH:mm} UTC" : "with no end";
        Outcome = LaunchOutcome.Approved;
        await stdout.WriteLineAsync($"with-secrets: grant {result.GrantId} approved {ends}. A run of this exact command (every argument, the same secrets, folder, script and .env plan) needs no approval page decision while it lasts. Nothing was run.");

        return 0;
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

    /// <summary>Test hook: runs once the shown files are held (and copied) and before the child is prepared: the window in which a file could be swapped.</summary>
    internal static Action? AfterHold { get; set; }

    /// <summary>Test hook: runs after the hold and the stale check, before a run under a grant asks the authority about the grant again.</summary>
    internal static Action? BeforeGrantRecheck { get; set; }

    /// <summary>Test hook: runs after every check of a launch (the grant check again and the stale check after it included), immediately before the values are read.</summary>
    internal static Action? BeforeDecrypt { get; set; }

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

    /// <summary>Told the link of the approval page when the authority shows it (remote mode); the service sends it to the client as an approval event.</summary>
    public Action<string>? OnApprovalLink { get; init; }

    internal Func<Task<Dictionary<string, string>>>? DotenvxResolver { get; init; }

    /// <summary>
    /// The host's signed audit trail. A secret-bearing run must commit its authorization event here before anything is decrypted, and does not run when it cannot.
    /// Null only for the in-process runs of tests, which then record nothing here.
    /// </summary>
    public IHostAudit? Audit { get; init; }

    /// <summary>The request that came over the API, when it did; the approval is checked against it.</summary>
    public LaunchRequest? Request { get; internal set; }

    /// <summary>
    /// Why the launch must not go on, or null: the client cancelled, the authority (when it is this service) locked, the authorization was invalidated since it began, or the
    /// request expired while it waited. The child starts only if this is null in the step that starts it, so a lock that has begun never starts one.
    /// </summary>
    internal string? StaleReason()
    {
        if (Cancel.IsCancellationRequested)
        {
            return "cancelled";
        }

        if (Authorization?.LockState?.IsLocked == true)
        {
            return "authority locked";
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
/// The shown script files, held until disposed, and what the program is told to run. Every file's bytes must still hash to what was shown.
/// On Windows each file is opened so that nobody can write, delete or rename it meanwhile (FileShare.Read) and the program reads the file itself.
/// Elsewhere the operating system gives no such lock, so the checked bytes are written once to a private folder (owner only, outside the project,
/// read-only, checked again after writing) and the program is told to run that copy: <see cref="PathFor" /> gives its path. Whatever the file at the
/// original path becomes afterwards cannot change what runs. The copy is deleted when this is disposed.
/// The copy sits in a folder of its own beside links to the entries of the original's folder, so what a script finds by its own location (a sourced
/// sibling, an imported module, a dot-sourced file) is found as before. Those links lead to the files as they are, not as they were: they are what the
/// script loads, never what was shown or approved, and they are no more checked than they were. <see cref="Verify" /> checks the copies once more in the step that starts the program.
/// What this protects against: the original changing or being replaced after approval (the copy is what runs), another user of the machine (the copy's folder is
/// owner-only), a mistake in a script that writes beside itself (read-only), and a copy that was altered before the check (found, nothing runs).
/// What it does not: a process of the same user. It may loosen the permissions it owns and rewrite the copy after <see cref="Verify" /> and before the interpreter
/// opens the file, because Verify reads by path and the interpreter opens by path, and no operating system call ties the two without a native helper or a privilege.
/// Such a process can already read the program's environment (and so the secrets) from /proc or by attaching to it, so the guarantee is not claimed against it.
/// </summary>
internal sealed class HeldFiles(bool? copy = null) : IDisposable
{
    private readonly List<FileStream> _streams = [];
    private readonly Dictionary<string, string> _copies = new(StringComparer.Ordinal);
    private readonly bool _copyFiles = copy ?? !OperatingSystem.IsWindows();
    private readonly Dictionary<string, string> _shown = new(StringComparer.Ordinal);
    private string? _folder;

    /// <summary>The most entries of a script's folder that are linked beside its copy: a folder with more (a home or a download folder) gets none, never an arbitrary part.</summary>
    internal const int MaxLinkedEntries = 1000;

    /// <summary>Opens and checks every file, and makes the copies where they are used. Returns why not, or null.</summary>
    public string? Hold(IReadOnlyList<ScriptView> files)
    {
        foreach (ScriptView file in files)
        {
            try
            {
                FileStream stream = new(file.Path, FileMode.Open, FileAccess.Read, FileShare.Read);
                _streams.Add(stream);
                using MemoryStream bytes = new();
                stream.CopyTo(bytes);
                byte[] content = bytes.ToArray();
                if (Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(content)) != file.Sha256)
                {
                    return "A file named in the command changed after it was shown, so nothing was run. Ask again.";
                }

                // The executable bit is read from the file that was opened and hashed, not from the path again.
                UnixFileMode mode = OperatingSystem.IsWindows() ? default : File.GetUnixFileMode(stream.SafeFileHandle);
                if (_copyFiles && !_copies.ContainsKey(file.Path) && Copy(file, content, mode) is { } failure)
                {
                    return failure;
                }
            }
            catch (Exception error) when (error is IOException or UnauthorizedAccessException)
            {
                return $"Cannot hold {ApprovalSummary.Clean(file.Path)} against changes ({error.Message}), so nothing was run.";
            }
        }

        return null;
    }

    /// <summary>The path the program is told to run for this shown file: the private copy where there is one, else the file itself.</summary>
    public string PathFor(string path) => _copies.TryGetValue(path, out string? copied) ? copied : path;

    /// <summary>
    /// Reads every copy again and compares it with what was shown, just before the program starts. A copy that is not a plain file, or whose bytes differ, is refused:
    /// nothing runs. Where nothing was copied (Windows, where the files are held) there is nothing to check here. Returns why not, or null.
    /// </summary>
    public string? Verify()
    {
        foreach ((string original, string copy) in _copies)
        {
            try
            {
                FileInfo info = new(copy);
                if (info.LinkTarget is not null || !info.Exists || !StillProtected(info) || Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(File.ReadAllBytes(copy))) != _shown[original])
                {
                    return $"The private copy of {ApprovalSummary.Clean(original)} is not the file that was shown, so nothing was run.";
                }
            }
            catch (Exception error) when (error is IOException or UnauthorizedAccessException)
            {
                return $"The private copy of {ApprovalSummary.Clean(original)} cannot be checked ({error.Message}), so nothing was run.";
            }
        }

        return null;
    }

    /// <summary>
    /// Off Windows: the copy is read-only for the owner and closed to everyone else, its folder cannot be written and the folders above it (the one of
    /// the copy, the private root) are folders and not links. A permission that was loosened, or a folder swapped for a link, is the first step of a change and is refused.
    /// </summary>
    private bool StillProtected(FileInfo copy)
    {
        if (OperatingSystem.IsWindows())
        {
            return true;
        }

        const UnixFileMode Others = UnixFileMode.GroupRead | UnixFileMode.GroupWrite | UnixFileMode.GroupExecute | UnixFileMode.OtherRead | UnixFileMode.OtherWrite | UnixFileMode.OtherExecute;
        DirectoryInfo folder = copy.Directory!;
        DirectoryInfo root = folder.Parent!;

        return (copy.UnixFileMode & (Others | UnixFileMode.UserWrite)) == 0
            && folder.LinkTarget is null && folder.UnixFileMode == (UnixFileMode.UserRead | UnixFileMode.UserExecute)
            && root.LinkTarget is null && string.Equals(root.FullName, _folder, StringComparison.Ordinal) && root.UnixFileMode == (UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
    }

    private string? Copy(ScriptView file, byte[] content, UnixFileMode mode)
    {
        try
        {
            if (_folder is null)
            {
                _folder = Path.Combine(Path.GetTempPath(), "with-secrets-" + Convert.ToHexString(System.Security.Cryptography.RandomNumberGenerator.GetBytes(12)).ToLowerInvariant());
                MakeFolder(_folder);
            }

            // One folder per file, named as the file is: an interpreter and a person see the same name and extension.
            string folder = Path.Combine(_folder, _copies.Count.ToString(System.Globalization.CultureInfo.InvariantCulture));
            MakeFolder(folder);
            string target = Path.Combine(folder, Path.GetFileName(file.Path));
            FileStreamOptions create = new() { Mode = FileMode.CreateNew, Access = FileAccess.Write, Share = FileShare.None };
            if (!OperatingSystem.IsWindows())
            {
                create.UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite;
            }

            using (FileStream output = new(target, create))
            {
                output.Write(content);
            }

            if (OperatingSystem.IsWindows())
            {
                File.SetAttributes(target, FileAttributes.ReadOnly);
            }
            else
            {
                // Read-only, and executable only if the file was (a text program run directly); the folder cannot be written either.
                File.SetUnixFileMode(target, UnixFileMode.UserRead | (mode & UnixFileMode.UserExecute));
                LinkNeighbours(folder, file.Path);
                File.SetUnixFileMode(folder, UnixFileMode.UserRead | UnixFileMode.UserExecute);
            }

            if (Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(File.ReadAllBytes(target))) != file.Sha256)
            {
                return $"The private copy of {ApprovalSummary.Clean(file.Path)} is not the file that was shown, so nothing was run.";
            }

            _copies[file.Path] = target;
            _shown[file.Path] = file.Sha256;

            return null;
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException)
        {
            return $"Cannot make a private copy of {ApprovalSummary.Clean(file.Path)} to run ({error.Message}), so nothing was run.";
        }
    }

    /// <summary>
    /// Beside the copy, a link for each entry of the original's folder (not the original itself), so a script that looks for a neighbour by its own location finds it. Nothing
    /// is opened or followed here: a link is made to the neighbour's path, in a folder only the owner can write, and what a neighbour is is decided when the script uses it. A folder
    /// with more than <see cref="MaxLinkedEntries" /> entries, or one that cannot be listed, gets no links. A name that cannot be linked is left out. Not made on Windows, where the original is held.
    /// </summary>
    private static void LinkNeighbours(string folder, string original)
    {
        string? directory = Path.GetDirectoryName(original);
        string own = Path.GetFileName(original);
        if (OperatingSystem.IsWindows() || directory is null || own.Length == 0)
        {
            return;
        }

        List<string> names;
        try
        {
            names = [.. Directory.EnumerateFileSystemEntries(directory).Select(entry => Path.GetFileName(entry)).Where(name => name.Length > 0 && !string.Equals(name, own, StringComparison.Ordinal)).Take(MaxLinkedEntries + 1)];
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException)
        {
            return;
        }

        if (names.Count > MaxLinkedEntries)
        {
            return;
        }

        foreach (string name in names)
        {
            try
            {
                File.CreateSymbolicLink(Path.Combine(folder, name), Path.Combine(directory, name));
            }
            catch (Exception error) when (error is IOException or UnauthorizedAccessException)
            {
                // A neighbour whose name collides with the copy (a different case on a case-insensitive system) is left out.
            }
        }
    }

    private static void MakeFolder(string path)
    {
        if (OperatingSystem.IsWindows())
        {
            Directory.CreateDirectory(path);
        }
        else
        {
            Directory.CreateDirectory(path, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        }
    }

    public void Dispose()
    {
        foreach (FileStream stream in _streams)
        {
            stream.Dispose();
        }

        if (_folder is not null)
        {
            RemoveFolder(_folder);
        }
    }

    private static void RemoveFolder(string path)
    {
        try
        {
            foreach (string folder in Directory.EnumerateDirectories(path))
            {
                if (!OperatingSystem.IsWindows())
                {
                    File.SetUnixFileMode(folder, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
                }

                // Windows only: a read-only file cannot be deleted. Elsewhere the folder's mode decides, and the links in it must not be followed (they lead to the person's own files).
                if (OperatingSystem.IsWindows())
                {
                    foreach (string file in Directory.EnumerateFiles(folder))
                    {
                        File.SetAttributes(file, FileAttributes.Normal);
                    }
                }
            }

            Directory.Delete(path, true);
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException)
        {
            // What is left is a copy of a file the person was shown, in a folder only they can open; the next temp clean-up takes it.
        }
    }
}
