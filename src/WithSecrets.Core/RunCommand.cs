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
public sealed class RunCommand(ISecretSource store, IApprover approver, TextWriter stdout, TextWriter stderr, GrantStore? grants = null, ReuseOffer? reuse = null, Func<string, string?>? environment = null, IStoreKeyProvider? keyProvider = null)
{
    private readonly IStoreKeyProvider _keys = keyProvider ?? new TapStoreKeyProvider(approver);

    /// <summary>What the last <c>approve</c> came to, for its audit event: a reason code for a refusal, the grant's id for a grant.</summary>
    private string _approveReason = "";
    private string _approveGrant = "";

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
        if (plan.Mappings.Count == 0 && encrypted.Count == 0)
        {
            return await Fail(Usage, "Name the secrets with --secrets NAME[,NAME...]. There is no option for all secrets.");
        }

        // The Dotenvx key secrets of the encrypted values that survived composition are requested like any secret: they are listed on
        // the page, covered by the approval, and read from the store only after it. A key nobody needs is never requested.
        IReadOnlyList<string> names = [.. plan.Mappings.Select(mapping => mapping.Secret).Concat(encrypted.Select(value => value.KeySecret)).Distinct(StringComparer.Ordinal)];
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

        string[] missingKeys = [.. encrypted.Select(value => value.KeySecret).Distinct(StringComparer.Ordinal).Where(name => !available.Contains(name, StringComparer.Ordinal))];
        if (missingKeys.Length > 0)
        {
            return await Fail(Usage, $"Missing secret: {string.Join(", ", missingKeys)}. It holds the Dotenvx private key for {string.Join(", ", encrypted.Where(value => missingKeys.Contains(value.KeySecret)).Select(value => value.Variable))}. Ask the user to add it.");
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
        // A remote authority approves and decrypts: a saved approval is a host-local record of an approval given here, so it is neither offered nor used (the authority's grants take its place).
        bool remote = context.Authorization is { IsRemote: true };
        ReuseOffer offer = !remote && !store.NeedsUnlock && grants is not null && reuse is { IsOn: true } ? reuse : ReuseOffer.Off;
        Dictionary<string, string> sources = names.ToDictionary(name => name, _ => store.Label, StringComparer.Ordinal);
        ApprovalRequest request = new(program, resolved, arguments, workingDirectory, reason, names, offer.IsOn ? offer : null, typedArguments, links, Sources: sources, Unlock: store.NeedsUnlock, Script: script, ProgramFile: programFile, Mappings: plan.Mappings, EnvFiles: plan.Files, EnvNames: [.. plan.Ordinary.Keys.Order(StringComparer.Ordinal)], EnvValues: plan.Ordinary, InheritedEnvironment: context.Environment, Decrypts: [.. encrypted.Select(value => value.ToItem())]);
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

        // A grant has its own scope key: the machine, the request fingerprint and the FULL argument list (inline code included), so a grant for one
        // command line never covers another. The saved-approval key above ignores the other arguments and is not used for grants.
        string? grantScope = context.Authorization is { } scopeHost ? GrantEvidence.Scope(scopeHost.Fingerprint, fingerprint.Key, arguments) : null;

        // The host's signed audit trail. Every run that gets here names secrets, so every one is
        // secret-bearing: its authorization event is committed durably BEFORE anything is decrypted, and a run whose event cannot be committed does not go on. The later
        // events (launch, execution) cannot be a condition of a launch that already happened, so a failure to record them is only logged. No value of any secret is
        // recorded: the arguments are redacted, and the reasons are codes.
        IHostAudit? hostAudit = context.Audit;
        string auditProgram = resolved;
        IReadOnlyList<string> auditArguments = hostAudit is null ? [] : AuditRedaction.Arguments(arguments);
        string auditRequestId = context.Request?.RequestId ?? "";
        // The metadata of every event of the run: what the person approved, by name and fingerprint only (secret names, the variable mapping, the .env files and the
        // fingerprints of the files the approval covers). Never a value. The approving key and the reuse minutes are added to the event that carries them.
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
            auditMetadata["decrypts"] = string.Join(",", decrypts.Select(item => item.Variable + "=" + item.KeySecret + ":" + item.Short));
        }

        if (fingerprint.Files.Count > 0)
        {
            auditMetadata["files"] = string.Join(";", fingerprint.Files.Select(file => file.Key + "=" + file.Value));
        }

        bool Record(string type, string outcome, string reason, string grantId = "", int? exit = null, string key = "", int? reuseMinutes = null)
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

            if (reuseMinutes is { } minutes)
            {
                metadata["reuseMinutes"] = minutes.ToString(System.Globalization.CultureInfo.InvariantCulture);
            }

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
                Record(AuditEventTypes.Authorization, "denied", context.Cancel.IsCancellationRequested ? "cancelled" : outcome.Code);

                return (context.Cancel.IsCancellationRequested ? await Cancelled() : await Fail(outcome.Code == "authority-locked" ? LaunchClient.AuthorityLocked : Denied, outcome.Message), null, "");
            }

            SecretValues values = outcome.Values!;
            bool viaGrant = outcome.Via == SecretsDelivery.ViaGrant;
            string grant = viaGrant ? outcome.GrantId : "";
            // The authorization event is committed before the program starts (the values are only in memory until then); a run whose event cannot be committed does not go on.
            if (!Record(AuditEventTypes.Authorization, viaGrant ? "granted" : "approved", viaGrant ? "online" : ReasonCodes.Approved, grant))
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

            // Approving binds the store key to a grant at the tap, so the request for it is committed first, like the authorization of a run: without it, no tap is asked for.
            if (!Record(AuditEventTypes.Authorization, "approval-requested", "grant"))
            {
                return await Fail(AuditError, AuditEventMessage);
            }

            int approved = await ApproveGrantOnly(request, fingerprint, context, grantScope);
            Record(AuditEventTypes.Authorization, approved == 0 ? "grant-approved" : "denied", approved == 0 ? "" : _approveReason.Length > 0 ? _approveReason : "refused", _approveGrant);

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
        bool keyFromGrant = false;
        string runGrant = grantUse is { Kind: GrantUseKind.Granted } usedGrant ? usedGrant.GrantId : "";
        SecretValues? delivered = null;
        try
        {
            if (saved.Rejected is not null)
            {
                await stderr.WriteLineAsync($"with-secrets: {GrantStore.RejectedMessage} ({saved.Rejected}).");
            }

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
                if (!Record(AuditEventTypes.Authorization, "granted", "online", granted.GrantId))
                {
                    return await Fail(AuditError, AuditEventMessage);
                }

                // What the store needs to open comes from the key provider: a passkey tap, or the key the service holds for this grant since an earlier tap.
                KeyRelease release = _keys.Obtain(store, request, context.Cancel, line => stderr.WriteLine(line), granted.GrantId, grantScope);
                if (!release.Ok)
                {
                    Record(AuditEventTypes.Launch, context.Cancel.IsCancellationRequested ? "cancelled" : "failed", "key-not-released", runGrant);

                    return context.Cancel.IsCancellationRequested ? await Cancelled() : await Fail(Denied, release.Detail);
                }

                unlock = release.Unlock;
                keyFromGrant = true;
            }
            else if (saved.Grant is { } grant)
            {
                // A saved approval stands in for the page, not for the authority: the machine must still be Trusted.
                if (context.Authorization is { } reusedHost && context.Request is { } reusedLaunch)
                {
                    AuthorizationOutcome reused = await reusedHost.AuthorizeAsync(reusedLaunch, () => ApprovalDecision.Allow("saved approval"), context.Cancel);
                    if (!reused.Decision.Approved)
                    {
                        Record(AuditEventTypes.Authorization, "denied", context.Cancel.IsCancellationRequested ? "cancelled" : reused.Code);

                        return context.Cancel.IsCancellationRequested ? await Cancelled() : await Fail(Denied, reused.AuthorityMessage ?? $"The user did not approve ({reused.Decision.Detail}). Do not retry. Ask the user.");
                    }
                }

                DateTimeOffset now = DateTimeOffset.UtcNow;
                string detail = $"approval by passkey {grant.KeyName} from {grant.Approved:O}, ends {grant.Expires:O}";
                await stderr.WriteLineAsync($"with-secrets: reusing the approval for this exact request ({Math.Max(0, (int)(grant.Expires - now).TotalMinutes)} min left).");
                if (!Record(AuditEventTypes.Authorization, "reused", "saved-approval", key: grant.KeyName))
                {
                    return await Fail(AuditError, AuditEventMessage);
                }
            }
            else
            {
                ApprovalDecision decision;
                string? authorityMessage = null;
                string? authorityCode = null;
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
                    authorityCode = outcome.Code;
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
                    Record(AuditEventTypes.Authorization, "denied", "cancelled");

                    return await Cancelled();
                }

                if (decision.Approved && !offer.Allows(decision.ReuseMinutes))
                {
                    decision = ApprovalDecision.Deny("the approval named a reuse time that was not offered");
                    authorityCode = "reuse-not-offered";
                }

                // The signed authorization event: for an approval it must be committed before anything is decrypted. A denial is recorded too (nothing runs either way).
                string authorizationCode = authorityCode ?? (decision.Approved ? ReasonCodes.Approved : ReasonCodes.UserDenied);
                if (!Record(AuditEventTypes.Authorization, decision.Approved ? "approved" : "denied", authorizationCode, key: AdminAudit.KeyName(decision.Detail), reuseMinutes: decision.Approved ? decision.ReuseMinutes : null) && decision.Approved)
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
                Record(AuditEventTypes.Launch, "failed", "files-not-held", runGrant);

                return await Fail(Denied, holdFailure);
            }

            // A launch that was cancelled while the page was open (the client left, or the service is stopping) decrypts nothing.
            if (context.StaleReason() is { } stale)
            {
                Record(AuditEventTypes.Launch, "cancelled", stale.Replace(' ', '-'), runGrant);

                return await Cancelled();
            }

            // Only the approved names are decrypted. The bytes are zeroed when the program ends; the strings the redactor and the
            // child's environment need cannot be wiped (see SecretValues). The store key itself is opened inside, from what the
            // passkey released, and zeroed there.
            SecretValues secrets;
            try
            {
                secrets = delivered ?? store.GetValues(names, unlock);
            }
            catch (Exception error)
            {
                if (keyFromGrant)
                {
                    _keys.Discard();
                }

                Record(AuditEventTypes.Launch, "failed", "decrypt-failed", runGrant);

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

                // Final filter, whatever the earlier checks said: nothing the page could not show goes to a variable that changes which code runs, where
                // traffic goes or who a commit is by. Nothing is run and nothing is decrypted.
                if (request.Mappings!.Select(mapping => mapping.Variable).Concat(encrypted.Select(value => value.Variable)).FirstOrDefault(EnvDeclarations.IsProtectedVariable) is { } protectedName)
                {
                    Record(AuditEventTypes.Launch, "failed", "protected-variable", runGrant);

                    return await Fail(Usage, $"A secret value cannot be given to {ApprovalSummary.Clean(protectedName)}, because it changes which code runs. Nothing was run.");
                }

                // Encrypted .env values: decrypted here, in memory, with the key secret that was approved, by the Dotenvx library. The key is never added
                // to the child's environment; it is added to what the output redactor masks. A failure names the variable only, never the value or the ciphertext.
                List<string> redactAlso = [];
                foreach (EncryptedValue value in encrypted)
                {
                    string key = secrets.Text(value.KeySecret);
                    redactAlso.Add(key);
                    string? plain = DecryptValue(value, key);
                    if (plain is null || !UsablePlaintext(plain))
                    {
                        // One message and one audit reason for every kind of failure: nothing here tells the cause apart (no oracle), and no value is named.
                        Record(AuditEventTypes.Launch, "failed", "env-decrypt-failed", runGrant);

                        return await Fail(Usage, $"Cannot use the encrypted .env value of {value.Variable}. Nothing was run.");
                    }

                    injected[value.Variable] = plain;
                }

                // Prepare the child and its environment, then commit through the gate: the process starts only if the launch was not
                // cancelled and the local authorization did not change since it began. The loser of that race starts nothing and
                // its prepared environment is thrown away. Once started, nothing here touches the child.
                PreparedChild prepared = ChildRunner.Prepare(new ChildSpec(resolved, arguments, workingDirectory, injected, plan.Ordinary, context.Environment, redactAlso));
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
                    Record(AuditEventTypes.Launch, "cancelled", "not-committed", runGrant);

                    return await Cancelled();
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
            unlock?.Dispose();
            delivered?.Dispose();

            // A run under a grant that did not end normally (any refusal, failure or cancel) drops whatever key is held for it.
            if (keyFromGrant && Outcome != LaunchOutcome.Exited)
            {
                _keys.Discard();
            }
        }
    }

    /// <summary>The plain text of an encrypted .env value, or null when it does not decrypt. Never throws; the cause is not reported, because it could carry the value.</summary>
    private static string? DecryptValue(EncryptedValue value, string privateKey)
    {
        try
        {
            return DotenvxCipher.Instance.Decrypt(privateKey, value.Ciphertext);
        }
        catch (Exception error) when (error is not OutOfMemoryException)
        {
            return null;
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
    /// <c>approve</c>: the person approves this exact request on the page and picks how long (the times the page offers); the authority records a grant for
    /// the request's scope (secrets, program, folder, script and .env plan: the fingerprint of the request) for that time and nothing is launched. A new
    /// approval needs the authority, so it fails while the authority cannot be reached. The page's unlock material is never used here.
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
            return await Fail(Usage, "a grant needs a time to choose on the approval page, and the settings offer none (reuseMaxMinutes is below 10). Raise it with: with-secrets --config");
        }

        // The page offers the times and no unlock: nothing is decrypted by an approval.
        // The page says plainly that this makes a grant (no program runs), what it covers, and what the first run under it will do with the key. What the
        // person signs includes the grant's scope and the machine's security revision, so the authority can keep the assertion as the grant's proof.
        List<string> lines =
        [
            "THIS CREATES A GRANT. No program runs now. If you approve, the agent may run exactly this command again without a page: the same program, EVERY argument shown above, the same folder, secrets and script, for the time you choose below, until it ends or is revoked.",
        ];
        if (store.NeedsUnlock)
        {
            lines.Add("The first run under the grant needs one passkey tap, and that tap makes the service keep the secret store key (it opens all your secrets) in memory until the grant ends (until restart for a grant with no end).");
        }

        lines.AddRange(GrantEvidence.ApproveLines(revision, grantScope, contents: GrantEvidence.ContentsKey(launch.SecretNames, launch.Program, launch.WorkingDirectory)));
        ApprovalRequest shown = request with { RequestId = grantScope, Reuse = times, Unlock = false, Heading = "Create a GRANT for this exact command. No program runs now. Read all of it before you approve.", ExtraLines = lines };
        GrantApproval result = await host.ApproveGrantAsync(launch, grantScope, () =>
        {
            stderr.WriteLine("with-secrets: waiting for the user to approve this request and choose how long the grant lasts...");
            stderr.WriteLine(ApprovalSummary.BuildMessage(shown, showValues: false));
            ApprovalDecision decision = approver.Request(shown, context.Cancel);
            if (decision.Approved && !times.Allows(decision.ReuseMinutes))
            {
                decision.Unlock?.Dispose();
                decision = ApprovalDecision.Deny("the approval named a time that was not offered");
            }

            // A script can change while the prompt is open. The person approved what they saw.
            if (decision.Approved && RequestFingerprint.Compute(request).Key != fingerprint.Key)
            {
                decision.Unlock?.Dispose();
                decision = ApprovalDecision.Deny("a file named in the command changed while the prompt was open");
            }

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
        if (store.NeedsUnlock)
        {
            await stdout.WriteLineAsync("with-secrets: the first run under the grant needs a passkey tap; the service then keeps the store key for the grant (see the page).");
        }

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

    /// <summary>
    /// The host's signed audit trail. A secret-bearing run must commit its authorization event here before anything is decrypted, and does not run when it cannot.
    /// Null only for the in-process runs of tests, which then record nothing here.
    /// </summary>
    public IHostAudit? Audit { get; init; }

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
