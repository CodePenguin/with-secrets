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

        string? batchRefusal = Policy.CheckBatchFile(resolved, args.Arguments);
        if (batchRefusal is not null)
        {
            return await Fail(Usage, batchRefusal);
        }

        // Write the program and the script as full paths. The prompt shows them, and they are what runs.
        resolved = PathExpander.Full(resolved, workingDirectory);
        IReadOnlyList<string> arguments = PathExpander.ExpandScript(args.Arguments, workingDirectory);
        string? tooLong = Policy.CheckLength(resolved, arguments);
        if (tooLong is not null)
        {
            return await Fail(Usage, tooLong);
        }

        int scriptIndex = PathExpander.ScriptArgumentIndex(arguments, workingDirectory);
        // The script file the run executes (the script argument, else the program itself when it is a file that is hashed) is shown
        // on the approval page. If it cannot be read, the person would approve unseen content: refuse.
        string? scriptPath = scriptIndex >= 0 ? arguments[scriptIndex] : HashedFileOrNull(resolved);
        ScriptView? script = null;
        if (scriptPath is not null)
        {
            try
            {
                script = ScriptView.Read(scriptPath);
            }
            catch (Exception error) when (error is IOException or UnauthorizedAccessException)
            {
                return await Fail(Usage, $"Cannot read the script {ApprovalSummary.Clean(scriptPath)} ({error.Message}), so the approval page could not show it. Nothing was run.");
            }
        }

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
        ApprovalRequest request = new(args.Program, resolved, arguments, workingDirectory, args.Reason, names, offer.IsOn ? offer : null, args.Arguments, links, Sources: sources, Unlock: store.NeedsUnlock, Script: script);
        Fingerprint fingerprint = RequestFingerprint.Compute(request);

        // What the page shows must be the file the fingerprint covers; a file that changed in between is not approved unseen.
        if (script is not null && fingerprint.Files.TryGetValue(Path.GetFullPath(scriptPath!, workingDirectory), out string? hashed) && hashed != script.Sha256)
        {
            return await Fail(Usage, "The script changed while the request was being made, so nothing was run. Ask again.");
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

    private async Task<int> Fail(int code, string message)
    {
        await stderr.WriteLineAsync("with-secrets: " + message);

        return code;
    }
}
