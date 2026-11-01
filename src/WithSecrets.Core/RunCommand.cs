using System.Text.Json;

namespace WithSecrets;

/// <summary>Writes one JSON line per event. It records names, never values.</summary>
public sealed class AuditLog(string path)
{
    /// <summary>Returns false when the line could not be written. The caller then refuses to continue.</summary>
    public bool TryWrite(string eventName, ApprovalRequest request, string detail, int? exitCode = null, IReadOnlyDictionary<string, string>? files = null)
    {
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(path)!);
            string line = JsonSerializer.Serialize(new
            {
                time = DateTimeOffset.UtcNow,
                @event = eventName,
                program = request.ResolvedProgram,
                arguments = request.Arguments,
                directory = request.WorkingDirectory,
                reason = request.Reason,
                secrets = request.SecretNames,
                detail,
                files,
                typedArguments = request.TypedArguments,
                links = request.Links,
                exitCode
            });
            File.AppendAllText(path, line + Environment.NewLine);

            return true;
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException)
        {
            return false;
        }
    }
}

public sealed record RunArgs(IReadOnlyList<string> Secrets, string Reason, string Program, IReadOnlyList<string> Arguments);

/// <summary>Exit codes: 2 usage, 3 denied, 4 store error, 5 audit error, 127 program not found. Anything else is the program's own.</summary>
public sealed class RunCommand(ISecretStore store, IApprover approver, AuditLog audit, TextWriter stdout, TextWriter stderr, GrantStore? grants = null, TimeSpan reuse = default)
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
        List<string> links = [];
        foreach (string? note in new[] { PathExpander.LinkNote(resolved), scriptIndex >= 0 ? PathExpander.LinkNote(arguments[scriptIndex]) : null })
        {
            if (note is not null)
            {
                links.Add(note);
            }
        }

        bool reuseOn = grants is not null && reuse > TimeSpan.Zero;
        ApprovalRequest request = new(args.Program, resolved, arguments, workingDirectory, args.Reason, names, reuseOn ? (int)reuse.TotalMinutes : 0, args.Arguments, links);
        Fingerprint fingerprint = RequestFingerprint.Compute(request);

        if (reuseOn && grants!.TryGet(fingerprint.Key, out DateTimeOffset approvedAt, out DateTimeOffset expiresAt))
        {
            DateTimeOffset now = DateTimeOffset.UtcNow;
            string detail = $"approval from {approvedAt:O}, ends {expiresAt:O}";
            await stderr.WriteLineAsync($"with-secrets: reusing the approval for this exact request ({Math.Max(0, (int)(expiresAt - now).TotalMinutes)} min left).");
            if (!audit.TryWrite("reused", request, detail, files: fingerprint.Files))
            {
                return await Fail(AuditError, "cannot write the audit log, so nothing was run.");
            }
        }
        else
        {
            await stderr.WriteLineAsync("with-secrets: waiting for the user to approve this request...");
            await stderr.WriteLineAsync(ApprovalSummary.BuildMessage(request));

            ApprovalDecision decision = approver.Request(request);
            if (!audit.TryWrite(decision.Approved ? "approved" : "denied", request, decision.Detail, files: fingerprint.Files))
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

            if (reuseOn)
            {
                grants!.Add(fingerprint.Key, reuse);
            }
        }

        IReadOnlyDictionary<string, string> values;
        try
        {
            values = store.GetValues(names);
        }
        catch (Exception error)
        {
            return await Fail(StoreError, $"cannot decrypt the secret store: {error.Message}");
        }

        int exitCode = await ChildRunner.RunAsync(new ChildSpec(resolved, arguments, workingDirectory, values), stdout, stderr);
        audit.TryWrite("finished", request, "", exitCode, fingerprint.Files);

        return exitCode;
    }

    private async Task<int> Fail(int code, string message)
    {
        await stderr.WriteLineAsync("with-secrets: " + message);

        return code;
    }
}
