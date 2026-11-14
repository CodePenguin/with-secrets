using System.Buffers.Text;
using System.Collections.Concurrent;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace WithSecrets;

/// <summary>Machine identity as shown on the Approvals queue and detail (trusted authority records only).</summary>
public sealed record ApprovalMachineView(string Fingerprint, string? FriendlyName, string HostName);

/// <summary>Bounded script/program-file view for the Approvals detail projection (never secret material).</summary>
public sealed record ApprovalScriptProjection(string? Path, string Sha256, long Length, string? Text, bool Guessed, bool Binary);

/// <summary>One decrypted-env metadata row: names and cipher fingerprint only.</summary>
public sealed record ApprovalDecryptProjection(string Variable, string File, string KeySecret, string CipherShort);

/// <summary>
/// Dedicated bounded review projection for the Approvals SPA. Built from trusted signed context; never a serialization of
/// <see cref="LaunchRequest" />, <see cref="ApprovalRequest" />, <see cref="PageContext" />, or encrypted dotenv ciphertext.
/// </summary>
public sealed record ApprovalReviewProjection(
    string RequestId,
    string FingerprintKey,
    string RequestDigest,
    DateTimeOffset SubmittedAt,
    DateTimeOffset ExpiresAt,
    ApprovalMachineView Machine,
    string Program,
    string ResolvedProgram,
    IReadOnlyList<string> Arguments,
    string WorkingDirectory,
    string Reason,
    IReadOnlyList<string> SecretNames,
    IReadOnlyDictionary<string, string> SecretSources,
    string? InlineCode,
    ApprovalScriptProjection? Script,
    ApprovalScriptProjection? ProgramFile,
    IReadOnlyList<string> EnvFiles,
    IReadOnlyList<string> EnvPairs,
    IReadOnlyList<(string Name, string Value)> ShownEnvValues,
    IReadOnlyList<(string Name, string Why)> CodeChangeWarnings,
    IReadOnlyList<ApprovalDecryptProjection> Decrypts,
    string? InheritedEnvironmentLine,
    IReadOnlyList<string> ExtraLines,
    string CanonicalText);

/// <summary>Queue list item (pending only).</summary>
public sealed record ApprovalQueueItemDto(
    string RequestId,
    string Status,
    DateTimeOffset SubmittedAt,
    DateTimeOffset ExpiresAt,
    ApprovalMachineView Machine,
    string Program,
    string Reason,
    IReadOnlyList<string> SecretNames);

/// <summary>Detail response including authoritative status and optional full review or minimal terminal facts.</summary>
public sealed record ApprovalDetailDto(
    string RequestId,
    string Status,
    DateTimeOffset SubmittedAt,
    DateTimeOffset ExpiresAt,
    DateTimeOffset? DecidedAt,
    ApprovalMachineView? Machine,
    string? Program,
    string? Reason,
    IReadOnlyList<string>? SecretNames,
    ApprovalReviewProjection? Review,
    bool DecisionInProgress,
    IReadOnlyList<string> Actions);

/// <summary>Prepared SPA challenge material.</summary>
public sealed record ApprovalChallengeDto(string FlowId, string Mode, JsonElement Payload, DateTimeOffset ExpiresAt);

/// <summary>API statuses for Approvals decision state (not execution).</summary>
public static class ApprovalStatuses
{
    public const string Pending = "pending";
    public const string Approved = "approved";
    public const string Denied = "denied";
    public const string Expired = "expired";
    public const string Cancelled = "cancelled";
}

/// <summary>
/// Authority-owned in-memory pending Approvals queue and short-lived proof flows. Pending review data is never persisted.
/// Decisions still complete through <see cref="LocalAuthority.Offer" /> / <see cref="LocalAuthority.DecideAsync" />.
/// </summary>
public sealed class ApprovalQueue(TimeProvider clock, Func<TimeSpan> approvalTimeout)
{
    public const int MaxPending = 64;
    public static readonly TimeSpan TerminalRetention = TimeSpan.FromMinutes(10);
    public static readonly TimeSpan ChallengeLifetime = TimeSpan.FromMinutes(2);
    public const string ApproveOnceDecision = "approve-once";

    private readonly Lock _gate = new();
    private readonly Dictionary<string, Entry> _entries = new(StringComparer.Ordinal);
    private readonly Dictionary<string, ProofFlow> _flows = new(StringComparer.Ordinal);

    private sealed class Entry
    {
        public required ApprovalReviewProjection Review { get; init; }
        public required TaskCompletionSource<ApprovalDecision> Decision { get; init; }
        public string Status { get; set; } = ApprovalStatuses.Pending;
        public DateTimeOffset? DecidedAt { get; set; }
        public string? Actor { get; set; }
        public bool DecisionInProgress { get; set; }
        public DateTimeOffset? TerminalUntil { get; set; }
        public CancellationTokenSource? Expiry { get; set; }
    }

    private sealed class ProofFlow
    {
        public required string FlowId { get; init; }
        public required string RequestId { get; init; }
        public required string SessionId { get; init; }
        public required string RequestDigest { get; init; }
        public required string CanonicalText { get; init; }
        public required string MachineFingerprint { get; init; }
        public required ProofContext Context { get; init; }
        public required ProofStart Start { get; init; }
        public required DateTimeOffset ExpiresAt { get; init; }
        public int Consumed;
    }

    /// <summary>Builds the bounded review projection and canonical signed text from trusted context.</summary>
    public static ApprovalReviewProjection BuildReview(
        string launchRequestId,
        string requestDigest,
        DateTimeOffset submittedAt,
        DateTimeOffset expiresAt,
        MachineRecord machine,
        ApprovalRequest page)
    {
        ApprovalRequest shown = page with { Reuse = ReuseOffer.Off };
        string canonical = BuildCanonicalText(launchRequestId, requestDigest, shown, submittedAt);
        string? inline = Policy.InlineCode(shown.Program, shown.Arguments);
        Dictionary<string, string> sources = shown.Sources is null
            ? shown.SecretNames.ToDictionary(name => name, _ => "", StringComparer.Ordinal)
            : shown.SecretNames.ToDictionary(name => name, name => shown.Sources.TryGetValue(name, out string? source) ? ApprovalSummary.Clean(source) : "", StringComparer.Ordinal);

        List<(string Name, string Value)> shownEnv = [];
        HashSet<string> warned = [.. ApprovalSummary.CodeChanges(shown).Select(item => item.Name)];
        if (shown.EnvValues is { } values)
        {
            foreach ((string name, string value) in values.Where(item => !warned.Contains(item.Key)).OrderBy(item => item.Key, StringComparer.Ordinal))
            {
                shownEnv.Add((ApprovalSummary.Clean(name), ApprovalSummary.Clean(value)));
            }
        }

        List<(string Name, string Why)> warnings = [.. ApprovalSummary.CodeChanges(shown).Select(item => (ApprovalSummary.Clean(item.Name), item.Reason))];
        List<string> pairs = [];
        foreach (SecretMapping pair in shown.Mappings ?? [])
        {
            pairs.Add(ApprovalSummary.Clean(pair.Display) + (pair.Variable != pair.Secret ? " (renamed)" : ""));
        }

        return new ApprovalReviewProjection(
            ApprovalSummary.Clean(launchRequestId),
            ApprovalSummary.Clean(shown.RequestId ?? ""),
            requestDigest,
            submittedAt,
            expiresAt,
            new ApprovalMachineView(machine.Fingerprint, machine.FriendlyName is null ? null : ApprovalSummary.Clean(machine.FriendlyName), ApprovalSummary.Clean(machine.HostName)),
            ApprovalSummary.Clean(shown.Program),
            ApprovalSummary.Clean(shown.ResolvedProgram),
            [.. shown.Arguments.Select(ApprovalSummary.Clean)],
            ApprovalSummary.Clean(shown.WorkingDirectory),
            ApprovalSummary.Clean(ApprovalSummary.Truncate(shown.Reason, ApprovalSummary.MaxReasonLength)),
            [.. shown.SecretNames.Select(ApprovalSummary.Clean)],
            sources,
            inline is null ? null : ApprovalSummary.Clean(inline.Length > ApprovalSummary.MaxInlineCharacters ? inline[..ApprovalSummary.MaxInlineCharacters] : inline),
            ScriptProjection(shown.Script),
            ScriptProjection(shown.ProgramFile),
            [.. (shown.EnvFiles ?? []).Select(ApprovalSummary.Clean)],
            pairs,
            shownEnv,
            warnings,
            [.. (shown.Decrypts ?? []).Select(item => new ApprovalDecryptProjection(ApprovalSummary.Clean(item.Variable), ApprovalSummary.Clean(item.File), ApprovalSummary.Clean(item.KeySecret), ApprovalSummary.Clean(item.Short)))],
            shown.InheritedEnvironment is { } inherited ? EnvironmentBinding.Line(inherited) : null,
            [.. (shown.ExtraLines ?? []).Select(ApprovalSummary.Clean)],
            canonical);
    }

    private static ApprovalScriptProjection? ScriptProjection(ScriptView? script)
    {
        if (script is null)
        {
            return null;
        }

        string? text = script.Text;
        if (text is not null)
        {
            List<string> lines = ApprovalSummary.Lines(text);
            if (lines.Count > ApprovalSummary.MaxScriptLines || Encoding.UTF8.GetByteCount(text) > ApprovalSummary.MaxScriptBytes)
            {
                int take = Math.Min(lines.Count, ApprovalSummary.MaxScriptLines);
                StringBuilder clipped = new();
                int bytes = 0;
                for (int i = 0; i < take; i++)
                {
                    string line = lines[i];
                    int next = bytes + Encoding.UTF8.GetByteCount(line) + (i == 0 ? 0 : 1);
                    if (next > ApprovalSummary.MaxScriptBytes)
                    {
                        break;
                    }

                    if (i > 0)
                    {
                        clipped.Append('\n');
                    }

                    clipped.Append(ApprovalSummary.Clean(line));
                    bytes = next;
                }

                text = clipped.ToString();
            }
            else
            {
                text = string.Join('\n', lines.Select(ApprovalSummary.Clean));
            }
        }

        return new ApprovalScriptProjection(
            script.Path.Length == 0 ? null : ApprovalSummary.Clean(script.Path),
            script.Sha256,
            script.Length,
            text,
            script.Guessed,
            script.Text is null);
    }

    /// <summary>Exact canonical review content bound into the approve-once proof (server-owned).</summary>
    public static string BuildCanonicalText(string launchRequestId, string requestDigest, ApprovalRequest page, DateTimeOffset issued)
    {
        ApprovalRequest once = page with { Reuse = ReuseOffer.Off };
        StringBuilder text = new();
        text.Append("Decision: ").Append(ApproveOnceDecision).Append('\n');
        text.Append("Launch request id: ").Append(ApprovalSummary.Clean(launchRequestId)).Append('\n');
        text.Append("Request digest: ").Append(requestDigest).Append('\n');
        text.Append(ApprovalSummary.BuildMessage(once));
        text.Append('\n').Append(ApprovalSummary.IssuedLine(issued));

        return text.ToString();
    }

    /// <summary>
    /// Registers a pending request. Returns false when the authority-wide pending cap is reached (caller must refuse with
    /// <see cref="ReasonCodes.ApprovalQueueFull" /> without evicting).
    /// </summary>
    public bool TryRegister(ApprovalReviewProjection review, out TaskCompletionSource<ApprovalDecision> waiter)
    {
        waiter = new TaskCompletionSource<ApprovalDecision>(TaskCreationOptions.RunContinuationsAsynchronously);
        lock (_gate)
        {
            SweepUnlocked();
            if (_entries.Values.Count(item => item.Status == ApprovalStatuses.Pending) >= MaxPending)
            {
                return false;
            }

            if (_entries.TryGetValue(review.RequestId, out Entry? existing))
            {
                if (existing.Status == ApprovalStatuses.Pending && existing.Review.RequestDigest == review.RequestDigest)
                {
                    waiter = existing.Decision;

                    return true;
                }

                return false;
            }

            TimeSpan timeout = approvalTimeout();
            if (timeout > TimeSpan.FromMinutes(ApprovalSettings.MaxTimeoutMinutes))
            {
                timeout = TimeSpan.FromMinutes(ApprovalSettings.MaxTimeoutMinutes);
            }

            if (timeout < TimeSpan.FromSeconds(1))
            {
                timeout = TimeSpan.FromSeconds(1);
            }

            DateTimeOffset effective = review.ExpiresAt;
            DateTimeOffset byTimeout = clock.GetUtcNow() + timeout;
            if (byTimeout < effective)
            {
                effective = byTimeout;
                review = review with { ExpiresAt = effective };
            }

            Entry entry = new()
            {
                Review = review,
                Decision = waiter,
                Expiry = new CancellationTokenSource(),
            };
            _entries[review.RequestId] = entry;
            TimeSpan delay = effective - clock.GetUtcNow();
            if (delay < TimeSpan.Zero)
            {
                delay = TimeSpan.Zero;
            }

            ScheduleExpiryUnlocked(entry);

            return true;
        }
    }

    private void ScheduleExpiryUnlocked(Entry entry)
    {
        entry.Expiry?.Cancel();
        entry.Expiry?.Dispose();
        entry.Expiry = new CancellationTokenSource();
        string requestId = entry.Review.RequestId;
        entry.Expiry.Token.Register(() => Expire(requestId));
        TimeSpan delay = entry.Review.ExpiresAt - clock.GetUtcNow();
        if (delay <= TimeSpan.Zero)
        {
            ReleaseUnlocked(entry, ApprovalDecision.Deny(ApprovalDecision.TimeLimitDetail, reasonCode: ReasonCodes.ApprovalTimeout));
        }
        else
        {
            entry.Expiry.CancelAfter(delay);
        }
    }

    private void Expire(string requestId)
    {
        lock (_gate)
        {
            if (!_entries.TryGetValue(requestId, out Entry? entry) || entry.Status != ApprovalStatuses.Pending)
            {
                return;
            }

            // Proof verification and the authority's commit are short critical phases. Do not let the deadline race
            // an already-reserved decision; retry until that decision commits or is released.
            if (entry.DecisionInProgress)
            {
                entry.Expiry?.Dispose();
                entry.Expiry = new CancellationTokenSource();
                entry.Expiry.Token.Register(() => Expire(requestId));
                entry.Expiry.CancelAfter(TimeSpan.FromMilliseconds(100));
                return;
            }

            ReleaseUnlocked(entry, ApprovalDecision.Deny(ApprovalDecision.TimeLimitDetail, reasonCode: ReasonCodes.ApprovalTimeout));
        }
    }

    /// <summary>Withdraws a pending request (cancellation, lock, handler dispose) and wakes the waiter.</summary>
    public void Cancel(string requestId, string detail = "cancelled")
    {
        lock (_gate)
        {
            if (!_entries.TryGetValue(requestId, out Entry? entry) || entry.Status != ApprovalStatuses.Pending)
            {
                return;
            }

            ReleaseUnlocked(entry, ApprovalDecision.Deny(detail, reasonCode: ReasonCodes.Cancelled));
        }
    }

    /// <summary>Removes an uncommitted registration when the authority offer is withdrawn or its durable decision failed.</summary>
    public void Withdraw(string requestId)
    {
        lock (_gate)
        {
            if (!_entries.TryGetValue(requestId, out Entry? entry) || entry.Status != ApprovalStatuses.Pending)
            {
                return;
            }

            entry.Expiry?.Cancel();
            entry.Expiry?.Dispose();
            entry.Expiry = null;
            DropFlowsUnlocked(requestId);
            _entries.Remove(requestId);
            entry.Decision.TrySetResult(ApprovalDecision.Deny("the authority offer ended before a decision was committed", reasonCode: ReasonCodes.Cancelled));
        }
    }

    /// <summary>Reconciles the SPA projection after LocalAuthority has committed the signed response.</summary>
    public void MarkCommitted(string requestId, AuthorityResponse response)
    {
        lock (_gate)
        {
            if (!_entries.TryGetValue(requestId, out Entry? entry) || entry.Status != ApprovalStatuses.Pending)
            {
                return;
            }

            entry.Status = response.Decision == AuthorityDecision.Approved ? ApprovalStatuses.Approved
                : response.ReasonCode == ReasonCodes.ApprovalTimeout ? ApprovalStatuses.Expired
                : response.ReasonCode == ReasonCodes.Cancelled ? ApprovalStatuses.Cancelled
                : ApprovalStatuses.Denied;
            entry.DecidedAt = response.Issued;
            entry.DecisionInProgress = false;
            entry.TerminalUntil = response.Issued + TerminalRetention;
            entry.Expiry?.Cancel();
            entry.Expiry?.Dispose();
            entry.Expiry = null;
            DropFlowsUnlocked(requestId);
        }
    }

    private void ReleaseUnlocked(Entry entry, ApprovalDecision decision)
    {
        entry.DecisionInProgress = true;
        entry.Actor = decision.Actor;
        entry.Expiry?.Cancel();
        entry.Expiry?.Dispose();
        entry.Expiry = null;
        DropFlowsUnlocked(entry.Review.RequestId);
        entry.Decision.TrySetResult(decision);
    }

    private void CompleteUnlocked(Entry entry, ApprovalDecision decision, string status)
    {
        entry.Status = status;
        entry.DecidedAt = clock.GetUtcNow();
        entry.Actor = decision.Actor;
        entry.DecisionInProgress = false;
        entry.TerminalUntil = entry.DecidedAt + TerminalRetention;
        entry.Expiry?.Cancel();
        entry.Expiry?.Dispose();
        entry.Expiry = null;
        DropFlowsUnlocked(entry.Review.RequestId);
        entry.Decision.TrySetResult(decision);
    }

    private void DropFlowsUnlocked(string requestId)
    {
        foreach (string flowId in _flows.Where(item => item.Value.RequestId == requestId).Select(item => item.Key).ToList())
        {
            _flows.Remove(flowId);
        }
    }

    public IReadOnlyList<ApprovalQueueItemDto> ListPending(int limit, string? cursor, out string? nextCursor)
    {
        nextCursor = null;
        lock (_gate)
        {
            SweepUnlocked();
            List<Entry> pending = [.. _entries.Values
                .Where(item => item.Status == ApprovalStatuses.Pending)
                .OrderBy(item => item.Review.SubmittedAt)
                .ThenBy(item => item.Review.RequestId, StringComparer.Ordinal)];
            int start = 0;
            if (!string.IsNullOrEmpty(cursor) && DecodeCursor(cursor) is { } after)
            {
                start = pending.FindIndex(item => string.CompareOrdinal(item.Review.RequestId, after) > 0);
                if (start < 0)
                {
                    start = pending.Count;
                }
            }

            limit = Math.Clamp(limit, 1, MaxPending);
            List<ApprovalQueueItemDto> items = [];
            for (int i = start; i < pending.Count && items.Count < limit; i++)
            {
                Entry entry = pending[i];
                items.Add(ToItem(entry));
            }

            if (start + items.Count < pending.Count && items.Count > 0)
            {
                nextCursor = EncodeCursor(items[^1].RequestId);
            }

            return items;
        }
    }

    private static ApprovalQueueItemDto ToItem(Entry entry) => new(
        entry.Review.RequestId,
        entry.Status,
        entry.Review.SubmittedAt,
        entry.Review.ExpiresAt,
        entry.Review.Machine,
        entry.Review.Program,
        entry.Review.Reason,
        entry.Review.SecretNames);

    public ApprovalDetailDto? GetDetail(string requestId, Func<string, ProcessedRequest?> processed)
    {
        lock (_gate)
        {
            SweepUnlocked();
            if (_entries.TryGetValue(requestId, out Entry? entry))
            {
                bool full = entry.Status == ApprovalStatuses.Pending || (entry.TerminalUntil is { } until && until > clock.GetUtcNow());
                List<string> actions = entry.Status == ApprovalStatuses.Pending && !entry.DecisionInProgress
                    ? ["approve-once", "deny"]
                    : [];

                return new ApprovalDetailDto(
                    entry.Review.RequestId,
                    entry.Status,
                    entry.Review.SubmittedAt,
                    entry.Review.ExpiresAt,
                    entry.DecidedAt,
                    entry.Review.Machine,
                    entry.Review.Program,
                    full ? entry.Review.Reason : null,
                    full ? entry.Review.SecretNames : null,
                    full ? entry.Review : null,
                    entry.DecisionInProgress,
                    actions);
            }
        }

        if (processed(requestId) is { } done)
        {
            string status = done.Response.Decision == AuthorityDecision.Approved
                ? ApprovalStatuses.Approved
                : done.Response.ReasonCode is ReasonCodes.ApprovalTimeout ? ApprovalStatuses.Expired
                : done.Response.ReasonCode is ReasonCodes.Cancelled ? ApprovalStatuses.Cancelled
                : ApprovalStatuses.Denied;

            return new ApprovalDetailDto(requestId, status, done.Response.Issued, done.Response.Issued, done.Response.Issued, null, null, null, null, null, false, []);
        }

        return null;
    }

    public (ApprovalChallengeDto? Challenge, string? ProblemCode, string? Detail) CreateOrReuseChallenge(
        string requestId,
        string sessionId,
        string origin,
        IProofMethod method)
    {
        lock (_gate)
        {
            SweepUnlocked();
            if (!_entries.TryGetValue(requestId, out Entry? entry) || entry.Status != ApprovalStatuses.Pending)
            {
                return (null, "request-not-pending", "this request is no longer pending");
            }

            ProofFlow? live = _flows.Values.FirstOrDefault(item => item.RequestId == requestId && item.ExpiresAt > clock.GetUtcNow() && Volatile.Read(ref item.Consumed) == 0);
            if (live is not null)
            {
                if (live.SessionId != sessionId)
                {
                    return (null, "approval-in-progress", "another session already prepared the active proof for this request");
                }

                return (ToChallenge(live), null, null);
            }

            string nonce = Base64Url.EncodeToString(RandomNumberGenerator.GetBytes(16));
            byte[] bind = RequestBinding.Compute(nonce, entry.Review.CanonicalText);
            // Bind also covers digest, machine and fixed decision already present in CanonicalText; ReuseBinding minutes 0 = approve once.
            ProofContext context = new(ReuseBinding.Challenge(bind, 0), origin);
            ProofStart start;
            try
            {
                start = method.Start(context);
            }
            catch (ProofUnavailableException error)
            {
                return (null, "internal-error", error.Message);
            }

            if (start.Mode != "webauthn")
            {
                return (null, "internal-error", "this proof method cannot be used inside the administration page");
            }

            DateTimeOffset expires = clock.GetUtcNow() + ChallengeLifetime;
            ProofFlow flow = new()
            {
                FlowId = Base64Url.EncodeToString(RandomNumberGenerator.GetBytes(16)),
                RequestId = requestId,
                SessionId = sessionId,
                RequestDigest = entry.Review.RequestDigest,
                CanonicalText = entry.Review.CanonicalText,
                MachineFingerprint = entry.Review.Machine.Fingerprint,
                Context = context,
                Start = start,
                ExpiresAt = expires,
            };
            _flows[flow.FlowId] = flow;

            return (ToChallenge(flow), null, null);
        }
    }

    private static ApprovalChallengeDto ToChallenge(ProofFlow flow)
    {
        using JsonDocument document = JsonDocument.Parse(flow.Start.Payload);

        return new ApprovalChallengeDto(flow.FlowId, flow.Start.Mode, document.RootElement.Clone(), flow.ExpiresAt);
    }

    public (ApprovalDetailDto? Detail, string? ProblemCode, string? DetailText) Approve(
        string requestId,
        string sessionId,
        string flowId,
        string proof,
        IProofMethod method,
        Func<string, ProcessedRequest?> processed)
    {
        ProofFlow? flow;
        Entry? entry;
        lock (_gate)
        {
            SweepUnlocked();
            if (!_flows.TryGetValue(flowId, out flow) || flow.RequestId != requestId)
            {
                return ReconcileConflict(requestId, processed, expected: ApprovalStatuses.Approved);
            }

            if (flow.SessionId != sessionId)
            {
                return (null, "approval-in-progress", "this proof belongs to another session");
            }

            if (flow.ExpiresAt <= clock.GetUtcNow() || Volatile.Read(ref flow.Consumed) != 0)
            {
                _flows.Remove(flowId);

                return (null, "request-not-pending", "this proof is no longer valid");
            }

            if (!_entries.TryGetValue(requestId, out entry) || entry.Status != ApprovalStatuses.Pending)
            {
                return ReconcileConflict(requestId, processed, expected: ApprovalStatuses.Approved);
            }

            if (entry.Review.RequestDigest != flow.RequestDigest)
            {
                return (null, "request-not-pending", "this proof is not for the current request");
            }

            entry.DecisionInProgress = true;
        }

        ProofResult verified = method.Verify(flow.Context, proof);
        if (!verified.Ok || verified.Credential is null)
        {
            lock (_gate)
            {
                if (_entries.TryGetValue(requestId, out Entry? current) && ReferenceEquals(current, entry) && current.Status == ApprovalStatuses.Pending)
                {
                    current.DecisionInProgress = false;
                    ScheduleExpiryUnlocked(current);
                }
            }

            return (null, "request-not-pending", "the passkey proof was not accepted");
        }

        if (Interlocked.Exchange(ref flow.Consumed, 1) != 0)
        {
            return ReconcileConflict(requestId, processed, expected: ApprovalStatuses.Approved);
        }

        ApprovalDecision decision = ApprovalDecision.Allow(verified.Detail, actor: verified.Credential.Name);
        lock (_gate)
        {
            _flows.Remove(flowId);
            if (!_entries.TryGetValue(requestId, out Entry? current) || !ReferenceEquals(current, entry) || current.Status != ApprovalStatuses.Pending)
            {
                return ReconcileConflict(requestId, processed, expected: ApprovalStatuses.Approved);
            }

            ReleaseUnlocked(current, decision);
        }

        return (GetDetail(requestId, processed), null, null);
    }

    public (ApprovalDetailDto? Detail, string? ProblemCode, string? DetailText) Deny(
        string requestId,
        string sessionIdentity,
        Func<string, ProcessedRequest?> processed)
    {
        lock (_gate)
        {
            SweepUnlocked();
            if (!_entries.TryGetValue(requestId, out Entry? entry))
            {
                return ReconcileConflict(requestId, processed, expected: ApprovalStatuses.Denied);
            }

            if (entry.Status == ApprovalStatuses.Denied)
            {
                return (GetDetail(requestId, processed), null, null);
            }

            if (entry.Status != ApprovalStatuses.Pending || entry.DecisionInProgress)
            {
                return (null, "decision-already-made", "a different decision is already being committed for this request");
            }

            ReleaseUnlocked(entry, ApprovalDecision.Deny("denied on the approvals page", sessionIdentity));
        }

        return (GetDetail(requestId, processed), null, null);
    }

    private (ApprovalDetailDto? Detail, string? ProblemCode, string? DetailText) ReconcileConflict(
        string requestId,
        Func<string, ProcessedRequest?> processed,
        string expected)
    {
        ApprovalDetailDto? detail = GetDetail(requestId, processed);
        if (detail is null)
        {
            return (null, "request-unavailable", "no request is available for that id");
        }

        if (detail.Status == expected)
        {
            return (detail, null, null);
        }

        if (detail.Status != ApprovalStatuses.Pending)
        {
            return (null, "decision-already-made", "a different decision was already recorded for this request");
        }

        return (null, "request-not-pending", "this request is no longer pending");
    }

    /// <summary>Waits for a SPA or CLI decision for a registered pending request.</summary>
    public ApprovalDecision Wait(string requestId, CancellationToken cancel)
    {
        TaskCompletionSource<ApprovalDecision>? waiter;
        lock (_gate)
        {
            waiter = _entries.TryGetValue(requestId, out Entry? entry) ? entry.Decision : null;
        }

        if (waiter is null)
        {
            return ApprovalDecision.Deny("nobody could be asked for exactly this request");
        }

        try
        {
            return waiter.Task.WaitAsync(cancel).GetAwaiter().GetResult();
        }
        catch (OperationCanceledException)
        {
            Cancel(requestId);

            return waiter.Task.IsCompletedSuccessfully ? waiter.Task.Result : ApprovalDecision.Deny("cancelled");
        }
    }

    /// <summary>Completes a pending request from the CLI one-shot page (first decision wins).</summary>
    public bool TryCompleteFromCli(string requestId, ApprovalDecision decision)
    {
        lock (_gate)
        {
            if (!_entries.TryGetValue(requestId, out Entry? entry) || entry.Status != ApprovalStatuses.Pending)
            {
                return false;
            }

            string status = decision.Approved ? ApprovalStatuses.Approved
                : decision.TimedOut ? ApprovalStatuses.Expired
                : ApprovalStatuses.Denied;
            CompleteUnlocked(entry, decision, status);

            return true;
        }
    }

    public int PendingCount
    {
        get
        {
            lock (_gate)
            {
                SweepUnlocked();

                return _entries.Values.Count(item => item.Status == ApprovalStatuses.Pending);
            }
        }
    }

    private void SweepUnlocked()
    {
        DateTimeOffset now = clock.GetUtcNow();
        foreach (string id in _entries.Where(item => item.Value.TerminalUntil is { } until && until <= now).Select(item => item.Key).ToList())
        {
            if (_entries.TryGetValue(id, out Entry? entry))
            {
                entry.Expiry?.Dispose();
                _entries.Remove(id);
            }
        }

        foreach (string flowId in _flows.Where(item => item.Value.ExpiresAt <= now || Volatile.Read(ref item.Value.Consumed) != 0).Select(item => item.Key).ToList())
        {
            _flows.Remove(flowId);
        }
    }

    private static string EncodeCursor(string requestId) => Base64Url.EncodeToString(Encoding.UTF8.GetBytes(requestId));

    private static string? DecodeCursor(string cursor)
    {
        try
        {
            return Encoding.UTF8.GetString(Base64Url.DecodeFromChars(cursor));
        }
        catch (Exception)
        {
            return null;
        }
    }
}
