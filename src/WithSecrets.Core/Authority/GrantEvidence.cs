using System.Globalization;
using System.Security.Cryptography;
using System.Text;

namespace WithSecrets;

/// <summary>What <see cref="IApprovalVerifier" /> found: whether the passkey assertion verifies, who signed, and whether that key is an admin key.</summary>
public sealed record ApprovalCheck(bool Ok, string SignerName, bool Admin, string Detail);

/// <summary>
/// Checks a passkey assertion the person made on an approval page (see <see cref="ApprovalEvidence" />) against the enrolled keys. The authority
/// uses it so that a grant row is believed only when a person's assertion backs its present state: a row that was written, changed or planted
/// by anything else has no valid evidence and is ignored.
/// </summary>
public interface IApprovalVerifier
{
    ApprovalCheck Verify(ApprovalEvidence evidence, int minutes);
    ApprovalCheck Signer(string proof);
}

/// <summary>Verifies against the keys of the signed manifest in <c>with-secrets.db</c> (the check a grant gets every time it is read).</summary>
public sealed class ManifestApprovalVerifier(StateDatabase db) : IApprovalVerifier
{
    public ApprovalCheck Signer(string proof) => Check(ReadManifest, proof, null);

    public ApprovalCheck Verify(ApprovalEvidence evidence, int minutes)
        => Check(ReadManifest, evidence.Proof, () => ReuseBinding.Challenge(RequestBinding.Compute(evidence.Nonce, evidence.Text), minutes));

    internal static ApprovalCheck Signer(Manifest manifest, string proof) => Check(() => manifest, proof, null);

    internal static ApprovalCheck Verify(Manifest manifest, ApprovalEvidence evidence, int minutes)
        => Check(() => manifest, evidence.Proof, () => ReuseBinding.Challenge(RequestBinding.Compute(evidence.Nonce, evidence.Text), minutes));

    private Manifest? ReadManifest() => db.Read(connection => connection is null ? null : db.CurrentManifest(connection, null));

    private static ApprovalCheck Check(Func<Manifest?> readManifest, string proof, Func<byte[]>? challenge)
    {
        try
        {
            Manifest? manifest = readManifest();
            if (manifest is null)
            {
                return new ApprovalCheck(false, "", false, "no signed manifest");
            }

            using System.Text.Json.JsonDocument document = System.Text.Json.JsonDocument.Parse(proof);
            string? id = document.RootElement.ValueKind == System.Text.Json.JsonValueKind.Object && document.RootElement.TryGetProperty("id", out System.Text.Json.JsonElement element) && element.ValueKind == System.Text.Json.JsonValueKind.String ? element.GetString() : null;
            ManifestKey? signer = manifest.Keys.FirstOrDefault(item => item.Id == id);
            if (signer is null)
            {
                return new ApprovalCheck(false, "", false, "the approving key is not enrolled");
            }

            if (challenge is null)
            {
                return new ApprovalCheck(true, signer.Name, signer.Admin, "");
            }

            AssertionResult result = WebAuthn.VerifyStored(signer.Record(0), challenge(), proof);

            return new ApprovalCheck(result.Ok, signer.Name, signer.Admin, result.Ok ? "" : "the signature does not verify");
        }
        catch (Exception error) when (error is StateDatabaseException or System.Text.Json.JsonException or ArgumentException or InvalidOperationException)
        {
            return new ApprovalCheck(false, "", false, "the evidence cannot be checked");
        }
    }
}

/// <summary>The approval evidence stored with a grant row: <see cref="Kind" /> is <c>approve</c> (the approval that made or updated it) or <c>admin</c> (an admin's extend or renew).</summary>
public sealed record StoredEvidence(string Kind, string Nonce, string Ciphertext, string Proof, int Minutes);

public sealed record PlainEvidence(string Kind, ApprovalEvidence Evidence, int Minutes);

/// <summary>
/// The scope of a grant and the evidence that backs it. The scope key covers the machine, the request fingerprint (program path, folder, secret names,
/// <c>.env</c> plan, script content and inherited environment) and the full argument list, inline code included (<c>python -c CODE</c>,
/// <c>bash -c</c>, <c>node -e</c>); it never includes the reason. It is deliberately not the Phase 1 saved-approval key, which ignores the other arguments.
/// </summary>
public static class GrantEvidence
{
    public const string ScopeDomain = "with-secrets grant scope v1\n";
    public const string ApproveKind = "approve";
    public const string AdminKind = "admin";

    public const string SecurityRevisionPrefix = "Security revision: ";
    public const string DecisionPrefix = "Decision: ";
    public const string ChangePrefix = "Change: ";
    public const string GrantIdPrefix = "Grant id: ";
    public const string GrantScopePrefix = "Grant scope: ";
    public const string MachinePrefix = "Machine fingerprint: ";
    public const string NewRevisionPrefix = "New revision: ";
    public const string NewEndPrefix = "New end: ";
    public const string NoEnd = "no end";
    public const string ContentsPrefix = "Grant contents: ";
    public const string ReplacesPrefix = "Replaces: ";
    public const string NewUsagePrefix = "New usage: ";

    /// <summary>
    /// What a grant covers besides its scope key: the exact secret names, the program and the working folder, as one SHA-256 (upper-case hex). The scope key is made by the
    /// host from things the authority cannot see, so the authority keeps this too: the passkey signs it (approve and admin pages) and a use is served only when the request
    /// has exactly these contents, so a grant can never release a name that was not approved.
    /// </summary>
    public static string ContentsKey(IEnumerable<string> secretNames, string program, string workingDirectory)
    {
        string[] names = [.. secretNames.Distinct(StringComparer.Ordinal).Order(StringComparer.Ordinal)];
        StringBuilder text = new("with-secrets grant contents v1\n");
        text.Append(names.Length.ToString(CultureInfo.InvariantCulture)).Append('\n');
        foreach (string name in names)
        {
            text.Append(name.Length.ToString(CultureInfo.InvariantCulture)).Append(':').Append(name).Append('\n');
        }

        text.Append(program.Length.ToString(CultureInfo.InvariantCulture)).Append(':').Append(program).Append('\n');
        text.Append(workingDirectory.Length.ToString(CultureInfo.InvariantCulture)).Append(':').Append(workingDirectory).Append('\n');

        return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(text.ToString())));
    }

    /// <summary>The names as a grant row keeps them: the sorted, distinct names joined by ", " (never truncated: they are security-relevant).</summary>
    public static string NamesText(IEnumerable<string> secretNames) => string.Join(", ", secretNames.Distinct(StringComparer.Ordinal).Order(StringComparer.Ordinal));

    /// <summary>The contents key of what a grant row records.</summary>
    public static string ContentsKey(GrantRecord row) => ContentsKey(row.SecretNames.Length == 0 ? [] : row.SecretNames.Split(", "), row.Program, row.WorkingDirectory);


    /// <summary>How far a page-issue time may be ahead of the authority's clock (the same machine's clock in local mode; a little slack for a remote one).</summary>
    public static readonly TimeSpan Skew = TimeSpan.FromMinutes(1);

    /// <summary>The grant scope: 64 upper-case hex digits (a SHA-256), so the authority treats it as an opaque key.</summary>
    public static string Scope(string machineFingerprint, string requestKey, IReadOnlyList<string> arguments)
    {
        StringBuilder text = new(ScopeDomain);
        text.Append(machineFingerprint).Append('\n').Append(requestKey).Append('\n').Append(arguments.Count.ToString(CultureInfo.InvariantCulture)).Append('\n');
        foreach (string argument in arguments)
        {
            text.Append(argument.Length.ToString(CultureInfo.InvariantCulture)).Append(':').Append(argument).Append('\n');
        }

        return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(text.ToString())));
    }

    /// <summary>The lines an approve page carries (in the text the person signs) so the evidence binds the machine's security revision.</summary>
    public static IReadOnlyList<string> ApproveLines(int securityRevision, string scopeKey, string? heldNote = null, string? contents = null)
    {
        List<string> lines = [SecurityRevisionPrefix + securityRevision.ToString(CultureInfo.InvariantCulture), GrantScopePrefix + scopeKey];
        if (contents is not null)
        {
            lines.Add(ContentsPrefix + contents);
        }

        if (heldNote is not null)
        {
            lines.Add(heldNote);
        }

        return lines;
    }

    /// <summary>The end as the signed text says it.</summary>
    public static string EndText(DateTimeOffset? end) => end is { } at ? CanonicalJson.Time(at) : NoEnd;

    /// <summary>The machine-readable lines of an admin grant page (the passkey signs them): what changes, to which grant, and its new revision and end.</summary>
    public static string AdminLines(string change, GrantRecord grant, int newRevision, DateTimeOffset? newEnd)
    {
        return string.Join('\n',
            ChangePrefix + change,
            GrantIdPrefix + grant.Id,
            GrantScopePrefix + grant.ScopeKey,
            MachinePrefix + grant.Fingerprint,
            ContentsPrefix + ContentsKey(grant),
            SecurityRevisionPrefix + grant.SecurityRevision.ToString(CultureInfo.InvariantCulture),
            NewRevisionPrefix + newRevision.ToString(CultureInfo.InvariantCulture),
            NewEndPrefix + EndText(newEnd));
    }

    /// <summary>
    /// The machine-readable lines of an admin replace page (the passkey signs them): the new grant's id, the consumed once-only grant it replaces, the scope it copies
    /// from that grant exactly (scope key, machine, contents, security revision), and the new grant's usage, revision and end.
    /// </summary>
    public static string ReplaceLines(GrantRecord original, string newGrantId, DateTimeOffset? newEnd)
    {
        return string.Join('\n',
            ChangePrefix + GrantOps.Replace,
            GrantIdPrefix + newGrantId,
            ReplacesPrefix + original.Id,
            GrantScopePrefix + original.ScopeKey,
            MachinePrefix + original.Fingerprint,
            ContentsPrefix + ContentsKey(original),
            SecurityRevisionPrefix + original.SecurityRevision.ToString(CultureInfo.InvariantCulture),
            NewUsagePrefix + GrantUsage.Reusable,
            NewRevisionPrefix + "1",
            NewEndPrefix + EndText(newEnd));
    }

    /// <summary>
    /// Null when the admin passkey's evidence in <paramref name="command" /> says exactly this change to <paramref name="grant" /> as it is now (the
    /// authority checks it inside the transaction), else why not. Revoke needs the same proof, with no end. For replace, <paramref name="grant" /> is the
    /// original, and the evidence must name the command's new grant id, that original, its scope exactly, a reusable usage and revision 1.
    /// </summary>
    public static string? AdminProblem(IApprovalVerifier? verifier, GrantAdminCommand command, GrantRecord grant, DateTimeOffset now)
    {
        if (verifier is null || command.Evidence is not { } evidence)
        {
            return "the change has no admin passkey evidence";
        }

        DateTimeOffset? issued = Issued(evidence.Text);
        if (issued is null || now < issued - Skew || now > issued.Value.AddMinutes(ApprovalSettings.MaxTimeoutMinutes - 1))
        {
            return "the admin page was not made when the change says";
        }

        DateTimeOffset? newEnd = command.Operation == GrantOps.Revoke || command.Indefinite ? null : command.NewEnd;
        if (command.Operation != GrantOps.Revoke && !command.Indefinite && newEnd is null)
        {
            return "the change has no end";
        }

        string change = command.Operation;
        bool replace = change == GrantOps.Replace;
        if (replace && (command.NewGrantId is null
            || Line(evidence.Text, GrantIdPrefix) != command.NewGrantId
            || Line(evidence.Text, ReplacesPrefix) != grant.Id
            || Line(evidence.Text, NewUsagePrefix) != GrantUsage.Reusable
            || Line(evidence.Text, NewRevisionPrefix) != "1"))
        {
            return "the admin page text is not this replacement of this grant";
        }

        if (!replace && (Line(evidence.Text, GrantIdPrefix) != grant.Id
            || Line(evidence.Text, ReplacesPrefix) is not null
            || Line(evidence.Text, NewRevisionPrefix) != (grant.Revision + 1).ToString(CultureInfo.InvariantCulture)))
        {
            return "the admin page text is not this change to this grant";
        }

        if (Line(evidence.Text, ChangePrefix) != change
            || Line(evidence.Text, GrantScopePrefix) != grant.ScopeKey
            || Line(evidence.Text, MachinePrefix) != grant.Fingerprint
            || Line(evidence.Text, ContentsPrefix) != ContentsKey(grant)
            || Line(evidence.Text, SecurityRevisionPrefix) != grant.SecurityRevision.ToString(CultureInfo.InvariantCulture)
            || Line(evidence.Text, NewEndPrefix) != EndText(newEnd))
        {
            return "the admin page text is not this change to this grant";
        }

        ApprovalCheck check = verifier.Verify(evidence, 0);

        return check is { Ok: true, Admin: true } ? null : "the change was not signed by an admin key (" + check.Detail + ")";
    }

    /// <summary>The value of the one line that starts with <paramref name="prefix" />, or null when there is none or more than one.</summary>
    public static string? Line(string text, string prefix)
    {
        string[] found = [.. text.Split('\n').Where(line => line.StartsWith(prefix, StringComparison.Ordinal))];

        return found.Length == 1 ? found[0][prefix.Length..] : null;
    }

    private static DateTimeOffset? Issued(string text)
    {
        return Line(text, ApprovalSummary.IssuedPrefix) is { } value && DateTimeOffset.TryParseExact(value, "O", CultureInfo.InvariantCulture, DateTimeStyles.None, out DateTimeOffset issued) ? issued : null;
    }

    /// <summary>
    /// Null when a person's assertion backs the grant's present state, else why not (the row is then ignored, as if there were no grant). An active
    /// grant counts only with evidence that fits the row exactly: the approval that made it (scope, security revision, minutes, time) or an admin's
    /// extend or renew (grant, scope, machine, revisions, new end), or the admin's replace that made it (also the grant it replaces and its usage). A revocation or an
    /// invalidation is never evidence of a usable grant.
    /// </summary>
    internal static string? RowProblem(Func<ApprovalEvidence, int, ApprovalCheck> verify, GrantRecord row, PlainEvidence plain)
    {
        string text = plain.Evidence.Text;
        DateTimeOffset? issued = Issued(text);
        if (issued is null || row.Updated < issued - Skew || row.Updated > issued.Value.AddMinutes(ApprovalSettings.MaxTimeoutMinutes))
        {
            return "the grant's evidence was not made when the grant says";
        }

        if (plain.Kind == ApproveKind)
        {
            // Minutes 0 ("Approve once") is a once-only grant's evidence, and only that: it has no end, and a reusable row never carries it.
            bool once = row.Usage == GrantUsage.Once;
            bool always = plain.Minutes == ReuseOffer.Always && row.Expires is null;
            if (once ? plain.Minutes != 0 || row.Expires is not null : !always && (plain.Minutes is < 1 or > ReuseSettings.MaxMinutes || row.Expires != row.Updated.AddMinutes(plain.Minutes)))
            {
                return "the grant's end does not match the minutes that were signed";
            }

            if (Line(text, ApprovalSummary.RequestIdPrefix) != row.ScopeKey || Line(text, SecurityRevisionPrefix) != row.SecurityRevision.ToString(CultureInfo.InvariantCulture) || Line(text, ContentsPrefix) != ContentsKey(row))
            {
                return "the signed text is not for this grant";
            }

            ApprovalCheck approved = verify(plain.Evidence, plain.Minutes);

            return approved.Ok ? null : "the approval does not verify (" + approved.Detail + ")";
        }

        if (plain.Kind != AdminKind)
        {
            return "the grant's evidence is of an unknown kind";
        }

        // A replacement is believed only as what its page made: a reusable grant with this id, linked to the grant it replaces, at its first revision.
        string? change = Line(text, ChangePrefix);
        bool replacement = change == GrantOps.Replace;
        if (replacement && (row.Replaces is null || row.Usage != GrantUsage.Reusable || Line(text, ReplacesPrefix) != row.Replaces || Line(text, NewUsagePrefix) != row.Usage))
        {
            return "the signed text is not for this grant as it is now";
        }

        if (change is not (GrantOps.Extend or GrantOps.Renew or GrantOps.Replace)
            || Line(text, GrantIdPrefix) != row.Id
            || Line(text, GrantScopePrefix) != row.ScopeKey
            || Line(text, MachinePrefix) != row.Fingerprint
            || Line(text, ContentsPrefix) != ContentsKey(row)
            || Line(text, SecurityRevisionPrefix) != row.SecurityRevision.ToString(CultureInfo.InvariantCulture)
            || Line(text, NewRevisionPrefix) != row.Revision.ToString(CultureInfo.InvariantCulture)
            || Line(text, NewEndPrefix) != EndText(row.Expires))
        {
            return "the signed text is not for this grant as it is now";
        }

        ApprovalCheck checkedAdmin = verify(plain.Evidence, 0);

        return checkedAdmin is { Ok: true, Admin: true } ? null : "the change was not signed by an admin key";
    }
}
