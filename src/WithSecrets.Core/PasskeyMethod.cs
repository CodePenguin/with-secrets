using System.Buffers.Text;
using System.Text.Json;

namespace WithSecrets;

/// <summary>
/// Proof by passkey: the person signs the request's binding with a key that was enrolled for the page's host name. Only keys
/// stored for that host (the rpId) may approve, and the key is chosen by the id in the response. <paramref name="readCode" />
/// reads the confirmation code that enrollment shows on the page; it returns null when nothing can be read. With
/// <paramref name="adminOnly" /> only the admin key may prove (for every change to the state); otherwise every enrolled key
/// may (for runs).
/// </summary>
public sealed class PasskeyMethod(PasskeyStore store, ApprovalSettings settings, Func<string?>? readCode = null, bool adminOnly = false) : IProofMethod
{
    public string Id => "passkey";

    /// <summary>True when only the admin key may prove with this method.</summary>
    public bool AdminOnly => adminOnly;

    /// <summary>The same method, where only the admin key may prove.</summary>
    public PasskeyMethod ForAdmin() => new(store, settings, readCode, true);

    /// <summary>What a verified proof says: "admin passkey NAME verified" for the admin key, else "passkey NAME verified".</summary>
    public static string Verified(PasskeyRecord key) => (key.Admin ? "admin passkey " : "passkey ") + key.Name + " verified";

    /// <summary>The keys that may prove at this host: all of them, or only the admin key.</summary>
    private IReadOnlyList<PasskeyRecord> Keys(string rpId) => [.. store.ForRp(rpId).Where(item => !adminOnly || item.Admin)];

    public ProofStart Start(ProofContext context)
    {
        string rpId = RpIdOf(context.Origin);
        IReadOnlyList<PasskeyRecord> keys = Keys(rpId);
        if (keys.Count == 0)
        {
            PasskeyRecord? admin = adminOnly ? store.All().FirstOrDefault(item => item.Admin) : null;
            throw new ProofUnavailableException(admin is not null
                ? $"Only the admin passkey (\"{admin.Name}\", for {admin.RpId}) can approve this change, and it does not work at {rpId}."
                : $"No passkey is enrolled for {rpId}. With nothing enrolled, set up the first one with: with-secrets --config (with-secrets --enroll adds more).");
        }

        string payload = JsonSerializer.Serialize(new
        {
            bind = Base64Url.EncodeToString(context.Bind),
            rpId,
            allowCredentials = keys.Select(item => new { id = item.Id, type = "public-key" }).ToArray(),
            timeout = (long)settings.Timeout.TotalMilliseconds,
        });

        return new ProofStart("webauthn", payload);
    }

    public ProofResult Verify(ProofContext context, string response)
    {
        try
        {
            string rpId = RpIdOf(context.Origin);
            string? id = ResponseId(response);
            PasskeyRecord? key = id is null ? null : Keys(rpId).FirstOrDefault(item => item.Id == id);
            if (key is null)
            {
                return new ProofResult(false, "unknown passkey");
            }

            AssertionResult result = WebAuthn.VerifyAssertion(key, context.Bind, context.Origin, rpId, response);
            if (!result.Ok)
            {
                return new ProofResult(false, result.Detail);
            }

            // The assertion was valid, so the approval stands even if the new count could not be saved.
            store.UpdateSignCount(key.Id, result.NewSignCount);

            return new ProofResult(true, Verified(key));
        }
        catch (Exception)
        {
            return new ProofResult(false, "the passkey proof could not be checked");
        }
    }

    public bool CanProve(string rpId)
    {
        return Keys(rpId).Count > 0;
    }

    /// <summary>The admin key's fingerprint line for the state this method reads.</summary>
    public string AdminLine() => AdminKey.Line(store.Database);

    /// <summary>Throws <see cref="ProofUnavailableException" /> when the file exists but cannot be read, so it never looks empty.</summary>
    public IReadOnlyList<EnrolledEntry> Enrolled()
    {
        return [.. Records().Select(item => new EnrolledEntry(item.Name, item.RpId, item.Created, item.Admin))];
    }

    /// <summary>
    /// Opens the enrollment page (see <see cref="PasskeyRegistration" />). Only the link goes to <paramref name="announce" />;
    /// the key is stored after the admin key signed the new manifest and the person typed the code from the page. Without a
    /// code reader nothing starts. <paramref name="askAdmin" /> asks the admin key on another page when it does not work at
    /// this page's host.
    /// </summary>
    public ApprovalDecision Enroll(string name, Action<string> announce, Func<string, ManifestApproval>? askAdmin = null)
    {
        return readCode is null
            ? ApprovalDecision.Deny("this enrollment has no way to ask for the code from the page")
            : PasskeyRegistration.Run(store, settings, name, announce, readCode, askAdmin);
    }

    /// <summary>
    /// Removes the one passkey with this name (the exact name, else the only one that matches without regard to case): a new
    /// manifest without it, signed by the admin key through <paramref name="askAdmin" />, stored only if the state has not
    /// changed since. The admin key, two passkeys with that name, or a store that cannot be read remove nothing.
    /// </summary>
    public ApprovalDecision Unenroll(string name, Func<string, ManifestApproval> askAdmin)
    {
        if (!store.TryRead(out IReadOnlyList<PasskeyRecord> records, out Manifest? current))
        {
            throw new ProofUnavailableException(store.UnreadableMessage);
        }

        string? stored = Enrollment.Match(records.Select(item => new EnrolledEntry(item.Name, item.RpId, item.Created, item.Admin)), name);
        List<PasskeyRecord> matches = [.. records.Where(item => item.Name == stored)];
        if (stored is null || matches.Count != 1 || current is null)
        {
            return ApprovalDecision.Deny("nothing was removed");
        }

        if (matches[0].Admin)
        {
            return ApprovalDecision.Deny(Enrollment.AdminStays);
        }

        Manifest next = current.WithoutKey(matches[0].Id);
        ManifestApproval approval = askAdmin(next.Canonical());
        if (!approval.Decision.Approved || approval.Signed is null)
        {
            return approval.Decision.Approved ? ApprovalDecision.Deny("nothing was removed") : approval.Decision;
        }

        return approval.Signed.Text != next.Canonical()
            ? ApprovalDecision.Deny("the admin approval did not sign the new state; nothing was removed")
            : PasskeyRegistration.Commit(store.Database, approval.Signed, () => ApprovalDecision.Allow($"Removed the passkey named \"{stored}\"."),
                (connection, transaction) => AuditLog.Append(connection, transaction, AuditLog.ChangeRow("key-removed",
                    $"passkey \"{stored}\" removed (with its saved approvals); admin passkey {current.Admin!.Name} verified", current.Admin.Name)));
    }

    private IReadOnlyList<PasskeyRecord> Records()
    {
        return store.TryAll(out IReadOnlyList<PasskeyRecord> records) ? records : throw new ProofUnavailableException(store.UnreadableMessage);
    }

    /// <summary>The host of the page origin. Throws <see cref="ProofUnavailableException" /> unless the page is https or on localhost.</summary>
    internal static string RpIdOf(string origin)
    {
        if (!Uri.TryCreate(origin, UriKind.Absolute, out Uri? uri))
        {
            throw new ProofUnavailableException("The approval page address is not a valid web address, so no passkey can be used.");
        }

        string host = uri.IdnHost;
        if (uri.Scheme != Uri.UriSchemeHttps && host != "localhost")
        {
            throw new ProofUnavailableException("Passkeys need an https address or localhost. Set 'baseUrl' to an https address.");
        }

        return host;
    }

    /// <summary>The "id" of the response, or null when the response is not a JSON object with a string id.</summary>
    private static string? ResponseId(string response)
    {
        try
        {
            using JsonDocument document = JsonDocument.Parse(response);
            JsonElement root = document.RootElement;

            return root.ValueKind == JsonValueKind.Object && root.TryGetProperty("id", out JsonElement id) && id.ValueKind == JsonValueKind.String
                ? id.GetString()
                : null;
        }
        catch (JsonException)
        {
            return null;
        }
    }
}
