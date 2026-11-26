using System.Buffers.Text;
using System.Text.Json;

namespace WithSecrets;

/// <summary>
/// Proof by passkey: the person signs the request's binding with a key that was enrolled for the page's host name. Only keys
/// stored for that host (the rpId) may approve, and the key is chosen by the id in the response. <paramref name="readCode" />
/// reads the confirmation code that enrollment shows on the page; it returns null when nothing can be read. With
/// <paramref name="adminOnly" /> only admin keys may prove (for every change to the state); otherwise every enrolled key
/// may (for runs). <paramref name="staysAdmin" /> narrows that to the admin keys that are still admins in a new state (see
/// <see cref="Signing" />).
/// </summary>
public sealed class PasskeyMethod(PasskeyStore store, ApprovalSettings settings, Func<string?>? readCode = null, bool adminOnly = false, Manifest? staysAdmin = null) : IProofMethod
{
    public string Id => "passkey";

    /// <summary>True when only admin keys may prove with this method.</summary>
    public bool AdminOnly => adminOnly;

    /// <summary>The same method, where only admin keys may prove.</summary>
    public PasskeyMethod ForAdmin() => new(store, settings, readCode, true);

    /// <summary>
    /// For signing <paramref name="next" />: only the admin keys that are admins in it too, so an admin never signs a state
    /// in which it is not one (for example its own removal), which would not verify when read.
    /// </summary>
    public PasskeyMethod Signing(Manifest next) => adminOnly ? new(store, settings, readCode, true, next) : this;

    /// <summary>What a verified proof says: "admin passkey NAME verified" for an admin key, else "passkey NAME verified".</summary>
    public static string Verified(PasskeyRecord key) => (key.Admin ? "admin passkey " : "passkey ") + key.Name + " verified";

    /// <summary>The keys that may prove at this host: all of them, or only the admin keys (that stay admins).</summary>
    private IReadOnlyList<PasskeyRecord> Keys(string rpId) => [.. store.ForRp(rpId).Where(item => !adminOnly || (item.Admin && (staysAdmin is null || staysAdmin.IsAdmin(item.Id))))];

    public ProofStart Start(ProofContext context)
    {
        string rpId = RpIdOf(context.Origin);
        IReadOnlyList<PasskeyRecord> keys = Keys(rpId);
        if (keys.Count == 0)
        {
            List<PasskeyRecord> admins = adminOnly ? [.. store.All().Where(item => item.Admin && (staysAdmin is null || staysAdmin.IsAdmin(item.Id)))] : [];
            throw new ProofUnavailableException(admins.Count > 0
                ? $"Only an admin passkey can approve this change ({string.Join(", ", admins.Select(item => $"\"{item.Name}\" for {item.RpId}"))}), and none works at {rpId}."
                : adminOnly && store.All().Any(item => item.Admin) ? "No other admin passkey can approve this change: an admin passkey cannot approve its own removal."
                : $"No passkey is enrolled for {rpId}. With nothing enrolled, set up the first one with: with-secrets admin (more are added in the admin web app).");
        }

        string payload = JsonSerializer.Serialize(new
        {
            bind = Base64Url.EncodeToString(context.Bind),
            rpId,
            timeout = (long)settings.Timeout.TotalMilliseconds,

            // All admin slots share this public salt, used as `eval` when the page requests PRF output.
            salt = keys.Select(item => item.Slot?.Salt).FirstOrDefault(item => item is not null),
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

            return new ProofResult(true, Verified(key), new VerifiedCredential(key.Id, key.Name, key.Admin));
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

    /// <summary>The admin keys' fingerprint line for the state this method reads.</summary>
    public string AdminLine() => AdminKey.Line(store.Database);

    /// <summary>Throws <see cref="ProofUnavailableException" /> when the file exists but cannot be read, so it never looks empty.</summary>
    public IReadOnlyList<EnrolledEntry> Enrolled()
    {
        return [.. Records().Select(item => new EnrolledEntry(item.Name, item.RpId, item.Created, item.Admin))];
    }

    /// <summary>
    /// Opens the enrollment page (see <see cref="PasskeyRegistration" />). <paramref name="name" /> is the name the page
    /// suggests; the person chooses the name on the page. Only the link goes to <paramref name="announce" />; the key is
    /// stored after an admin key signed the new manifest and the person typed the code from the page. Without a code reader
    /// nothing starts. <paramref name="askAdmin" /> asks an admin key on another page when none works at this page's host.
    /// </summary>
    public ApprovalDecision Enroll(string name, Action<string> announce, Func<string, ManifestApproval>? askAdmin = null, Unlock? approval = null)
    {
        return readCode is null
            ? ApprovalDecision.Deny("this enrollment has no way to ask for the code from the page")
            : PasskeyRegistration.Run(store, settings, name, announce, readCode, askAdmin, approval);
    }

    internal ApprovalDecision EnrollWithAdminRelease(string name, Action<string> announce, Func<string, ManifestApproval> askAdmin, Func<string, ApprovalDecision> release)
    {
        return readCode is null
            ? ApprovalDecision.Deny("this enrollment has no way to ask for the code from the page")
            : PasskeyRegistration.Run(store, settings, name, announce, readCode, plan: null, askAdmin, releaseAdmin: release);
    }

    /// <summary>
    /// Removes the one passkey with this name (the exact name, else the only one that matches without regard to case): a new
    /// manifest without it, signed by another admin key through <paramref name="askAdmin" />, stored only if the state has not
    /// changed since. The last admin key, two passkeys with that name, or a store that cannot be read remove nothing.
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

        if (matches[0].Admin && records.Count(item => item.Admin) == 1)
        {
            return ApprovalDecision.Deny(Enrollment.LastAdmin);
        }

        Manifest next = current.WithoutKey(matches[0].Id);
        ManifestApproval approval = askAdmin(next.Canonical());
        if (!approval.Decision.Approved || approval.Signed is null)
        {
            return approval.Decision.Approved ? ApprovalDecision.Deny("nothing was removed") : approval.Decision;
        }

        VerifiedCredential? signer = Signer(current, approval.Signed);

        return approval.Signed.Text != next.Canonical()
            ? ApprovalDecision.Deny("the admin approval did not sign the new state; nothing was removed")
            : PasskeyRegistration.Commit(store.Database, approval.Signed, () => ApprovalDecision.Allow($"Removed the passkey named \"{stored}\"."),
                (connection, transaction) => store.Database.AppendAudit(connection, transaction, AdminEvent.Change("key-removed",
                    $"passkey \"{stored}\" removed{(matches[0].Admin ? ", it was an admin" : "")}; admin passkey {signer?.Name ?? "?"} verified", signer?.Name ?? "", signer)));
    }

    /// <summary>The enrolled admin key that signed <paramref name="signed" />, as <paramref name="current" /> names it.</summary>
    internal static VerifiedCredential? Signer(Manifest current, SignedManifest signed)
    {
        return current.Keys.FirstOrDefault(key => key.Id == signed.SignerId && key.Admin) is { } signer
            ? VerifiedCredential.From(signer)
            : null;
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
    internal static string? ResponseId(string response)
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
