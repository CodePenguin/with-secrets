using System.Globalization;
using System.Text;

namespace ArcanaGuardian;

public sealed class GrantSealException(string message) : Exception(message);

/// <summary>Encrypts signed approval text for review and authenticates the grant fields needed for unattended use.</summary>
public sealed class GrantSealer(AuthorityStore store, AuthorityKeyRing keys, IApprovalVerifier verifier, ISecretCipher? cipher = null)
{
    private readonly StateDatabase _state = new(store.Database);
    private readonly ISecretCipher _cipher = cipher ?? JweCipher.Instance;

    internal void Write(AuthorityStore.GrantTx tx, GrantRecord row, PlainEvidence plain)
    {
        Manifest? manifest = tx.Manifest(_state);
        if (manifest?.Review is not { } review)
        {
            throw new GrantSealException("the store has no review key, so no grant is made");
        }

        ApprovalCheck check = verifier is ManifestApprovalVerifier
            ? ManifestApprovalVerifier.Verify(manifest, plain.Evidence, plain.Minutes)
            : verifier.Verify(plain.Evidence, plain.Minutes);
        ApprovalCheck Verify(ApprovalEvidence _, int __) => check;

        if (GrantEvidence.RowProblem(Verify, row, plain) is { } problem)
        {
            throw new GrantSealException(problem);
        }

        if (check.Credential is { } credential)
        {
            row = row.ApprovedKey is null
                ? row with { ApprovedKey = credential }
                : row with { ChangedKey = credential };
        }

        ISigningKey key = keys.Current(tx.ActiveKey() ?? throw new GrantSealException("the authority has no signing key"));
        ApprovalEvidence approval = plain.Evidence;
        StoredEvidence stored = new(plain.Kind, approval.Nonce, _cipher.Encrypt(approval.Text, review.PublicKey), approval.Proof, plain.Minutes);
        tx.WriteEvidence(GrantSeals.Sign(row with { Evidence = stored, ReviewKey = review.PublicKey }, key));
    }

    public string? Problem(GrantRecord row)
    {
        return Problem(row, keys.ActivePublicKey(), () => _state.Read(connection => _state.CurrentManifest(connection, null)));
    }

    internal string? Problem(AuthorityStore.GrantTx tx, GrantRecord row)
    {
        return Problem(row, tx.ActiveKey() is { } active ? keys.PublicKey(active) : null, () => tx.Manifest(_state));
    }

    private string? Problem(GrantRecord row, byte[]? active, Func<Manifest?> readManifest)
    {
        if (row.Seal is null || row.SealKey is null || row.Evidence is not { } evidence || row.ReviewKey is null)
        {
            return "the grant has no seal";
        }

        if (active is null || row.SealKey != KeyIdentity.Fingerprint(active))
        {
            return "the grant is sealed by a key that is not the active authority key";
        }

        if (!GrantSeals.Verifies(row, active))
        {
            return "the seal does not verify";
        }

        Manifest? manifest = readManifest();
        if (manifest?.Review?.PublicKey != row.ReviewKey)
        {
            return "the evidence is for another review key";
        }

        if (row.ApprovedKey is { } approver && !manifest.Keys.Any(key => key.Id == approver.Id)
            || row.ChangedKey is { } changer && !manifest.Keys.Any(key => key.Id == changer.Id))
        {
            return "a passkey that approved or changed the grant is no longer enrolled";
        }

        ApprovalCheck signer = verifier is ManifestApprovalVerifier
            ? ManifestApprovalVerifier.Signer(manifest, evidence.Proof)
            : verifier.Signer(evidence.Proof);
        return signer.Ok ? null : "the approving passkey is not enrolled";
    }
}

public static class GrantSeals
{
    public const string Context = "arcana-guardian grant seal v1";

    internal static byte[] Text(GrantRecord row, string authorityFingerprint)
    {
        StoredEvidence evidence = row.Evidence!;
        string[] fields =
        [
            row.Id, row.Fingerprint, row.ScopeKey, row.Program, row.WorkingDirectory, row.SecretNames, CanonicalJson.Time(row.Created),
            CanonicalJson.Time(row.Updated), Time(row.Expires), Number(row.Revision), Number(row.SecurityRevision), row.Status, row.Usage,
            Time(row.Consumed), row.Replaces ?? "", row.ApprovedBy, evidence.Kind, evidence.Nonce, Number(evidence.Minutes),
            SecretStore.Hash(evidence.Proof), SecretStore.Hash(evidence.Ciphertext), row.ReviewKey!, authorityFingerprint,
            new AuditKeys(GrantApproved: row.ApprovedKey, GrantChanged: row.ChangedKey).Wire(),
        ];
        StringBuilder text = new StringBuilder(Context).Append('\n');
        foreach (string field in fields)
        {
            text.Append(Number(Encoding.UTF8.GetByteCount(field))).Append(':').Append(field).Append('\n');
        }

        return Encoding.UTF8.GetBytes(text.ToString());
    }

    private static string Time(DateTimeOffset? value) => value is { } time ? CanonicalJson.Time(time) : "";
    private static string Number(int value) => value.ToString(CultureInfo.InvariantCulture);

    internal static GrantRecord Sign(GrantRecord row, ISigningKey key)
    {
        string fingerprint = KeyIdentity.Fingerprint(key.PublicKey);
        return row with { SealKey = fingerprint, Seal = key.Sign(Text(row, fingerprint)) };
    }

    internal static bool Verifies(GrantRecord row, byte[] publicKey)
    {
        return row is { Revoked: null, Status: "active" or "consumed", Evidence: not null, ReviewKey: not null, SealKey: { } fingerprint, Seal: { } signature }
            && fingerprint == KeyIdentity.Fingerprint(publicKey)
            && KeyIdentity.Verify(publicKey, Text(row, fingerprint), signature);
    }

    internal static void Reseal(AuthorityStore.GrantTx tx, byte[] oldAuthorityPublicKey, ISigningKey next)
    {
        foreach (GrantRecord row in tx.Sealed())
        {
            tx.WriteEvidence(Verifies(row, oldAuthorityPublicKey)
                ? Sign(row, next)
                : row with { Evidence = null, ReviewKey = null, SealKey = null, Seal = null });
        }
    }

    internal static void Rekey(AuthorityStore.GrantTx tx, string oldReviewPrivate, string newReviewPublic, ISigningKey key)
    {
        JweCipher cipher = JweCipher.Instance;
        string oldReviewPublic = cipher.Derive(oldReviewPrivate);
        foreach (GrantRecord row in tx.Sealed())
        {
            if (row.ReviewKey != oldReviewPublic || !Verifies(row, key.PublicKey))
            {
                tx.WriteEvidence(row with { Evidence = null, ReviewKey = null, SealKey = null, Seal = null });
                continue;
            }

            StoredEvidence evidence = row.Evidence!;
            string plaintext = cipher.Decrypt(oldReviewPrivate, evidence.Ciphertext);
            string ciphertext = cipher.Encrypt(plaintext, newReviewPublic);
            tx.WriteEvidence(Sign(row with { Evidence = evidence with { Ciphertext = ciphertext }, ReviewKey = newReviewPublic }, key));
        }
    }
}
