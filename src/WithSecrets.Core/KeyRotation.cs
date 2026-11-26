using System.Buffers.Text;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Data.Sqlite;

namespace WithSecrets;

/// <summary>
/// The rotation of the store keys (admin app, Secrets): new store key K and new master key MK, for when the keys may have been seen (an admin key lost, a
/// device given away). Admin only, two taps.
/// <para>
/// Tap 1 (the approval page) is an admin approval that also releases the PRF output of the tapped key S. The page lists the
/// keys that will be removed. The program derives the key encryption key from S's slot, opens the old master key and the old
/// store key, makes the new ones and re-encrypts every row (one at a time, in memory; only ciphertext is kept). The new manifest
/// (version + 1) has the new store public key, the vault of the new store key under the new master key, only S with a slot
/// that wraps the new master key (same salt and same PRF output, so S still works), a new recovery slot with a new recovery
/// code, and the hashes of the new rows.
/// </para>
/// <para>
/// Tap 2 ("Step 2 of 2", an explicit page of its own) has S sign that manifest; no PRF. The signed bind is
/// <see cref="SecretCrypto.ManifestBind" /> of the request bind and the digest of the new rows, so a row changed between the
/// page and the tap fails the check. When the proof verifies, one transaction replaces the manifest and the rows, deletes the
/// removed keys' grants and adds the audit row <c>key-rotated</c> (key names and a count, no key material). The new recovery
/// code is shown once on the final page, only after that write. K_old, K_new, MK_old, MK_new, the PRF output and the key
/// encryption key are zeroed on every path. A failure or a timeout leaves the old state as it was.
/// </para>
/// </summary>
public sealed class KeyRotation(StateDatabase db, SecretStore store, EnrollmentTarget primaryTarget, EnrollmentTarget localTarget, Action<string>? announce = null)
{
    private readonly EnrollmentTarget primary = primaryTarget.Admin();
    private readonly EnrollmentTarget local = localTarget.Admin();

    /// <summary>Answers null while the rotation may go on and a short reason once it must not (the request was cancelled or the authority was locked); it is asked before the new state is written.</summary>
    public Func<string?>? StopReason { get; init; }

    internal Func<SqliteConnection, SqliteTransaction, string, string, string?>? RekeyReview { get; init; }

    private const string Heading = "Rotate the keys";
    private const string SignHeading = "Confirm the key change";

    /// <summary>For tests: runs on the new rows when the proof is checked, after the page got its bind; it may change them.</summary>
    internal Action<Dictionary<string, string>>? RowsBeforeSign { get; set; }

    public ConfigChange Run()
    {
        ConfigChange change;
        try
        {
            change = RunCore();
        }
        catch (ProofUnavailableException failure)
        {
            change = Denied(failure.Message);
        }
        catch (Exception)
        {
            change = Denied("the key rotation failed: " + HandleGuard.Reason + "; nothing was changed");
        }

        if (!change.Done)
        {
            db.Audit.TryWriteDenied("rotate-store-key", [], change.Detail);
        }

        return change;
    }

    private static ConfigChange Denied(string detail) => new(RunCommand.Denied, detail);

    private ConfigChange RunCore()
    {
        if (!db.TryManifest(out Manifest? manifest, out string? error))
        {
            return new ConfigChange(RunCommand.StoreError, error!);
        }

        if (manifest is null || manifest.Keys.Count == 0)
        {
            return Denied(PasskeyRegistration.NothingEnrolled);
        }

        if (manifest.Store.Length == 0 || manifest.Vault.Length == 0)
        {
            return Denied("the state has no secret store key; delete " + db.FileLabel + " and set up again with: with-secrets admin");
        }

        EnrollmentTarget? target = EnrollmentTarget.FirstThatCanProve(primary, local);
        if (target is null)
        {
            return Denied(Enrollment.NoTargetMessage(primary.Method.Id, primary.Host, local.Host));
        }

        Dictionary<string, string> oldRows;
        try
        {
            (_, oldRows) = store.Snapshot();
        }
        catch (SecretStoreException failure)
        {
            return new ConfigChange(RunCommand.StoreError, "cannot use the secret store: " + failure.Message);
        }

        string text = "New secret store and master keys; every secret is encrypted again.\n"
            + "Only the key you tap now stays. Removed (add them again as passkeys): "
            + RemovedList(manifest, null) + ".\n"
            + "You get a new recovery code; the old one stops working.\n"
            + "Nothing changes until you confirm on the next page.";
        announce?.Invoke(AdminKey.Line(manifest) + "\nIf it is not the one you noted, stop.");
        // One link: tap 1 leads to the Step 2 page.
        using IDisposable flow = PageFlow.Enter();
        PageFlow.Plan("a", target.Approver.Settings);
        ApprovalDecision asked = target.Approver.Ask(new ApprovalPrompt(Heading, text), unlock: true);
        try
        {
            if (!asked.Approved)
            {
                return Denied(asked.Detail);
            }

            if (asked.Unlock is not { } unlock)
            {
                return Denied("the key did not release its PRF output, which a key rotation needs; nothing was changed");
            }

            return Rotate(manifest, oldRows, target, unlock);
        }
        finally
        {
            asked.Unlock?.Dispose();
        }
    }

    /// <summary>The names of the keys other than <paramref name="keep" /> (the id of the key that stays; null when not known yet).</summary>
    private static string RemovedList(Manifest manifest, string? keep)
    {
        List<string> names = [.. manifest.Keys.Where(key => key.Id != keep).Select(key => ApprovalSummary.Clean(key.Name))];

        return names.Count == 0 ? "(none)" : string.Join(", ", names) + " (all but the key you tap)";
    }

    private ConfigChange Rotate(Manifest manifest, Dictionary<string, string> oldRows, EnrollmentTarget target, Unlock unlock)
    {
        ManifestKey? signer = manifest.Keys.FirstOrDefault(key => key.Id == unlock.CredentialId);
        if (signer is null || !signer.Admin || signer.Slot is null)
        {
            return Denied("only an admin key with a key slot can rotate the keys; nothing was changed");
        }

        byte[]? oldMaster = null;
        byte[]? oldKey = null;
        byte[]? oldReview = null;
        byte[]? newMaster = null;
        byte[]? newKey = null;
        try
        {
            try
            {
                oldMaster = KeyVault.OpenMaster(manifest, unlock);
                oldKey = KeyVault.UnwrapVault(manifest.Vault, oldMaster, manifest.Store);
                if (manifest.Review is { } review)
                {
                    oldReview = KeyVault.UnwrapReview(review.Vault, oldMaster, review.PublicKey);
                }
            }
            catch (CryptographicException)
            {
                return Denied("the key's PRF output does not open the store key; nothing was changed");
            }

            (string publicKey, string privateText) = JweCipher.Instance.NewKeyPair();
            newKey = Encoding.UTF8.GetBytes(privateText);
            privateText = "";

            // Every row, one at a time, decrypted with the old key and encrypted for the new one. Only ciphertext is kept.
            string oldPrivate = Encoding.UTF8.GetString(oldKey);
            Dictionary<string, string> rows = new(StringComparer.Ordinal);
            foreach ((string name, string ciphertext) in oldRows.OrderBy(item => item.Key, StringComparer.Ordinal))
            {
                string value = JweCipher.Instance.Decrypt(oldPrivate, ciphertext);
                rows[name] = JweCipher.Instance.Encrypt(value, publicKey);
            }

            newMaster = KeyVault.NewMasterKey();
            string vault = KeyVault.WrapVault(newKey, newMaster, publicKey);
            byte[] credentialId = Base64Url.DecodeFromChars(signer.Id);
            byte[] salt = Base64Url.DecodeFromChars(signer.Slot.Salt);
            ManifestKey kept = signer with { Slot = new KeySlot(signer.Slot.Salt, KeyVault.WrapSlot(newMaster, unlock.Output, credentialId, salt)) };
            byte[] code = KeyVault.NewRecoveryCode();
            KeySlot recovery;
            string recoveryText;
            try
            {
                recovery = KeyVault.NewRecoverySlot(newMaster, code, publicKey);
                recoveryText = RecoveryCode.Format(code);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(code);
            }

            SortedDictionary<string, string> hashes = new(StringComparer.Ordinal);
            foreach ((string name, string ciphertext) in rows)
            {
                hashes[name] = SecretStore.Hash(ciphertext);
            }

            ReviewKey nextReview = KeyVault.NewReviewKey(newMaster);
            Manifest next = manifest.Rotated(kept, publicKey, vault, recovery, hashes, nextReview);
            string nextText = next.Canonical();
            List<string> removedNames = [.. manifest.Keys.Where(key => key.Id != signer.Id).Select(key => key.Name)];
            int calls = 0;

            RowsCommit commit = new(
                () =>
                {
                    // The second call is the check of the proof: a test may change the rows between the two.
                    if (++calls > 1)
                    {
                        RowsBeforeSign?.Invoke(rows);
                    }

                    return RowsDigest(rows);
                },
                (signed, detail) =>
                {
                    if (PasskeyMethod.ResponseId(signed.Proof) != signer.Id)
                    {
                        return "the key that confirmed is not the key that was tapped first; nothing was changed";
                    }

                    if (StopReason?.Invoke() is { } stopped)
                    {
                        return "nothing was changed: " + stopped;
                    }

                    string note = $"keys rotated; {removedNames.Count.ToString(CultureInfo.InvariantCulture)} key(s) removed"
                        + (removedNames.Count == 0 ? "" : ": " + string.Join(", ", removedNames.Select(ApprovalSummary.Clean))) + $"; {rows.Count.ToString(CultureInfo.InvariantCulture)} secret(s) encrypted again";

                    return store.TryApply(manifest.Version, signed, rows, [], AdminEvent.Change("key-rotated", note, signer.Name, VerifiedCredential.From(signer)), (connection, transaction) =>
                    {
                        if (RekeyReview is { } rekey && oldReview is not null)
                        {
                            return rekey(connection, transaction, Encoding.UTF8.GetString(oldReview), nextReview.PublicKey);
                        }

                        if (ProviderStore.HasEncryptedConfigurations(connection, transaction))
                        {
                            return "the authority must re-encrypt the provider configurations; nothing was changed";
                        }


                        return WithSecretsDatabase.Scalar(connection, transaction, "SELECT 1 FROM grants WHERE seal IS NOT NULL LIMIT 1") is null
                            ? null : "the authority must re-encrypt the grant evidence; nothing was changed";
                    });
                },
                recoveryText);

            string signText = "Rotate the store keys and keep only " + ApprovalSummary.Clean(signer.Name) + ".\n"
                + "Removed (add them again): " + (removedNames.Count == 0 ? "(none)" : string.Join(", ", removedNames.Select(ApprovalSummary.Clean))) + ".\n"
                + rows.Count.ToString(CultureInfo.InvariantCulture) + " secret(s) will be encrypted again under the new keys.\n"
                + "Encrypted provider configurations are re-encrypted too. Reloaded providers may need new grant approvals.\n"
                + "Confirm with the same admin key.";
            ManifestApproval confirmed = target.Approver.AskManifest(new ApprovalPrompt(SignHeading, signText), nextText, commit);
            if (!confirmed.Decision.Approved)
            {
                return Denied(confirmed.Decision.Detail + "; nothing was changed");
            }

            return new ConfigChange(0, $"Rotated the keys. Kept: {signer.Name}. Removed: {(removedNames.Count == 0 ? "none" : string.Join(", ", removedNames))}. "
                + $"{rows.Count.ToString(CultureInfo.InvariantCulture)} secret(s) encrypted again. The authority is locked now: unlock it again with the kept passkey. The new recovery code is shown on the last page only once. If the page did not show it (lost connection), the old code is already dead: rotate again.");
        }
        finally
        {
            SecretValues.Clear(oldMaster);
            SecretValues.Clear(oldKey);
            SecretValues.Clear(oldReview);
            SecretValues.Clear(newMaster);
            SecretValues.Clear(newKey);
        }
    }

    /// <summary>SHA-256 over, for each name ascending (ordinal), UTF-8 name, 0x00, UTF-8 ciphertext, 0x0A.</summary>
    internal static byte[] RowsDigest(IReadOnlyDictionary<string, string> rows)
    {
        using IncrementalHash hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        foreach ((string name, string ciphertext) in rows.OrderBy(item => item.Key, StringComparer.Ordinal))
        {
            hash.AppendData(Encoding.UTF8.GetBytes(name));
            hash.AppendData([0]);
            hash.AppendData(Encoding.UTF8.GetBytes(ciphertext));
            hash.AppendData([10]);
        }

        return hash.GetHashAndReset();
    }
}
