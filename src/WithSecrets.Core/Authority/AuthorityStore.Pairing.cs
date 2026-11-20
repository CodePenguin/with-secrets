using Microsoft.Data.Sqlite;

namespace WithSecrets;

/// <summary>One pairing invitation as the authority keeps it: its status and times, never the code or the verifier key (that is held in memory by <see cref="PairingService" />).</summary>
public sealed record PairingInvitationRecord(string Id, DateTimeOffset Created, DateTimeOffset Expires, string Status, int Failed, DateTimeOffset? Ended, string? MachineFingerprint, string? RequestDigest, string? Result)
{
    /// <summary>pending, consumed, expired or revoked, as it stands at <paramref name="now" />.</summary>
    public string StatusAt(DateTimeOffset now) => Status == "pending" && now >= Expires ? "expired" : Status;
}

/// <summary>How a registration came out at the store.</summary>
public enum PairingOutcome
{
    /// <summary>The invitation was consumed and a Pending record was created.</summary>
    Registered,

    /// <summary>The invitation was consumed and the existing Pending record was refreshed.</summary>
    Refreshed,

    /// <summary>The same request was committed before: its original result.</summary>
    Replayed,

    /// <summary>Unknown, expired, consumed (by another request), withdrawn: the invitation cannot be used.</summary>
    InvitationRefused,

    /// <summary>The machine is already known and is not Pending (Trusted, Disabled or Untrusted): nothing was changed and the invitation was not consumed.</summary>
    MachineRefused,

    /// <summary>Too many machines are waiting: nothing was changed and the invitation was not consumed.</summary>
    TooManyPending,
}

public sealed record PairingConsumeResult(PairingOutcome Outcome, string Status, string Reason);

public sealed partial class AuthorityStore
{
    private const string InvitationSchema = """
        CREATE TABLE IF NOT EXISTS pairing_invitations (
            id TEXT PRIMARY KEY NOT NULL, created TEXT NOT NULL, expires TEXT NOT NULL, status TEXT NOT NULL, failed INTEGER NOT NULL,
            ended TEXT, machine TEXT, request_digest TEXT, result TEXT);
        """;

    private static PairingInvitationRecord ReadInvitation(SqliteDataReader reader) => new(reader.GetString(0), ParseTime(reader.GetString(1)), ParseTime(reader.GetString(2)),
        reader.GetString(3), reader.GetInt32(4), reader.IsDBNull(5) ? null : ParseTime(reader.GetString(5)), reader.IsDBNull(6) ? null : reader.GetString(6), reader.IsDBNull(7) ? null : reader.GetString(7), reader.IsDBNull(8) ? null : reader.GetString(8));

    private const string InvitationColumns = "id, created, expires, status, failed, ended, machine, request_digest, result";

    private static string Short(string id) => id.Length > 8 ? id[..8] : id;

    /// <summary>Ends every pending invitation whose time has passed, writing one audit row for each. Part of a write transaction.</summary>
    private void ExpireIn(SqliteConnection connection, SqliteTransaction transaction)
    {
        string now = Time(Now);
        foreach (string id in Query(connection, transaction, "SELECT id FROM pairing_invitations WHERE status = 'pending' AND expires <= $now", reader => reader.GetString(0), ("$now", now)))
        {
            StateDatabase.Execute(connection, transaction, "UPDATE pairing_invitations SET status = 'expired', ended = $now WHERE id = $id", ("$now", now), ("$id", id));
            Audit(connection, transaction, "pairing-invitation-expired", null, null, "authority", "invitation " + Short(id) + " expired unused");
        }
    }

    /// <summary>Expires what has run out (audited). Cheap when nothing has.</summary>
    public void ExpireInvitations()
    {
        bool any = Read(connection => connection is not null && Query(connection, null, "SELECT 1 FROM pairing_invitations WHERE status = 'pending' AND expires <= $now LIMIT 1", reader => reader.GetInt32(0), ("$now", Time(Now))).Count > 0);
        if (any)
        {
            Write((connection, transaction) =>
            {
                ExpireIn(connection, transaction);

                return 0;
            });
        }
    }

    /// <summary>
    /// Ends every pending invitation, audited. Called when the service starts: the key an invitation needs is held in memory only, so one made by a run that has ended can never be answered. Returns how many it ended.
    /// </summary>
    public int EndOpenInvitations()
    {
        // A service that is only a host (it has no authority database to write to) finds nothing and writes nothing.
        if (!Read(connection => connection is not null && Query(connection, null, "SELECT 1 FROM pairing_invitations WHERE status = 'pending' LIMIT 1", reader => reader.GetInt32(0)).Count > 0))
        {
            return 0;
        }

        return Write((connection, transaction) =>
        {
            string now = Time(Now);
            IReadOnlyList<string> open = Query(connection, transaction, "SELECT id FROM pairing_invitations WHERE status = 'pending'", reader => reader.GetString(0));
            foreach (string id in open)
            {
                StateDatabase.Execute(connection, transaction, "UPDATE pairing_invitations SET status = 'expired', ended = $now WHERE id = $id", ("$now", now), ("$id", id));
                Audit(connection, transaction, "pairing-invitation-expired", null, null, "authority", "invitation " + Short(id) + " ended: the service restarted and its key was only in memory");
            }

            return open.Count;
        });
    }

    /// <summary>Stores a new invitation and audits it. Refused (with the reason) when too many are open.</summary>
    public string? CreateInvitation(string id, DateTimeOffset expires, string actor, int maxOpen)
    {
        return Write((connection, transaction) =>
        {
            ExpireIn(connection, transaction);
            string now = Time(Now);
            if (Query(connection, transaction, "SELECT COUNT(*) FROM pairing_invitations WHERE status = 'pending'", reader => reader.GetInt32(0)).Single() >= maxOpen)
            {
                return "too many invitations are open; wait for one to be used or to expire, or revoke one";
            }

            StateDatabase.Execute(connection, transaction, "INSERT INTO pairing_invitations (id, created, expires, status, failed) VALUES ($id, $now, $expires, 'pending', 0)",
                ("$id", id), ("$now", now), ("$expires", Time(expires)));
            Audit(connection, transaction, "pairing-invitation-created", null, null, actor, "invitation " + Short(id) + ", expires " + Time(expires));

            return null;
        });
    }

    /// <summary>The invitations, newest first (status only: never a code or a key). Expired ones are ended first.</summary>
    public IReadOnlyList<PairingInvitationRecord> Invitations()
    {
        ExpireInvitations();

        return Read(connection => connection is null ? [] : Query(connection, null, $"SELECT {InvitationColumns} FROM pairing_invitations ORDER BY created DESC, id LIMIT 200", ReadInvitation));
    }

    public PairingInvitationRecord? Invitation(string id)
    {
        return Read(connection => connection is null ? null : Query(connection, null, $"SELECT {InvitationColumns} FROM pairing_invitations WHERE id = $id", ReadInvitation, ("$id", id)).FirstOrDefault());
    }

    /// <summary>Counts a refused attempt against an invitation; at the limit it is withdrawn. Returns the failures so far (0 when the invitation is not pending).</summary>
    public int RecordInvitationFailure(string id, string reason, int limit)
    {
        return Write((connection, transaction) =>
        {
            if (Query(connection, transaction, $"SELECT {InvitationColumns} FROM pairing_invitations WHERE id = $id", ReadInvitation, ("$id", id)).FirstOrDefault() is not { Status: "pending" } invitation)
            {
                return 0;
            }

            int failed = invitation.Failed + 1;
            StateDatabase.Execute(connection, transaction, "UPDATE pairing_invitations SET failed = $failed WHERE id = $id", ("$failed", failed), ("$id", id));
            Audit(connection, transaction, "pairing-attempt-refused", null, null, "pairing", $"invitation {Short(id)}: {reason} (failure {failed} of {limit})");
            if (failed >= limit)
            {
                StateDatabase.Execute(connection, transaction, "UPDATE pairing_invitations SET status = 'revoked', ended = $now WHERE id = $id", ("$now", Time(Now)), ("$id", id));
                Audit(connection, transaction, "pairing-invitation-withdrawn", null, null, "authority", "invitation " + Short(id) + " withdrawn after too many wrong proofs");
            }

            return failed;
        });
    }

    /// <summary>Withdraws a pending invitation (an administrator's revoke). False when it is not pending.</summary>
    public bool RevokeInvitation(string id, string actor)
    {
        return Write((connection, transaction) =>
        {
            ExpireIn(connection, transaction);
            if (StateDatabase.Execute(connection, transaction, "UPDATE pairing_invitations SET status = 'revoked', ended = $now WHERE id = $id AND status = 'pending'", ("$now", Time(Now)), ("$id", id)) != 1)
            {
                return false;
            }

            Audit(connection, transaction, "pairing-invitation-revoked", null, null, actor, "invitation " + Short(id) + " revoked");

            return true;
        });
    }

    /// <summary>Writes one audit row of the pairing route (never a code, a proof or a key).</summary>
    public void RecordPairingEvent(string eventName, string? fingerprint, string detail)
    {
        Write((connection, transaction) =>
        {
            Audit(connection, transaction, eventName, fingerprint, null, "pairing", detail);

            return 0;
        });
    }

    /// <summary>How many machines are Pending, and how many of them have this host name.</summary>
    public (int Total, int WithName) PendingCount(string hostName)
    {
        IReadOnlyList<MachineRecord> pending = [.. Machines().Where(machine => machine.Status == MachineStatus.Pending)];

        return (pending.Count, pending.Count(machine => string.Equals(machine.HostName, hostName, StringComparison.OrdinalIgnoreCase)));
    }

    /// <summary>
    /// The one atomic step: in ONE write transaction the invitation is consumed (single use: only a pending, unexpired one) and the machine's Pending record is created or refreshed, with their audit rows. The same request
    /// again after it was committed (a lost answer) returns the same result and changes nothing; any other request for a consumed invitation is refused. A machine that is already known and not Pending (Trusted, Disabled,
    /// Untrusted) is left exactly as it is and the invitation is not consumed. Anything that throws inside rolls the whole step back.
    /// </summary>
    public PairingConsumeResult ConsumeAndRegister(string invitationId, string requestDigest, byte[] publicKey, string hostName, byte[] identityCertificate, int maxPending, int maxPendingPerHost)
    {
        string fingerprint = KeyIdentity.Fingerprint(publicKey);

        return Write((connection, transaction) =>
        {
            ExpireIn(connection, transaction);
            if (Query(connection, transaction, $"SELECT {InvitationColumns} FROM pairing_invitations WHERE id = $id", ReadInvitation, ("$id", invitationId)).FirstOrDefault() is not { } invitation)
            {
                return new PairingConsumeResult(PairingOutcome.InvitationRefused, "", "unknown invitation");
            }

            if (invitation.Status == "consumed")
            {
                return invitation.RequestDigest == requestDigest && invitation.Result is { } committed
                    ? new PairingConsumeResult(PairingOutcome.Replayed, committed, "the same registration, committed before")
                    : new PairingConsumeResult(PairingOutcome.InvitationRefused, "", "invitation already used");
            }

            if (invitation.Status != "pending")
            {
                return new PairingConsumeResult(PairingOutcome.InvitationRefused, "", "invitation " + invitation.Status);
            }

            MachineRecord? known = Query(connection, transaction, "SELECT * FROM machines WHERE fingerprint = $fp", Machine, ("$fp", fingerprint)).FirstOrDefault();
            if (known is { Status: not MachineStatus.Pending })
            {
                Audit(connection, transaction, "pairing-refused", fingerprint, null, "pairing", $"invitation {Short(invitationId)}: the machine is already known as {known.Status}; nothing was changed and the invitation was not used");

                return new PairingConsumeResult(PairingOutcome.MachineRefused, known.Status.ToString(), "the machine is already known and is not Pending");
            }

            if (known is null)
            {
                int total = Query(connection, transaction, "SELECT COUNT(*) FROM machines WHERE status = 'Pending'", reader => reader.GetInt32(0)).Single();
                int sameName = Query(connection, transaction, "SELECT COUNT(*) FROM machines WHERE status = 'Pending' AND host_name = $host COLLATE NOCASE", reader => reader.GetInt32(0), ("$host", hostName)).Single();
                if (total >= maxPending || sameName >= maxPendingPerHost)
                {
                    Audit(connection, transaction, "pairing-refused", fingerprint, null, "pairing", $"invitation {Short(invitationId)}: too many machines are waiting for approval; the invitation was not used");

                    return new PairingConsumeResult(PairingOutcome.TooManyPending, "", "too many machines are waiting");
                }
            }

            string now = Time(Now);
            if (StateDatabase.Execute(connection, transaction, "UPDATE pairing_invitations SET status = 'consumed', ended = $now, machine = $fp, request_digest = $digest, result = 'Pending' WHERE id = $id AND status = 'pending' AND expires > $now",
                ("$now", now), ("$fp", fingerprint), ("$digest", requestDigest), ("$id", invitationId)) != 1)
            {
                return new PairingConsumeResult(PairingOutcome.InvitationRefused, "", "invitation cannot be used now");
            }

            Fault?.Invoke("pairing-after-consume");
            if (known is null)
            {
                StateDatabase.Execute(connection, transaction, "INSERT INTO machines (fingerprint, public_key, host_name, friendly_name, status, security_revision, pending_host_name, created, updated) VALUES ($fp, $key, $host, NULL, 'Pending', 1, NULL, $now, $now)",
                    ("$fp", fingerprint), ("$key", Convert.ToBase64String(publicKey)), ("$host", hostName), ("$now", now));
                History(connection, transaction, fingerprint, "registered", null, MachineStatus.Pending, 1, "pairing", "registered by pairing (invitation, certificate and proof of possession verified); host name " + hostName);
                Audit(connection, transaction, "machine-registered", fingerprint, null, "pairing", "Pending; host name " + hostName + "; by pairing invitation " + Short(invitationId));
            }
            else
            {
                StateDatabase.Execute(connection, transaction, "UPDATE machines SET host_name = $host, updated = $now WHERE fingerprint = $fp", ("$host", hostName), ("$now", now), ("$fp", fingerprint));
                History(connection, transaction, fingerprint, "pairing-refreshed", MachineStatus.Pending, MachineStatus.Pending, known.SecurityRevision, "pairing", "registered again by pairing; host name " + hostName);
                Audit(connection, transaction, "machine-pairing-refreshed", fingerprint, null, "pairing", "Pending record refreshed; host name " + hostName + "; by pairing invitation " + Short(invitationId));
            }

            SetCertificate(connection, transaction, fingerprint, identityCertificate);
            Audit(connection, transaction, "pairing-invitation-consumed", fingerprint, null, "pairing", "invitation " + Short(invitationId) + " used by machine " + KeyIdentity.Display(fingerprint) + " (" + hostName + ")");
            Fault?.Invoke("pairing-before-commit");

            return new PairingConsumeResult(known is null ? PairingOutcome.Registered : PairingOutcome.Refreshed, "Pending", "");
        });
    }
}
