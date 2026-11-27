namespace WithSecrets;

public sealed partial class WithSecretsDatabase
{
    private const string Schema = """
        CREATE TABLE schema_version (version INTEGER NOT NULL);
        CREATE TABLE manifest (
            id INTEGER PRIMARY KEY NOT NULL, version INTEGER NOT NULL, text TEXT NOT NULL, bind TEXT NOT NULL,
            credential_id TEXT NOT NULL, authenticator_data TEXT NOT NULL, client_data TEXT NOT NULL, signature TEXT NOT NULL);
        CREATE TABLE sign_counts (id TEXT PRIMARY KEY NOT NULL, count INTEGER NOT NULL);
        CREATE TABLE secrets (name TEXT PRIMARY KEY NOT NULL, ciphertext TEXT NOT NULL);

        CREATE TABLE machines (
            fingerprint TEXT PRIMARY KEY NOT NULL, public_key TEXT NOT NULL, host_name TEXT NOT NULL, friendly_name TEXT,
            status TEXT NOT NULL, security_revision INTEGER NOT NULL, pending_host_name TEXT, created TEXT NOT NULL, updated TEXT NOT NULL);
        CREATE TABLE machine_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT, fingerprint TEXT NOT NULL, time TEXT NOT NULL, kind TEXT NOT NULL,
            from_status TEXT, to_status TEXT, security_revision INTEGER NOT NULL, actor TEXT NOT NULL, detail TEXT NOT NULL);
        CREATE TABLE grants (
            id TEXT PRIMARY KEY NOT NULL, fingerprint TEXT NOT NULL, scope_key TEXT NOT NULL, program TEXT NOT NULL, working_directory TEXT NOT NULL,
            secret_names TEXT NOT NULL, created TEXT NOT NULL, updated TEXT NOT NULL, expires TEXT, grant_revision INTEGER NOT NULL,
            security_revision INTEGER NOT NULL, status TEXT NOT NULL, approved_by TEXT NOT NULL, revoked TEXT,
            evidence_kind TEXT, evidence_nonce TEXT, evidence_ciphertext TEXT, evidence_proof TEXT, evidence_minutes INTEGER,
            usage TEXT NOT NULL, consumed TEXT, replaces TEXT, review_key TEXT, seal_key TEXT, seal BLOB, approved_key_id TEXT, approved_key_name TEXT, approved_key_admin INTEGER,
            changed_key_id TEXT, changed_key_name TEXT, changed_key_admin INTEGER);
        CREATE TABLE provider_instances (
            id TEXT PRIMARY KEY, name TEXT NOT NULL UNIQUE, provider_type TEXT NOT NULL, configuration TEXT NOT NULL,
            max_stale_seconds INTEGER NOT NULL CHECK (max_stale_seconds BETWEEN 0 AND 86400), revision INTEGER NOT NULL);
        CREATE TABLE mounts (
            id TEXT PRIMARY KEY, instance_id TEXT NOT NULL REFERENCES provider_instances(id),
            kind TEXT NOT NULL CHECK (kind IN ('tree','single')), logical_path TEXT NOT NULL, base_path TEXT NOT NULL, UNIQUE(kind, logical_path));
        CREATE TABLE namespace_entries (
            mount_id TEXT NOT NULL REFERENCES mounts(id), logical_path TEXT NOT NULL, provider_path TEXT NOT NULL, external_id TEXT NOT NULL,
            description TEXT, description_source TEXT NOT NULL CHECK (description_source IN ('provider','local')), PRIMARY KEY (mount_id, logical_path));
        CREATE TABLE provider_cache (
            instance_id TEXT NOT NULL, external_id TEXT NOT NULL, ciphertext TEXT NOT NULL, last_verified INTEGER NOT NULL,
            store_public_key TEXT NOT NULL, authority_key TEXT NOT NULL, signature BLOB NOT NULL, PRIMARY KEY (instance_id, external_id));
        CREATE TABLE grant_events (
            seq INTEGER PRIMARY KEY AUTOINCREMENT, fingerprint TEXT NOT NULL, grant_id TEXT NOT NULL, scope_key TEXT NOT NULL, kind TEXT NOT NULL,
            grant_revision INTEGER NOT NULL, state TEXT NOT NULL, created TEXT NOT NULL, acknowledged TEXT);
        CREATE TABLE processed_grant_requests (
            request_id TEXT PRIMARY KEY NOT NULL, fingerprint TEXT NOT NULL, request_digest TEXT NOT NULL, response TEXT NOT NULL, created TEXT NOT NULL);
        CREATE TABLE authority_keys (
            generation INTEGER PRIMARY KEY NOT NULL, fingerprint TEXT NOT NULL UNIQUE, public_key TEXT NOT NULL, status TEXT NOT NULL,
            created TEXT NOT NULL, retired TEXT, previous_fingerprint TEXT, transition_signature TEXT, how TEXT NOT NULL);
        CREATE TABLE audit_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT, time TEXT NOT NULL, event TEXT NOT NULL, fingerprint TEXT, request_id TEXT,
            actor TEXT NOT NULL, detail TEXT NOT NULL, key_id TEXT, key_name TEXT, key_admin INTEGER, metadata TEXT);
        CREATE TABLE processed_requests (
            request_id TEXT PRIMARY KEY NOT NULL, fingerprint TEXT NOT NULL, request_digest TEXT NOT NULL, response TEXT NOT NULL,
            created TEXT NOT NULL);
        CREATE TABLE pending_invalidations (
            fingerprint TEXT NOT NULL, security_revision INTEGER NOT NULL, state TEXT NOT NULL, created TEXT NOT NULL,
            acknowledged TEXT, PRIMARY KEY (fingerprint, security_revision));

        CREATE TABLE audit_events (
            fingerprint TEXT NOT NULL, event_id TEXT NOT NULL, epoch TEXT NOT NULL, sequence INTEGER NOT NULL, time TEXT NOT NULL, type TEXT NOT NULL, outcome TEXT NOT NULL,
            reason TEXT NOT NULL, request_id TEXT NOT NULL, folder TEXT NOT NULL, program TEXT NOT NULL, arguments TEXT NOT NULL, grant_id TEXT NOT NULL,
            exit_code INTEGER, event_json TEXT NOT NULL, received TEXT NOT NULL, acknowledged TEXT NOT NULL, PRIMARY KEY (fingerprint, event_id));
        CREATE INDEX audit_events_machine ON audit_events (fingerprint, sequence);
        CREATE INDEX audit_events_time ON audit_events (time);
        CREATE TABLE audit_machine_state (fingerprint TEXT NOT NULL, epoch TEXT NOT NULL, highest INTEGER NOT NULL, updated TEXT NOT NULL, PRIMARY KEY (fingerprint, epoch));
        CREATE TABLE audit_gaps (
            id INTEGER PRIMARY KEY AUTOINCREMENT, fingerprint TEXT NOT NULL, epoch TEXT NOT NULL DEFAULT '', kind TEXT NOT NULL, from_sequence INTEGER NOT NULL, to_sequence INTEGER NOT NULL,
            detected TEXT NOT NULL, resolved TEXT);
        CREATE TABLE authority_settings (name TEXT PRIMARY KEY NOT NULL, value TEXT NOT NULL);
        CREATE TABLE admin_spent_nonces (nonce TEXT PRIMARY KEY NOT NULL, expires TEXT NOT NULL);

        CREATE TABLE machine_certificates (fingerprint TEXT PRIMARY KEY NOT NULL, certificate TEXT NOT NULL, updated TEXT NOT NULL);

        CREATE TABLE copy_warnings (
            fingerprint TEXT PRIMARY KEY NOT NULL, count INTEGER NOT NULL, first_address TEXT NOT NULL, last_address TEXT NOT NULL,
            first_seen TEXT NOT NULL, last_seen TEXT NOT NULL, audited TEXT);

        CREATE TABLE pairing_invitations (
            id TEXT PRIMARY KEY NOT NULL, created TEXT NOT NULL, expires TEXT NOT NULL, status TEXT NOT NULL, failed INTEGER NOT NULL,
            ended TEXT, machine TEXT, request_digest TEXT, result TEXT);

        CREATE TABLE outbox_counter (id INTEGER PRIMARY KEY CHECK (id = 1), last_sequence INTEGER NOT NULL, epoch TEXT NOT NULL, machine TEXT NOT NULL);
        CREATE TABLE outbox_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT, machine TEXT NOT NULL, sequence INTEGER NOT NULL, event_id TEXT NOT NULL UNIQUE, json TEXT NOT NULL, created TEXT NOT NULL,
            state TEXT NOT NULL, reason TEXT);
        CREATE INDEX outbox_events_upload ON outbox_events (machine, state, id);
""" + "\n" + SecretWritesSchema;

    private const string SecretWritesSchema = """
        CREATE TABLE secret_writes (
            version INTEGER PRIMARY KEY NOT NULL, text TEXT NOT NULL, bind TEXT NOT NULL, proof TEXT NOT NULL);
        """;
}
