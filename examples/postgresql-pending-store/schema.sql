-- Apply through an application migration before serving OAuth/OIDC or WebAuthn traffic.
-- The namespace clock row is an authoritative fence. Never recreate it on request traffic.
CREATE TABLE pending_authorization_clock (
    namespace text PRIMARY KEY,
    observed_seconds bigint NOT NULL,
    observed_nanos integer NOT NULL CHECK (observed_nanos BETWEEN 0 AND 999999999)
);

CREATE TABLE pending_authorization (
    namespace text NOT NULL REFERENCES pending_authorization_clock(namespace),
    storage_key bytea NOT NULL CHECK (octet_length(storage_key) = 32),
    opaque_record text NOT NULL,
    expires_seconds bigint NOT NULL,
    expires_nanos integer NOT NULL CHECK (expires_nanos BETWEEN 0 AND 999999999),
    charged_bytes integer NOT NULL CHECK (charged_bytes > 32),
    PRIMARY KEY (namespace, storage_key)
);

-- For a new deployment only, after choosing a stable application namespace:
-- INSERT INTO pending_authorization_clock(namespace,observed_seconds,observed_nanos)
-- VALUES ('my_application',0,0);

-- Optional shared CIMD metadata cache. It is never an authorization or replay store.
CREATE TABLE cimd_cache_namespace (
    namespace text PRIMARY KEY,
    next_order bigint NOT NULL CHECK (next_order >= 0)
);

CREATE TABLE cimd_cache_entry (
    namespace text NOT NULL REFERENCES cimd_cache_namespace(namespace),
    storage_key text NOT NULL CHECK (char_length(storage_key) = 109),
    version text NOT NULL CHECK (char_length(version) = 43),
    expires_seconds bigint NOT NULL,
    sealed_form text NOT NULL CHECK (char_length(sealed_form) BETWEEN 1 AND 16384),
    write_order bigint NOT NULL CHECK (write_order > 0),
    PRIMARY KEY (namespace, storage_key)
);

CREATE INDEX cimd_cache_eviction_order ON cimd_cache_entry(namespace,write_order,storage_key);

-- For a new cache namespace only, before serving traffic:
-- INSERT INTO cimd_cache_namespace(namespace,next_order) VALUES ('my_cache',0);

-- Optional authoritative OAuth issuer store. Every participating node and operator mutation
-- must serialize through the same provisioned namespace row. Never TTL-delete live entries,
-- retained replay records, or permanent issuer/subject fences.
CREATE TABLE issuer_store_namespace (
    namespace text PRIMARY KEY
);

CREATE TABLE issuer_store_entry (
    namespace text NOT NULL REFERENCES issuer_store_namespace(namespace),
    storage_key text COLLATE "C" NOT NULL CHECK (char_length(storage_key) BETWEEN 1 AND 256),
    kind text COLLATE "C" NOT NULL,
    version text COLLATE "C" NOT NULL CHECK (char_length(version) = 43),
    retain_seconds bigint NOT NULL,
    retain_nanos integer NOT NULL CHECK (retain_nanos BETWEEN 0 AND 999999999),
    sealed_form text COLLATE "C" NOT NULL CHECK (octet_length(sealed_form) BETWEEN 1 AND 16384),
    PRIMARY KEY (namespace, storage_key)
);

-- For a new issuer namespace only, before initialization and serving traffic:
-- INSERT INTO issuer_store_namespace(namespace) VALUES ('my_issuer');

-- Optional authoritative WebAuthn store. Every participating node, including account
-- management, must lock the provisioned namespace row before reading or writing. Retain
-- credential tombstones and account fences; do not TTL-delete live protocol state.
CREATE SEQUENCE webauthn_store_version_seq AS bigint NO CYCLE;

CREATE TABLE webauthn_store_namespace (
    namespace text PRIMARY KEY
);

CREATE TABLE webauthn_store_entry (
    namespace text NOT NULL REFERENCES webauthn_store_namespace(namespace),
    storage_key text COLLATE "C" NOT NULL CHECK (char_length(storage_key) BETWEEN 1 AND 640),
    kind text COLLATE "C" NOT NULL,
    version bigint NOT NULL CHECK (version > 0),
    sealed_form text COLLATE "C" NOT NULL CHECK (octet_length(sealed_form) BETWEEN 1 AND 350000),
    PRIMARY KEY (namespace, storage_key)
);

-- Optional application recovery marker used by the local WebAuthn fixture. Its matching
-- epoch and sealing-key fingerprint must also be retained in an independent durable control
-- plane outside the restored database snapshot.
CREATE TABLE webauthn_recovery_epoch (
    namespace text PRIMARY KEY REFERENCES webauthn_store_namespace(namespace),
    epoch text COLLATE "C" NOT NULL CHECK (octet_length(epoch) = 43),
    sealer_digest text COLLATE "C" NOT NULL CHECK (octet_length(sealer_digest) = 43)
);

-- Provision only a new namespace before WebAuthn traffic:
-- INSERT INTO webauthn_store_namespace(namespace) VALUES ('my_passkeys');

-- Optional application browser sessions for a multi-process issuer example. The same provisioned
-- namespace row serializes creation, login rotation, pending replacement, consent claim and logout.
-- Store only SHA-256 of the random cookie ID; the app-sealed row binds that hash and namespace.
CREATE TABLE issuer_browser_namespace (
    namespace text PRIMARY KEY,
    observed_seconds bigint NOT NULL,
    observed_nanos integer NOT NULL CHECK (observed_nanos BETWEEN 0 AND 999999999)
);

CREATE TABLE issuer_browser_session (
    namespace text NOT NULL REFERENCES issuer_browser_namespace(namespace),
    session_key bytea NOT NULL CHECK (octet_length(session_key) = 32),
    sealed_form text COLLATE "C" NOT NULL CHECK (octet_length(sealed_form) BETWEEN 1 AND 3800),
    expires_seconds bigint NOT NULL,
    expires_nanos integer NOT NULL CHECK (expires_nanos BETWEEN 0 AND 999999999),
    PRIMARY KEY (namespace, session_key)
);

CREATE INDEX issuer_browser_session_expiry ON issuer_browser_session(namespace,expires_seconds,expires_nanos);

-- For a new browser namespace only, before admitting browser traffic:
-- INSERT INTO issuer_browser_namespace(namespace,observed_seconds,observed_nanos)
-- VALUES ('my_issuer_browser',0,0);
