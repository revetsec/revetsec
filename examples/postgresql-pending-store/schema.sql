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

-- Copyright 2026 Revetware LLC. Apache-2.0. Unpublished application fixture.
-- Fresh or fully quiesced schema-2 namespaces only; never an online legacy ALTER.
-- Admission mirrors are not UTC, recovery freshness or old-writer exclusion evidence.
CREATE TABLE issuer_store_namespace (
    namespace text COLLATE "C" PRIMARY KEY CHECK(char_length(namespace) BETWEEN 1 AND 128 AND namespace ~ '^[A-Za-z0-9_-]+$'),
    physical_namespace text COLLATE "C" NOT NULL UNIQUE CHECK(char_length(physical_namespace)=43),
    authority_id text COLLATE "C" NOT NULL CHECK(char_length(authority_id)=43),
    recovery_generation text COLLATE "C" NOT NULL CHECK(char_length(recovery_generation)=43),
    clock_generation text COLLATE "C" NOT NULL CHECK(char_length(clock_generation)=43),
    maximum_utc_error_nanos bigint NOT NULL CHECK(maximum_utc_error_nanos BETWEEN 0 AND 250000000),
    allocation_generation text COLLATE "C" NOT NULL CHECK(char_length(allocation_generation)=43),
    format_version integer NOT NULL CHECK(format_version=2),
    maximum_entries integer NOT NULL CHECK(maximum_entries BETWEEN 1 AND 1000000),
    admission_open boolean NOT NULL
);
-- Per-issuer first-root activation survives ordinary data loss. A missing registered root is unavailable,
-- not confirmed absence or permission for lazy recreation. It is not an external recovery witness.
CREATE TABLE issuer_store_root (
    namespace text COLLATE "C" NOT NULL REFERENCES issuer_store_namespace(namespace),
    storage_key text COLLATE "C" NOT NULL CHECK(char_length(storage_key) BETWEEN 1 AND 640),
    PRIMARY KEY(namespace,storage_key)
);
CREATE TABLE issuer_store_entry (
 namespace text COLLATE "C" NOT NULL REFERENCES issuer_store_namespace(namespace),
 storage_key text COLLATE "C" NOT NULL CHECK(char_length(storage_key) BETWEEN 1 AND 256),
 kind text COLLATE "C" NOT NULL CHECK(kind IN ('ISSUER_STATE','SUBJECT_STATE','INTERACTION','CODE','GRANT','ACCESS_TOKEN','REFRESH_TOKEN')),
 version text COLLATE "C" NOT NULL CHECK(char_length(version)=43),
 retain_seconds bigint NOT NULL,
 retain_nanos integer NOT NULL CHECK(retain_nanos BETWEEN 0 AND 999999999),
 sealed_form text COLLATE "C" NOT NULL CHECK(octet_length(sealed_form) BETWEEN 1 AND 16384),
 PRIMARY KEY(namespace,storage_key)
);
CREATE INDEX issuer_store_retention ON issuer_store_entry(namespace,retain_seconds,retain_nanos)
 WHERE kind NOT IN ('ISSUER_STATE','SUBJECT_STATE');
CREATE TABLE issuer_store_escrow (
    family text COLLATE "C" NOT NULL CHECK(family='ISSUER'),
    namespace text COLLATE "C" NOT NULL REFERENCES issuer_store_namespace(physical_namespace),
    bucket integer NOT NULL CHECK(bucket BETWEEN 0 AND 255),
    allocation_generation text COLLATE "C" NOT NULL CHECK(char_length(allocation_generation)=43),
    entry_limit bigint NOT NULL CHECK(entry_limit BETWEEN 0 AND 1000000),
    used_entries bigint NOT NULL CHECK(used_entries BETWEEN 0 AND entry_limit),
    byte_limit bigint NOT NULL CHECK(byte_limit=0),
    used_bytes bigint NOT NULL CHECK(used_bytes=0),
    PRIMARY KEY(family,namespace,bucket)
);

-- Optional authoritative WebAuthn store. Every participating node, including account
-- management, must lock the provisioned namespace row before reading or writing. Retain
-- credential tombstones and account fences; only expired ceremonies are reclaimed.
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
    expires_at timestamptz,
    PRIMARY KEY (namespace, storage_key)
);

CREATE INDEX webauthn_store_ceremony_expiry ON webauthn_store_entry(namespace, expires_at)
    WHERE kind = 'CEREMONY' AND expires_at IS NOT NULL;

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
