-- Copyright 2026 Revetware LLC. Apache-2.0. Unpublished application fixture.
-- Fresh or fully quiesced and migrated WAR2 namespaces only; never an online ALTER of legacy rows.
-- Admission mirrors do not certify UTC, recovery freshness, old-writer exclusion or migration fit.
CREATE SEQUENCE webauthn_store_version_seq AS bigint NO CYCLE;
CREATE TABLE webauthn_store_namespace (
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
-- Per-RP first-root activation survives ordinary data loss. A missing registered root is unavailable,
-- not confirmed absence or permission for lazy recreation. It is not an external recovery witness.
CREATE TABLE webauthn_store_root (
    namespace text COLLATE "C" NOT NULL REFERENCES webauthn_store_namespace(namespace),
    storage_key text COLLATE "C" NOT NULL CHECK(char_length(storage_key) BETWEEN 1 AND 640),
    PRIMARY KEY(namespace,storage_key)
);
CREATE TABLE webauthn_store_entry (
    namespace text COLLATE "C" NOT NULL REFERENCES webauthn_store_namespace(namespace),
    storage_key text COLLATE "C" NOT NULL CHECK(char_length(storage_key) BETWEEN 1 AND 640),
    kind text COLLATE "C" NOT NULL CHECK(kind IN ('CEREMONY','CREDENTIAL','ACCOUNT_CREDENTIAL_INDEX','ACCOUNT_FENCE','NAMESPACE_CLOCK')),
    version bigint NOT NULL CHECK(version>0),
    sealed_form text COLLATE "C" NOT NULL CHECK(char_length(sealed_form) BETWEEN 1 AND 350000 AND sealed_form ~ '^[A-Za-z0-9_-]+$'),
    sealed_size integer NOT NULL CHECK(sealed_size BETWEEN 1 AND 262144 AND sealed_size=(char_length(sealed_form)*3)/4),
    expires_seconds bigint,
    expires_nanos integer,
    PRIMARY KEY(namespace,storage_key),
    CHECK((kind='CEREMONY' AND expires_seconds IS NOT NULL AND expires_nanos IS NOT NULL AND expires_nanos BETWEEN 0 AND 999999999)
       OR (kind<>'CEREMONY' AND expires_seconds IS NULL AND expires_nanos IS NULL))
);
-- Exact SQL projection, never rounded TIMESTAMPTZ. Ordinary reads never use it for cleanup/absence.
CREATE INDEX webauthn_store_ceremony_expiry ON webauthn_store_entry(namespace,expires_seconds,expires_nanos) WHERE kind='CEREMONY';
CREATE TABLE webauthn_store_escrow (
    family text COLLATE "C" NOT NULL CHECK(family='WEBAUTHN'),
    namespace text COLLATE "C" NOT NULL REFERENCES webauthn_store_namespace(physical_namespace),
    bucket integer NOT NULL CHECK(bucket BETWEEN 0 AND 255),
    allocation_generation text COLLATE "C" NOT NULL CHECK(char_length(allocation_generation)=43),
    entry_limit bigint NOT NULL CHECK(entry_limit BETWEEN 0 AND 1000000),
    used_entries bigint NOT NULL CHECK(used_entries BETWEEN 0 AND entry_limit),
    byte_limit bigint NOT NULL CHECK(byte_limit=0),
    used_bytes bigint NOT NULL CHECK(used_bytes=0),
    PRIMARY KEY(family,namespace,bucket)
);
-- Application recovery marker remains distinct from shared-clock admission and durable UTC floors.
CREATE TABLE webauthn_recovery_epoch (
    namespace text PRIMARY KEY REFERENCES webauthn_store_namespace(namespace),
    epoch text NOT NULL CHECK(char_length(epoch)=43),
    sealer_digest text NOT NULL CHECK(char_length(sealer_digest)=43)
);
-- Runtime gets SELECT/INSERT/UPDATE, ceremony-only DELETE through RLS, and sequence USAGE.
-- All 256 entry quotas are allocated under closed administrator inventory, not borrowed normally.
