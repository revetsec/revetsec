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
