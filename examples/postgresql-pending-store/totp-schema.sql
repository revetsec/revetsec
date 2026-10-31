-- Copyright 2026 Revetware LLC. Apache-2.0. Unpublished application fixture.
-- New-format deployment only: independently close/fence/drain old writers, perform complete
-- closed migration/preflight and provision witness admission before any new writer is started.
-- This schema is not an online upgrade and its rows cannot certify their own recovery admission.
CREATE TABLE totp_store_namespace (
    namespace text COLLATE "C" PRIMARY KEY
        CHECK (char_length(namespace) BETWEEN 1 AND 128 AND namespace ~ '^[!-~]+$'),
    physical_namespace text COLLATE "C" NOT NULL UNIQUE
        CHECK (char_length(physical_namespace)=43 AND physical_namespace ~ '^[A-Za-z0-9_-]+$'),
    active_epoch text COLLATE "C" NOT NULL
        CHECK (char_length(active_epoch) BETWEEN 1 AND 128 AND active_epoch ~ '^[!-~]+$'),
    activation_state text COLLATE "C" NOT NULL CHECK (activation_state IN ('NEW','ACTIVATED')),
    authority_id text COLLATE "C" NOT NULL CHECK(char_length(authority_id)=43),
    recovery_generation text COLLATE "C" NOT NULL CHECK(char_length(recovery_generation)=43),
    clock_generation text COLLATE "C" NOT NULL CHECK(char_length(clock_generation)=43),
    maximum_utc_error_nanos bigint NOT NULL CHECK(maximum_utc_error_nanos BETWEEN 0 AND 250000000),
    allocation_generation text COLLATE "C" NOT NULL CHECK(char_length(allocation_generation)=43),
    format_version integer NOT NULL CHECK(format_version=3),
    maximum_entries integer NOT NULL CHECK(maximum_entries BETWEEN 1 AND 65536),
    maximum_reserved_bytes bigint NOT NULL CHECK(maximum_reserved_bytes BETWEEN 1 AND 268435456)
);
CREATE TABLE totp_store_epoch (
    namespace text COLLATE "C" NOT NULL REFERENCES totp_store_namespace(namespace),
    recovery_epoch text COLLATE "C" NOT NULL
        CHECK(char_length(recovery_epoch) BETWEEN 1 AND 128 AND recovery_epoch ~ '^[!-~]+$'),
    activated boolean NOT NULL DEFAULT false,
    PRIMARY KEY(namespace,recovery_epoch)
);
CREATE TABLE totp_store_entry (
    namespace text COLLATE "C" NOT NULL,
    recovery_epoch text COLLATE "C" NOT NULL,
    storage_key text COLLATE "C" NOT NULL CHECK(char_length(storage_key) BETWEEN 1 AND 430),
    kind text COLLATE "C" NOT NULL CHECK(kind IN ('NAMESPACE_STATE','ACCOUNT_STATE')),
    version text COLLATE "C" NOT NULL CHECK(char_length(version)=43),
    sealed_form text COLLATE "C" NOT NULL
        CHECK(char_length(sealed_form) BETWEEN 1 AND 87382 AND sealed_form ~ '^[A-Za-z0-9_-]+$'),
    sealed_size integer NOT NULL
        CHECK(sealed_size BETWEEN 1 AND 65536 AND sealed_size=(char_length(sealed_form)*3)/4),
    reserved_size bigint NOT NULL CHECK(reserved_size BETWEEN sealed_size AND 65536),
    PRIMARY KEY(namespace,recovery_epoch,storage_key),
    FOREIGN KEY(namespace,recovery_epoch) REFERENCES totp_store_epoch(namespace,recovery_epoch)
);
-- namespace is the exact physical namespace ID used by the trusted witness/advisory grammar.
CREATE TABLE totp_store_escrow (
    family text COLLATE "C" NOT NULL CHECK(family='TOTP'),
    namespace text COLLATE "C" NOT NULL REFERENCES totp_store_namespace(physical_namespace),
    bucket integer NOT NULL CHECK(bucket BETWEEN 0 AND 255),
    allocation_generation text COLLATE "C" NOT NULL CHECK(char_length(allocation_generation)=43),
    entry_limit bigint NOT NULL CHECK(entry_limit BETWEEN 0 AND 65536),
    used_entries bigint NOT NULL CHECK(used_entries BETWEEN 0 AND entry_limit),
    byte_limit bigint NOT NULL CHECK(byte_limit BETWEEN 0 AND 268435456),
    used_bytes bigint NOT NULL CHECK(used_bytes BETWEEN 0 AND byte_limit),
    PRIMARY KEY(family,namespace,bucket)
);
-- Only the closed administrator creates namespace/epoch/all 256 quota rows. Actual usage starts
-- at retained actual A_i (zero for a fresh namespace), not the planned bootstrap seed A_i+S_i.
-- Quota_i=seed_i+floor((Q-sum(seed))/256)+(i<(Q-sum(seed)) mod256 ? 1:0), independently by dimension.
-- Every planned initialization root is included at its exact bucket/K64 reservation before
-- distributing the remainder. Reallocation is closed, exclusive, exact and generation-changing.
-- Runtime roles receive SELECT/INSERT/UPDATE only on permanent records; no DELETE/TRUNCATE.
