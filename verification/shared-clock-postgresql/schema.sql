-- Copyright 2026 Revetware LLC. Apache-2.0. Inactive owned fixture schema only.
-- Provisioned by its disposable-fixture administrator, never by a normal callback.
CREATE TABLE scp05_admission (
 family text COLLATE "C" NOT NULL CHECK (family IN ('ISSUER','TOTP','WEBAUTHN')),
 namespace text COLLATE "C" NOT NULL,
 authority_id text COLLATE "C" NOT NULL,
 recovery_generation text COLLATE "C" NOT NULL,
 clock_generation text COLLATE "C" NOT NULL,
 profile_commitment text COLLATE "C" NOT NULL,
 schema_commitment text COLLATE "C" NOT NULL,
 metadata_commitment text COLLATE "C" NOT NULL,
 writer_role_identity text COLLATE "C" NOT NULL,
 allocation_generation text COLLATE "C" NOT NULL,
 format_version integer NOT NULL CHECK (format_version IN (2,3)),
 mode text COLLATE "C" NOT NULL CHECK (mode IN ('CLOSED','ACTIVE')),
 PRIMARY KEY (family,namespace)
);
CREATE TABLE scp05_escrow (
 family text COLLATE "C" NOT NULL,
 namespace text COLLATE "C" NOT NULL,
 bucket integer NOT NULL CHECK (bucket BETWEEN 0 AND 255),
 allocation_generation text COLLATE "C" NOT NULL,
 entry_limit bigint NOT NULL CHECK (entry_limit>=0),
 used_entries bigint NOT NULL CHECK (used_entries BETWEEN 0 AND entry_limit),
 byte_limit bigint NOT NULL CHECK (byte_limit>=0),
 used_bytes bigint NOT NULL CHECK (used_bytes BETWEEN 0 AND byte_limit),
 CHECK (family='TOTP' OR (byte_limit=0 AND used_bytes=0)),
 PRIMARY KEY(family,namespace,bucket)
);
CREATE TABLE scp05_entries (
 family text COLLATE "C" NOT NULL,
 namespace text COLLATE "C" NOT NULL,
 storage_key text COLLATE "C" NOT NULL CHECK (octet_length(storage_key) BETWEEN 1 AND 640),
 version text COLLATE "C" NOT NULL CHECK (length(version)=43),
 payload bytea NOT NULL CHECK (octet_length(payload) BETWEEN 1 AND 262144),
 actual_size integer NOT NULL CHECK (actual_size BETWEEN 1 AND 262144),
 reserved_bytes bigint NOT NULL CHECK (reserved_bytes>=0),
 expiry_seconds bigint,
 expiry_nanos integer CHECK (expiry_nanos BETWEEN 0 AND 999999999),
 CHECK ((expiry_seconds IS NULL) = (expiry_nanos IS NULL)),
 CHECK (actual_size=octet_length(payload)),
 PRIMARY KEY(family,namespace,storage_key)
);
CREATE TABLE scp05_capacity_probe(namespace text PRIMARY KEY,value integer NOT NULL);
