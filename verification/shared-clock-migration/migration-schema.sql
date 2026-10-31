-- Copyright 2026 Revetware LLC. Apache-2.0. Private disposable migration fixture.
-- Applied only while all runtime roles and old sessions are excluded.
-- This is fixture transport for actual family tables, not an online schema upgrade.
CREATE TABLE scp10_control (
 migration_id text PRIMARY KEY,
 writer_fence text NOT NULL,
 source_recovery text NOT NULL,
 target_authority text NOT NULL,
 target_recovery text NOT NULL,
 mode text NOT NULL CHECK(mode IN ('CLOSED','ACTIVE')),
 activation_commitment text
);
CREATE TABLE totp_store_namespace(namespace text PRIMARY KEY,active_epoch text NOT NULL,activation_state text NOT NULL);
CREATE TABLE totp_store_epoch(namespace text NOT NULL REFERENCES totp_store_namespace(namespace),recovery_epoch text NOT NULL,PRIMARY KEY(namespace,recovery_epoch));
CREATE TABLE totp_store_entry(namespace text NOT NULL,recovery_epoch text NOT NULL,storage_key text NOT NULL,kind text NOT NULL,version text NOT NULL,sealed_form text NOT NULL,sealed_size integer NOT NULL,reserved_size bigint,
 PRIMARY KEY(namespace,recovery_epoch,storage_key),FOREIGN KEY(namespace,recovery_epoch) REFERENCES totp_store_epoch(namespace,recovery_epoch));
CREATE TABLE webauthn_store_namespace(namespace text PRIMARY KEY);
CREATE SEQUENCE webauthn_store_version_seq AS bigint NO CYCLE;
CREATE TABLE webauthn_store_entry(namespace text NOT NULL REFERENCES webauthn_store_namespace(namespace),storage_key text NOT NULL,kind text NOT NULL,version bigint NOT NULL,sealed_form text NOT NULL,sealed_size integer,expires_at timestamptz,expires_seconds bigint,expires_nanos integer,
 PRIMARY KEY(namespace,storage_key));
CREATE TABLE issuer_store_namespace(namespace text PRIMARY KEY);
CREATE TABLE issuer_store_entry(namespace text NOT NULL REFERENCES issuer_store_namespace(namespace),storage_key text NOT NULL,kind text NOT NULL,version text NOT NULL,retain_seconds bigint NOT NULL,retain_nanos integer NOT NULL,sealed_form text NOT NULL,
 PRIMARY KEY(namespace,storage_key));
CREATE TABLE totp_store_escrow(namespace text NOT NULL,bucket integer NOT NULL CHECK(bucket BETWEEN 0 AND 255),entry_limit bigint NOT NULL,used_entries bigint NOT NULL,byte_limit bigint NOT NULL,used_bytes bigint NOT NULL,
 PRIMARY KEY(namespace,bucket),CHECK(used_entries BETWEEN 0 AND entry_limit),CHECK(used_bytes BETWEEN 0 AND byte_limit));
CREATE TABLE webauthn_store_escrow(LIKE totp_store_escrow INCLUDING ALL);
CREATE TABLE issuer_store_escrow(LIKE totp_store_escrow INCLUDING ALL);

CREATE TABLE scp10_quota_plan(id integer PRIMARY KEY CHECK(id=1),allocation jsonb NOT NULL);
