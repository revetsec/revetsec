-- Copyright 2026 Revetware LLC. Apache-2.0.
-- Only the owned fixture administrator creates these tables/seed, never an issuer request.
CREATE TABLE issuer_mutex (id integer PRIMARY KEY CHECK (id=1));
INSERT INTO issuer_mutex VALUES(1);
CREATE TABLE issuer_entries (
 storage_key text COLLATE "C" PRIMARY KEY,
 kind text COLLATE "C" NOT NULL,
 version text COLLATE "C" NOT NULL CHECK (length(version)=43),
 retain_seconds bigint NOT NULL,
 retain_nanos integer NOT NULL CHECK (retain_nanos BETWEEN 0 AND 999999999),
 sealed text COLLATE "C" NOT NULL CHECK (octet_length(sealed)<=16384)
);
