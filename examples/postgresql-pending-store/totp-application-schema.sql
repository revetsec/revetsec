-- Copyright 2026 Revetware LLC. Apache-2.0. Unpublished application fixture.
-- Test-only application state. Apply with totp-schema.sql before admitting traffic.
-- These rows are deliberately separate from core's opaque TOTP store records. Every
-- application transition and lookup locks totp_store_namespace, checks its active epoch,
-- and also holds the external fixture recovery gate. The controller owns that marker.

-- Application time is retained per epoch under the authoritative namespace mutex. A node
-- presenting older wall time fails closed, so expiry cannot revive after process restart.
-- A fresh recovery epoch starts a fresh clock fence. This database-local history does not
-- detect an unannounced backup rollback; the external marker and restore gate remain required.
CREATE TABLE totp_app_clock (
    namespace text COLLATE "C" NOT NULL,
    recovery_epoch text COLLATE "C" NOT NULL,
    last_seen_ms bigint NOT NULL CHECK (last_seen_ms >= 0),
    PRIMARY KEY (namespace, recovery_epoch),
    FOREIGN KEY (namespace, recovery_epoch)
        REFERENCES totp_store_epoch(namespace, recovery_epoch)
);

CREATE TABLE totp_app_session (
    namespace text COLLATE "C" NOT NULL REFERENCES totp_store_namespace(namespace),
    session_hash text COLLATE "C" NOT NULL CHECK (char_length(session_hash) = 43),
    recovery_epoch text COLLATE "C" NOT NULL CHECK (char_length(recovery_epoch) BETWEEN 1 AND 128),
    account_id text COLLATE "C" NOT NULL CHECK (char_length(account_id) BETWEEN 1 AND 1024),
    kind text COLLATE "C" NOT NULL CHECK (kind IN ('PRIMARY', 'TOTP', 'RECOVERY_CODE')),
    csrf_hash text COLLATE "C" NOT NULL CHECK (char_length(csrf_hash) = 43),
    expires_at_ms bigint NOT NULL,
    revoked boolean NOT NULL DEFAULT false,
    PRIMARY KEY (namespace, session_hash)
);

CREATE TABLE totp_app_pending_login (
    namespace text COLLATE "C" NOT NULL REFERENCES totp_store_namespace(namespace),
    operation_binding text COLLATE "C" NOT NULL
        CHECK (char_length(operation_binding) BETWEEN 1 AND 128),
    recovery_epoch text COLLATE "C" NOT NULL CHECK (char_length(recovery_epoch) BETWEEN 1 AND 128),
    account_id text COLLATE "C" NOT NULL CHECK (char_length(account_id) BETWEEN 1 AND 1024),
    expected_factor_id text COLLATE "C" NOT NULL CHECK (char_length(expected_factor_id) BETWEEN 1 AND 128),
    old_session_hash text COLLATE "C" NOT NULL,
    old_csrf_hash text COLLATE "C" NOT NULL CHECK (char_length(old_csrf_hash) = 43),
    expires_at_ms bigint NOT NULL,
    consumed boolean NOT NULL DEFAULT false,
    PRIMARY KEY (namespace, operation_binding),
    FOREIGN KEY (namespace, old_session_hash)
        REFERENCES totp_app_session(namespace, session_hash)
);

CREATE TABLE totp_app_approval (
    namespace text COLLATE "C" NOT NULL REFERENCES totp_store_namespace(namespace),
    approval_hash text COLLATE "C" NOT NULL CHECK (char_length(approval_hash) = 43),
    recovery_epoch text COLLATE "C" NOT NULL CHECK (char_length(recovery_epoch) BETWEEN 1 AND 128),
    account_id text COLLATE "C" NOT NULL CHECK (char_length(account_id) BETWEEN 1 AND 1024),
    session_hash text COLLATE "C" NOT NULL,
    expires_at_ms bigint NOT NULL,
    consumed boolean NOT NULL DEFAULT false,
    PRIMARY KEY (namespace, approval_hash),
    FOREIGN KEY (namespace, session_hash)
        REFERENCES totp_app_session(namespace, session_hash)
);
