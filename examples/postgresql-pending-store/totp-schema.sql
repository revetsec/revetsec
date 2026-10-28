-- Copyright 2026 Revetware LLC. Apache-2.0. Unpublished application fixture.
-- Apply through a migration before starting any TOTP node. Every participant must use the
-- namespace row as the transaction mutex. Grant runtime roles SELECT/INSERT/UPDATE only;
-- never grant DELETE or TRUNCATE on these permanent tables.

CREATE TABLE totp_store_namespace (
    namespace text COLLATE "C" PRIMARY KEY
        CHECK (char_length(namespace) BETWEEN 1 AND 128
            AND namespace ~ '^[!-~]+$'),
    active_epoch text COLLATE "C" NOT NULL
        CHECK (char_length(active_epoch) BETWEEN 1 AND 128
            AND active_epoch ~ '^[!-~]+$'),
    activation_state text COLLATE "C" NOT NULL
        CHECK (activation_state IN ('NEW', 'ACTIVATED'))
);

-- The unique history prevents choosing an old epoch within the lifetime of this primary.
-- A recovery controller must additionally retain a monotonic marker OUTSIDE any database
-- backup being restored; restoring this history from an old backup is not epoch freshness.
CREATE TABLE totp_store_epoch (
    namespace text COLLATE "C" NOT NULL REFERENCES totp_store_namespace(namespace),
    recovery_epoch text COLLATE "C" NOT NULL
        CHECK (char_length(recovery_epoch) BETWEEN 1 AND 128
            AND recovery_epoch ~ '^[!-~]+$'),
    PRIMARY KEY (namespace, recovery_epoch)
);

CREATE TABLE totp_store_entry (
    namespace text COLLATE "C" NOT NULL,
    recovery_epoch text COLLATE "C" NOT NULL,
    storage_key text COLLATE "C" NOT NULL
        CHECK (char_length(storage_key) BETWEEN 1 AND 430),
    kind text COLLATE "C" NOT NULL
        CHECK (kind IN ('NAMESPACE_STATE', 'ACCOUNT_STATE')),
    version text COLLATE "C" NOT NULL CHECK (char_length(version) = 43),
    sealed_form text COLLATE "C" NOT NULL
        CHECK (char_length(sealed_form) BETWEEN 1 AND 87382
            AND sealed_form ~ '^[A-Za-z0-9_-]+$'),
    sealed_size integer NOT NULL
        CHECK (sealed_size BETWEEN 1 AND 65536
            AND sealed_size = (char_length(sealed_form) * 3) / 4),
    PRIMARY KEY (namespace, recovery_epoch, storage_key),
    FOREIGN KEY (namespace, recovery_epoch)
        REFERENCES totp_store_epoch(namespace, recovery_epoch)
);

-- For a new namespace only, seed both rows in one operator-controlled transaction.
-- Choose the recovery epoch with the independent controller; do not derive it from this DB.
-- BEGIN;
-- INSERT INTO totp_store_namespace(namespace, active_epoch, activation_state)
-- VALUES ('my_application', 'fresh-controller-epoch-1', 'NEW');
-- INSERT INTO totp_store_epoch(namespace, recovery_epoch)
-- VALUES ('my_application', 'fresh-controller-epoch-1');
-- COMMIT;
-- Then call TotpAuthenticator.initializeNamespaceResult() before admitting users.
