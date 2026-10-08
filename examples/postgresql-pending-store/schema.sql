-- Apply through an application migration before serving OAuth/OIDC callbacks.
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
