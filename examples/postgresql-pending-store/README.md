# PostgreSQL pending authorization example

This application-side example implements `PendingAuthorizationStore` for OAuth and OIDC callbacks that can reach different JVMs. It uses Pyranid 4.7.0 for transaction lifecycle and PostgreSQL for one authoritative primary. The Revetsec core artifact retains zero runtime dependencies.

Apply `schema.sql` with your migration tool, then create one clock row for a **new** stable namespace. Pass the same namespace and database to every JVM. For example:

```java
var store = new PostgresqlPendingAuthorizationStore(
    "my_application", connectionSource, 1_024, 8 * 1_024, 4L * 1_024 * 1_024);
```

`connectionSource.open(remaining)` is application-owned and thread-safe. It must bound pool acquisition, DNS and connection setup by the shrinking budget, return a distinct logical connection to the authoritative primary for each call, and preserve the normal PostgreSQL TLS/certificate policy. The example sets a driver network timeout and a transaction-local statement timeout for subsequent SQL. Connection sources that can block without honoring `remaining` do not meet the `PendingAuthorizationStore` contract.

The example caps one database operation at one minute even if a caller supplies a longer budget. It never extends a shorter caller budget.

Every operation locks the namespace clock row. It stores the largest observed database instant, so an observed backward clock step cannot revive an expired record. Save prunes expired rows, rejects a duplicate live key and refuses capacity without evicting live logins. Consume removes once across JVMs. The browser binding and state are hashed for the table key; the opaque record is stored as plaintext and contains sensitive pending authorization data, so applications must protect database access, transport, backups and logs.

The result is released only after Pyranid reports a confirmed COMMITTED transaction. A failed or uncertain commit produces a fixed storage failure; callers must not automatically retry a callback or treat an uncertain save as successful. The local fixture injects a lost COMMIT acknowledgement after the database commit and verifies both application boundaries: the save path withholds its redirect, and the callback path withholds tokens and makes no token request. A consumed record may be lost under an uncertain commit, requiring a new login. The application owns database credentials, capacity settings, migrations, monitoring, backups and restore admission. A restored snapshot can restore an authentically consumed record and an older clock fence; keep routes closed until the application's external recovery fence and key procedure are complete. This source does not establish high availability, cross-host failover or power-loss durability on its own.

`run.py` compiles the example with warning-fatal Java 17 settings and exercises duplicate, expiry, capacity, rollback fencing, browser binding, cross-JVM single use, lock timeout, database outage and restart against a cached disposable PostgreSQL image. A loopback-only synthetic token endpoint also checks the authorization-code form and persisted PKCE verifier: a valid callback redeems once, replay and wrong-browser binding send no token request, and simultaneous callbacks in two JVMs produce exactly one redemption. This is a local protocol fixture, not a real provider qualification. The runner requires absolute paths to a current core JAR, Java home, and the pinned Pyranid, PostgreSQL, JSpecify and JSR-305 JARs; run `python3 run.py --help` for the arguments. Docker resources, the local endpoint and test credentials are removed after the run.
