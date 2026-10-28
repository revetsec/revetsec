# Complete Soklet 4 TOTP integration

This unpublished example includes every TOTP/recovery route, actual Soklet bootstrap/configuration, application-owned JSON serialization and explicit account/session/recovery-controller interfaces. The [complete source](src/main/java/example/totp/TotpApplication.java) compiles with Java 21 or newer; Revetsec core remains Java 17.

This is an injected integration, not a login server. There is deliberately no launcher that assumes an authenticated user, generates a replacement identity after restart or installs an always-open recovery gate. An application supplies the configured `TotpAuthenticator` and implements the annotated `TotpApplication.ApplicationSecurity` boundary. Call `TotpApplication.run(totp, security, 8094)` from that application's launcher, behind its trusted HTTPS edge. Bind a different address only after making that deployment choice explicitly.

## Configure and initialize

```java
TotpAuthenticator totp = TotpAuthenticator.withIssuer("Example")
    .credentialNamespace("production-accounts")
    .recoveryEpoch(deploymentRecoveryEpoch)
    .store(applicationTotpStore)
    .stateSealer(applicationStateSealer)
    .recoveryGate(applicationRecoveryGate)
    .build();

// Provisioning controller only: handle the explicit initialization outcome
// before admitting ordinary requests. Existing nodes do not initialize on absence.
TotpNamespaceInitializationResult initialization = totp.initializeNamespaceResult();

// After the controller confirms initialization and opens this epoch:
TotpApplication.run(totp, applicationSecurity, 8094);
```

The snippet's collaborators and epoch come from the application's deployment configuration. Handle `Initialized` or `AlreadyInitialized` as confirmed initialization; keep traffic closed on `Unavailable` or `Indeterminate` and reconcile under the recovery controller. Do not invoke the initialization path on every process startup without an explicitly authorized provisioning scope.

Use an authoritative durable `TotpStore` and an external `TotpRecoveryGate` for established accounts. The store compares every observed version/absence, commits all transitions atomically and checks the active epoch inside the same transaction. No record TTLs or eviction are allowed. The explicitly selected bounded in-memory store is single-process and volatile; it is suitable for isolated tests, not restart/restore protection. See the [durable-record and recovery contract](../../docs/totp-recovery.md).

## Routes and application responsibilities

| Route | Required application context |
| --- | --- |
| `POST /account/totp/enrollment` | Recent enrollment approval, account label, unpredictable browser binding |
| `POST /account/totp/replacement` | Recent replacement/recovery approval and expected active factor generation |
| `POST /account/totp/confirm` | Approved pending enrollment, browser binding and submitted six-digit string |
| `POST /login/totp` | Current primary-authenticated pending login and operation binding |
| `POST /login/recovery` | Approved recovery fallback for that pending login |
| `POST /account/recovery-codes/rotate` | Fresh approval with exact factor and recovery batch generations |
| `POST /account/totp/remove` | Fresh removal approval with exact factor generation |
| `POST /account/totp/enrollment/cancel` | Approved pending enrollment and matching browser binding |
| `GET`, `HEAD /account/totp` | Authorized account status access |

Every `admit...` implementation validates body size/media type, duplicate fields, exact trusted Host/Origin, session, CSRF and network admission **before** extracting a code. IDs, labels, generations and bindings come from current server-owned state, not trusted request fields. Primary-authenticated pending logins have a short fixed expiry that code failures do not extend; admission rejects expired or previously consumed login state. A null context is ordinary application rejection. Context implementations are immutable and have redacted diagnostics. The example does not define production account/session/CSRF storage because those are application policy and transaction boundaries.

The `ApplicationSecurity.acquireRequestPermit(...)` hook holds outer recovery admission through the library call, the application transaction and the final response decision. It nests the same reentrant recovery gate or uses an application transaction fence coordinated with the same recovery controller. A separate preflight epoch lookup is insufficient. Failed acquisition releases every partial lock or lease before returning or throwing. Permits have bounded lifetime, remain caller-thread scoped and close idempotently; route admission checks their epoch and currentness. After the permit closes, the route checks its monotonic 10-second deadline again and withholds secrets and session cookies if release consumed the remaining budget.

Before completing TOTP login, `completeTotpLogin(...)` must compare the proof's account, operation binding and recovery epoch, recheck account access and pending-login expiry, consume the exact unused primary-authenticated login and rotate the session/CSRF token atomically. The recovery completion hook applies the same expiry and one-use checks. It returns `LoginCompletion` only after confirmed completion, with the new secure cookies to attach to the response. A null receipt means no authenticated success is delivered. Configure session cookies as `__Host-`, Secure, HttpOnly and SameSite according to application policy; store the epoch in session/approval state and reject it after recovery changes the epoch.

Recovery login has a separate `RecoveryCodeUse` proof and completion hook. This example chooses a restricted recovery session, rather than treating a recovery code as current authenticator possession. The application decides the allowed recovery workflow. Its completion still consumes the exact primary-authenticated pending login and rotates cookies.

Enrollment remembers only the pending ID, candidate factor ID and expiry before returning its secret. Completion invalidates the management approval and reconciles application state before releasing recovery plaintext. Rotation/removal/cancellation hooks consume their corresponding approvals and update/invalidate affected sessions according to application policy. On an uncertain library mutation, `requireReconciliation(...)` prevents a stale approval from being reused. If application completion itself is unconfirmed, return 503 and reconcile; never expose a new recovery batch as if it were delivered successfully.

## Serialization, secrets and HEAD

Routes return `MarshaledResponse`. The app explicitly builds `JsonObject` documents, serializes them to UTF-8 and sets `Cache-Control: no-store`, `Referrer-Policy: no-referrer` and `X-Content-Type-Options: nosniff`. No custom `ResponseMarshaler` is configured. Soklet's default marshaler suppresses the HEAD body automatically.

Provisioning responses include the URI/manual key only after confirmed persistence and approved browser-state capture. QR rendering stays local and app-owned; no third-party service, analytics or remote image URL receives the secret. Recovery plaintext appears only after confirmed enrollment or rotation. Do not store these payloads in logs, telemetry, browser local/session storage or account settings records.

The source handles every defined outcome and rejects future variants by default. Invalid credentials yield one generic remote response. Throttling sets a rounded-up `Retry-After`. Infrastructure/indeterminate outcomes return 503 without secrets or authentication proofs. An uncertain verification never becomes login success through a later status read: leave primary authentication pending and require a fresh code or approved alternate path. A consumed code and an undelivered HTTP response may coexist.

After restore, provision a new never-reused epoch with an empty namespace, invalidate old sessions/approvals and require approved reenrollment. Preserve the application's MFA requirement outside the restored factor state: empty factor state must not allow a protected account to log in with only a password.

## Compile and check

Build the current core JAR first. The isolated builder verifies the exact Soklet 4 artifact checksum from `examples/pins.json`, compiles all sources with warnings as errors, audits every source-declared reference signature for explicit JSpecify annotations, and runs boundary/lifecycle checks. It writes only to a new private output directory. The runtime classpath contains core and Soklet; annotation artifacts are compile-time only.

```sh
python3 examples/totp-soklet/build.py \
  --work /absolute/new/private-totp-build \
  --java-home /absolute/jdk21-or-newer \
  --core-jar /absolute/revetsec/target/revetsec-1.0.0-SNAPSHOT.jar \
  --soklet-jar /absolute/soklet-4.0.0.jar \
  --jspecify-jar /absolute/jspecify-1.0.1.jar \
  --jsr305-jar /absolute/jsr305-3.0.2.jar \
  --socket-check
```

Authorized lifecycle checks use the real authenticator and bounded in-memory backend, with an independent JCA OTP generator and explicit test-only application grants. They cover enrollment/confirmation, status, TOTP login/replay rejection, recovery consumption, rotation and old-batch rejection, replacement/cancellation, replacement confirmation and removal. Completion hooks check proof account, generation, method, operation binding and epoch while the same gate retains its outer permit. Unconfirmed application completion releases neither recovery plaintext nor a session cookie.

Boundary checks prove denied routes never reach credential storage, closed/wrong/stale recovery admission fails closed, permits close, and default marshaling remains installed. Lifecycle checks also advance the monotonic deadline during permit release and verify that an enrollment secret and a login cookie are withheld. The optional loopback socket check reaches all routes and verifies HEAD suppresses JSON bytes. It requires local socket permission. Core's TOTP tests separately cover cryptography, replay, recovery consumption, atomic races, uncertain acknowledgements and sealing/restore boundaries. This example does not qualify a production database, distributed recovery controller or trusted HTTPS edge.
