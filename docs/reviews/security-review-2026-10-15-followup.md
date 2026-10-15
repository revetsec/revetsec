# Security review follow-up (2026-10-15)

**Status:** pre-release working tree. This records the disposition of the 2026-10-15 security review supplied with the workspace. It is not a release sign-off. The changes described here are uncommitted.

## Addressed in this working tree

| Review finding | Change |
| --- | --- |
| §1.1–1.2 JWKS and issuer clock races | Sample the clock while holding each cache or lifecycle lock. Concurrency regressions cover both paths. |
| §1.3–1.4 WebAuthn ceremony retention and namespace contention | Stores can see ceremony expiry. The in-memory store reclaims expired ceremonies and bounds its expiry index; the PostgreSQL reference store deletes them under its namespace lock. Namespace clock writes advance in coarse steps, confirmed conflicts receive bounded retries, and rejection-only completion avoids clock writes. |
| §1.5 issuer clock and shared row | Admit bounded skew and reserve at most 100 ms in the existing issuer high-water field. Every transaction still conditions on the issuer version; ordinary independent mutations within the reservation do not rewrite that row. Epoch changes and reservation rollover do. The remaining backend and retry limits are below. |
| §1.6 and §1.9 SAML attribute and replay boundaries | A signed leaf AttributeValue cannot be hidden by rebinding an unsigned `xsi:type` prefix. Replay admission carries a connection namespace and the in-memory cache reserves one quarter of configured capacity per connection. An expiry index bounds cleanup work to expired entries. Custom replay caches must implement the connection-aware method to provide isolation. |
| §1.7 WebAuthn step-up | `completeReauthenticationResult` requires the expected account handle and action purpose and refuses a discoverable sign-in ceremony as step-up. The Servlet recipes and passkey example use it. |
| §1.8 outbound HTTP credentials | Injected JDK `HttpClient` instances with an `Authenticator` or `CookieHandler` are refused. |
| §2 release-candidate code findings | Added canonical `credProtect` handling, malformed Ed25519 signature rejection, permanent WebAuthn record resealing, forward-clock-skew rejection, SAML session-reference persistence, SCIM configured construction and delegated `co` work limits, and the OAuth cache/introspection/CIMD recovery and admission fixes. |
| §2 assurance documents | Added focused OIDC, resource-server, issuer and WebAuthn invariant rows and registered explicit compatibility switches. The consolidated release review still needs to check completeness. |
| §3 bounded fixes | Corrected the confirmed SAML, SCIM, WebAuthn, adapter and example issues that could be changed without a persisted-identity migration or a wider API design. The remaining items are below. |

## Remaining decisions and qualification

- **Issuer throughput and retries (§1.5).** The core reservation passed a 32-code, two-coordinator contention regression on the CAS test store. Its configured attempt count is still fixed, so repeated epoch changes or reservation rollovers may exhaust retries. The runnable PostgreSQL issuer store still locks a namespace row for every read and commit, serializing its traffic. Qualify that backend under target load and decide its atomic capacity/locking design before freezing the store SPI.
- **SAML persistent identity and admission (§3).** Normalizing persistent NameID default qualifiers or `SPProvidedID` changes account keys and needs an account-linking migration. An unsigned encrypted response may require private-key work before its inner signature is visible. Anonymous begins can fill a bounded pending store. The SAML guide calls for minimal rollover keys, edge admission/rate limits, and durable pending storage where needed.
- **Earlier lower-severity API and policy items.** A module boundary for `JwtValidationAccess`, diagnostics for skipped static JWKs, OIDC `acr_values` and refresh ACR binding, OIDC revocation/end-session API, issuer client-registration and settings migration, CIMD `Vary` handling and loopback profile, and issuer failure taxonomy need separate API or migration decisions. `ConcurrentLruMap` capacity under direct write contention is latent for its serialized consumer. These are not represented as closed by this patch.
- **Release gates.** Physical discoverable UV-capable FIDO2-key testing, the full PostgreSQL/browser lane, and the consolidated API/claims/release review remain open. The expanded invariant and compatibility documents are inputs to that review.
- **Public-contract review.** The 2026-10-14 SAML RC-2 review and SCIM API freeze predate the connection-aware replay-cache SPI, persistable SAML session reference, SCIM canonical path API and new work-limit exception. Recheck those public contracts before treating either freeze as current.
- **Cross-repository CI pins.** The Servlet recipe and fixture now call the new core reauthentication API. Their GitHub Actions core SHA pins must move to a pushed core commit containing this patch before those remote jobs can pass. No commit or pin update was made in this working tree.

## Verification completed

- Core JDK 21 Maven `verify`: 18,827 tests, zero failures, zero errors, one skipped. JDK 21 static analysis and SpotBugs passed.
- Java 17 Maven `verify`: Soklet 155 tests, Jakarta Servlet 42 tests, javax Servlet 42 tests; zero failures and errors. Their JDK 21 static-analysis and SpotBugs profiles passed.
- JDK 26 Javadoc generation passed for core and all three adapters. Both paired Servlet workflow source recipes compiled with Java 17 `-Xlint:all -Werror`.
- Pinned Tomcat 11 and 9 real-container checks passed for both Servlet twins: seven M12, six SAML and seven SCIM checks per twin; each runner stopped its owned server process.
- Barebones OIDC, playground and self-issued example Maven verification passed. The passkey example's route and localhost socket checks passed; the PostgreSQL reference module packaged. A direct PostgreSQL expiry probe reported `EXPIRY_RECLAIMED` and its temporary server was stopped.

The container and local database checks do not substitute for hardware qualification, multi-host restore qualification, or an application-specific throughput target.
