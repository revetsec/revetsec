# Changelog

All notable changes to Revetsec are recorded in this file.

Each release gets a `## X.Y.Z (YYYY-MM-DD)` heading with Added, Changed, Fixed, Security and Migration Notes sections as needed. A security fix names its GHSA or CVE ID. Changes that reject previously accepted insecure input, or that remove an algorithm from a default, are listed under Security (see the security-tightening policy in [COMPATIBILITY.md](COMPATIBILITY.md)).

- Added an unpublished self-issued Soklet MCP example with app-owned login/consent, bounded volatile storage, issuance and online revocation checks.

- Added the public OAuth authorization-server builder and endpoint operations, initial consent policy recheck, M5 plus authoritative online validation, explicit first-use initialization, and authenticated reseal maintenance. Application storage/domain interfaces remain pluggable.

- Add internal authenticated client metadata cache records, conservative HTTP freshness, and bounded synchronous fetch coordination through the pinned HTTPS transport. Cache reuse remains optional and separate from issuer credential transitions.

- Add bounded OAuth issuer store carriers, atomic commit contracts and internal sealed record/read-set foundation.

- Add the explicit fixed Microsoft Entra common/organizations OIDC issuer policy, authenticated tenant predicate, advertised-issuer accessor and tenant-bound UserInfo/refresh checks. Hosted Entra acceptance remains unproven.

## Unreleased

Nothing has been released. The version is `1.0.0-SNAPSHOT`, and there is no compatibility promise before 1.0.0.

### Added
- Restricted OAuth issuer interaction/result/exception/observer contracts and safe local HTTP failure mapping. Public server builder and endpoint wiring follow separately.
- Restricted immutable `OAuthServerResponse` with explicit credential-bearing Location/body emission, no Location in ordinary headers, bounded defensive copies and fixed redacted diagnostics. Internal endpoint preparation now retains this response; public server routing remains pending.
- The remaining22 approved issuer limit rows and pure internal checked settings, including nullable default resets, lifetime/deadline ordering and sealer-cap alignment. Public server-builder setters remain pending.
- Internal typed canonical authorization-code/refresh handles, separate ledger digests of their full wire spelling, and bounded303 consent responses prepared before atomic approval/denial commit.
- Pluggable OAuth client-metadata cache storage with bounded opaque carriers, atomic version checks, a bounded in-memory default and metadata-policy builder injection. Authenticated cache and issuer-flow integration remain under implementation.
- Internal numeric-peer-pinned HTTPS transport using JDK nonblocking TCP/TLS, original-hostname verification and locally validated certificate chains without secondary retrieval. Client-metadata cache and issuer integration remain under implementation.
- Internal copied-address admission and bounded HTTP/1.1 metadata response parsing for the pinned HTTPS transport. Live TCP/TLS and distributed cache integration remain under implementation.
- Opt-in client metadata policy and trusted bounded address resolver contracts, with strict internal public-client document admission. The dedicated pinned HTTPS transport and public issuer integration remain under implementation.
- Application-owned issuer signing-key and immutable lifecycle snapshot/provider APIs, with internal publication/retirement checks and public-only RFC 8414 metadata/JWKS preparation. Public authorization-server endpoints remain under implementation.
- Internal whole-grant access/refresh revocation and registered confidential resource-only introspection: complete atomic barriers, fixed inactive responses, precommit bounded bytes and fail-closed uncertain outcomes. Public endpoints remain under implementation.
- Internal strict OAuth refresh rotation: atomic replacement and issued-jti records, full-grant invalidation on bound used-token replay, original grant scopes and fixed lifetime/retention pins, fresh continuing policy, and response release only after COMMITTED. Public refresh endpoints remain under implementation.
- Internal OAuth issuer token status: fixed RS256 at+jwt verification, exact issuance/grant binding and authoritative condition-only read-set admission. Revocation and missing issuance reject; unknown commits and backend corruption remain infrastructure failures. Public issuer validation and refresh endpoints remain under implementation.
- Internal OAuth code exchange: current registered-client authentication, S256 and exact grant binding, continuing policy checks, precommit RS256 access JWT and bounded retained response bytes, atomic issued-jti/initial refresh records with pinned retention, and bound replay grant revocation. Public endpoints and key lifecycle remain under implementation; internal online status admission is implemented.
- Internal OAuth consent ledger: bounded typed interaction/code/pending-grant records, browser and client security binding, atomic approval/denial, no duplicate code return, and checked retention arithmetic. Public issuance endpoints remain under implementation.
- Internal OAuth issuer store coordination: typed permanent issuer/subject fences, checked revocation epochs and clock high-water updates, single-use complete read-set barriers, and bounded conflict reloads under one cooperative deadline. Unknown commits fail without automatic replay. Tests use controlled two-coordinator interleavings over a single-process test double; durable backend and credential engine integration remain pending.


- Implement internal bounded OAuth issuer parsing, registered Basic authentication and exact redirect/resource/scope admission. Public issuance endpoints remain under implementation.
- Start OAuth authorization-server application contracts: registered clients, Basic secret-verifier policy, authorization decisions and restricted grant context. Issuance endpoints remain under implementation.

- Selected comprehensive OIDF private-key client profile: exact registered public JWKS and raw assertion checks, with explicit unsupported-profile exclusions and the suite's mandatory Basic exception.
- Local private-key integration checks against pinned Keycloak 26.7.4 and node-oidc-provider 9.12.2: independent registrations, RS256/RS384/PS256, both audiences, all POST roles and wrong-key/algorithm rejection. Keycloak revocation in endpoint audience mode is a documented provider limitation.

- Generated OAuth `private_key_jwt` assertions: immutable rotating key snapshots, per-role metadata, issuer or explicit endpoint audiences, original operation deadlines and preparation failure observation.

- Shared RSA signing (`JwsSigner`): PS256/RS256/RS384, checked public-key snapshots, exact bounded JSON claims and pair verification before credential output. Explicit `warmUp` performs a noncredential probe; factories perform no signing. Opaque application-owned private keys are retained without export. Fixed `JwsSigningException` reasons distinguish provider unavailability, pair mismatch and exhausted budgets. OAuth assertion integration is implemented; issuance remains planned.

- JOSE (milestone M2): verification of signed JWTs against JSON Web Key Sets.
  - `com.revetsec.jose`, 16 public types:
    - `JwtValidator`: validates a JWT in the JWS compact serialization for one issuer. By default it allows RS256 alone, `typ` absent or `JWT`, 60 s of clock skew and tokens up to 64 KiB, and requires `iss`, `exp` and an expected audience. It never accepts `none`, an HMAC algorithm, a key or key URL in the header (`jwk`, `jku`, `x5u`), `crit`, `b64`, `zip`, `cty`, an encrypted or JSON-serialized token, or a token with a `cnf` claim. A malformed signature is refused before any key is looked up;
    - `Jwt` and `JwtClaims`: the validated token and its claims, which only validation creates;
    - `JwsAlgorithm`: RS256, RS384, RS512, PS256, PS384, PS512, ES256, ES384, ES512, Ed25519 and EdDSA, plus HS256, HS384 and HS512, which `JwtValidator` refuses;
    - `JsonWebKeySet`, `JsonWebKey` and `JsonWebKeySkipReason`: a key set keeps only usable public verification keys and skips the rest with one of 13 reasons. RSA keys are 2,048 to 16,384 bits, with an odd, minimal modulus, an odd public exponent of at least 65,537 and no ROCA fingerprint; EC keys lie on P-256, P-384 or P-521; Ed25519 keys decode to a point of more than small order. An RSA key without `alg` serves only a sole allowed RSA algorithm, and a key's `issuer` member binds it to that issuer, with one exception for Microsoft Entra ID's `{tenantid}` template;
    - `JsonWebKeySource`, `StaticJsonWebKeySource` and `RemoteJsonWebKeySource`: keys the application holds, or a key set fetched lazily on the caller's thread and cached by `Cache-Control` and `Expires` within 1 minute and 6 hours by default. An unknown key refreshes it at most once per cooldown, failures back off from 30 s to 5 minutes at the defaults without resetting on success, at most two requests start per cooldown, which may not be longer than the minimum time to live, and stale keys are served for a bounded time while refreshes fail;
    - `JoseObserver`, with nine hooks; `JoseException`, sealed, with one shared `Reason` and three subclasses, `MalformedJoseInputException`, `UnsupportedJoseFeatureException` and `JwtValidationException`; and `JsonWebKeySetUnavailableException`, whose category says why a key set could not be had.
  - `OutboundUriPolicy.publicAddressesOnlyInstance()`: permits only globally reachable addresses and DNS names outside the local and special-use names it lists.
  - Compatibility modes, the first two: `acceptAnyAudience(true)` and `acknowledgeUnpatchedRuntime(true)`.
  - Internal, not API: signature verification by curve and hash, with the ECDSA shape and range check, DER encoding, EC on-curve checks, the RSA key policy, Ed25519 point decoding and HMAC-SHA-384 and -512; compact JWS parsing, the header and claims policies and key selection; the RFC 9111 cache lifetime and HTTP dates; and one URI check shared by build time and request time.
  - Tests: 28 Wycheproof test-vector files, vendored at a pinned commit with a SHA-256 manifest and run against per-vector expectation manifests; the examples of RFC 7515, 7517, 7520 and 8037, and the test vectors of RFC 8032 and RFC 4231; Microsoft Entra ID's key sets as read on 2026-09-27; key sets and tokens captured from local Keycloak and node-oidc-provider test containers, replayed offline; hostile key-set endpoints, including ones that always fail, alternate with valid key sets or never answer; Jazzer fuzz targets for compact JWS parsing, JSON Web Keys, `JwtValidator`, ECDSA signatures and cache lifetimes; new source-policy rules; and a check that every threat-model invariant cites the tests or build checks that enforce it.
  - Build: coverage floors for `jose` and `internal.jose`, and the other floors re-measured; PIT targets for `jose`, `internal.jose` and the new signature and key classes; larger ClusterFuzzLite budgets; and packaged consumers that call the `jose` API.
- Foundations (milestone M1), still with no protocol code:
  - `com.revetsec`:
    - `RevetsecException` and `ErrorCategory`: the root of Revetsec's exceptions, each with a category, a transience flag that follows from the category and the cause, a fixed message, and suppression disabled;
    - `StateSealer`, `SealingKey` and `InvalidSealedStateException`: short strings sealed with AES-256-GCM under a per-value key derived with HKDF-SHA256, bound to a context and a lifetime, with key IDs for rotation and one exception for every failure to open;
    - `OutboundUriPolicy`: classifies IP address literals, and never resolves hostnames.
  - `com.revetsec.json`: an immutable JSON value model, `JsonValue` and its six permitted types plus `JsonObject.Builder`, with redacted `toString()`, equality by numeric value for numbers, and a depth limit of 64.
  - Internal, not API:
    - a strict JSON parser ported from Soklet's codec, with per-profile limits, and RFC 7638 thumbprint input;
    - strict Base64, base64url, percent, form and UTF-8 codecs, and PEM parsing;
    - HKDF and the sealer's format;
    - a bounded HTTP exchange on the JDK `HttpClient`, with deadlines, size limits, and rejection of redirects, content encodings, framing anomalies and unexpected media types, plus a lazily created default client;
    - the resource-limits registry and contained observer dispatch.
  - Tests: the JSONTestSuite parsing files, vendored at a pinned commit with a SHA-256 manifest; a catalog of hostile HTTP responses; known-answer and tamper tests for the sealer; Jazzer fuzz targets for the JSON codec and model, RFC 7638, the sealer, PEM and the encoders, in place of M0's placeholder target; and new source-policy rules.
  - Build: a Javadoc CI job on a checksum-pinned JDK 26 with every doclint group except `html`; a Gradle consumer next to the Maven one in the packaged-consumer check, both calling the public API; and coverage floors set from measured runs.
- Repository scaffold (milestone M0), with no protocol code yet:
  - a single-module Maven build for `com.revetsec:revetsec`, targeting Java 17, that fails if any compile or runtime dependency is declared;
  - placeholder packages;
  - contract tests for public API shape, package dependencies, source policy and documentation wording;
  - CI workflows, a fuzzing skeleton, and a test-only certificate authority;
  - the repository documents: README, COMPATIBILITY, SECURITY, CONTRIBUTING, NAMING_CONVENTIONS, NOTICE, and skeletons under `docs/`.

### Security

Nothing below was ever released; each item rejects input that milestone M1 accepted, so it is listed here, as the security-tightening policy requires.

- `OutboundUriPolicy.defaultInstance()` also rejects more of the cloud metadata endpoints known as of 2026-09-27 (100.100.100.200, 168.63.129.16, fd00:ec2::23 and fd20:ce::254, and the names `metadata.google.internal` and `metadata.goog` and every name under them), the RFC 8215 local-use NAT64 prefix 64:ff9b:1::/48, and IPv4-translated literals around a rejected IPv4 address.

- Internal issuer client selection now checks exact registrations first and fetches fresh CIMD metadata for each code/refresh attempt before authoritative credential reads or consumption. Source-separated security fingerprints bind consent and grants; metadata scopes remain untrusted and app approval remains required.
