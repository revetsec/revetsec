# Changelog

All notable changes to Revetsec are recorded in this file.

Each release gets a `## X.Y.Z (YYYY-MM-DD)` heading with Added, Changed, Fixed, Security and Migration Notes sections as needed. A security fix names its GHSA or CVE ID. Changes that reject previously accepted insecure input, or that remove an algorithm from a default, are listed under Security (see the security-tightening policy in [COMPATIBILITY.md](COMPATIBILITY.md)).

## Unreleased

Nothing has been released. The version is `1.0.0-SNAPSHOT`, and there is no compatibility promise before 1.0.0.

### Added

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
