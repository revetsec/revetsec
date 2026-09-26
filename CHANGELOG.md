# Changelog

All notable changes to Revetsec are recorded in this file.

Each release gets a `## X.Y.Z (YYYY-MM-DD)` heading with Added, Changed, Fixed, Security and Migration Notes sections as needed. A security fix names its GHSA or CVE ID. Changes that reject previously accepted insecure input, or that remove an algorithm from a default, are listed under Security (see the security-tightening policy in [COMPATIBILITY.md](COMPATIBILITY.md)).

## Unreleased

Nothing has been released. The version is `1.0.0-SNAPSHOT`, and there is no compatibility promise before 1.0.0.

### Added

- Foundations (milestone M1), still with no protocol code:
  - `com.revetsec`:
    - `RevetsecException` and `ErrorCategory`: the root of Revetsec's exceptions, each with a category, a transience flag that follows from the category and the cause, a fixed message, and suppression disabled;
    - `StateSealer`, `SealingKey` and `InvalidSealedStateException`: short strings sealed with AES-256-GCM under a per-value key derived with HKDF-SHA256, bound to a context and a lifetime, with key IDs for rotation and one exception for every failure to open;
    - `OutboundUriPolicy` (provisional): classifies IP address literals, and never resolves hostnames.
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
