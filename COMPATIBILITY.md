# Compatibility Policy

RevetSec is pre-release. The version is `1.0.0-SNAPSHOT`, and **there is no compatibility promise before 1.0.0**. Until then, any public type, member, default or behavior may change incompatibly, without deprecation.

From 1.0.0, RevetSec follows [Semantic Versioning](https://semver.org/), with release tags `vX.Y.Z`:

* **Major** (`2.0.0`): may remove or incompatibly change public API. Migration notes are provided in the CHANGELOG.
* **Minor** (`1.1.0`): additive public API, and behavior changes documented under "Migration Notes" in the CHANGELOG.
* **Patch** (`1.0.1`): fixes only; no new public API.

The [security-tightening policy](#security-tightening-policy) below is the one deliberate exception.

## What counts as public API

Everything `public` or `protected` in the exported packages of the `revetsec` artifact. The package layout is still under review and may change before 1.0.0. Each package's API is frozen when its protocol area is ready for release.

| Package | Planned contents |
| --- | --- |
| `com.revetsec` | shared, protocol-neutral types |
| `com.revetsec.json` | JSON values that appear in public signatures (under review) |
| `com.revetsec.jose` | JWS verification, JWK and JWK Sets, JWT validation |
| `com.revetsec.oauth` | OAuth 2.0 client and resource server |
| `com.revetsec.oidc` | OpenID Connect relying party |
| `com.revetsec.saml` | SAML 2.0 service provider |
| `com.revetsec.scim` | SCIM 2.0 server primitives |

These are not API:

* **`com.revetsec.internal` and every package under it.** Its types are `public` only because Java requires that for use across packages. They are excluded from Javadoc, a contract test keeps them out of every public signature, and they may change in any release, including a patch.
* Package-private types and members.
* **Diagnostic text**: exception messages and `toString()` renderings. When a change could break log parsers, the CHANGELOG says so, but such changes may occur in minor releases.
* Test code, and the unpublished tooling projects in the repository (such as `fuzz/`, `interop/` and `verification/`).

A sealed type whose Javadoc designates it for exhaustive `switch` keeps its permitted subtypes within a major version. Other sealed types may gain subtypes in a minor release.

The adapters (`revetsec-soklet`, `revetsec-servlet-jakarta` and `revetsec-servlet-javax`) are separate artifacts in their own repositories. Each starts at `1.0.0-SNAPSHOT`, releases 1.0.0 together with core, and then has its own version line. From 1.0.0, each adapter's README states the minimum core version it requires.

## How the policy is enforced

Before 1.0.0, contract tests run in every build:

* `PublicApiContractTests` checks the shape of the public API: no public records, JSpecify nullness annotations on every public element, and exactly one thread-safety annotation on every exported type.
* `PackageDependencyTests` checks the allowed dependencies between packages, and that no `internal` type appears in a public or protected signature.
* `SourcePolicyTests` bans a list of source constructs, including `sun.*` imports and `setAccessible`.

From 1.0.0, the [japicmp](https://siom79.github.io/japicmp/) Maven plugin (the `api-diff` profile) compares each build with the previous release. It fails the build on binary- or source-incompatible changes and checks the version number against the nature of the change. Until 1.0.0 the profile is a stub, because there is no baseline.

## Security-tightening policy

These changes may ship in a minor or patch release, and they are not treated as Semantic Versioning breaks:

* rejecting input that an earlier release accepted, when that input is insecure;
* removing an algorithm from a default allowlist.

Each such change is listed under Security in the CHANGELOG, with migration notes. Compatibility presets only ever widen what is accepted, and every change to a preset is recorded in the CHANGELOG.

## Supported JDKs

* **Source and binary baseline:** Java 17 (`<release>17</release>`). There is no multi-release JAR.
* **Minimum runtime:** Java 17.0.3, the first Java 17 update with the fixes for CVE-2022-21449 (ECDSA signature verification) and CVE-2022-21476 (XML Signature validation). Types that perform network I/O are planned to refuse to build on an older runtime unless the application explicitly acknowledges it.
* **Tested:** CI is configured to build and test on Java 17, 21, 25 and 27 (Amazon Corretto).
* RevetSec uses no `sun.*` APIs and no `setAccessible` (a source-policy test bans both), so `--add-opens` is never required.
* The JAR declares `Automatic-Module-Name: com.revetsec`.

## Dependencies

The core `revetsec` artifact declares **zero compile or runtime dependencies**. A Maven Enforcer `bannedDependencies` rule enforces this at build time, and it is visible in the published POM. The annotation dependencies (JSpecify, JSR 305 concurrency annotations and Error Prone annotations) are `provided` scope and are not needed at runtime.

Each adapter depends on RevetSec core and on its framework's API, both `provided`, so applications declare both explicitly.

## Supported algorithms

Not yet written. The table in [docs/supported-algorithms.md](docs/supported-algorithms.md) will list, for each protocol area, the algorithms allowed by default, those available only by explicit opt-in, and those never accepted.

## Compatibility-mode registry

Not yet written. Every compatibility mode will be registered in [docs/compatibility-modes.md](docs/compatibility-modes.md), with its conditions and the release that added it.

### saml2int deviations

Not yet written. The SAML service provider's deviations from the saml2int SP requirements will be listed in [docs/compatibility-modes.md](docs/compatibility-modes.md#saml2int-deviations), each with its reason.

## Interop matrix

Not yet written. It will be a dated provider matrix, modeled on Pyranid's table of wire-compatible databases. Each row will name the provider and version observed, say whether its CI leg gates or is advisory, carry an "observed on YYYY-MM-DD" date, and list divergences. Any combination found unsafe will carry an explicit warning.

**No production consumer.** RevetSec has no production consumer, and none is planned for 1.0.0, including for SCIM. The evidence at 1.0.0 will come from self-hosted test partners, conformance suites run locally, and dated captures from provider accounts.

## Conformance suites

None has been run yet. Results will be stated only for suites actually run, with the suite release and the date of the run.
