# Changelog

All notable changes to RevetSec are recorded in this file.

Each release gets a `## X.Y.Z (YYYY-MM-DD)` heading with Added, Changed, Fixed, Security and Migration Notes sections as needed. A security fix names its GHSA or CVE ID. Changes that reject previously accepted insecure input, or that remove an algorithm from a default, are listed under Security (see the security-tightening policy in [COMPATIBILITY.md](COMPATIBILITY.md)).

## Unreleased

Nothing has been released. The version is `1.0.0-SNAPSHOT`, and there is no compatibility promise before 1.0.0.

### Added

- Repository scaffold (milestone M0), with no protocol code yet:
  - a single-module Maven build for `com.revetsec:revetsec`, targeting Java 17, that fails if any compile or runtime dependency is declared;
  - placeholder packages;
  - contract tests for public API shape, package dependencies, source policy and documentation wording;
  - CI workflows, a fuzzing skeleton, and a test-only certificate authority;
  - the repository documents: README, COMPATIBILITY, SECURITY, CONTRIBUTING, NAMING_CONVENTIONS, NOTICE, and skeletons under `docs/`.
