# Revetsec 1.0.0 security claims audit

**Scope:** public claims in the four 1.0.0 release-source repositories. This document records the allowed wording boundary; it is not an independent audit, an owner-acceptance receipt, or proof that the release was published. Final security-claims and release acceptance remain separate, hash-bound owner gates in the release record.

## Approved

- Revetsec core has zero compile-time and runtime dependencies. The build enforces that boundary, the published POM is checked independently, and the packaged-consumer and Central verifiers inspect the resolved artifact. This claim does not include the JDK or unpublished build and verification tools.
- Core targets Java 17 and requires Java 17.0.3 or newer. The Soklet adapter targets Java 21 and Soklet 4.0.0; the Servlet adapters target Java 17 and their named Servlet API versions.
- Revetsec implements the exact application-side OAuth, OpenID Connect, JOSE, SAML, SCIM, WebAuthn, TOTP/recovery and password-hashing surfaces described in the [README](../README.md), [public API inventory](../docs/public-api-inventory.md), and protocol guides. The application-owned responsibilities and unsupported protocol profiles stated there remain part of each claim.
- Inputs, algorithms, work, storage effects and network operations are bounded only where the corresponding API or guide states an exact bound. Named compatibility modes are explicit, off by default and documented in the [compatibility-mode registry](../docs/compatibility-modes.md).
- Release tooling can verify signed Central bundles, reproducible payloads, hosted provenance, Central publication, fresh Maven and Gradle consumers, API documentation and the final release record. These are verifier capabilities; they become release evidence only when successful receipts are bound to the exact release commits and artifacts.

## Narrowed

- Security wording is limited to documented defaults, invariants, rejection behavior and responsibility boundaries. Revetsec does not claim to secure an application or deployment end to end.
- Conformance, fuzzing, differential testing, mutation testing, scripted-provider checks and hosted interoperability apply only to their named versions, inputs, platforms and recorded cases. They are supporting evidence, not general certification or universal provider compatibility.
- Cryptographic support means only the algorithms, key forms, providers and limits documented in the [supported-algorithms guide](../docs/supported-algorithms.md). Time budgets require cooperating JCA providers and are not a constant-time or hard real-time guarantee.
- In-memory implementations are bounded single-process references. Durable storage, authoritative time, cross-node atomicity, backup recovery, availability, tenancy, rate limiting, account policy, sessions and deployment operations remain application responsibilities as mapped by the [threat model](../docs/threat-model.md).
- “Secure defaults” is a design goal meaning named relaxations are off by default and observable. It is not a claim of vulnerability freedom, production readiness for every deployment, or correct application configuration.

## Rejected

- Any claim that Revetsec is independently audited, certified, formally verified, vulnerability-free, secure by itself, or production-ready for arbitrary applications or deployments.
- Any unqualified claim of complete OAuth, OpenID Connect, JOSE, SAML, SCIM, WebAuthn, TOTP, password-hashing or OWASP ASVS compliance.
- Any claim that local or hosted test success proves compatibility with every provider, JDK, servlet container, database, network edge or storage implementation.
- Any claim of constant-time execution, hard wall-clock deadlines, unlimited input or work, all-provider cryptographic support, automatic account linking, application authorization, durable single use, distributed consistency or end-to-end recovery.
- Any claim that an unsigned candidate build, a verifier dry run, an intermediate review, a template record or an unaccepted receipt constitutes the 1.0.0 release.

The detailed reporting and non-claim boundary is in [SECURITY.md](../SECURITY.md). The release-evidence model and required receipts are in [verification/README.md](../verification/README.md) and [RELEASING.md](../RELEASING.md).
