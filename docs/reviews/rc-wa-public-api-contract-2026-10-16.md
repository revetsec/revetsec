# WebAuthn public API contract audit — 2026-10-16

**Status:** source-bound pre-release audit of the current uncommitted WebAuthn API. This is not the RC-WA API freeze, an independent security review, a production recovery qualification, or 1.0.0 release sign-off.

## Boundary and findings

`com.revetsec.webauthn` was listed as exported in [the compatibility policy](../../COMPATIBILITY.md) but omitted from the source-contract package inventory. The package now participates in the same public type, nullability, thread-safety, Javadoc, builder, and source-policy checks as the other exported packages. A regression sentinel keeps it in that inventory.

The expanded source check found eleven WebAuthn type declarations whose inline `@since` text was not parsed as a Javadoc tag. Those comments now put the tag on its own line. The builder-conventions check found fifteen additional findings: a primitive recovery-permit value, primitive settings accessors, required builder properties with nonnullable setters, and builders without `@CheckReturnValue`. The permit and value accessors now use nonnull boxed values. Passing null to a required registration-options or relying-party setter clears that selection so `build()` fails; passing null to optional settings restores defaults. Nonnull values still receive the existing eager validation. Tests cover the clear-and-rebuild behavior.

The R17 proof inventory now explicitly includes `WebAuthnAuthentication`, `WebAuthnRegistration`, and the `Succeeded` leaves of their completion results. The relying party and those result leaves are reviewed instance sources of the proofs. Prepared browser requests carry pre-commit ceremony data, not a verified identity proof, and remain outside this R17 list. The checker now resolves inventory entries against analyzed binary names and reports stale or misspelled entries; it previously dropped unresolved names. A nested enum that describes a proof is metadata, while a nested holder can still carry a proof. Negative fixtures exercise both cases and the stale-name failure.

## Evidence and limits

Focused Java 17 contract and WebAuthn tests pass. The full Java 17 core `verify` run passed 19,077 tests with zero failures, zero errors and one skip. A clean JDK 21 Error Prone/NullAway build and warning-fatal JDK 26 Javadoc/package verification passed. The Soklet passkey example, PostgreSQL WebAuthn fixture sources, and WebAuthn fuzz sources compile against the boxed recovery-permit API. The Soklet adapter passed 168 tests, and both Servlet adapters compiled and passed their 48-test suites against the rebuilt core snapshot on JDK 21. Their test fixtures use the boxed permit return as well. The pinned Tomcat 11 and 9 M12 fixtures each passed seven real HTTP checks after their gate call sites were updated, and each stopped its owned process.

The JDK 21 SpotBugs run at this checkpoint reported seven findings confined to the previously uncommitted password implementation (`Argon2id`, `Blake2b`, the vendored bcrypt source and `PasswordHasher`); it reported no WebAuthn finding. The later [password SpotBugs disposition](password-spotbugs-2026-10-16.md) closes that local gate. This WebAuthn audit itself did not disposition those findings.

This check establishes that the exported WebAuthn declarations follow the repository's selected source conventions. It does not settle protocol semantics, independent interop, production store/recovery behavior, mutation and pentest closure, or the owner's final API freeze. Hosted CI on pushed source remains separate evidence.
