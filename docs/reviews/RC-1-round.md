# RC-1 OAuth, OIDC, JOSE and JSON review — 2026-10-14

**Internal, AI-assisted adversarial review; not independent. All automated local
RC-1 closeout lanes are complete within the recorded Burp boundary. Release
acceptance remains open for the gates listed below.**
The entry snapshot is commit `dd5c10b984ca48ff38e728c5cd70d8fded92173f`
plus the uncommitted closeout changes recorded in the source-bound evidence.
This ledger covers shared foundations, JOSE, the OAuth client and resource
server, and OIDC. The OAuth issuer has a separate RC-AS review. SAML and SCIM
retain their separately closed review records.

Two reviewers used different prompt configurations from the same model family:
one emphasized specification, cryptography and attacker-controlled inputs; the
other emphasized API misuse, resource/concurrency behavior and fail-closed trust
boundaries. This establishes prompt-configuration diversity, not model-family
or external-review diversity. Each configuration first inspected the same
throwaway planted source without the seed manifest, live-source diff or the
other reviewer's findings.

## Calibration

Both configurations identified all four effective planted guard changes before
seed disclosure. The plants existed only in a private copy; none was copied into
the repository. A separate reproduction ran the normal source and each plant in
isolation.

| Seed in throwaway source | Configuration A | Configuration B | Failing-test proof |
| --- | --- | --- | --- |
| Discard the public-key signature-verification result before creating verified JWT data | Found | Found | Eleven flipped-signature cases fail on the plant; all pass on normal source. |
| Return before checking the configured JWT audience | Found | Found | The foreign/missing-audience case fails on the plant; it passes on normal source. |
| Accept any nonempty OIDC nonce without comparing it to the requested nonce | Found | Found | One wrong-nonce case fails among 27 ID-token cases; all pass on normal source. |
| Accept any nonempty OAuth callback state without comparing it to opened pending state | Found | Found | The cross-flow pending-state case fails on the plant; it passes on normal source. |

Each configuration's effective-seed recall was **4/4**. These are detection
counts for known planted changes, not an estimate of unseen-defect discovery.
The separate healthy reproduction passed 40/40 cases. The four isolated plants
produced the expected 11, 1, 1 and 1 assertion failures respectively, with no
unexpected compiler or infrastructure result counted as a finding.

## Current-source review

Configuration A completed its current-source pass and reported no actionable
finding under the rule that a security finding needs a reproducible failing
test. Its focused current-source replay passed 41/41 cases with no failures,
errors or skips. The read followed compact JWS parsing and signature proof,
registered-claim policy, OIDC nonce/subject/session continuity, OAuth state and
pending-flow correlation, introspection, URI/deadline admission, JSON bounds and
sealed-state context.

Configuration B also completed its current-source pass and reported no
actionable finding. Its focused replay covered 33 suites and passed 1,534 tests
on JDK 17 and 1,534 on JDK 21, with no failures, errors or skips. The first two
invocations accidentally inherited JDK 26; both passed 1,535 tests and remain
preserved as preliminary evidence rather than receiving JDK 17/21 credit. Both
configuration results remain internal, AI-assisted review evidence from one
model family rather than independent review.

## Qualification joined to this review

The RC-1 differential gate compares JOSE behavior with Nimbus 10.10 and jose4j
0.9.7, and strict JSON behavior with Jackson 2.18.8. Its retained reports pass
on JDK 17 and 21: each JDK ran 930 JOSE cases and 1,310 JSON cases, 2,240 total,
with no failures, errors or skips. The exact permitted differences are recorded
in [`differential/RC1-DISPOSITIONS.md`](../../differential/RC1-DISPOSITIONS.md).

The current-source PIT ledger contains 9,525 canonical mutation identities:
8,416 original named kills, 795 survivors, 146 uncovered identities, 167
timeouts and one run error. Every 1,109 original non-kill has an individual
resolution or narrow source-backed disposition; the open count is zero. The
run-error identity keeps its original status and has a separate exact named
assertion kill. The final 350-case regression union passes on JDK 17 and 21 and
under the static-analysis/SpotBugs build recorded by that ledger.

The final Jazzer composition passes all 72 configured campaigns, 36 each on
JDK 17 and 21: 244,850,771 qualifying inputs over 17,352 measured campaign
seconds, with no final finding. It retains the original JDK 21
resource-metadata failure. That run exposed a real mismatch between the
implementation and its separate oracle: production correctly rejected
duplicate introspection signing-algorithm metadata, while the oracle had
omitted that role-specific member and `token_endpoint`. The oracle was
repaired, the minimized JSON became a permanent seed, all 12 runs from the
changed class were replaced, and the two originally missing JDK 21 runs were
completed. The original failure remains historical evidence rather than being
discarded.

The first local ClusterFuzzLite attempt compiled successfully, then the local
Docker VM was interrupted during all-target startup under memory pressure. It
does not count as a pass. The complete replacement run passes compilation,
startup for all 67 targets and all 36 configured campaigns: 9,035,060 qualifying
inputs over 756 measured campaign seconds, with no finding. Its receipt is bound
to the final oracle, permanent regression seed, sorted 237-row seed manifest and
the same 4,739-input source snapshot used by the final release matrix.

The final local infrastructure and release matrix passes all 13 required legs
against that exact source snapshot. It includes Python verification gates,
packaged Maven and Gradle consumers on Java 17 and 27, provider qualification on
Java 17 and 21 with 18,825 tests per leg, ARM64 Linux Temurin 17 and Corretto 25
with 18,763 tests per leg under a two-CPU quota, Keycloak TLS smoke, actionlint,
and two 60-execution OIDF runs. Each OIDF run reports 56 passes and the same four
documented unsigned-token skips; five comprehensive-profile exclusions remain
not run. Final cleanup found no lingering task-owned or newly introduced
container. Only the README and the two RC-1 public ledger documents changed
after the qualified snapshot, so no code, test, build or workflow result was
invalidated. This is local qualification and does not claim hosted CI, OIDF
certification or external review.

## Released-client and application boundary

The released Inspector evidence preserves two distinct statements. The
minimal component diagnostic reproduced generic HTTP 403 recovery failure in
Inspector 2.9.0 with causal controls. The identical diagnostic did not
reproduce that behavior in Inspector 2.11.0: its default, explicit-throw and
no-auto-refresh variants all respected the policy denial. This diagnostic does
not use Soklet or the Revetsec application and is not host qualification.

The current fixture pins unmodified Inspector 2.11.0, commit
`074b8108f340590268f2900741403755e923a11c`, with npm integrity
`sha512-gqMw2x0NCotTdjLNv3PSm/IJSeXL7O8u0SpyZXtXGhSukJ2DMoAy8RR7xKngHTCETJcG5gyPdxhOn8zf/ofSRA==`.
All eight released-client variants pass the real browser, issuer, Soklet
resource server and MCP call path: public and confidential clients, legacy and
modern transports, and both expiry refresh and scope step-up recovery. The
step-up runs include 401 discovery, `insufficient_scope`, a second
authorization-code grant, successful retry and application denial after
admission. The generic-403 component diagnostic remains separate, and its
application-host recovery fence now passes in the
[bounded local RC-1 qualification](../pentest/2026-10-15-rc1.md). That run also
passes 33 named OIDC and resource-server cases through ZAP and the released
Inspector JWT and opaque paths. Burp did not reach application traffic because
its fresh private state presented first-run terms requiring explicit human
acceptance; the report records no result or product inference from that lane.
Historical documents that describe the original Inspector 2.9.0 observation
retain that version and scope.

Soklet 4 supplies header values as lists. The adapter collects every occurrence
case-insensitively and forwards duplicates to core protocol code, where
singleton ambiguity is rejected. Public self-issued documentation has been
updated to match this current transport contract.

## API and responsibility records

The generated RC-1 declaration inventory measures 92 top-level public types,
135 types including nested types, 614 declared public methods, 18 builders and
170 enum constants across the shared root, JSON, JOSE, OAuth/resource-server and
OIDC areas. It finds no public/protected data fields or copiers and one
application-accessible protected constructor, the documented
`RevetsecException` extension contract. The internal freeze proposal recommends
accepting that measured surface. Owner acceptance remains a separate gate.

The [threat model](../threat-model.md) now states the scope of its original
invariant table explicitly. It is not a complete OIDC, resource-server or OAuth
issuer threat map. The [OAuth and token responsibility map](../asvs-5.0-oauth-self-assessment.md)
accounts for all 43 OWASP ASVS 5.0 V9 and V10 identifiers as Revetsec,
application-owned, unsupported or not applicable responsibilities, without an
ASVS level or deployed-application claim.

For this checkout, the core claims, threat-map and contract-meta tests pass 96
tests; the adapter claims and contract-meta tests pass 14. Actionlint reports no
workflow issue, all nine workflow YAML files parse, the two retained
differential reports pass their exact verifier, the documentation links in this
ledger resolve and the working-tree diff has no whitespace error. These checks
must be rerun if their source or public text changes before release.

## Open items

The source-bound local closeout is complete. RC-1 release acceptance still has
three explicit gates:

1. applicable hosted CI must run after this uncommitted source is pushed;
2. the owner must accept the RC-1 and OAuth issuer API freeze proposals;
3. the Burp second-proxy lane requires explicit human acceptance of Burp's
   first-run terms before it can execute, or an explicit owner decision to
   accept the documented coverage boundary. ZAP's 33 cases, the released
   Inspector JWT and opaque paths, and the generic-403 application recovery
   fence are complete. Burp contributed no application result or product
   inference.

The parallel internal RC-AS source and qualification review is complete. Its
final receipt has SHA-256
`428fd219252856da475dbccf415ce2849cf57202bb9c9c020a4613daff337572`.
That sealed receipt predates the released-consumer and final local matrix
evidence, which are now complete. It does not close hosted CI, accept either API
proposal, authorize publication or characterize an application deployment.
