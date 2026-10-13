# RC-2 SAML and XML review, round 1 — 2026-10-12

**Internal, AI-assisted adversarial review; not independent. Review round complete; RC-2 remains open.**
The reviewed source was checkout `e52e162dcdcbc4706321b275f4da12ead9db832d`
plus the uncommitted RC-2 edits described below. Three reviewers used distinct
SAML protocol/API, XML/cryptography, and cross-boundary attacker prompts. They
used the same model family, so this is prompt-configuration diversity, not a
claim of independent model families or external review. Each first inspected
throwaway seeded source without the seed manifest or other reviewers' findings;
then the SAML and XML reviewers inspected actual source. A separate cross-boundary
reviewer verified the actual finding and checked seed effectiveness after the
blind round.

## Calibration

The candidate source existed only under `/private/tmp/revetsec-rc2-calibration-2026-10-12/`.
No planted change was copied into the repository. Five effective guard changes
were identified before seed disclosure: both authentication-boundary changes
and all three XML guard removals. The XML observations establish removed checks,
not a demonstrated identity forgery through the remaining defenses.

| Seed, in candidate source only | Blind result | Failing test proof |
| --- | --- | --- |
| Invert `AudienceRestriction` match | SAML and cross-boundary reviewers identified the cross-SP acceptance risk. | Isolated audience-only candidate made `SamlResponseSemanticsTests.bindingAndAudienceFailuresCannotWriteReplay` accept a foreign audience; normal source rejects it. |
| Remove bearer `SubjectConfirmationData/@Recipient` equality | SAML and cross-boundary reviewers identified the assertion-only destination gap. | Isolated recipient-only candidate made `SamlResponseSemanticsTests.assertionOnlySignatureBindsRecipientWithoutResponseDestination` accept a wrong ACS; normal source rejects wrong and absent recipients and accepts the control. |
| Admit duplicate ID-like values during raw XML parsing | XML and cross-boundary reviewers found the disabled uniqueness guard. | Seeded `SecureXmlParserTests.rejectsDuplicateIdentifiersAcrossAttributeSpellingsAndNamespaces` fails. |
| Admit relative namespace declarations during SAML shape inspection | XML and cross-boundary reviewers found the disabled guard. | Seeded `SamlResponseStructureTests.rejectsSignatureWrappingAndNamespaceAndAttributePollution` fails. |
| Treat a missing cached digest input as signed-target proof | XML and cross-boundary reviewers found the fail-open return. | Seeded `EnvelopedSignatureVerifierTests.digestInputMustBeginWithTheExactSignedQName` fails. |

A sixth planted edit removed the semantic RelayState comparison. The separate
verification found it ineffective through the public login paths:
`SamlServiceProvider` resolves pending state by incoming RelayState and checks
the same handle before calling semantics; unsolicited login rejects any
RelayState. This seed is excluded from the effective-seed denominator rather
than counted as a reviewer miss. No Critical-class seed was planted. Effective
guard recall was **5/5**; the two demonstrated authentication-boundary seeds
were **2/2**. These are seeded-change detection counts, not a measured defect
discovery rate on unseen source.

For a runnable check, the normal-source Corretto 17 four-class suite passed
70/70 tests. The combined six-edit candidate failed 37/70 checks, with failures
in each XML guard's focused test. The two authentication-boundary seeds were
also run separately against their named tests: each failed 1/1 on the
candidate and passed on normal source. The temporary candidate builds were
kept outside the repository.

## Actual-source findings

No reviewer confirmed a Critical or High authentication bypass, replay,
logout, XML signature, or CBC integrity defect in the actual source. The
following availability/API-contract defect was reproduced by a separate reviewer:

| Severity | Finding | Verification and disposition |
| --- | --- | --- |
| Medium | `SamlIdentityProvider.Builder.build()` accepted 5–8 IdP signing keys, while `EnvelopedSignatureVerifier.verify()` rejected more than four before checking any signature. Every SSO completion for such an IdP could throw instead of returning a typed result. | The cross-boundary reviewer reproduced the exception through the public SSO API. A new hosted-Shibboleth regression with the signer eighth failed before the fix with `IllegalArgumentException`. Message-signature verification now accepts 1–8 keys, matching IdP configuration; metadata trust-key verification retains its distinct 1–4 limit. Corretto 17 focused replay/verifier/semantics tests then passed 62/62. |

On the repaired source with the imported hosted fixtures and final subject-key
and pending-store tests, isolated full core tests passed 17,677/17,677 on each
of Corretto 17 and 21 (one intentional locale skip per run). The complete JDK
17 differential module passed 37/37 against the repaired local core JAR. The
CI differential guard now requires all three captured-provider comparator
methods, the renamed signed XSW/Fragile Lock comparator method, and the
libxmlsec full signed-mutation matrix. Its embedded report check passed against
all 37 local Surefire results with zero skips. The
Shibboleth capture workflow now requires all six hosted replay methods,
including the eight-key rollover case; its report check passed against the
local six-case replay, and the hosted rerun still awaits the user push. The
final-source full `internal.xml.*` PIT report has 599 assertion kills, 41
survivors and 27 no-coverage actions out of 667. The final-source full
`saml.*` report has 2,198 assertion kills, 128 survivors, 174 no-coverage
actions and two timeouts out of 2,502. The corrected seven-target live fuzz
campaign completed 237,851,042 executions and 0.6380 measured process CPU
hours without a finding. These are test and mutation receipts, not a second
review round.

The XML reviewer verified that actual-source duplicate-ID, relative-namespace,
and null-digest guards reject their corresponding inputs. The SAML reviewer
checked audience, recipient, pending request, replay, signed-node selection,
and Redirect logout paths. No other actual-source finding met the review rule
of a reproducible failing test.

## Post-round disposition

The maintainer reviewed and confirmed the `internal.xml` message-signature
key-limit diff and the [SAML public API inventory](rc-2-saml-api-freeze-candidate.md)
on 2026-10-12. The API freeze is complete. The owner also accepted the
source-backed non-applicability disposition for the relative-namespace
void-canonicalization precondition; a full validly signed exploit was not
reproduced. The [2026-10-13 strict live-browser pass](../pentest/2026-10-13.md)
records 30 ACS and eight SLO cases through Burp, with the signature
preconditions and limits of each result. A [selected ZAP-routed pass](../pentest/2026-10-13-zap.md)
adds a second live proxy observation for clean SSO/SLO, a signed wrong-RelayState
ACS rejection and a duplicate-SigAlg logout rejection.

A later [hosted Shibboleth capture](../../src/test/resources/fixtures/shibboleth/README.md)
ran all six required replay methods and imported the GCM and signed-Response
CBC fixtures. The current checkout includes those fixtures. This hosted receipt
and the local pentest do not substitute for hosted differential and capture
checks on the final pushed source. PIT survivor/uncovered/timeout dispositions
and final-source hosted checks remain RC-2 work. The review findings and
tests above retain their stated source and tool scope.
