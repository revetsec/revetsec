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
local six-case replay. A later hosted rerun is recorded below. The
then-reviewed `internal.xml.*` PIT report has 599 assertion kills, 41
survivors and 27 no-coverage actions out of 667. The then-reviewed full
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
CBC fixtures. The current checkout includes those fixtures. After the owner
pushed `eccaa18743bc2efc0287c171a7e027139e0e9eef`, [CI run 38456477929](https://github.com/revetsec/revetsec/actions/runs/38456477929)
passed all 43 required SAML differential methods with zero skips or failures,
all three Keycloak SAML integration methods, and the 7,330-case fuzz replay.
The overall CI run failed in the examples and packaged-consumer jobs. On the
same pushed SHA, [Shibboleth run 38456503172](https://github.com/revetsec/revetsec/actions/runs/38456503172)
completed successfully: six required methods passed with zero skips, both
GCM and CBC captures were present, all 11 capture-file hashes matched the
manifest, and independent offline replay of the downloaded artifact passed
six of six. The artifact ZIP SHA-256 is
`9480f3eb811aafa9c73aacdc9b547b473ee1abf47e27aadd8eee76acf5407d23`.
PIT survivor/uncovered/timeout dispositions remained open at this checkpoint.
The later fixed-source full run and current RC-2 status are recorded below.
The review findings and tests above retain their stated source and tool scope.

## Post-hosted replay finding — 2026-10-13

After this review and the hosted checks on
`eccaa18743bc2efc0287c171a7e027139e0e9eef`, a new public-API
regression reproduced a replay acceptance with two disjoint bearer
confirmation windows. The same signed unsolicited Response succeeded at
00:01:00 and again at 00:01:21 after its first replay mark expired; the second
result should have been `Rejected(REPLAYED)`. The failing-before evidence and
the exact pre-fix mutation are recorded in the
[SAML mutation ledger](../saml-mutation-triage-2026-10-11.md#2026-10-13-post-hosted-bearer-replay-finding-and-repair).
The first working-tree fix retained the replay mark through every structurally
valid bearer window bound to the current request while requiring one to be
valid at admission.
Focused Corretto 17 and 21 tests pass 55 each, and a targeted fixed-source
PIT run kills the moved maximum-end conditional. A subsequent
[full fixed-source local PIT run](../saml-mutation-triage-2026-10-11.md#2026-10-13-full-fixed-source-samlxml-pit-receipt)
generated 3,176 actions: 2,904 assertion kills, 113 individually
source-dispositioned survivors, 158 uncovered limits, and one detected
timeout. It meets RC-2's no unjustified survivors criterion on that
intermediate repaired source. This later finding does not change what the
round-1 reviewers observed on their reviewed source.

Further adversarial review reproduced two more accepted replays on the
first repaired source: one signed assertion crossed two pending request
bindings after the first confirmation expired, and one crossed unsolicited
and requested login after the unsolicited two-minute age bound expired. A
stricter working-tree repair now keeps the replay key until no supported
completion context can accept the signed assertion. The replay deadline uses
the latest structurally usable signed bearer end across bindings, the signed
Conditions end when present, and the shared maximum configuration limits of
15 minutes for assertion age and five minutes for skew. The public
authentication expiry remains specific to the accepted context. A third
regression checks that a second node with more permissive skew still sees the
replay. Both reproduced public-API cases and the skew regression pass; the
255 SAML-named tests pass on Corretto 17 and 21, and JDK 21 static analysis passes.

On 2026-10-14 the maintainer personally reviewed and confirmed this stricter
bearer replay fix, including the longer replay-cache retention tradeoff. The
earlier full PIT receipt is bound to the intermediate repair. A
[new full current-source PIT run](../saml-mutation-triage-2026-10-11.md#2026-10-14-full-stricter-source-samlxml-pit-receipt)
meets the local survivor criterion with 160 explicit uncovered limits. The
hosted receipts remain bound to an earlier pushed source. RC-2 remains open
pending push, green full CI, and hosted differential and Shibboleth reruns.
