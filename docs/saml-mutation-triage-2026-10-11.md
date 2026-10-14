# SAML mutation triage — 2026-10-11

This is a chronological local RC-2 evidence ledger. The earlier results below
describe the source and test snapshots on which they were measured; they are
not all fresh results for the current checkout. PIT 1.30.0 ran on JDK 21 with
the SAML test families selected. The earlier full `internal.xml.*`
run examined 667 mutations: 596 assertion kills, 43 survivors, and 28 with no
coverage. Later whole-package results are recorded below. This is an
inventory, not a closure: parser configuration and other defense controls
remain among the survivors.

The earlier full `saml.*` run examined 2,502 mutations: 2,166 assertion kills,
152 survivors, 182 with no coverage, and two timeouts. Exact 255-character
literal-scope and 32-scope tests killed both open metadata-boundary mutants.
The two timeouts are the `SamlPostBindingDecoder.validQuery` subtraction mutant
at line 132 and the `InMemorySamlReplayCache.markIfAbsent` removed-unlock
mutant at line 114. They are nonterminating mutant executions, **not** assertion
kills; PIT's aggregate "Killed" display includes them, while the XML report
keeps them as `TIMED_OUT`.

| Target | Killed | No coverage | Survived | Disposition |
| --- | ---: | ---: | ---: | --- |
| `SamlPostBindingDecoder` | 165/173 | 0 | 8 | Source-reviewed semantic equivalents. |
| `EnvelopedSignatureVerifier` | 195/223 | 18 | 10 | Further fault-injection and review required. |
| `XmlEncryptionDecryptor` | 127/139 | 2 | 10 | The remaining public-result survivors are source-reviewed; buffer-wipe effects and two unvisited branches need separate evidence. |

The full `internal.xml.*` inventory retains 10 verifier, 10 decryptor, 13
parser, six Response-shape and four XML-writer survivors. The parser group
includes the JAXP secure-processing, DTD/entity/external-access, namespace,
resolver and lexical-handler settings. The writer group includes transformer
security and UTF-8 settings. These settings are layered defenses on the JDK
provider; single-call removal mutations do not necessarily change an admitted
document while the other defenses are active. They remain open for an explicit
source and fault-model disposition, not counted as assertion kills.

A focused JDK 21 parser rerun on 2026-10-12 uses a one-byte malformed input at
the minimum accepted input budget. It kills the two line-78/84 boundary mutants
in the prior inventory. The focused `SecureXmlParser` report is 35 killed, 11
survived and two with no coverage out of 48; the remaining survivors remove
JAXP/SAX security configuration calls. This focused result does not update the
earlier whole-package totals or dispose of the defense controls.

A separate focused `SamlResponseStructure` rerun adds an error Response with
two conflicting `StatusCode` children and no Assertion. It kills the line-159
false-return mutant that could otherwise classify that malformed error as a
valid status-only shape. The report is 107 killed, five survived and one with
no coverage out of 113. The five surviving changes are equivalent on the
reachable tree: changing the Assertion or EncryptedAssertion counters from
increment to decrement (lines 114/118), subtraction or a constant true at the
final count (line 142), and changing `<` to `<=` in the second order check
(line 91). `inspect` already rejects a second direct identity carrier before
the walk; a nested carrier fails the node/parent check. A repeated non-carrier
position is rejected by the first order check, and a repeated carrier is
rejected while scanning its child. The uncovered line-124 return requires a
root Signature that differs from the unique direct Signature selected by
`inspect`; a second direct Signature is rejected before the walk. These are
source-reachability dispositions for this class, not new assertion kills or a
disposition of the other `internal.xml` classes.

The POST decoder's eight survivors preserve the same parsed result: they alter
rejection paths for a trailing or empty query segment, an already invalid MIME
parameter, or a third field after the only two permitted names; one allocates
unused extra bytes within the existing raw-body limit. The exact body and
predecode Base64 caps, raw query whitespace, percent-hex case and duplicate
RelayState now have boundary tests. No POST mutation remains uncovered.

The verifier's digest-input guard now has direct malformed, truncated and
matching-prefix tests. Its three surviving return-value substitutions replace
`false` with `false` or `true` with `true`. A relocated but otherwise valid
signature test killed the node-identity and schema-position survivors. The
other survivors include stricter key-boundary behavior; post-unmarshal checks
also made by the precheck; the URI dereferencer that is constrained by exact
fragment precheck and single-node ID registration; and the secure-validation
context setting. The last two are defense-in-depth controls, so their survival
is **not** treated as a closed mutation gate. The 18 no-coverage mutations are
mostly JDK provider-failure returns and need fault-injection or a reviewed
unreachable-path rationale.

For encryption, tests now pin the raw wrapped-key Base64 length before
whitespace removal and the exact 131,072-byte GCM wire cap. One survivor
tightens the eight-key limit; one replaces subtraction with addition inside a
modulo-16 CBC alignment check, which has the same remainder; three replace
`null` with an empty key-candidate list, which the caller rejects identically.
The remaining five survivors remove `Arrays.fill` calls on temporary buffers; a
public result test cannot observe zeroization. One such wipe and the duplicate
retrieval-reference branch have no coverage. These require a separate
zeroization/source review and parser-reachability disposition before RC-2.

The full suite, differential partners, live fuzzing and integration tests are
separate checks. These whole-package PIT runs establish the remaining exact
mutation inventory but do not yet justify every survivor or uncovered branch.
This file does not close the manual pentest, calibrated review, hosted
Shibboleth capture or RC-2 mutation disposition gate.

Additional focused evidence, expanded on 2026-10-12: three signed real-provider
encrypted responses (Shibboleth GCM and CBC, SimpleSAMLphp CBC) pass an
isolated decryptor baseline and an 11-edit ciphertext/key/algorithm matrix.
The end-to-end matrix applies those 11 edits plus 19 envelope attacks to each
signed capture, and 11 edits plus 17 applicable envelope attacks to
SimpleSAMLphp's unsigned Response with an encrypted, signed assertion: 118
rejection checks, with the three original signed captures still accepted
afterward. CBC ciphertext is malleable at the decryption layer;
its integrity check is the signed Response, which the end-to-end matrix also
exercises. A deterministic substitute key keeps the isolated CBC failure cases
repeatable. The focused decryptor PIT run has 127/139 killed, 11 survivors and
one no-coverage mutation. It reached one previously uncovered temporary-buffer
wipe, which remains a survivor requiring source review. This focused run does
not replace the whole-package report above.

An exact SP builder boundary test accepts four decryption credentials and each
documented time-policy endpoint, then rejects five credentials or values one
nanosecond beyond those endpoints. The focused builder PIT run killed the five
boundary mutants that had survived the earlier whole-package campaign (lines
1091, 1096, 1098, 1099 and 1101). Its other results are scoped to the builder
configuration test class and are not a new whole-package count.

The Docker-backed libxmlsec oracle now also checks six real-provider ciphertext
bit flips: wrapped key and encrypted data for the two signed Shibboleth captures
and signed SimpleSAMLphp CBC capture. Both GCM decryptions fail authenticated
decryption; all six changed outer Response signatures fail. A CBC ciphertext
may fail decryption or produce altered plaintext, so CBC's signed-Response
integrity requirement is kept explicit. The focused differential test passed
on JDK 17 with the pinned local scripted IdP image. This remains a partial
real-provider matrix, not the full RC-2 differential gate.

The public metadata parser now has an exact 2,048-character entity-ID control
and a 2,049-character rejection. JDK 17 metadata tests pass, and focused JDK
21 PIT kills the previously surviving `parse` line-180 boundary mutation.
The remaining metadata certificate-size survivors still need disposition:
the Base64 text limit is checked after XML whitespace removal, and at most
32,768 Base64 characters decode to 24,576 bytes, so the later `> 24,576`
decoded-size branch cannot be reached through this parser. This is a source
argument for that branch, not an assertion kill or a verdict on the separate
Base64 text boundary.

After installing the current core checkout into the local Maven cache, the
complete JDK 17 `differential` module passed 31 tests across OpenSAML, Spring
Security and the Docker-backed libxmlsec oracle. Five one-minute JDK 17 Jazzer
runs completed without a finding: signed/encrypted structure (16,356), metadata
(531,888), Redirect/inflation (38,961,927), POST (15,402,769) and signed logout
(820,147), totaling 55,733,087 executions. The short duration and existing
seed/mutation selection limit this evidence; a reviewed longer campaign and
the remaining RC-2 assurance actions are still open.

The expanded differential suite was rerun in full on 2026-10-12 after the
encrypted-wrapper and real-capture additions: JDK 17 `verify` passed 34/34
tests, zero failures, errors or skips. This supersedes the 31-test count for
the differential module only; it does not close the separate manual or hosted
RC-2 gates.

The metadata certificate boundary now has a certificate-only DER fixture at
exactly 24,576 bytes (32,768 unpadded Base64 characters), with a noncritical
unknown extension. The parser accepts it and rejects an over-limit value.
Focused JDK 21 PIT kills both previously surviving certificate-size boundary
mutants (lines 302 and 305). Tests also cover the two public convenience
overloads, a failing validation clock, a duplicate POST SSO endpoint, the
missing XMLDSig provider result, and the redacted description. The current
focused metadata report is 166 killed, one survived, two no coverage out of
169 mutants; JDK 17 metadata tests pass 13/13.

The remaining `textOnly` survivor substitutes an empty string for `null` on a
nested non-text child. The two callers (certificate and literal Scope) reject
both empty and null, so this is an equivalent public rejection. The parser's
`Unavailable` result at line 145 requires a failure configuring its JDK SAX/DOM
factory; the test has no safe injection point for that environment fault. The
line-150 root-null path cannot follow an `Accepted` parser result: the parser
checks for a nonnull document element before constructing `Accepted`, and the
metadata code does not mutate that document before reading its root. These
two no-coverage identities retain their source dispositions rather than being
counted as assertion kills. The focused run does not requalify other SAML
classes or close the whole RC-2 mutation gate.

The metadata Jazzer target now asserts accepted certificate count/DER size,
entity-ID and literal-scope bounds, and HTTPS endpoint host/user-info/fragment
conditions. Its corpus includes the exact-size certificate XML. JDK 17 seed
replay passed six cases, followed by a three-minute live run of 592,952 inputs
with no finding. This is a focused metadata campaign; parser, walker,
decryptor, inflate and structure-aware targets retain their earlier runs and
the broader RC-2 campaign remains open.

On 2026-10-12, the pinned `i2incommon/shib-idp:5.2.3_20260824_rocky10_multiarch`
image (`sha256:bb6bbf1cfe935d20cb2d312e121fc6540cd367d18eee40ea263592c873efc7e5`)
produced a fresh local GCM and a fresh CBC capture in a private scratch
directory. The JDK 17 `ShibbolethCapturedResponseTests` replay accepted both
and passed 5/5 tests with `revetsec.shibboleth.fixtures` pointing to that
directory. GitHub Actions run `38311798191` then captured an 8,661-byte GCM
and an 8,551-byte CBC response from the same pinned image on source
`e52e162dcdcbc4706321b275f4da12ead9db832d`; hosted Corretto 17 replay
passed 5/5 tests. The uploaded `shibboleth-capture-38311798191-1` artifact
(ID `11775191823`, SHA-256 `5be33cf755163f298e54db0ba101203c224f3b9b4298bb0ae19de19e8f8acbf4`)
contains the capture and Surefire report. The artifact ZIP was supplied, its
archive SHA-256 and all 11 capture-file SHA-256 values matched, and the hosted
fixtures replaced the earlier local captures. An isolated, unchanged-source
Corretto 17 offline replay passed 5/5 tests against the imported files. The
checkout's Corretto 17 hosted-capture replay passed 6/6 after a rollover-key
regression was added and fixed. The fixture replacement was uncommitted at
that checkpoint; commit `33bbac0` subsequently included the imported captures.

A seven-target, five-minute-per-target Corretto 17 Jazzer campaign finished
without a finding on the pre-rollover-repair core source. It exercised the
curated SAML seed corpora with one fuzzer worker per sequential target:

| Target | Executions | Nominal single-worker hours |
| --- | ---: | ---: |
| Raw HTTP-POST binding | 76,300,443 | 0.083 |
| Raw HTTP-Redirect binding and inflate | 204,966,288 | 0.083 |
| Bounded IdP metadata | 1,773,454 | 0.083 |
| Signed/encrypted response structure | 82,135 | 0.083 |
| Signed Redirect logout | 3,858,319 | 0.083 |
| Raw XML parser and walker | 3,957,126 | 0.083 |
| Encrypted data and wrapped-key ciphertext | 43,692 | 0.083 |
| **Total** | **290,981,457** | **0.583** |

These hours are the nominal five-minute single-worker budgets, not measured
process CPU time. The campaign ran before the message-signature verifier's
four-to-eight-key consistency repair. After a namespace-declaration name
collision was added to the parser corpus, the current source passed all 91
SAML fuzz seed/layout checks on Corretto 17. The replay is separate from the
live campaign and its measured CPU accounting below.

The repaired production source then completed a second seven-target Corretto
17 campaign, with five minutes allocated to each target. The parser/walker
target initially stopped on a fuzz-harness false positive: `xmlns:ID` was
counted as an ID attribute even though it is a namespace declaration. The
minimized input is retained as a seed; after the harness excluded the XMLNS
namespace from that check, its five-minute rerun passed. All seven successful
runs ended with `DONE` and `BUILD SUCCESS`, with no security finding or crash.
Actual process CPU below is `/usr/bin/time -l` user plus system time for each
Maven/Jazzer run, including its startup and instrumentation; it is not inferred
from the nominal wall-clock budget.

| Target | Executions | Measured process CPU hours |
| --- | ---: | ---: |
| Raw HTTP-POST binding | 64,258,263 | 0.0866 |
| Raw HTTP-Redirect binding and inflate | 163,986,838 | 0.0903 |
| Bounded IdP metadata | 1,796,661 | 0.0918 |
| Raw XML parser and walker, corrected rerun | 3,905,119 | 0.0915 |
| Signed/encrypted response structure | 72,185 | 0.0923 |
| Encrypted data and wrapped-key ciphertext | 44,394 | 0.0908 |
| Signed Redirect logout | 3,787,582 | 0.0947 |
| **Successful-run total** | **237,851,042** | **0.6380** |

The failed harness-only parser run is excluded from the successful-run total.
The 91/91 SAML seed/layout replay includes its minimized input. This completes
the local live-fuzz accounting for these targets, while ongoing ClusterFuzzLite
and later source changes remain separate evidence.

A final-source full JDK 21 PIT run of `internal.xml.*` examined 667 mutants:
599 `KILLED`, 41 `SURVIVED`, and 27 `NO_COVERAGE`. It confirms the key-limit
repair is reached and killed, but does not justify the remaining 68 mutants.
The final-source complete `saml.*` rerun, including the subject-key and both
pending-store contention tests, examined 2,502 mutants: 2,198 `KILLED`, 128
`SURVIVED`, 174 `NO_COVERAGE`, and two `TIMED_OUT` in `mutations.xml`. PIT's
displayed aggregate of 2,200 kills includes those two timeouts; the
assertion-kill count is 2,198. Compared with the earlier repaired-source full
run, six subject-key and nine pending-store mutants changed from `SURVIVED` to
`KILLED`; a further two pending-store interrupted-wait mutations changed from
`NO_COVERAGE` to `KILLED`. No earlier kill regressed. The remaining 302 SAML
survivors/uncovered actions still need disposition; this report does not close
the PIT gate. Together with the 68 open `internal.xml.*` actions, that is 370
survivor or uncovered actions across the two packages. The interrupted-wait
test also passed on Corretto 25 and 27.

After the repaired core JAR was installed locally, the complete JDK 17
`differential` module passed 37/37 tests. The three new whole-SP cases cover
the hosted Shibboleth GCM/CBC captures, SimpleSAMLphp's signed CBC capture,
and its assertion-signed CBC capture through direct OpenSAML and Spring
Security. The unsigned envelope's two OpenSAML acceptances retain the original
signed identity; Spring and Revetsec reject those changed envelopes. The
precise comparator policy and the 57 signed-envelope rejections are recorded
in `differential/README.md`. This is additional real-producer evidence, while
the full fixture-by-mutation RC-2 cross-product remains open.

An exact-identity JDK 21 PIT follow-up on the same production source added
security-boundary regressions for SP and IdP entity IDs, SAML timestamp offsets
and lexical endpoints, and the authenticated pending-state codec's entity-ID,
application-data and whole-frame limits. The two entity-ID factory classes
have 374 shared mutation identities: two prior boundary survivors changed to
`KILLED`, with no previous kill regressed (290 killed, 21 survived, 63 no
coverage). The scoped date-time/codec report has the same 88 identities as
the whole-package baseline: nine prior survivors changed to `KILLED`, with
no previous kill regressed (82 killed, six survived). The JDK 17 focused
regressions pass 25/25 before the final length additions and 9/9 afterward;
the added structure positions pass in the 25-case run. These scoped reports
do not replace the earlier full-package totals, so no combined full-package
mutation score is claimed.

The six remaining date-time/codec survivors have exact source dispositions:

| Class/method and PIT location | Disposition |
| --- | --- |
| `SamlDateTime.parse` line 55, `ConditionalsBoundary`, index 109/block 28 | Equivalent: for a nine-digit fraction, choosing the full string or `substring(0, 9)` yields the same nine digits. |
| `PendingSamlAuthenticationCodec.fromPart` line 99, `Math` division-to-multiplication, index 13/block 3 | Equivalent acceptance: this only enlarges the preliminary Base64 text bound; the 8,192-character whole-frame bound, strict Base64 decoder and subsequent decoded-byte limit remain in force. |
| `PendingSamlAuthenticationCodec.fromPart` lines 99/102/103/107, `EmptyObjectReturnVals`, indexes 19/34/43/71 | Each substitutes `""` for `null` on an already invalid field. Required fields reject both null and empty. Timestamp parsing rejects empty. An optional context becomes an empty class URI rejected by its builder; an optional application-data field lacks the required `x` marker and is rejected before construction. No invalid sealed payload becomes a pending authentication. |

The source review above is limited to these six identities; the other SAML
and XML survivors/uncovered branches still need their own dispositions.

A separate JDK 21 verifier rerun uses the original full test selection and
matches all 219 `EnvelopedSignatureVerifier` mutation identities. A test-only
16,384-bit RSA public key is compatible with the configured key policy, but
cannot verify a fixture signed by another key; the `keyMatches` line-294
boundary mutant at index 36/block 8 changed from `SURVIVED` to `KILLED`.
The scoped result is 194 killed, nine survived and 16 uncovered, with no prior
kill regressed. The JDK 17 verifier tests pass 21/21. The JDK rejects a
16,385-bit constructed RSA key, so this regression tests the exact admitted
endpoint without claiming an oversized-key oracle. The remaining verifier
mutants retain their earlier open status.

The test-only differential expansion applies the 19-name signed-envelope
matrix to all 30 Revetsec-accepted controls in the five signed semantic and
structure corpora. It finds 568 effective changed documents (two inert
substitutions are excluded). Revetsec rejects all 568. OpenSAML accepts 48
and Spring accepts 78, with the accepted mutation names and counts pinned in
the comparator; every acceptance retains the original signed identity.
The complete JDK 17 differential module then passed 38/38 tests with zero
skips, including the Docker-backed libxmlsec oracle. The embedded CI guard
requires all 38 method names and passed against those local Surefire reports;
both edited workflow files parsed as YAML. This supersedes the earlier
37-case differential result for the expanded test source only. The plan's
all-fixture applicability review remains open.

The remaining 65 rejected originals in those same five signed
semantic/structure families now receive the same 19-name envelope matrix.
The 1,232 effective changed documents all remain rejected by Revetsec.
OpenSAML accepts 60 and Spring accepts 96 changed documents; every acceptance
keeps the identity selected from the original fixture. The six rejected
encrypted baselines (four negative algorithms or ciphertexts, assertion-only
CBC, and unsigned encryption) received all 19 wrapper attacks: 114 effective
changed documents. Revetsec rejects all 114; direct OpenSAML accepts three
with the original signed identity, and Spring accepts none. The complete
JDK 17 differential module passed 42/42 with zero skips, including the live
Docker-backed libxmlsec oracle. The edited CI guard requires all 42 method
names and passed against the local Surefire reports. The broader fixture
applicability review remains open; this is not a claim that every SAML fixture
family has been crossed.

The signed XSW/Fragile Lock matrix now also includes four standalone
algorithm fixtures: EC-P521 Assertion, RSA-384 both placements, RSA-256
Response, and RSA-256 with SHA-1 digest. Its 61 signed fixtures produce
1,159 effective changed documents. The direct OpenSAML/Spring whole-SP
method and the Docker-backed libxmlsec exact-target method each pass over
that expanded inventory. The complete module rerun also passes 42/42 with
zero skips after this inventory change.

Five additional signed sibling wrapped-key fixtures receive 95 effective
encrypted-wrapper mutations. Revetsec accepts only two missing-Destination
edits on assertion-signed EncryptedID controls; the full checked
authentication matches each original. OpenSAML rejects every changed
envelope. Spring accepts twelve named unsigned-envelope edits and keeps the
original signed identity. The full module and 41-name CI guard pass after
this addition.

The nine separately minted libxmlsec/signxml fixtures add 171 effective
signed or encrypted wrapper mutations with fixture-specific public signing
certificates and SP decryption key supplied to the whole-SP comparators.
Revetsec accepts two missing-Destination edits with unchanged full checked
authentication. OpenSAML accepts 19 and Spring 21, all retaining the original
comparator-selected identity. Exact mutation-family counts are pinned in the
test. The Docker-backed libxmlsec oracle now checks each original signed
target and all 171 changes with the fixture's allowlisted test certificate
and, for EncryptedAssertion, its separate test-only decryption key. Exact
per-mutation verdicts are pinned: 99 retain the original signature, 51 break
it, and 21 are rejected as ambiguous oracle input. The complete module and
43-name CI guard pass with zero skips after this oracle addition.

The eight surviving `SamlPostBindingDecoder` actions from the final-source
full-package report are source-equivalent at the public result boundary:

| Exact PIT identity (line, index/block) | Reason the accepted message cannot change |
| --- | --- |
| `decode` 58, 84/19, boundary | `start == body.length` is possible only after a terminal `&`; the explicit terminal-ampersand check rejects that body either way. |
| `decode` 61, 109/25, increment | Decrementing the two-field counter cannot admit a third distinct allowed name: only `SAMLResponse` and `RelayState` are permitted, and a separate check rejects duplicates. |
| `decodeComponent` 138, 5/0, subtraction-to-addition | The mutation allocates a larger temporary byte array; exactly `used` bytes are written and decoded, with the raw body already bounded. |
| `validContentType` 99, 35/10, boundary | The changed printable-ASCII endpoint is `~`. No recognized media type or `charset=utf-8` parameter can contain that character; spaces at the other endpoint are covered by the exact 256-character MIME control. |
| `validContentType` 106, 108/26, boundary | A one-character parameter name cannot equal `charset`, so it is rejected by the next comparison either way. |
| `validContentType` 108, 136/35, boundary | A two-character quoted charset is `""`; stripping its quotes or leaving them both fails `utf-8`. |
| `validQuery` 122, 67/13, boundary | An extra loop visit can only inspect an empty terminal segment; it has no parameter name or value to promote. |
| `validQuery` 125, 91/18, boundary | Treating an empty segment as present decodes an empty name, which is not a forbidden SAML binding name and leaves the parsed query outcome unchanged. |

This disposition is for the eight exact decoder survivors. It does not
dispose of the timed-out `validQuery` arithmetic mutation, whose nontermination
is recorded separately, or of other SAML validators.

The final-source `SamlResponseStructure` report's six unresolved validator
identities also have exact reachability dispositions:

| Exact PIT identity (line, index/block) | Reachable-tree argument |
| --- | --- |
| `allDescendantsHaveSafeShape` 114, 65/14, assertion increment | A second Assertion differs from the unique direct one selected by `inspect` and fails node identity; there is no reachable second count. |
| `allDescendantsHaveSafeShape` 118, 89/20, encrypted increment | `inspect` rejects a second direct carrier and the walk rejects a nested encrypted carrier's parent. |
| `allDescendantsHaveSafeShape` 124, 141/37, uncovered true return | A different root Signature would have been rejected as a second direct Signature in `inspect` before this walk. |
| `allDescendantsHaveSafeShape` 142, 270/73, addition-to-subtraction | On a tree surviving `inspect`, assertion and encrypted-assertion counts cannot both be positive; the final `<= 1` result is identical. |
| `allDescendantsHaveSafeShape` 142, 280/76, true return | The final count condition is already true on every tree reaching it after the single-carrier and parent checks. |
| `inspect` 91, 251/53, boundary | Changing the second order check's `<` to `<=` only rejects repeated positions. Earlier duplicate-Issuer, Signature, Status and carrier checks, or the first order check for Extensions, already reject them. |

The separate `Shape.toString` no-coverage mutation is presentation only and
cannot alter `inspect`, signature verification, or identity release. These
arguments preserve the guard against relative namespace declarations; the
calibrated review and new root/Extensions/Assertion tests exercise that guard.

The JDK 21 `XmlEncryptionDecryptor` scoped rerun matched all 139 earlier
mutation identities using the original full test selection: 129 `KILLED`,
nine `SURVIVED`, one `NO_COVERAGE`. Two previous survivors changed to
`KILLED`, and no kill regressed. An exact eight-unreferenced-key acceptance
test kills `decrypt` line 86, boundary index 261/block 73. A test-only
`SecureRandom` retains the substitute CEK array across a failed unwrap and
checks it is zeroed after decryption; this kills the compiled `Arrays.fill`
removal at line 132 (indexes 384/562/467/580/520/572). JDK 17 focused tests
pass 1/1 for each addition. Report:
`/private/tmp/revetsec-rc2-xml-decryptor-wipe-mutations.xml`.

The ten residual decryptor actions have these source dispositions:

| Exact method/line and PIT action | Disposition |
| --- | --- |
| `decrypt` 113, subtraction to addition | Equivalent: this is the CBC alignment check `(encrypted.length - 16) % 16`; adding 16 instead changes the dividend by 32 and cannot change divisibility by 16. GCM bypasses this check. |
| `decrypt` 121/125/129/134/136, remove `Arrays.fill` | These five calls wipe otherwise inaccessible temporary plaintext, wrapped-key ciphertext or encrypted content. A caller can observe neither the local arrays nor their eventual garbage collection. They remain security cleanup requirements verified by source review, not functional-equivalence claims about memory hygiene. The CEK cleanup at line 132 has an observable test and is killed above. |
| `keyCandidates` 179/182/191/194, replace `null` with empty list | Equivalent at the sole caller: `decrypt` line 86 rejects both `null` and empty before trying a private key. The line-191 duplicate-reference branch is `NO_COVERAGE` after the upstream XML parser rejects duplicate `Id` values, but even direct DOM entry still rejects either substituted return. |

This disposes of the exact residual decryptor actions without treating a PIT
survivor for a wipe as evidence that the wipe is unnecessary. Other XML and
SAML classes still have open mutations.

A JDK 21 `SamlResponseSemantics` scoped rerun matched all 476 prior mutation
identities with the original full test selection: 451 `KILLED`, eleven
`SURVIVED`, fourteen `NO_COVERAGE`. A signed Assertion containing whitespace
direct text still authenticates. That regression kills two earlier
`hasNonWhitespaceDirectText` survivors: line 750 negated condition index
32/block 9 and line 751 boundary index 45/block 13. No earlier kill
regressed. Report: `/private/tmp/revetsec-rc2-saml-semantics-mutations.xml`.
The remaining 25 semantic actions still need exact dispositions; this scoped
result does not close the SAML PIT gate.

An `ECPublicKey` test fixture with a valid point/encoding but altered curve
cofactor confirms that the signature verifier rejects incompatible pinned
keys before validation. A JDK 21 full-test-selection verifier rerun matches
all 219 prior identities: 196 `KILLED`, seven `SURVIVED`, sixteen
`NO_COVERAGE`. The `keyMatches` line-300 true-return index 107/block 32 and
`namedCurve` line-311 true-return index 60/block 21 both changed from
`SURVIVED` to `KILLED`, with no previous kill regressed. The JDK 17 focused
test passes 1/1. Report: `/private/tmp/revetsec-rc2-verifier-ec-mutations.xml`.
The 23 remaining verifier actions retain their open status pending source
disposition or further tests.

The valid signed `AuthnStatement` control now asserts that the exact
`SessionNotOnOrAfter` reaches both `SamlAuthentication` and its
`SamlSessionReference`. A scoped JDK 21 PIT run of
`SamlResponseSemantics*` with the service-provider and semantics tests kills
the formerly surviving `Accepted.sessionNotOnOrAfter` null-return action at
line 128. That selection examined 510 mutations; its 480 killed, 13 survived
and 17 uncovered totals do not replace the full-package PIT result because
other SAML tests were omitted. Report:
`/private/tmp/revetsec-rc2-session-expiry-mutations.xml`.

An exact source audit of the remaining `internal.xml` PIT survivors finds these
accepted-input equivalences. The controls stay in production as layered
defenses; this disposition concerns one-at-a-time PIT removals only.

| Class and exact survivor location | Disposition |
| --- | --- |
| `EnvelopedSignatureVerifier.digestInputStartsWith` 343/344 false-return and 345 true-return | The first two branches already return `false`; the final branch already returns `true`. The four-way short/mismatched/exact-prefix test runs, and these three replacements are bytecode-equivalent at their return sites. |
| `EnvelopedSignatureVerifier.verifyMetadata` 128 increment-to-decrement | The only use of `index` is the `index != 0` check at line 125. The first element leaves zero before the check; every later element has a nonzero index in either direction. The bounded parser prevents integer wraparound. |
| `EnvelopedSignatureVerifier.postcheck` 330 negated loop condition | `inspectSignature` already checked the single Reference and its one or two ordered transforms at lines 238–245, and `postcheck` checks their count at line 329. Skipping this second algorithm loop cannot admit a transform rejected by the precheck. |
| `EnvelopedSignatureVerifier.verifySignedElement` 164 removed URI dereferencer | The precheck requires exactly `#` plus the signed element's NCName ID; the parser rejects duplicate ID-like values, the DOM ID table is checked against that same node before and after validation, and the digest input must begin with that node's QName. The JDK default same-document dereference cannot select an alternate accepted target under these checks. |
| `SecureXmlParser` 91–96, 99–100, 111–113 | Removing one parser-hardening call leaves the independent DOCTYPE prohibition, no-external-entity settings, resolver, lexical DTD rejection, no schema/stylesheet request, and input/tree limits. The default namespace-aware SAX factory has XInclude off. The test suite rejects DTDs, entities, processing instructions and malformed XML and checks preserved namespace declarations. The error-handler removal does not turn a fatal parse error into an accepted document. |
| `SamlXmlWriter` 36–38, 40 | The input is a library-built DOM sent through an identity transformer; it contains no stylesheet or external source to load. Removing one factory hardening call has no accepted-output effect with the other guards. Without the explicit encoding setter, Corretto 17 and 21 default transformers still emitted UTF-8 for a non-ASCII DOM in a local check. |

The verifier's `SECURE_VALIDATION` conditional mutation at line 161 is now
killed by a valid RSA-SHA1 signature over a SHA-256-digested Response. The
control rejects without compatibility and verifies with it, distinguishing
the signature-algorithm branch from the digest-algorithm branch. Focused JDK 17
and 21 tests pass 23/23; scoped JDK 21 PIT marks line 161 `KILLED` in
`/private/tmp/revetsec-rc2-sha1-mixed-mutations.xml`. Its single-class test
selection leaves some other actions uncovered, so it does not replace the
whole-package counts. The other `NO_COVERAGE` actions and SAML package
survivors remain open. This table does not close the PIT gate.

The Redirect binding's DER canonicalizer is now package-accessible solely for
same-package tests; the public SAML API is unchanged. Direct tests cover the
smallest positive `(r,s)` DER pair, a P-256 full-width integer requiring one
sign-padding byte, and a P-521 sequence with exactly 128 content bytes in
long-form length encoding. Focused JDK 21 PIT matched all 184 earlier
`SamlRedirectBindingMessage` identities and killed three previously surviving
boundaries: line 180's minimum DER length, line 183's 128-byte long-form
threshold, and line 190's one-byte integer minimum. Its selected test class
produced 173 killed, ten survived and one uncovered; the narrower test
selection does not replace full-package PIT. Report:
`/private/tmp/revetsec-rc2-der-boundary-mutations.xml`.

One further direct DER case supplies a second INTEGER length byte with no
corresponding value byte. The production parser returns `null` before any
array access. The arithmetic mutation at line 190 instead skips that bound
and throws, so the same-package test kills it; the JDK 17 and 21 focused
tests pass 34/34 across the verifier and Redirect test classes. The scoped
407-mutant rerun records the exact action as `KILLED` in
`/private/tmp/revetsec-rc2-typed-der-mutations.xml`. That run also kills three
previously uncovered verifier return substitutions: absent Assertion at line
97, wrong-document metadata at line 119, and unsigned metadata at line 130.
It does not replace a full-package rerun.

The remaining Redirect parser survivors from the prior full-package report
have these accepted-input or cleanup dispositions, pending the current full
rerun:

| Exact location | Disposition |
| --- | --- |
| `fromRawQueryResult` 78 | The boundary changes treatment of a one-character field name. Every permitted name has at least six characters; unknown names fail the immediately following allowlist. |
| `canonicalEcdsaSignature` 183, 184, 188 and 194 | The minimum eight-byte sequence makes the 183 position-equals-length case unreachable. A short-form 128-byte sequence at 184, an INTEGER header with no bytes at 188, or an unnecessary sign pad admitted at 194 all fail the final DER re-encoding equality or the subsequent length/shape check. |
| `inflate` 217 and 218 | The 131,072-byte cap is a multiple of the 4,096-byte output buffer. With the entire compressed input supplied up front, the inflater fills each buffer until it finishes or cannot continue. At exactly the cap, the 217 boundary variant asks for zero bytes and is rejected; the 218 arithmetic variant reaches the outer cap guard before a further full buffer. Exact-cap acceptance and cap-plus-one rejection have direct tests. |
| `inflate` 224 | Removing `Inflater.end()` does not change a parsed result but leaks native inflater state until reclamation. The cleanup call remains required and is source-reviewed as resource hygiene. |
| `percent` 236 | The surviving boundary treats a zero high hex nibble as invalid. Such a decoded octet is below 16 and fails the later printable-ASCII check for every field, so no accepted query changes. |

The arithmetic DER action at line 190 is excluded from this disposition
because the new test kills it. No claim is made that these source arguments
replace a full SAML-package mutation inventory.

## Current complete XML rerun

On the current test source, the complete JDK 21 `internal.xml.*` run passes
17,692 core tests (one expected locale skip) and examines all 667 XML
mutations: 610 `KILLED`, 35 `SURVIVED`, and 22 `NO_COVERAGE`. All 667 exact
class/method/descriptor/line/mutator/index/block identities match the preceding
complete run. Five formerly uncovered verifier result branches changed to
`KILLED`: absent Assertion (97), wrong-document metadata (119), unsigned
metadata (130), signed element without an ID (138), and malformed XML
`SignatureValue` (184). No prior kill regressed. Raw report:
`/private/tmp/revetsec-rc2-final-xml-mutations.xml`.

The residual raw XML results are not 57 demonstrated vulnerabilities. The
six verifier survivors, five Response-structure survivors, eleven parser
configuration survivors and four writer survivors have the source arguments
above. The decryptor's nine survivors consist of the modulo-16 equivalent
at line 113 (`encrypted.length - 16` and `encrypted.length + 16` have the same
remainder), five plaintext/CEK/ciphertext buffer-wipe removals at lines
121/125/129/134/136, and three `null`-to-empty-list substitutions at
`keyCandidates` 179/182/194; both list outcomes are rejected by the caller.
The cleanup and hardening calls remain in production. The following table
accounts for all 22 uncovered XML actions without treating them as kills.

| Uncovered identity group | Source disposition and test limit |
| --- | --- |
| `EnvelopedSignatureVerifier.keyMatches` 303, `namedCurve` 316 | The fallback 303 applies to a signature algorithm/key-type mismatch; passing such a key to JDK XMLDSig cannot validate that signature, though a mutated branch could change the rejection reason. The 316 exception requires the pinned JDK EC provider to fail initialization of one of its three supported named curves. Neither is counted as an assertion kill. |
| `EnvelopedSignatureVerifier.postcheck` 325/329/332 | `inspectSignature` has already checked the sole Reference, algorithm and transform order on the same DOM used by Revetsec's synchronous SSO path; JDK unmarshalling of that node supplies the same properties. A contradictory post-unmarshal object is not constructible through the pinned provider. |
| `EnvelopedSignatureVerifier.verifySignedElement` 149/154/173/177/179/189 | These require, respectively, a null default JDK URI dereferencer; a document ID lookup contradicting the parser's unique-ID check immediately after `setIdAttributeNS`; unmarshalling that contradicts the prechecked signature; a validated signature whose cached digest input does not start with its exact signed QName; an ID-table change during one synchronous validation; or an outer JDK runtime fault. The pinned JDK/DOM path did not reach them. A return-null mutant in a reachable fault path would violate the sealed-result contract, so this is a provider/fault-model limit rather than a claim of universal equivalence. |
| `XmlEncryptionDecryptor.keyCandidates` 191 | This branch needs two sibling wrapped keys with the same referenced `Id`, which the parser's global ID-like-value uniqueness check rejects before decryption. `null` and empty candidates both fail the caller's admission check. |
| `SamlResponseStructure.allDescendantsHaveSafeShape` 124 | It requires a root Signature distinct from the one selected by the direct-child inspection. A second root Signature is rejected before the descendant walk. |
| `SecureXmlParser.parse` 104/115 and `DomBuilder.characters` 222/223 | The pinned JDK accepts the parser configuration; a malformed document with no root throws before the post-parse null check. SAX rejects non-whitespace outside the document element before delivering it to `characters`; whitespace there is permitted by either branch. These are provider and well-formedness reachability limits. |
| Three result/shape `toString` replacements | The covered protocol APIs never use diagnostic `toString` output to select identity, signature, replay, or authorization decisions. No security outcome is affected by those diagnostic-only substitutions. |

This table records why the uncovered branches did not fire on the pinned JDK
and which public-result fault behaviors remain untested. It does not convert
them into assertion kills or establish the same behavior on arbitrary XML
providers. The SAML-package rerun and manual gate are separate.

## Current complete SAML rerun

The combined checkout passed 17,698 core tests on Corretto 17 and 21 (one
expected locale skip on each). The complete JDK 21 `saml.*` PIT run examined
2,504 mutations: 2,235 `KILLED`, 97 `SURVIVED`, 170 `NO_COVERAGE`, and two
`TIMED_OUT`. PIT's aggregate display says 2,237 killed because it includes the
two timeouts; the XML statuses above distinguish them. Report:
`/private/tmp/revetsec-rc2-final-combined-saml-mutations.xml`.

Against the immediately preceding complete SAML report, 2,495 exact mutation
identities match and eight `SURVIVED` actions became `KILLED`, with no killed
identity regressing. Exact boundary tests account for two requested
AuthnContext limits, three IdP connection/scope limits, the pending browser
binding limit, the CSP nonce guard, and HTML form escaping. The internal
pending-budget seam replaced seven old bytecode identities with nine new ones;
all nine new actions were killed. The direct test covers the exact elapsed
deadline, one nanosecond before it, a backward clock, and interruption. These
are tests of implementation boundaries, not a change to the public SAML API.

The remaining 97 survivors and 170 uncovered actions still require exact
justification or stronger tests; the source/reachability arguments above cover
only the identities they name. They are not assertion kills. The two timeout
identities remain nonterminating mutants. This complete rerun does not by
itself close the RC-2 PIT assurance gate or the manual pentest.

The same combined source passed the configured Corretto 21 Error Prone,
NullAway, SpotBugs and FindSecBugs `verify` profile with 17,698 tests, zero
failures/errors, one expected skip, and no static findings. After a local
Corretto 17 core install, the complete `differential` module passed 43/43
tests across OpenSAML, Spring and the libxmlsec oracle, with no skips. These
are local checks; a hosted workflow on the final pushed revision is separate.

## Final observer and deadline continuation

The next complete Corretto 21 SAML run passed 17,701 core tests (one expected
locale skip) and examined 2,508 mutations: 2,271 `KILLED`, 81 `SURVIVED`,
154 `NO_COVERAGE`, and two `TIMED_OUT`. Of 2,492 exact identities shared with
the preceding complete report, fifteen survivors and fifteen uncovered actions
became kills; no prior kill regressed. The cache deadline seams replaced twelve
old identities with sixteen new ones. Report:
`/private/tmp/revetsec-rc2-final-cache-saml-mutations.xml`.

A subsequent focused full-test-selection run on the two in-memory stores and
SP metadata matched all 177 of their prior identities. It killed the two new
`expired` false-return wrappers and the newly reached SLO `Binding`
attribute omission, with no kill regression. The **composite** final-source
inventory is 2,274 `KILLED`, 78 `SURVIVED`, 154 `NO_COVERAGE`, and two
`TIMED_OUT` out of 2,508. This is a complete run plus a focused continuation,
not another complete-package PIT run. Focused report:
`/private/tmp/revetsec-rc2-final-three-mutations.xml`.

All 78 residual survivors have the following exact-location source
dispositions. These are not assertion kills; production guards and cleanup
calls remain in place.

| Class (count) | Source disposition |
| --- | --- |
| `SamlResponseSemantics` (11) | At 435, only zero versus nonzero audience-restriction count matters. At 426, an adjusted-time overflow can reject or fail closed, not release identity. At 741, null versus empty nested leaf is rejected by issuer, NameID and audience callers; AttributeValue calls `leaf` only without element children. The 571/576/582/598 order boundaries require an absent Subject or Issuer already rejected before release. At 772, `sameNode` receives only the parser/verifier's private proof over one DOM. At 664, an empty `xsi:type` prefix resolves to no required namespace. At 680, a trailing `@` cannot pass the nonempty configured scope allowlist. |
| `SamlServiceProvider` (6) | At 322, the two-minute age cap is identical at equality. At 820/822/823, non-element SLO node handling can change rejection or availability, while the signed Redirect query and checked element/session binding still prevent identity release. At 653/657, only the redacted observer elapsed time changes. |
| `SamlRedirectBindingMessage` (9), `SamlPostBindingDecoder` (8) | The exact DER, query, percent, inflate, MIME and field-shape arguments appear above. No changed accepted identity-bearing binding results. Removed `Inflater.end()` at Redirect 224 is retained resource cleanup. |
| `SamlRedirectAuthnRequest` (12) | `deflate` 273/274 changes outbound availability under a zero-output/provider or oversized-buffer state; 281 removes resource cleanup. At 287, only initial builder capacity changes. At 313, later empty/reserved-name checks remain. At 215, the JDK signer chooses a different XML prefix. Writer calls 251/253/255/256/257/259 are redundant for normal pinned-provider output, but retained for portability. None is inbound identity admission. |
| `SamlRedirectLogout` (11), `SamlServiceProviderMetadata` (5) | The surviving writer end/flush/close removals affect outbound output or lifecycle; positive SLO/metadata tests parse the output. The calls stay explicit. Redirect logout 139 removes only `Deflater.end()`. |
| `PendingSamlAuthenticationCodec` (5) | At 99, a relaxed early Base64 estimate is still bounded by the whole 8,192-character seal and decoded-byte check at 103. Empty-for-null substitutions at 99/102/103/107 fail required field, date, context or application-data validation afterward. |
| `SamlInboundResponse` (3) | At 142, a counter is consumed only as `clearIds != 0`. At 121/163, removed plaintext wipes cannot be observed through a public result; the wipes remain source-reviewed security hygiene, not equivalents. |
| `InMemoryPendingSamlAuthenticationStore` (2), `InMemorySamlReplayCache` (2) | Pending 144 and replay 88 select the same 30-second cap at equality. Pending 153 and replay 92 can attempt a zero-wait lock, but post-lock expiration prevents record release or mutation. Exact deadline and interruption are directly tested. |
| `SamlAuthenticationResult.Succeeded` and `.Rejected` (2), `SamlDateTime` (1), `SamlIdentityProviderMetadata` (1) | The result `toString` changes affect redacted diagnostics only. DateTime 55 selects the same nine digits at exactly nine fractional digits. Metadata `textOnly` 330 maps nested content to empty text, which certificate and Scope callers reject like null. |

These source arguments cover all 78 survivor identities in the composite
report. They do not turn the 154 uncovered actions or two timeouts into kills,
and are limited to the pinned JDK/provider and checked admission paths.
The manual pentest and hosted final-revision workflow remain separate RC-2
decisions.

The exact checkout after this continuation passed Corretto 17 `clean verify`
with 17,701 tests, zero failures/errors and the expected locale skip. It also
passed Corretto 21 `-Pstatic-analysis,spotbugs verify` with the same test count
and no SpotBugs/FindSecBugs findings. After a local Corretto 17 install of
that build, the `differential` module passed all 43 tests with zero skips.
The local logs are `/private/tmp/revetsec-rc2-final-source-jdk17.log`,
`/private/tmp/revetsec-rc2-final-source-static.log`, and
`/private/tmp/revetsec-rc2-final-source-differential.log`. These checks do not
replace the hosted workflow on the owner's final pushed revision.

## 2026-10-13 replay-lock continuation and current PIT disposition

The current core HEAD is `33bbac0`. Its 56 `saml` and `internal.xml` production
Java files have SHA-256 `b5fe1132abef182c677fbf57a256b23e7889629b0fe615264d58921eaeedb4a8`
when sorted paths and their bytes are joined with NUL separators. There is no
uncommitted production change in either package. The new test-only
`SamlReplayUnlockMutationTests` checks that a successful replay insertion on a
worker thread releases the cache lock so a different thread can insert a
distinct key. Its second call has a two-second budget; on the unmodified cache
the whole test completes in about 25–35 ms. Corretto 17 and 21 each pass 1/1
focused test.

An isolated Corretto 21 PIT run selected only this test and
`InMemorySamlReplayCache`. The exact line-114 `VoidMethodCallMutator` identity,
including all nine index/block positions, matches the preceding complete
`saml.*` report and changes from `TIMED_OUT` to `KILLED` by
`completedAdmissionReleasesLockForAnotherThread`. The isolated report examines
49 cache mutations: 23 killed, 12 survived and 14 uncovered. Its narrower test
selection changes other statuses, which **do not** supersede the complete
package and previous focused reports. Raw evidence:
`/private/tmp/revetsec-rc2-lock-isolated-mutations-2s.xml`, SHA-256
`58b5c5240b3b7f0096814a491d84e5298f11b7b14b612f25bcc4ea58f945cf9f`.

The other timeout is the `SamlPostBindingDecoder.validQuery` line-132,
index-144/block-32 mutation replacing `start = end + 1` with subtraction.
For a nonempty query, the mutated loop repeatedly visits the same final
segment or separator and does not terminate. PIT reports `TIMED_OUT`; it is a
detected availability defect in the mutant, not an assertion kill. The
production loop advances past the separator and is bounded by the 8,192-character
query cap. The two timeout identities therefore have separate, explicit
dispositions: one now has an assertion kill and one remains a detected
nonterminating mutant.

Combining the unchanged complete-package identities with the exact focused
continuations gives the following **composite**, not a new full-package run:

| Package | Total | Assertion kills | Survived with source disposition | No coverage | Timeout |
| --- | ---: | ---: | ---: | ---: | ---: |
| `internal.xml.*` | 667 | 610 | 35 | 22 | 0 |
| `saml.*` | 2,508 | 2,275 | 78 | 154 | 1 |
| **Total** | **3,175** | **2,885** | **113** | **176** | **1** |

The SAML assertion-kill score is 2,275/2,508 (90.71% of all generated
mutants); among covered mutants, 2,275/2,354 (96.64%). PIT's convention also
counts the one timeout as detected, giving 2,276/2,354 (96.69%). XML has
610/667 assertion kills (91.45% of all mutants) and 610/645 among covered
mutants (94.57%). The combined covered score by PIT's convention is
2,886/2,999 (96.23%). These scores use the explicit composite above, not the
isolated cache run's whole-class score.

The earlier exact-location tables give source dispositions for all 78 SAML
and 35 XML survivors. None is silently called an assertion kill. The 176
uncovered mutations remain coverage limits. In SAML, they comprise 101
null-return substitutions, 37 empty-object substitutions, seven true-return,
five negated-conditional and four false-return substitutions. Twenty-six of
the 37 empty-object actions are diagnostic `toString` methods; others include
accessors and branches in authentication, signature and logout result paths.
An unvisited null-return branch could violate a sealed-result contract under
its fault precondition, so this inventory does **not** assert that uncovered
branches are equivalent or universally safe. The XML uncovered groups and
their pinned-provider/fault-model limits are listed above. RC-2's stated PIT
criterion is no *unjustified survivor* and publication of the score; these
source dispositions are ready for maintainer review. This local result alone
does not close the other RC-2 gates or prove untested provider-failure paths.

## 2026-10-13 reachable security-branch continuation

The added `SamlSecurityBranchMutationTests` ran in an isolated `33bbac0`
snapshot containing only the two new SAML test files. It uses the same 56
production `saml`/`internal.xml` Java bytes fingerprinted above, without the
concurrent SCIM implementation. Corretto 17 and 21 each pass its five tests
with zero failures or skips. The semantics cases use locally signed responses;
the other cases exercise error-Response and sealed pending-state boundaries:

| Previously uncovered exact identity | Security assertion and scoped PIT result |
| --- | --- |
| `SamlResponseSemantics.validAttributeStatement` line 610, `BooleanTrueReturnValsMutator`, index 88/block 29 | A signed scoped subject attribute containing `<a:Other>` instead of `<a:AttributeValue>` is rejected as `ASSERTION_SHAPE`, with zero replay writes. Returning true at that guard would let the downstream attribute reader treat the wrong element's text as a value. `KILLED`. |
| `SamlResponseSemantics.validate` line 166, `NullReturnValsMutator`, index 30/block 6 | A failing application clock returns sealed `Unavailable`, with zero replay writes. `KILLED`. |
| `SamlResponseSemantics.validate` line 253, `NullReturnValsMutator`, index 691/block 205 | A replay-store exception returns sealed `Indeterminate`, never an identity. `KILLED`. |
| `SamlInboundResponse.verifySuccessSignatures` line 91, `NullReturnValsMutator`, index 17/block 5 | An assertion-free error Response yields `SignatureRejected(ASSERTION_NOT_AVAILABLE)` if this internal verifier is called. `KILLED`; the normal SP status-only path remains separately tested. |
| `SamlServiceProvider.completeAuthenticationInternal` line 246, `NullReturnValsMutator`, index 145/block 43 | A sealed pending request created for one SP entity is rejected as `PENDING` by another SP entity, before malformed response XML is parsed. This checks the boundary and the sealed result contract. `KILLED`. |

Scoped JDK 21 PIT selected `SamlSecurityBranchMutationTests` with each mutated
class separately. All 476 `SamlResponseSemantics`, 93 `SamlInboundResponse`,
and 404 `SamlServiceProvider` class/method/descriptor/line/mutator/index/block
identities match the preceding complete SAML report. Only the five exact
`NO_COVERAGE` → `KILLED` transitions above are carried into the composite;
statuses that regress under narrower test selection are ignored. The raw
scoped reports are `/private/tmp/revetsec-rc2-security-semantics-mutations.xml`
(SHA-256 `f2bb9db8be5243326706333a4adbaf09cfabd054bdef6a506a3a482ea285dfa8`)
and `/private/tmp/revetsec-rc2-security-inbound-mutations.xml` (SHA-256
`64c417a4af3914ccc919ff7f59c6d20bab32e079ff33bb49acf2d6d42e25f85d`).
The SP report is `/private/tmp/revetsec-rc2-security-sp-mutations.xml`
(SHA-256 `f0461143264232ba694d13279bf537d2c3cd044927a7b95e989a2d5c7086cd19`).

The updated exact-identity **composite** is 2,280 SAML assertion kills,
78 source-dispositioned survivors, 149 uncovered and one detected loop timeout
out of 2,508. XML remains 610 killed, 35 source-dispositioned survivors and
22 uncovered out of 667. Combined, that is **2,890 assertion kills, 113
source-dispositioned survivors, 171 uncovered and one timeout out of 3,175**.
SAML's covered score is 2,280/2,359 (96.65% assertion kills) or 2,281/2,359
(96.69%) under PIT's timeout-as-detected convention. The combined PIT covered
score is 2,891/3,004 (96.24%). The remaining SAML uncovered actions include
98 null-return, 37 empty-object, six true-return, five negated-conditional and
four false-return substitutions. They are reported as coverage limits, not
equivalents or kills. This is a bounded continuation targeting reachable
identity/result branches; it does not claim exhaustive coverage of provider
faults or every diagnostic accessor.

### Bounded audit of the 171 uncovered identities at this checkpoint

The 149 SAML identities fall into these disjoint, source-reviewed groups. This
classification describes where PIT did not enter an action; it does not imply
that an uncovered action is equivalent to production code.

| SAML group | Count | Examples and significance |
| --- | ---: | --- |
| Sealed-result and provider-fault branches | 86 | Includes signature/parse outcomes, pending auth and logout resolution, replay and expiry, and SP completion. Some are reachable using injected failing stores or clocks. A null-result substitution could break the sealed-result contract under its fault precondition. |
| Diagnostic and observer reporting | 28 | Twenty-six `toString` mutations plus two observer outcome mutations. These affect reporting, not the authentication decision. |
| Accessors and factories | 19 | Identity and pending-state getters, attribute metadata, `isTransient`, and default/construction helpers; these remain API or configuration test gaps. |
| Semantic and shape helpers | 16 | Assertion ordering, status flattening, structural whitespace, and related guards. These warrant security review even where another guard rejects the same malformed input. |

The 22 XML identities divide into 11 verifier actions (key-type mismatch,
post-unmarshal checks, and provider/dereferencer failures), two secure-parser
provider-fault returns, one duplicate-reference decryptor guard, one
already-rejected Response descendant shape, four SAX character callbacks
outside the pinned parser's accepted document path, and three diagnostic
`toString` actions. The verifier's RSA-signature/EC-only-key mismatch can
change the rejection reason in a mutant; it does not make that signature
valid. The other cited structural conditions are rejected earlier by the
normal parser or verifier, or require a provider fault. These are source-backed
reachability assessments, not assertion kills or claims of equivalence.

The highest-risk reachable actions selected during this bounded audit were
the five exact identities killed above: signed attribute shape, clock fault,
replay-store fault, error-Response verifier result, and sealed pending SP
boundary. Remaining pending-source fault-result paths are reachable with
pluggable stores, including auth `resolve` lines 93, 98, 100 and 101 and
logout `resolve` lines 90, 94, 96, 98 and 99. They remain explicit contract
test gaps at this audit stage, without an observed identity bypass; the
continuation below tests these exact branches. Review of the remaining
Assertion ordering guards found that a
second/out-of-order Issuer is already rejected by `unique`, and an
out-of-position Signature is rejected by signature position checks. The
uncovered SLO `ignorableStructuralNode` CDATA branch is normalized to text by
the pinned SAX builder; nonwhitespace text takes the already-covered reject
path. No concrete reachable authentication or signature bypass was identified
in the remaining 171 identities. That finding does not prove the untested
fault/result branches safe; it leaves them visible for later targeted testing.

## 2026-10-13 pending-source fault-contract continuation

The remaining store-fault cluster was exercised through the public
`completeAuthenticationResult` and `completeLogoutResult` APIs in the same
isolated `33bbac0` source snapshot. `SamlPendingSourceFaultMutationTests`
injects a store that throws, returns `null`, or reports `Missing`,
`Unavailable`, or `Indeterminate`; it also sends a message without RelayState.
The login message has deliberately invalid XML, while the logout message has
a valid IdP Redirect signature. Each case asserts the expected sealed public
result, the number of store consumes, and zero replay writes. No case returns
an identity or successful logout. Corretto 17 and 21 each pass 2/2 focused
tests with no failures or skips.

| Store condition | Public login result | Public logout result | Newly killed exact `NullReturnValsMutator` identities |
| --- | --- | --- | --- |
| Missing RelayState; no consume | `Rejected(PENDING)` | `Rejected` | Auth `resolve` 93 index 26/block 4; logout `resolve` 90 index 26/block 4 |
| Consume throws | `Indeterminate` | `Indeterminate` | Logout `resolve` 94 index 52/block 9; auth throw branch was already covered |
| Consume returns `null` | `Indeterminate` | `Indeterminate` | Auth `resolve` 98 index 65/block 13; logout `resolve` 96 index 66/block 13 |
| Consume reports `Missing` | `Rejected(PENDING)` | `Rejected` | Both branches were already covered |
| Consume reports `Unavailable` | `Unavailable` | `Unavailable` | Auth `resolve` 100 index 81/block 17; logout `resolve` 98 index 82/block 17 |
| Consume reports `Indeterminate` | `Indeterminate` | `Indeterminate` | Auth `resolve` 101 index 89/block 19; logout `resolve` 99 index 90/block 19 |

Scoped JDK 21 PIT selected only that test class and the two pending-source
classes. All 42 class/method/descriptor/line/mutator/index/block identities
match the preceding complete SAML report. The nine identities in the table
changed from `NO_COVERAGE` to `KILLED`; other statuses from the narrower
selection are not carried forward. The raw report is
`/private/tmp/revetsec-rc2-pending-source-mutations.xml`, SHA-256
`7297a71b3756b3fb691c8770a2866722d29f28575b74365b5fc4192c0324caaa`.

The resulting exact-identity **composite**, not a new full-package run, is
2,289 SAML assertion kills, 78 source-dispositioned survivors, 140 uncovered,
and one detected loop timeout out of 2,508. XML remains 610 killed, 35
source-dispositioned survivors, and 22 uncovered out of 667. Combined, that
is **2,899 assertion kills, 113 source-dispositioned survivors, 162 uncovered,
and one timeout out of 3,175**. SAML's covered score is 2,289/2,368 (96.66%
assertion kills), or 2,290/2,368 (96.71%) counting the detected timeout. The
combined PIT covered score is 2,900/3,013 (96.25%). The residual SAML
classification is now 77 sealed-result/provider-fault, 28
diagnostic/observer, 19 accessor/factory, and 16 semantic/shape identities.
These 140 SAML and 22 XML actions remain declared coverage limits, not
assertion kills or proven equivalents.

## 2026-10-13 post-hosted bearer replay finding and repair

The exact old-source `SamlResponseSemantics.validBearerEnd` mutation at line
378 (`NegateConditionalsMutator`, index 202/block 63) was previously
`NO_COVERAGE`. The new
`SamlResponseSemanticsTests.laterBearerConfirmationKeepsReplayMarkedAfterEarlierConfirmationExpires`
assertion killed it in an isolated Corretto 21 PIT run. Investigation of that
boundary then found a separate real defect through the public
`SamlServiceProvider.completeUnsolicitedAuthenticationResult` API on pushed
source `eccaa18743bc2efc0287c171a7e027139e0e9eef`.

A single signed Response without `InResponseTo` or RelayState carried two
bound bearer confirmations with zero clock skew: A ended at 00:01:10; B had
`NotBefore` 00:01:20 and ended at 00:01:50. The first admission at 00:01:00
returned `Succeeded`. At 00:01:21, the **same signed Response** returned
`Succeeded` again instead of `Rejected(REPLAYED)`. The failing-before public
regression is retained at
`/private/tmp/revetsec-rc2-bearer-public-failing-before.log`. The old replay
mark expired at A's end because `validBearerEnd` considered only
confirmations valid at first admission; B became usable after the mark was
gone. This is a reproduced replay acceptance, not an inferred mutation risk.

The working-tree repair in `SamlResponseSemantics.validBearerEnd` still
requires at least one bound bearer confirmation to be valid **now**, but
retains the replay mark through the latest end of every structurally valid,
bound bearer window. The final cutoff remains the minimum of assertion-age
end, maximum bearer end and any Conditions end, plus permitted clock skew.
The public unsolicited-login regression and a semantics regression now pin
the disjoint-window case and reject a future-only confirmation at first
admission. Post-fix focused Corretto 17 and 21 runs passed 55 tests each;
broader Corretto 17 SAML/XML/threat-model tests passed 323, and policy and
nullability checks passed 11. A fixed-source targeted Corretto 21 PIT run
enumerated 337 `NegateConditionalsMutator` actions: 332 killed, four
uncovered, and one preexisting survivor. The moved maximum-end conditional
was killed. These are scoped local results, not a full-package PIT rerun.

The 3,175-action composite above remains a dated result on its stated earlier
production source. The old exact mutation's kill must not be added to those
counts as if it were a same-source continuation after this production change.
The hosted [differential CI run](https://github.com/revetsec/revetsec/actions/runs/38456477929)
and [Shibboleth capture run](https://github.com/revetsec/revetsec/actions/runs/38456503172)
passed on pushed SHA `eccaa18743bc2efc0287c171a7e027139e0e9eef`, before
this repair. RC-2 remains **OPEN**; after the owner pushes the repair, the
hosted checks must be rerun on that new revision. The full fixed-source PIT
receipt below completes the local survivor-disposition check; full CI and
same-revision hosted evidence remain open.

## 2026-10-13 full fixed-source SAML/XML PIT receipt

A complete Corretto 21 PIT run covered `saml.*` and `internal.xml.*` on the
working tree based on pushed commit
`eccaa18743bc2efc0287c171a7e027139e0e9eef`, with the bearer replay
production fix and its SAML test/documentation overlay. It generated **3,176**
mutations. These are fixed-source counts, not arithmetic updates to the
earlier 3,175-action composite:

| Package | Generated | `KILLED` | `SURVIVED` | `NO_COVERAGE` | `TIMED_OUT` |
| --- | ---: | ---: | ---: | ---: | ---: |
| `saml.*` | 2,509 | 2,294 | 78 | 136 | 1 |
| `internal.xml.*` | 667 | 610 | 35 | 22 | 0 |
| **Combined** | **3,176** | **2,904** | **113** | **158** | **1** |

All 113 survivors are exact identities with prior individual source
dispositions; no new survivor appeared. The one timeout is the same detected
`SamlPostBindingDecoder.validQuery` loop action, which PIT counts as detected
in its aggregate display (2,905 detected versus 2,904 assertion kills).
All 158 uncovered actions belong to the exact previously reviewed subset;
they remain declared coverage limits, not kills or proven equivalents. Their
disjoint breakdown is 74 SAML fault/result, 28 diagnostic/observer, 19
accessor/factory, 15 semantic/shape and 22 XML actions. The repaired source
therefore meets RC-2's local **no unjustified survivors** PIT criterion, with
those coverage limits visible.

The exact-source comparison found six new `validBearerEnd` conditionals
`KILLED` and three former SP `NO_COVERAGE` identities now `KILLED`. The
rewrite removed five old identities (four prior kills and one uncovered);
no old kill regressed. This is a new complete source-bound run, so the
old-source `validBearerEnd` mutation kill described above is not separately
added to it. The raw XML report has SHA-256
`627990e8ba6e9eadf76fc5b5b67faf70d0fab5965a52b9198d0792bb740551ac`;
the exact-identity comparison JSON has SHA-256
`8b72d299a687df034e87416f5151a78a089b3c6d0ba5534ad5ffb1663e024d7b`.

This is local evidence on unpushed production bytes. RC-2 remains **OPEN**
pending the owner push, a green full CI run, and differential and Shibboleth
hosted reruns on the same repaired revision. The earlier hosted PASS receipts
remain bound to `eccaa18743bc2efc0287c171a7e027139e0e9eef` and do not
qualify the changed bearer logic.

## 2026-10-13 hosted post-repair SAML receipts

The owner pushed the bearer replay repair in
`348da72b82f2709c21e744791e33e2297b5d4b34`. On that exact revision,
[CI run 38498924770](https://github.com/revetsec/revetsec/actions/runs/38498924770)
passed all 43 required SAML differential methods with zero skips or failures.
The overall run was **red only in the packaged-consumer JDK 17 and 27 jobs**:
their public API inventory omitted eight new SCIM PATCH types. This is not a
green full-CI receipt.

[Shibboleth capture run 38499662838](https://github.com/revetsec/revetsec/actions/runs/38499662838)
also succeeded on `348da72b82f2709c21e744791e33e2297b5d4b34`. All six
required hosted replay methods passed with zero skips, including the GCM and
signed-Response CBC captures. The downloaded
`shibboleth-capture-38499662838-1.zip` has SHA-256
`66465f0f60d9e1adc72e47a8638dc563e9d75593f188481abb7876a71b6821bf`;
all 11 capture-file hashes match its manifest. These same-revision hosted
receipts qualify the first bearer replay repair on that SHA for the
differential and Shibboleth RC-2 checks; they do not change the earlier local
PIT source and coverage limits above. At that checkpoint RC-2 remained open
pending green full CI and maintainer review of the post-round finding. The
earlier Burp and ZAP reports retain their recorded packaged-artifact scope.

## 2026-10-14 stricter bearer replay retention and owner review

Further adversarial review reproduced two more public-API replay acceptances
on the first repair: across two pending request bindings, and across
unsolicited and requested completion after the shorter unsolicited age bound.
The [round-1 review addendum](reviews/rc-2-round-1.md#post-hosted-replay-finding--2026-10-13)
records the stricter working-tree fix and its tests. The replay key now remains
marked until no supported completion context can accept the signed assertion;
the accepted authentication retains its own context-specific expiry. On
2026-10-14 the maintainer personally reviewed and confirmed this fix,
including its longer replay-cache retention tradeoff. The 255 SAML-named tests pass
on each of Corretto 17 and 21, and JDK 21 static analysis passes.

The 3,176-action full PIT receipt above belongs to the intermediate repair,
and the hosted CI and Shibboleth receipts belong to pushed
`348da72b82f2709c21e744791e33e2297b5d4b34`. Neither qualifies the
stricter source. The current-source local receipt follows; hosted checks still
require a pushed revision.

## 2026-10-14 full stricter-source SAML/XML PIT receipt

The Corretto 21 full-package PIT run used base commit
`348da72b82f2709c21e744791e33e2297b5d4b34` plus the six current SAML
source/test changes. All 56 targeted SAML/XML production files and both changed
test files matched the shared checkout byte for byte; the source-manifest
SHA-256 is `44ec657340d61b163ace477eea9161a1f2f2b8e789a63dd39ddc5748a6514ccd`.
The complete run generated **3,187** mutations:

| Package | Generated | `KILLED` | `SURVIVED` | `NO_COVERAGE` | `TIMED_OUT` |
| --- | ---: | ---: | ---: | ---: | ---: |
| `saml.*` | 2,520 | 2,304 | 77 | 138 | 1 |
| `internal.xml.*` | 667 | 610 | 35 | 22 | 0 |
| **Combined** | **3,187** | **2,914** | **112** | **160** | **1** |

All 112 survivors have exact identities and individual source dispositions in
the earlier full-run ledger; there are **no new survivors** and **no old
assertion-kill regressions**. Against the previous full run, 3,110 mutation
identities are shared, 77 are new and 66 were removed by the code rewrite.
The new identities comprise 73 kills and four uncovered actions. One earlier
`SamlResponseSemantics.inspectConditions` survivor is now killed by the new
bounded/unbounded Conditions regression. The sole timeout is the previously
identified `SamlPostBindingDecoder.validQuery` arithmetic mutation, counted
as detected by PIT but not as an assertion kill. PIT's aggregate display
therefore says 2,915 detected, while the XML records 2,914 kills.

The four new uncovered actions are null-return substitutions in
`SamlResponseSemantics.validate` at current lines 251, 255, 259 and 262 on
exceptional expiry/crypto-result branches. They remain explicit coverage
limits, as do the other 156 uncovered actions; none is represented as a kill
or equivalent. The raw XML report SHA-256 is
`496a3aae871e51e92824bbf49cdbd5673c12d6f455cec0813e5f3daa3cc36b5c`,
the run-log SHA-256 is
`c91016811743798790beb01eb5db7ef17fa60b22f2512a866284084ddc2aa107`,
and the exact-identity comparison JSON SHA-256 is
`a58c1d94e7ebd8a7eebb413a330f91a17adb2a6d373f8fe44e1ebf9a48e20265`.
This full current-source run meets RC-2's local **no unjustified survivors**
criterion with the 160 uncovered limits visible.

Other local checks on production-byte-identical snapshots passed: 18,110 core
tests on each of Corretto 17 and 21 (one expected locale skip each), JDK 21
static analysis and SpotBugs with zero findings, 43/43 required SAML
differential methods with 13/13 live libxmlsec oracle cases, 91/91 SAML seed
and layout replays plus nine provenance checks, and a one-minute live Jazzer
response-semantics target with 15,309 executions and no finding. The live-fuzz
log SHA-256 is
`0b812274f72feda4ccc9405e36f8a555a25d66c5dafd6d83cf305dc7641aa3e7`.
The full core and coverage snapshots preceded the final three test-only regressions;
the checkout's final 255 SAML-named tests passed on both JDKs. The coverage
profile completed its tests but missed two inherited branch floors: bundle
17,533/19,459 (90.10% versus 92%) and SAML 2,197/2,616 (83.98% versus
85%). This is a separate overall release-coverage gap, not a green coverage
claim. The earlier seven-target SAML fuzz campaign and manual Burp/ZAP passes
retain their documented earlier-source and packaged-artifact scope.

RC-2 remains **OPEN** pending the owner's push, green full CI, and differential
and Shibboleth hosted reruns on the same new revision. The prior hosted receipts
on `348da72b82f2709c21e744791e33e2297b5d4b34` do not qualify this
stricter replay logic.
