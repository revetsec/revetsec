# SAML mutation triage — 2026-10-11

This is local RC-2 evidence for the uncommitted checkout. PIT 1.30.0 ran on
JDK 21 with the SAML test families selected. The earlier full `internal.xml.*`
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
regression was added and fixed. The fixture replacement remains uncommitted.

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
