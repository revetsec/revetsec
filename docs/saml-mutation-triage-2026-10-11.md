# SAML mutation triage — 2026-10-11

This is local RC-2 evidence for the uncommitted checkout. PIT 1.30.0 ran on
JDK 21 with the SAML test families selected. The final full `internal.xml.*`
run examined 667 mutations: 596 assertion kills, 43 survivors, and 28 with no
coverage. Compared with the first whole-package run, exact tests killed two
attribute-name boundary mutants and reached the XMLDSig-provider-absence
return path. This is an inventory, not a closure: parser configuration and
other defense controls remain among the survivors.

The final full `saml.*` run examined 2,502 mutations: 2,166 assertion kills,
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

Additional focused evidence from the same checkout: three signed real-provider
encrypted responses (Shibboleth GCM and CBC, SimpleSAMLphp CBC) now pass an
isolated decryptor baseline and an 11-edit ciphertext/key/algorithm matrix.
The end-to-end matrix applies all 11 edits plus five envelope attacks to those
three captures and to SimpleSAMLphp's unsigned Response with an encrypted,
signed assertion: 64 rejection checks, with the three original signed captures
still accepted afterward. CBC ciphertext is malleable at the decryption layer;
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
