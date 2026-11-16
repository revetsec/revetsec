# Protocol differential tests

This is a test-only Maven project that compares Revetsec with separate implementations of the same
protocols and formats. It is never published. Every comparison library is a test dependency of
this project only, so none of them reaches Revetsec's published core POM or runtime classpath.

For SAML, it compares Revetsec's service provider (SP) with two other SP paths, Spring Security's
SAML SP and a direct OpenSAML harness, and uses libxmlsec1 inside the scripted identity provider
(IdP) container as a cryptographic oracle. For JOSE, JSON and SCIM filter syntax, it compares
Revetsec's results with established Java libraries.

Each comparator requires agreement, or an exact, pinned difference. A new unexplained difference
fails the test. These are implementation comparisons, not an independent audit, and agreement with
another library does not prove that either is correct.

## Lanes

| Lane | Compared with | Needs Docker | CI job |
|---|---|---|---|
| JOSE and JSON | Nimbus JOSE+JWT 10.10 (with Tink 1.24.0 as its Ed25519 implementation), jose4j 0.9.7, Jackson-core 2.22.4 | no | `rc1-differential`, JDK 17 and 21 |
| SAML | Spring Security 7.1.1's SAML SP, a direct OpenSAML 5.2.3 SP harness, and libxmlsec1 in the scripted IdP container | yes | `differential`, JDK 17 |
| SCIM filter syntax | Ping Identity UnboundID SCIM SDK 6.1.0 | no | `differential`, JDK 17 |

| Class | Lane | What it compares |
|---|---|---|
| `JoseComparatorTests` | JOSE | Tokens from JCA, Nimbus and jose4j for every accepted asymmetric algorithm, and their signed identity, policy and serialization mutations, through Revetsec, Nimbus and jose4j. |
| `JsonComparatorTests` | JSON | Typed trees from Revetsec and Jackson for the vendored JSONTestSuite inputs and their framing probes, duplicate names, large numbers, Unicode and malformed number grammar. |
| `SpringSamlComparatorTests` | SAML | Revetsec and Spring Security's whole SP: signed placements and tampering, legacy SHA-1, encrypted assertions, CBC, encrypted negatives and wrapper mutations. |
| `OpenSamlSpComparatorTests` | SAML | Revetsec and the direct OpenSAML SP harness: signed placements, forged `KeyInfo`, legacy SHA-1, the full signed-envelope matrix, the signed parser-policy corpora, encrypted assertions and EncryptedID, encrypted negatives and the encrypted wrapper matrices. |
| `CapturedProviderSpComparatorTests` | SAML | Real Shibboleth and SimpleSAMLphp captures, untouched and with envelope attacks, through Revetsec, OpenSAML and Spring Security. |
| `OpenSamlLogoutComparatorTests` | SAML | Signed Redirect logout messages through OpenSAML's HTTP-Redirect decoder and simple-signature handler, alongside Revetsec. |
| `LibxmlsecOracleComparatorTests` | SAML | Cryptographic signature and decryption verdicts from libxmlsec1 for the same fixtures and mutations. This is the class that needs Docker. |
| `ScimFilterComparatorTests` | SCIM | Filter grammar and typed AST from Revetsec and the SCIM SDK. |

`SignedSamlMutationMatrix` holds the 19 named signed-envelope mutations that the core SP
regression corpus also uses, and `ForgedKeyInfoCorpus` builds the forged-`KeyInfo` documents.

## Running

Run from the repository root with JDK 17. The first command installs the current checkout's core
JAR into the local Maven cache; it does not publish it.

All comparators (needs Docker for the libxmlsec1 oracle):

```sh
mvn -B -ntp -DskipTests -Dmaven.javadoc.skip=true install
docker build --pull=false -t revetsec-scripted-idp:local interop/scripted-idp
mvn -B -ntp -f differential/pom.xml verify
```

The oracle test never pulls an image; it starts `revetsec-scripted-idp:local`, or the image named
by `-Dscripted-idp.image=<name>`.

JOSE and JSON only, without Docker, through the `rc1` profile. CI runs this on JDK 17 and 21, and
`verify_rc1_reports.py` then requires the complete executed-case set with zero failures, errors or
skips:

```sh
mvn -B -ntp -DskipTests -Dmaven.javadoc.skip=true install
mvn -B -ntp -f differential/pom.xml -Prc1 clean verify
python3 differential/verify_rc1_reports.py
```

SCIM filter syntax only, without Docker:

```sh
mvn -B -ntp -DskipTests -Dmaven.javadoc.skip=true install
mvn -B -ntp -f differential/pom.xml -Dtest=ScimFilterComparatorTests test
```

CI's `differential` job also checks the Surefire reports: every required SAML comparator method
must have run, `ScimFilterComparatorTests` must have run exactly 306 cases, and nothing may be
skipped or fail.

## SAML

The SAML comparators read checked-in fixtures signed by the scripted IdP's pinned test key. They
use a replay-only clock skew based on the fixture date, so their results cover signed identity and
XML structure, **not** expiration policy. The direct OpenSAML harness uses OpenSAML parsing,
signature profile and cryptographic validation, decryption, and native assertion validation, then
checks the fixture's Response binding and subject identity. It uses a fixed fixture clock for its
own expiry checks, while the OpenSAML assertion validator receives the replay-only skew.

The oracle container receives test-only keys and a pinned local TLS trust store. Its verdicts are
cryptographic; Revetsec's SP result supplies the identity and protocol-policy verdict. A libxmlsec1
verdict never substitutes for a whole-SP policy check.

### libxmlsec1 oracle

`LibxmlsecOracleComparatorTests` verifies the signed Response/Assertion matrix, rejects modified
signed identities, decrypts all 47 positive GCM/CBC fixtures, confirms that decryptable CBC without
a signed Response is rejected, and confirms that a valid Assertion signature inside an ambiguous
unsigned wrapper cannot release the added identity.

For every modern signed fixture, four additional structural mutations are checked against
libxmlsec1: an attacker Assertion sibling, an attacker Extensions Assertion, a changed destination,
and a duplicate Status. The original Assertion signature remains valid when the Response was
unsigned; the signed Response variants lose their outer signature. Revetsec rejects all 224
mutated envelopes.

The oracle also checks the 1,159 documents of the signed-envelope matrix (below) against the
original signed target. Ten mutation types leave an assertion-only signature cryptographically
valid while Revetsec rejects the changed envelope; no changed Response-signed target remains
valid. Duplicate IDs and a removed signed Assertion fail the oracle's input selection before
cryptographic verification. These per-mutation verdicts are pinned in the tests.

### Real-provider captures

The libxmlsec1 oracle verifies the real Shibboleth 5.2.3 GCM and CBC Response signatures against
its captured public certificate, decrypts both assertions, and rejects tampering of each signed
Destination. Revetsec's offline SP tests separately check acceptance, CBC opt-in, correlation and
replay. The SimpleSAMLphp 2.5.0 CBC captures provide another producer: libxmlsec1 verifies its
signed Response, decrypts both CBC assertions, and verifies the signature inside the encrypted
assertion of the unsigned-Response variant. Revetsec's offline SP tests accept the first only with
CBC opt-in and reject the second even with that opt-in.

The two signed Shibboleth captures and the signed SimpleSAMLphp capture each also receive 19
envelope attacks: plaintext attacker siblings and Extensions, copied signatures, duplicate
carriers, issuer and Status changes, missing or changed Destination, unexpected request
correlation, qualified IDs and relative namespaces.

- libxmlsec1 parses all 57 changed documents and finds every outer Response signature invalid.
- The offline Revetsec SP tests reject the same 57 documents, then accept each untouched capture
  through the same pending authentication and replay state.
- Direct OpenSAML and Spring Security each accept all three original responses, select the same
  per-capture NameID, and reject all 19 changed envelopes for each response.

For the unsigned SimpleSAMLphp assertion-signed CBC capture, the comparators receive the 17
attacks that do not require copying a Response signature:

- Direct OpenSAML accepts the original plus two of the 17 changed unsigned envelopes: an
  Extensions child and an extra success StatusCode. Both still select the original signed
  identity.
- Spring Security rejects the original and all 17 changes under its configured policy.
- Revetsec rejects all 17 changes under CBC opt-in, because the inner signature does not authorize
  a changed unsigned envelope or unsigned CBC.
- libxmlsec1 rejects one duplicate-carrier case as ambiguous oracle input; 16 decrypt. Of those,
  15 retain the valid inner signature and one relative-namespace edit invalidates it.

The capture comparisons use the captured AuthnRequest ID and RelayState, trusted IdP certificate,
SP/IdP identities, ACS and captured time. The offline fixtures have no authenticated client IP,
so the comparators do not check `SubjectConfirmationData/@Address` or `SubjectLocality/@Address`;
the other listed bindings and signature checks stay active.

Six ciphertext probes flip one Base64 character in the wrapped key or encrypted data of each
signed capture. libxmlsec1 rejects both GCM decryptions and finds every changed outer Response
signature invalid. CBC decryption can either fail or produce altered plaintext; the signed
Response is the required integrity boundary. Revetsec's offline tests reject those probes and nine
further key, ciphertext and algorithm edits per capture.

This is envelope coverage for these real producers, not a cross-product across all real-provider
and scripted fixture families.

### Signed-envelope matrix

For the 56 modern-signature fixtures, all three SP paths accept the original identity and reject
signed NameID tampering. The signed-envelope matrix runs 19 named XSW, Fragile Lock and structure
mutations against those fixtures, the SHA-1 compatibility fixture and four additional standalone
signed algorithm fixtures: 1,159 changed documents.

- Revetsec rejects every one.
- Direct OpenSAML accepts only two unsigned Extensions changes for assertion-only signatures.
- Spring Security accepts those two and a duplicate Status.
- Every accepted result retains the original signed `minted-user` identity.

Spring Security accepts the legacy RSA-SHA1 fixture by default; Revetsec requires explicit
`SHA1_SIGNATURES` compatibility.

### Forged KeyInfo

The forged-`KeyInfo` corpus re-signs Response, Assertion, and both placements with a separate
test-only attacker key and an `attacker-user` NameID. It advertises either the attacker
certificate or the genuine IdP certificate in `KeyInfo`. OpenSAML, Spring Security and Revetsec
reject every forged document when configured with the genuine IdP key. The attacker-certificate
variants succeed under an explicitly configured attacker key, and all three SP paths also accept
the misleading-`KeyInfo` variants under that attacker key. libxmlsec1 verifies all eight signatures
with the attacker certificate and rejects all eight with the genuine certificate. This
distinguishes a valid hostile signature from an untrusted signer and checks that embedded
`KeyInfo` cannot become a trust anchor.

### Encrypted assertions

The encrypted comparison covers 47 positive fixtures: GCM/OAEP data and key transport
combinations, three signed CBC responses, an encrypted assertion with RSA-SHA512 signing, and an
EncryptedID. The libxmlsec1 oracle checks their plaintext. Revetsec and direct OpenSAML accept all
47 (Revetsec requires explicit CBC compatibility). Spring Security rejects 13 encrypted assertions
whose outer Response is unsigned, even though Revetsec verifies the signed assertion after
decryption. Spring Security accepts signed CBC responses by default.

Four encrypted negative fixtures:

- Revetsec rejects all four.
- libxmlsec1 can decrypt the RSA1_5 ciphertext.
- Spring Security accepts both RSA1_5 and a malformed MGF child under mgf1p; each acceptance
  returns the original signed identity.
- libxmlsec1 and Spring Security reject the nonempty OAEPparams and corrupted ciphertext cases.

Direct OpenSAML accepts RSA1_5, malformed MGF under mgf1p, and assertion-only CBC without an outer
signature, each with the original signed identity. It rejects unsigned encrypted responses,
nonempty OAEPparams and corrupted ciphertext. These are pinned policy and parser differences, not
claims that the engines enforce identical acceptance rules.

The encrypted wrapper matrix applies 19 structure mutations (attacker siblings and Extensions,
duplicate carriers, status and issuer changes, missing or changed Destination, unexpected request
correlation, copied signatures, qualified IDs and relative namespaces) to several fixture groups:

| Fixtures | Changed documents | Verdicts |
|---|---:|---|
| 47 positive encrypted fixtures | 893 | Revetsec rejects 879 and accepts 14 unsigned-Response cases with a missing Destination, with every identity-bearing field and signature flag matching the untouched fixture. Direct OpenSAML accepts 42 unsigned-envelope changes and Spring Security accepts six in the EncryptedID fixture; Spring Security still rejects the 13 assertion-only encrypted baselines. libxmlsec1 pins all 893: 627 changed signed Responses have invalid outer signatures, 236 unsigned-envelope edits retain a valid inner signature, 16 invalidate the inner signature, and 14 duplicate-carrier cases fail its input selection. |
| The four encrypted negatives, assertion-only CBC without an outer signature, and an unsigned encrypted Response | 114 | Revetsec rejects all 114. Direct OpenSAML accepts three changed envelopes, each with its original signed identity; Spring Security accepts none. No original rejection becomes an accepted identity. |
| Five signed fixtures that place wrapped keys beside EncryptedAssertion or alongside EncryptedID | 95 | Revetsec accepts only the two `missing-destination` edits to the assertion-signed EncryptedID controls, with every checked authentication field unchanged. Direct OpenSAML accepts none. Spring Security accepts twelve across six named unsigned-envelope edits on those same two controls. |
| Nine `saml-independent` fixtures, minted by separate libxmlsec and signxml producer paths | 171 | Revetsec accepts only two missing-Destination edits on assertion-signed controls, with the full checked authentication preserved. Direct OpenSAML accepts 19 and Spring Security accepts 21, each yielding the same identity as that comparator's original fixture. libxmlsec1 verifies every original signed target and pins 99 still-valid original signatures in edited envelopes, 51 broken signatures and 21 ambiguous input rejections. |

Every comparator acceptance in these matrices retains the original signed `minted-user` (or the
fixture's own) identity; none is a successful wrapping attack. The `saml-independent` captures use
their own signing certificates and SP decryption key, supplied to each whole-SP comparator; the
oracle's decryption key selector is allowlisted to that separate test-only key, and no fixture
certificate or embedded `KeyInfo` becomes a trust anchor.

### Signed parser-policy corpora

These corpora hold documents signed by the test IdP, so their differences are parser-policy
differences, not evidence of an unsigned forgery. Each comparator's exact verdicts and selected
identities are pinned.

- **Structure corpus.** An offline corpus signs the *mutated Response itself* with the test IdP key
  and verifies each signature with libxmlsec1 before writing the 15 fixtures: a clean control plus
  14 duplicate, nested, reordered, namespace, qualified-ID and misplaced-signature shapes.
  Revetsec accepts the clean control and rejects all 14 malformed responses. Direct OpenSAML
  accepts seven with the original identity; Spring Security accepts ten. For the
  duplicate-Assertion-before case, Spring Security selects `attacker-user`, which is inside the
  IdP-signed Response. This is a parser selection difference when a trusted IdP signs an ambiguous
  document; it does not show an unsigned adversary forging the IdP signature.
- **Assertion-signed corpus.** 23 malformed structures, five valid variants and a clean control.
  Revetsec accepts the six controls with the original NameID and rejects all 23 malformed
  assertions, including duplicate `AuthnContext` and `AuthnContextClassRef` descriptors,
  out-of-order signed Assertion children, nilled Assertion and attribute containers, and
  unsupported nested context elements. Valid attribute statements may appear before or after
  AuthnStatement. Direct OpenSAML and Spring Security both accept 16 malformed assertions while
  selecting the original NameID.
- **AttributeValue corpus.** 12 assertion-signed documents use a transient NameID, so an approved
  `subject-id` is the only stable key source. libxmlsec1 verifies every signature. Revetsec exposes
  seven signed leaf-text values as text, independent of unsigned type bindings, and keeps five
  nilled or mixed-element values opaque; those cannot become a scoped account key. Direct OpenSAML
  and Spring Security authenticate the original NameID in all 12 cases. This pins parser
  acceptance and NameID selection, not the other libraries' attribute-value interpretation.
- **Identity-shape corpus.** 20 documents with nilled or misdeclared NameID, Issuer, Audience and
  authentication-context scalars, an Assertion version mismatch, and reordered
  Subject/AuthnStatement children. Revetsec accepts seven controls and rejects all 13 malformed
  cases. Direct OpenSAML accepts ten, including seven malformed cases; Spring Security accepts
  twelve, including eight malformed cases. Both return the original signed NameID in every
  accepted case.
- **Bearer/Conditions corpus.** 19 signed bearer and Conditions shape fixtures. Revetsec accepts
  four controls and rejects 15 malformed signed variants. Direct OpenSAML accepts ten and Spring
  Security accepts twelve; all accepted cases still select the original signed `minted-user`. The
  comparators accept several nilled structures and a mismatched confirmation NameID that Revetsec
  rejects. Direct OpenSAML rejects the valid OneTimeUse/ProxyRestriction control under its
  configured assertion-validator policy; Revetsec treats it as a terminal SP login.

The five signed semantic and structure corpora contain 95 documents. Applying every effective
member of the 19-name signed-envelope matrix to them (inert replacements excluded) gives:

- for the 30 original controls Revetsec accepts, 568 changed documents. Revetsec rejects all 568.
  Direct OpenSAML accepts 48: `attacker-extension` and `copied-signature-extension` on 24
  assertion-signed controls each. Spring Security accepts 78: those two variants plus
  `duplicate-status` on 26 controls each. Every acceptance retains the original signed NameID;
  none selects an attacker identity;
- for the other 65 originals, the malformed-shape cases with their exact verdicts above, 1,232
  changed envelopes. Revetsec rejects all 1,232. Direct OpenSAML accepts 60 and Spring Security
  accepts 96, each selecting the same identity as its original fixture. No rejected fixture gains
  an accepted attacker identity under a comparator.

### Single logout

`OpenSamlLogoutComparatorTests` replays 14 fixed-key, Python-signed Redirect fixtures through
OpenSAML 5.2.3's HTTP-Redirect decoder, simple-signature security handler, and
LogoutRequest/LogoutResponse models, alongside Revetsec. Both accept the two valid messages and
reject six signed semantic mutations in each direction under the checked SP policy. An equivalent
percent encoding of RelayState breaks both binding signatures. The comparator's
application-level destination, issuer, timing, correlation and structure checks are explicit test
policy around OpenSAML; they are not claims that OpenSAML enforces all of those conditions
automatically. The fixtures come from `interop/scripted-idp/mint_slo_corpus.py` and use a
deterministic test-only SP pending ID and RelayState.

### Mutation applicability

The XSW, Fragile Lock and structure mutation cross-products apply only where a fixture family has
the protocol message and trusted-signature precondition that the mutations need:

| Fixture family | Applicable mutated documents | Boundary checked |
| --- | ---: | --- |
| 61 trusted signed SSO controls, including SHA-1 compatibility and standalone RSA/EC algorithms | 1,159 | All 19 signed-envelope edits through both whole-SP paths and libxmlsec1 on the original signed target. |
| Five signed semantic/structure corpora: 30 accepted and 65 already rejected originals | 568 + 1,232 effective edits | The 19-name matrix omits inert substitutions; all changed documents run through both whole-SP paths, with accepted identities compared to each original. |
| 47 positive encrypted controls and five additional signed sibling-key controls | 893 + 95 | All 19 encrypted-wrapper edits; libxmlsec1 checks the original signed target and the whole-SP paths check identity. |
| Six rejected encrypted originals | 114 | All 19 wrapper edits are checked for unexpected acceptance of an already rejected baseline. |
| Three signed real-product captures and one unsigned, assertion-signed CBC capture | 57 + 17 | All 19 signed-Response edits; the unsigned capture takes the 17 edits that do not require copying a Response signature. |
| Nine separately minted libxmlsec/signxml controls | 171 | All 19 applicable edits with each fixture's own allowlisted signing certificate and separate decryption key. |
| Eight forged-KeyInfo documents | Separate trust-anchor matrix | Each attacker signature validates under the attacker key and fails under the trusted IdP key. Adding XSW to an already untrusted signer does not create the trusted-signature precondition; this family is checked for signer confusion instead. |
| Redirect SLO request/response corpus | Separate 14-document binding matrix and 12 signed semantic edits | POST-binding XSW templates do not apply to raw signed Redirect query octets; the SLO matrix checks query tampering, signed XML semantics, correlation and replay. |

Metadata XML and unsigned parsing fixtures do not carry a trusted SSO identity signature for an XSW
comparison. Their structure, signature and parser boundaries are covered in the core metadata and
XML tests. The matrix has no fixture for a validly signed void-canonicalization variant. This table
records which mutation families apply; it does not claim that a cryptographic oracle enforces
Revetsec's application policy.

### Related core integration tests

The core build's Docker-backed integration tests (`ScriptedIdpSsoIT`, run with
`mvn -Pintegration verify` after building the scripted IdP image) check two more boundaries
against the same scripted IdP. Neither is a second SP implementation.

- libxmlsec1 runs three envelope probes for each of the 47 positive encrypted fixtures. Adding an
  attacker Assertion outside the encrypted carrier or changing the destination leaves the
  decrypted plaintext byte-for-byte identical, and the outer Response signature, when present,
  becomes invalid. Duplicating the carrier is rejected by the oracle's exact-one-EncryptedData
  boundary. Revetsec rejects all 141 mutated responses. The test selects the trusted Assertion ID
  from the original fixture before inserting an attacker Assertion, so verification cannot
  accidentally target the injection.
- Python cryptography signs live IdP-initiated LogoutRequests and SP-initiated LogoutResponses,
  including 12 altered XML messages whose Redirect signatures remain valid. Revetsec rejects the
  altered destination, issuer, timing, request correlation, duplicate child and malformed status
  cases before accepting the original messages. It also rejects raw-query changes, including a
  different percent encoding of the same RelayState value, and rejects replay of both original
  messages.

## SCIM filter syntax and typed AST

`ScimFilterComparatorTests` uses the [Ping Identity UnboundID SCIM SDK 6.1.0
release](https://github.com/pingidentity/scim2/releases/tag/scim2-6.1.0), published from tag
`scim2-6.1.0`, as a test-only grammar and AST comparator under its Apache-2.0 license.
[scim-oracle.json](scim-oracle.json) records the SDK and Jackson artifact digests and the official
release, artifact and advisory sources checked for them. It does not claim that unpublished issues
or issues in transitive dependencies are absent.

The test traverses both libraries' separately parsed typed trees. It compares operator kinds,
ordered operands, NOT grouping, the same-element valuePath boundary, schema/attribute/subattribute
components and decoded string/number/boolean/null literals. Only equivalent n-ary AND/OR
flattening, ASCII path case and exact numeric scale are normalized. It never uses Revetsec
rendering as the expected AST, and it never erases numeric precision loss. A control test plants
precedence, literal-type, literal-value and same-element defects and requires each to produce a
different projection.

The lane has 276 shared valid expressions, 26 shared malformed expressions and four focused
disposition and negative-control tests: 306 executions. Any unexplained acceptance, structure or
typed-value difference fails. This is syntax and AST evidence only; schema binding and policy,
filter evaluation, authorization, PATCH transformations and database behavior have separate tests.

Each observed difference is asserted as an exact row rather than accepted through a broad
exception or grammar allow-list:

| Case | Revetsec | SDK 6.1.0 | Disposition |
| --- | --- | --- | --- |
| Lone escaped high surrogate in a string | Rejects | Parses | Revetsec preserves its strict well-formed Unicode literal policy. |
| `name.givenName.other` | Rejects | Parses | Revetsec's approved attribute path has one optional subattribute; SDK Path supports deeper paths. |
| No whitespace between a string literal and `or` | Rejects | Parses | Keep the SCIM token-separator requirement. |
| Missing closing valuePath `]` | Rejects | Parses | Keep complete delimiter validation; SDK acceptance is an observed oracle limitation. |
| Absolute schema URI containing bracketed IPv6 | Parses | Rejects | Keep the approved absolute-URI schema grammar; SDK token scanning treats brackets differently. |
| Horizontal tabs around comparison tokens | Parses | Rejects | Distinct input whitespace profiles, recorded explicitly. |
| Seventeen nested grouping levels | Rejects under shared default limits | Parses | Revetsec applies configured transient nesting/work limits before recursion/allocation. |
| Array/object comparison literals | Fixed syntax rejection | `ClassCastException` | Non-scalar values remain invalid; the exact SDK faults are tested only for these two rows. Unexpected oracle faults fail. |
| `0.123456789012345678901234` | Exact decimal | Double-rounded decimal | SDK's default Jackson node loses precision. Preserve the mismatch explicitly; use exactly representable decimals in the common AST corpus. |
| `1e309` and `1e1000` | Exact bounded decimal | Infinite DoubleNode; decimal extraction throws `JsonNodeException` | Keep exact core values and record the SDK floating representation limit explicitly. |

## JOSE and JSON

The `rc1` profile runs only `JoseComparatorTests` and `JsonComparatorTests`; the default profile
runs them alongside the SAML and SCIM comparators. The pins are Nimbus JOSE+JWT 10.10, jose4j
0.9.7, Jackson-core 2.22.4 and Nimbus's optional Ed25519 implementation, Tink 1.24.0.

JOSE compares all eleven accepted asymmetric algorithm names through 32 token fixtures produced by
JCA, Nimbus and jose4j. Every fixture receives the full signed identity, policy and serialization
mutation matrix. The comparators use trusted fixed keys, fixed clocks, issuer and audience policy,
required expiration and zero skew. Success compares the original checked subject, issuer,
audiences and expiry; the three JWK thumbprints also agree. Nimbus/Tink supplies a separate
Ed25519 implementation; RSA and EC use each library's JCA integration. These libraries still share
parts of the JDK crypto stack, so this is implementation comparison rather than an independent
audit.

JSON compares typed trees without floating-point conversion. Every one of the 318 vendored
JSONTestSuite inputs has a pinned verdict row and receives three framing probes. Additional cases
cover escaped duplicate names, exact large integers and decimals, Unicode pairs and malformed
number grammar. Jackson duplicate detection is explicitly enabled; all input tokens must be
consumed.

[The difference ledger](RC1-DISPOSITIONS.md) explains every retained acceptance or capability
difference. The JSON TSV must cover exactly the vendored fixture set. New unexplained divergences
fail the comparator. `verify_rc1_reports.py` pins the executed case count of every method (930
JOSE cases and 1,310 JSON cases in all), so missing, duplicate or skipped cases fail it. Jackson 2.22.4
rejects two malformed Unicode corpus inputs that earlier Jackson versions accepted; [the
dependency refresh notes](RC1-DISPOSITIONS.md#2026-10-28-dependency-refresh) record the changed
rows and member-name controls.

These are parser and signature comparisons only. They make no network, provider-account or
whole-OIDC-flow claim.
