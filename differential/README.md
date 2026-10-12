# SAML differential tests

This is a test-only Maven project. It compares Revetsec with two separate SAML
service-provider paths: Spring Security 7.0.7's provider and a direct OpenSAML
5.2.2 harness, plus a live libxmlsec1 cryptographic oracle in the scripted IdP
container. The direct harness uses OpenSAML parsing, signature profile and
cryptographic validation, decryption, and native assertion validation, then checks
the fixture's Response binding and subject identity. Those libraries are absent
from Revetsec's published core POM and runtime classpath.

Run from the repository root with JDK 17:

```sh
mvn -B -ntp -DskipTests -Dmaven.javadoc.skip=true install
docker build --pull=false -t revetsec-scripted-idp:local interop/scripted-idp
mvn -B -ntp -f differential/pom.xml verify
```

The first command installs the current checkout's core JAR into the local Maven
cache; it does not publish it. The comparator reads checked-in fixtures signed
by the scripted IdP's pinned test key. The test uses a replay-only clock skew based on the
fixture date, so its results cover signed identity and XML structure, **not**
expiration policy.

The live libxmlsec1 leg verifies the signed Response/Assertion
matrix, rejects modified signed identities, decrypts all 47 positive GCM/CBC
fixtures, confirms that decryptable CBC without a signed Response is rejected,
and confirms that a valid Assertion signature inside an ambiguous unsigned
wrapper cannot release the added identity. The container receives
test-only keys and a pinned local TLS trust store. Its verdict is cryptographic;
Revetsec's SP result supplies the identity and protocol-policy verdict.
For every modern signed fixture, four additional structural mutations are
checked against libxmlsec: an attacker Assertion sibling, an attacker
Extensions Assertion, a changed destination, and a duplicate Status. The
original Assertion signature remains valid when the Response was unsigned;
the signed Response variants lose their outer signature. Revetsec rejects all
224 mutated envelopes.
The same libxmlsec oracle verifies the real Shibboleth 5.2.3 GCM and CBC
Response signatures against its captured public certificate, decrypts both
assertions, and rejects tampering of each signed Destination. Revetsec's offline
SP tests separately check acceptance, CBC opt-in, correlation and replay.
The SimpleSAMLphp 2.5.0 CBC captures provide another producer: libxmlsec
verifies its signed Response, decrypts both CBC assertions, and verifies the
signature inside the encrypted assertion of the unsigned-Response variant.
Revetsec's offline SP tests accept the first only with CBC opt-in and reject
the second even with that opt-in.
The two signed Shibboleth captures and signed SimpleSAMLphp capture each also
receive 19 envelope attacks: plaintext attacker siblings and Extensions,
copied signatures, duplicate carriers, issuer and Status changes, missing or
changed Destination, unexpected request correlation, qualified IDs and
relative namespaces. The independent libxmlsec oracle parses all 57 changed
documents and finds every outer Response signature invalid. The offline
Revetsec SP tests reject the same 57 documents and then accept each untouched
capture through the same pending authentication and replay state. The unsigned
SimpleSAMLphp capture receives the 17 attacks that do not require copying a
Response signature; Revetsec rejects them all under CBC opt-in. This is
real-producer envelope coverage, not the full RC-2 cross-product or an
independent SP comparison for these captures.
An additional six real-provider ciphertext probes flip one Base64 character in
the wrapped key or encrypted data of each signed capture. libxmlsec rejects both
GCM decryptions and finds every changed outer Response signature invalid. CBC
decryption can either fail or produce altered plaintext; the signed Response is
the required integrity boundary. Revetsec's offline tests reject those probes
and nine further key, ciphertext and algorithm edits per capture.
For the unsigned SimpleSAMLphp capture, libxmlsec checks all 17 applicable
envelope edits. One duplicate-carrier case is rejected as ambiguous oracle
input; 16 decrypt. Of those, 15 retain the valid inner signature and one
relative-namespace edit invalidates it. Revetsec rejects all 17 because the
inner signature does not authorize a changed unsigned envelope or unsigned CBC.

The 19 signed bearer/Conditions shape fixtures pin another policy boundary.
Revetsec accepts four controls and rejects 15 malformed signed variants.
The direct OpenSAML path accepts ten and Spring accepts twelve; all accepted
cases still select the original signed `minted-user`. In particular, the
comparators accept several nilled structures and a mismatched confirmation
NameID that Revetsec rejects. The direct OpenSAML path rejects the valid
OneTimeUse/ProxyRestriction control under its configured assertion-validator
policy; Revetsec treats it as a terminal SP login.

For the 56 modern-signature fixtures, all three SP paths accept the original
identity and reject signed NameID tampering. The expanded signed-envelope
matrix runs 19 named XSW, Fragile Lock and structure mutations against those
fixtures plus the SHA-1 compatibility fixture: 1,083 changed documents.
Revetsec rejects every one. The direct OpenSAML path accepts only two unsigned
Extensions changes for assertion-only signatures; Spring accepts those two
and a duplicate Status. Every accepted result retains the original signed
`minted-user` identity. Spring accepts the legacy RSA-SHA1 fixture by default;
Revetsec requires explicit `SHA1_SIGNATURES` compatibility.

The forged-KeyInfo corpus re-signs Response, Assertion, and both placements with
a separate test-only attacker key and an `attacker-user` NameID. It advertises
either the attacker certificate or the genuine IdP certificate in `KeyInfo`.
OpenSAML, Spring, and Revetsec reject every forged document when configured with
the genuine IdP key; the attacker-certificate variants succeed under an explicitly
configured attacker key. All three SP paths also accept the misleading-KeyInfo
variants under that attacker key. The separate libxmlsec1 oracle verifies all
eight signatures with the attacker certificate and rejects all eight with the
genuine certificate. This distinguishes a valid hostile signature from an
untrusted signer and checks that embedded `KeyInfo` cannot become a trust anchor.

The libxmlsec1 oracle checks the same 1,083 documents against the original
signed target. Ten mutation types leave an assertion-only signature
cryptographically valid while Revetsec rejects the changed envelope; no
changed Response-signed target remains valid. Duplicate IDs and a removed
signed Assertion fail the oracle's input selection before cryptographic
verification. These per-mutation verdicts are pinned in the differential tests.

The encrypted comparison covers 47 positive fixtures: GCM/OAEP data and key
transport combinations, three signed CBC responses, an encrypted assertion
with RSA-SHA512 signing, and an EncryptedID. The integration test checks their
plaintext with the scripted IdP's libxmlsec oracle. Revetsec and direct OpenSAML
accept all 47 (Revetsec requires explicit CBC compatibility). Spring rejects 13 encrypted assertions
whose outer Response is unsigned, even though Revetsec verifies the signed
assertion after decryption. Spring accepts signed CBC responses by default.

For four encrypted negative fixtures, Revetsec rejects all. libxmlsec can
decrypt the RSA1_5 ciphertext, while Spring accepts both RSA1_5 and a malformed
MGF child under mgf1p; each Spring acceptance returns the original signed
identity. libxmlsec and Spring reject the nonempty OAEPparams and corrupted
ciphertext cases. These are pinned policy and parser differences, not claims
that the three engines enforce identical acceptance rules.

The direct OpenSAML harness accepts RSA1_5, malformed MGF under mgf1p, and
assertion-only CBC with the original signed identity. It rejects unsigned
encrypted responses, nonempty OAEPparams and corrupted ciphertext. The harness
uses a fixed fixture clock for its own expiry checks; the OpenSAML assertion
validator receives a replay-only skew, so this differential leg is not expiry
policy evidence.

The encrypted wrapper matrix applies 19 structure mutations to each of the 47
positive encrypted fixtures: 893 changed documents. It covers attacker siblings
and Extensions, duplicate carriers, status and issuer changes, missing or changed
Destination, unexpected request correlation, copied signatures, qualified IDs,
and relative namespaces. Revetsec rejects 879. It accepts 14 unsigned-Response
cases with a missing Destination; every identity-bearing field and signature flag
matches the untouched fixture. Direct OpenSAML accepts 42 unsigned-envelope
changes and Spring accepts six in the EncryptedID fixture. Every acceptance
retains the original signed `minted-user`. Spring still rejects 13 assertion-only
encrypted baselines. The separate libxmlsec1 oracle pins all 893 mutations:
627 changed signed Responses have invalid outer signatures; 236 unsigned-envelope
edits retain a valid inner signature; 16 invalidate the inner signature; and 14
duplicate-carrier cases fail its input selection before signature verification.
Those cryptographic verdicts do not substitute for the whole-SP policy checks.

The Docker-backed integration gate separately runs libxmlsec over three
envelope probes for each of the same 47 fixtures. Adding an attacker Assertion
outside the encrypted carrier or changing the destination leaves the decrypted
plaintext byte-for-byte identical; the outer Response signature, when present,
becomes invalid. Duplicating the carrier is rejected by the oracle's exact-one-
EncryptedData boundary. Revetsec rejects all 141 mutated responses. The test
selects the trusted Assertion ID from the original fixture before inserting an
attacker Assertion, so verification cannot accidentally target the injection.

A second, offline structure corpus signs the *mutated Response itself* with the
test IdP key and verifies each signature with libxmlsec before writing the 15
fixtures. It covers a clean control plus 14 duplicate, nested, reordered,
namespace, qualified-ID, and misplaced-signature shapes. Revetsec accepts the
clean control and rejects all 14 malformed responses. The pinned direct
OpenSAML harness accepts seven with the original identity; Spring accepts ten.
For the duplicate-Assertion-before case, Spring selects `attacker-user`, which
is inside the IdP-signed Response. This demonstrates a parser selection
difference when a trusted IdP signs an ambiguous document; it does not show an
unsigned adversary forging the IdP signature. The comparator pins both
providers' exact verdicts and selected identities.

An assertion-signed corpus contains 23 malformed structures, five valid
variants and a clean control. Revetsec accepts the six controls with the
original NameID and rejects all 23 malformed assertions. The pinned OpenSAML
and Spring paths both accept 16 malformed assertions while selecting the
original NameID; their exact acceptance set is gated. A failing-before test found that duplicate
`AuthnContext` and `AuthnContextClassRef` elements were previously treated as
an absent optional class reference. Revetsec now rejects duplicate context
descriptors, out-of-order signed Assertion children, nilled Assertion and
attribute containers, and unsupported nested context elements before identity
release. Valid attribute statements may appear before or after AuthnStatement.

A separate 12-document assertion-signed AttributeValue corpus uses a transient
NameID so an approved `subject-id` is the only stable key source. Libxmlsec
verifies every signature. Revetsec exposes five plain or explicit XML Schema
string values as text and keeps seven nilled, non-string, spoofed-type or mixed
values opaque; the latter cannot become a scoped account key. The pinned direct
OpenSAML and Spring SP paths authenticate the original NameID in all 12 cases.
That comparison pins parser acceptance and NameID selection, not the other
libraries' attribute-value interpretation.

The 20-document identity-shape corpus extends this check to nilled or
misdeclared NameID, Issuer, Audience and authentication-context scalars; an
Assertion version mismatch; and reordered Subject/AuthnStatement children.
Revetsec accepts seven controls and rejects all 13 malformed cases. The pinned
direct OpenSAML path accepts ten, including seven malformed cases; Spring
accepts twelve, including eight malformed cases. Both return the original
signed NameID in every accepted case. These are parser-policy differences for
documents signed by the test IdP, not evidence of an unsigned forgery.

The Docker-backed SLO matrix uses Python cryptography to sign live
IdP-initiated LogoutRequests and SP-initiated LogoutResponses, including 12
altered XML messages whose Redirect signatures remain valid. Revetsec rejects
the altered destination, issuer, timing, request correlation, duplicate child,
and malformed status cases before accepting the original messages. It also
rejects raw-query changes, including a different percent encoding for the same
RelayState value, and rejects replay of both original messages. This checks
Revetsec's SP behavior against a wire fixture signed by the scripted IdP; it is not
a second SP implementation.

The offline differential leg replays 14 fixed-key, Python-signed Redirect
fixtures through OpenSAML 5.2.2's HTTP-Redirect decoder, simple-signature
security handler, and LogoutRequest/LogoutResponse models, alongside Revetsec.
Both accept the two valid messages and reject six signed semantic mutations in
each direction under the checked SP policy. An equivalent percent encoding of
RelayState breaks both binding signatures. The comparator's application-level
destination, issuer, timing, correlation, and structure checks are explicit
test policy around OpenSAML; they are not claims that OpenSAML enforces all of
those conditions automatically. The fixtures come from
`interop/scripted-idp/mint_slo_corpus.py` and use a deterministic test-only SP
pending ID and RelayState.

The remaining RC-2 assurance is open: extension of the full mutation
cross-product to encrypted and real-product fixture families, manual pentest,
calibrated review, hosted Shibboleth dispatch run, other real-product rows and
the final API freeze. The signed-envelope matrix and local fuzz campaigns do
not replace those gates.
