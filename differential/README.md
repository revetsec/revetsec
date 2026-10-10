# SAML differential tests

This is a test-only Maven project. It compares Revetsec with two separate SAML
service-provider paths: Spring Security 7.0.7's provider and a direct OpenSAML
5.2.2 harness. The direct harness uses OpenSAML parsing, signature profile and
cryptographic validation, decryption, and native assertion validation, then checks
the fixture's Response binding and subject identity. Those libraries are absent
from Revetsec's published core POM and runtime classpath.

Run from the repository root with JDK 17:

```sh
mvn -B -ntp -DskipTests -Dmaven.javadoc.skip=true install
mvn -B -ntp -f differential/pom.xml verify
```

The first command installs the current checkout's core JAR into the local Maven
cache; it does not publish it. The comparator reads checked-in fixtures signed
by the scripted IdP's pinned test key. The test uses a replay-only clock skew based on the
fixture date, so its results cover signed identity and XML structure, **not**
expiration policy.

The 19 signed bearer/Conditions shape fixtures pin another policy boundary.
Revetsec accepts four controls and rejects 15 malformed signed variants.
The direct OpenSAML path accepts ten and Spring accepts twelve; all accepted
cases still select the original signed `minted-user`. In particular, the
comparators accept several nilled structures and a mismatched confirmation
NameID that Revetsec rejects. The direct OpenSAML path rejects the valid
OneTimeUse/ProxyRestriction control under its configured assertion-validator
policy; Revetsec treats it as a terminal SP login.

For the 56 modern-signature fixtures, all three SP paths accept the original identity and
reject signed NameID tampering. Revetsec rejects all nine wrapper/namespace
mutations. Spring accepts three unsigned wrapper changes in assertion-only
responses (an extension, a second Status and a copied signature under an
extension), but returns the original signed identity in each case. This is a
documented policy difference, not an attacker identity release. Spring also
accepts the legacy RSA-SHA1 fixture by default; Revetsec accepts it only when
`SHA1_SIGNATURES` compatibility is explicitly enabled.

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
encrypted responses, nonempty OAEPparams and corrupted ciphertext. Across 56
modern signed fixtures and nine wrapper/namespace mutations, its only accepted
mutations are two unsigned Extensions changes in assertion-only responses; both
retain the original signed identity. Revetsec rejects those changes. The harness
uses a fixed fixture clock for its own expiry checks; the OpenSAML assertion
validator receives a replay-only skew, so this differential leg is not expiry
policy evidence.

The encrypted wrapper matrix adds ten structure mutations to each of the 47
positive encrypted fixtures: attacker siblings and Extensions, a duplicate
encrypted carrier, destination and Status edits, qualified Response ID, copied
signature, relative namespace and duplicate issuer. Revetsec rejects all 470
mutated responses. Direct OpenSAML accepts two unsigned Extensions changes in
each of 14 assertion-signed fixtures (28 acceptances); Spring accepts three
unsigned envelope changes in the EncryptedID fixture. Every acceptance returns
the original signed `minted-user` identity. The test pins each verdict by
fixture and mutation, including Spring's rejection of 13 assertion-only
encrypted baselines.

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

The remaining RC-2 assurance is open: the full XSW/Fragile-Lock and
structure-aware mutation matrix, fuzz/pentest,
calibrated review, real-product captures and the final API freeze.
