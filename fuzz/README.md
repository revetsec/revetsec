# Revetsec Fuzz Tests

This module holds Revetsec's [Jazzer](https://github.com/CodeIntelligenceTesting/jazzer) fuzz
targets. It has its own `pom.xml`, the root build never sees it, and it is never published: the
pom skips `install` and `deploy` and builds no jar. Fuzzing dependencies therefore stay out of the
published `com.revetsec:revetsec` artifact, which keeps zero runtime dependencies.

The module compiles Revetsec's sources directly, the same way Soklet's `fuzz/` does:

- `../src/main/java` as main sources;
- `../src/test/java` and `../src/test/resources` as test sources and resources, so targets can
  reuse test fixtures. Three groups of files are left out: Failsafe integration tests
  (`**/*IT.java`), the Testcontainers-backed classes for the scripted SAML identity provider (IdP)
  (`com/revetsec/saml/ScriptedIdp*`), and the Netty-backed HTTP/2 harness and tests. Nothing here
  needs Docker, Testcontainers or Netty.

`build-helper-maven-plugin` cannot filter the test sources it adds, so the compiler's
`testExcludes` does the filtering. The excluded files stay on javac's source path. If an included
file ever references one of them, javac compiles it implicitly and the build fails on the missing
Testcontainers classes. That failure is deliberate.

Because the targets sit in the packages they exercise, they can use package-private hooks. The
targets use these:

- `JsonLimits.maximumCaps()` and the `JsonLimits` constructor (for SCIM's exact-name twin and the
  tight profile), reached through the helper `com.revetsec.internal.json.JsonFuzzSupport` in this
  module;
- the input-size caps `JsonLimits.PROTOCOL_DOCUMENT_INPUT_BYTES_CAP` and `SCIM_INPUT_BYTES_CAP`;
- `JsonInvariants.depthOf` in `com.revetsec.json`;
- `PreparedJws`'s signing input, payload, signature and JSON profile after
  `JwtProcessor.prepare` (`internal.jose`), and `JoseException.Reason`'s category and fixed
  message (`jose`).

No target uses a core test helper, and neither do the seed generator and the seed checks (below),
so the module also builds with `-Drevetsec.fuzz.mainSourcesOnly`.

Versions: Jazzer 0.30.0 (as in Soklet's `fuzz/`) and JUnit 6.1.3 through the JUnit BOM, on Java
17 or newer. The BOM aligns Jazzer's transitive JUnit Platform modules with the explicit API,
engine and launcher dependencies. Without it, older Platform classes stay on the test classpath
and a run can fail before any input executes.

## Targets

Each `@FuzzTest` method is one ClusterFuzzLite target, named `<SimpleClassName>_<method>`. The
tables below list every target class by area. Packages are relative to `com.revetsec`; "root"
means `com.revetsec` itself.

### Codecs, sealing, PEM and encoding

| Class (package) | Method | Input | What it checks |
|---|---|---|---|
| `JsonCodecFuzzTests` (`internal.json`) | `parseRejectsOnlyWithJsonParseExceptionAndAcceptsOnlyValuesInsideTheProfile` | JSON bytes | Under `protocolDocument` (4 MiB), `jose` (1 KiB), `scim` (10 MiB, 1,000 nodes), a tight profile (below) and the maximum-cap profile: only `JsonParseException`, with its Kind's message, no cause and an offset inside the input. `INPUT_SIZE`, `BOM` and `INVALID_UTF8` exactly when they apply, in that order, and `INVALID_UTF8` at the offset where the JDK's strict decoder stops. An accepted document is inside every limit of its profile, on the value (depth, nodes, string length, digits, canonical number length, adjusted exponent) and on the text (each number's length and written exponent, found by a lexer written here). It holds only exact `BigDecimal`s and well-formed strings, and equals what the maximum-cap profile parses. |
| | `acceptedValuesRoundTripUnderTheMaximumCapProfile` | JSON bytes | Whatever a profile accepts, `toJson()` parses back under the maximum-cap profile to an equal value with an equal hash, and the canonical text is a fixed point. It also parses under the accepting profile whenever it fits that profile's byte limit. |
| | `scimAcceptsOnlyWhatTheExactNameProfileAccepts` | JSON bytes | SCIM accepts exactly what its exact-name twin accepts without ASCII case-variant names (see below). Up to eight accepted objects are also retried, each with one added near-miss of the first member name that holds an ASCII letter: that letter with its case flipped, which SCIM must reject, and `ı`, `İ`, the Kelvin sign or the long s in its place, which SCIM must keep apart. |
| `JsonModelFuzzTests` (`json`) | `factoriesAcceptExactlyTheValuesInsideTheModelInvariants` | `FuzzedDataProvider` | Drives the public factories and `JsonObject.Builder` with unpaired surrogates, oversized numbers, lying `BigDecimal` subclasses, repeated builder names and nesting past 64. Each call succeeds exactly when an oracle for the model's invariants says so, and otherwise throws `IllegalArgumentException` with the fixed message of the first failed check. Accepted values keep their invariants, equal a rebuilt copy with members reversed and numbers rescaled (with an equal hash), and round-trip through the codec unless a canonical number is over 4,096 characters, which is then `NUMBER_LENGTH`. |
| | `parsedValuesKeepEqualityUnderReorderingAndRescaling` | JSON bytes | For what the maximum-cap profile parses: equality and hashing ignore member order and number scale, a changed leaf breaks equality, arrays are ordered, `toString()` is redacted, and `find`, `findString`, `findLong`, `findBoolean` and `findStringList` agree with `getMembers()`. |
| `Rfc7638FuzzTests` (`internal.json`) | `canonicalJwkAgreesWithAnIndependentEncoder` | JSON bytes | For every object in the document, `canonicalJwk` gives exactly the bytes, or exactly the `JsonFieldException` Kind, of an encoder written from RFC 7638 section 3. The result ignores member order and is a fixed point. |
| `StateSealerFuzzTests` (root) | `unsealRejectsEverythingButAuthenticValuesWithOneFixedException` | sealed text | `StateSealer.unsealResult` returns only the one `StateUnsealResult.Rejected`, rendered the same whichever step failed, and `SealedStateAccess` only `UnsealException`, `INVALID`, or `EXPIRED` for a value that opens at an earlier time. Nothing longer than the 3,800-character maximum opens. A value that opens is bound to its label, context, key and expiry, and one changed character makes it fail. It also opens, to the same plaintext, under an implementation of the v1 construction written in the target (see below). |
| | `sealedValuesOpenOnlyUnchangedUnderTheirOwnLabelContextAndTime` | `FuzzedDataProvider` | Seals fuzzed plaintexts under fuzzed contexts, labels, lifetimes and expiry instants. Each value has the v1 length and opens with the same plaintext until its notAfter, then reports `EXPIRED`, and the target's own v1 implementation opens it to the same plaintext and notAfter. It fails under every other label, under a longer context and under a different context of the same length, and after any edit, and it opens after the next rotation step only while its key is held. An invalid `seal` throws `IllegalArgumentException` with the first failed check's message, never the plaintext or context. |
| `PemFuzzTests` (`internal.pem`) | `pemParsersRejectOnlyWithPemExceptionAndAcceptAtMostOneLabel` | PEM text | The three parsers throw only `PemException` with its Kind's message. At most one of them accepts a text, and the other two reject it with `UNSUPPORTED_LABEL`. Accepted values re-parse from the JDK's own encoding. An accepted body is exactly one DER `SEQUENCE`, and a PKCS#8 body's `privateKey` octets hold exactly one element, both checked with a DER reader written in the target. |
| | `derParsersRejectOnlyWithPemExceptionAndAgreeWithTheirArmoredForms` | DER bytes | `parseCertificateDer` and all four labels over the same DER throw only `PemException`, and the certificate parser gives the same outcome with and without armor. Where the target's DER reader finds no minimal definite-length `SEQUENCE`, all five fail with `MALFORMED_DER`, and where bytes follow it, all five fail with `TRAILING_DATA`. An accepted PKCS#8 key's `privateKey` octets hold exactly one element. |
| `EncodingFuzzTests` (`internal.encoding`) | `base64DecodersAcceptExactlyTheCanonicalEncodings` | text and octets | `Base64Url`, `StandardBase64` and `SamlBase64` agree with an RFC 4648 oracle: the exact octets, or the exact Kind of the first failed check, so each octet string has one accepted encoding. Every encoding round-trips, and a line-wrapped one also round-trips through `SamlBase64`. |
| | `urlAndUtf8CodecsMatchTheirOraclesExactly` | octets, also read as text | `StrictUtf8`, `PercentDecoding`, `FormUrlEncoding` and `QueryParameters` agree with oracles written from RFC 3629, RFC 3986 and RFC 6749 Appendix B. `FormUrlEncoding` also agrees with `URLDecoder` where it accepts and with `URLEncoder` for well-formed input. Query parameters survive re-encoding. |

### JOSE, keys and signing

| Class (package) | Method | Input | What it checks |
|---|---|---|---|
| `CompactJwsFuzzTests` (`internal.jose`) | `compactSerializationsSplitIntoThreeCanonicalSegmentsOrFailInStepOrder` | token text | `CompactJwsParser.parse` under two maximum lengths, then `JwtProcessor.prepare` under three header policies (the first five processing steps): the oracle's decoded segments and the received signing input, or the reason of the first failed step, from `TOKEN_TOO_LARGE` through `JSON_SERIALIZATION`, `TOKEN_SYNTAX`, `ENCRYPTED_TOKEN` and the header reasons to `SIGNATURE_MALFORMED`. An empty payload or signature passes the split. Every `JoseFailure` names only its reason, with no cause and no stack trace. |
| | `headerChecksAgreeWithAnIndependentOracleForP3ToP8` | JSON bytes | `JoseHeaderPolicy.check` under three policies against an oracle for header rules P3 to P8 (listed on `JoseHeaderPolicy`), with its own table of `alg` wire values and its own `typ` normalization: `HEADER`, `ALGORITHM_NOT_ALLOWED` (every spelling of `none`), `CRITICAL_HEADER`, `UNENCODED_PAYLOAD`, `COMPRESSED_PAYLOAD`, `UNTRUSTED_KEY_REFERENCE`, `INVALID_TYPE` and `NESTED_TOKEN`, in that order, or the header's algorithm, `kid` and raw `typ`. For every string in the header, `normalizeType`, `allowsType` and `JwsAlgorithm.findByWireValue` agree with the oracle. |
| `JwkFuzzTests` (`internal.jose`) | `keySetDocumentsSkipExactlyTheKeysAnIndependentOracleRefuses` | JSON bytes | `JwksParser` under the default and tight limits: `KEY_SET` exactly for the oracle's document failures, and otherwise every key kept or skipped with the reason of the first of the twelve key rules it breaks, at its index. Every object in the document also goes through `JwkParser` alone. A kept key has the oracle's `kid`, `kty`, `crv`, `alg`, `use`, JWK `issuer`, RFC 7638 thumbprint and JCA key values. `Jwks.fromJsonResult` agrees on the same text, escapes the `kid` in `toString`, and a `StaticJwksSource` needs one usable key. |
| | `keysBuiltFromFuzzedIntegersAgreeWithTheCurveAndThumbprintOracle` | `FuzzedDataProvider` | Builds the JWKs that byte mutation seldom reaches: RSA moduli of chosen sizes and parity, some built to carry the ROCA fingerprint for every prime or for all but one; exponents at their bounds; EC points computed on the curve, moved off it, or past the field prime; Ed25519 small-order points, `y` at or past the field prime, and `x = 0` with the sign bit; encodings that are not minimal or not the curve's length; every optional member, valid and invalid. `JwkParser`, and a one-key document through `JwksParser`, give the oracle's verdict. |
| `JwtValidatorFuzzTests` (`jose`) | `validateAcceptsOnlyWhatTheJdkVerifiersAccept` | token text | Three validators over the TEST ONLY fixture keys' public halves (see below). A token is accepted only if the JDK's own verifier for its algorithm accepts its signature with the one key the selection rules pick, and every header and claim rule passes; then it carries exactly the oracle's claims. A rejection has the reason of the oracle's first failed step, in that reason's exception class, with its fixed message, no cause, never transient, and `didFailToValidateJwt` gets the same instance. |
| | `signedTokensAreJudgedLikeTheOracleWhateverTheirHeaderAndClaims` | signing program | The same validators and oracle over fuzz-only keys. The input spells a header and a payload, which the target signs and may then damage (a flipped bit, a byte cut or added, a zeroed or emptied signature, the high-S twin, `r` of 0 or `n`, another key's signature, a changed payload, padding), so fuzzed headers and claims reach the checks after the signature. |
| `EcdsaFuzzTests` (`internal.crypto`) | `shapeCheckAndDerEncodingAgreeWithTheRangeRuleAndAnX690Reader` | signature octets | For each curve, `EcdsaSignatures.findShapeFailure` gives RFC 7518 section 3.4's verdict (the exact length, then `1 <= r, s <= n - 1` over the curve orders the JDK names). `toDer` refuses a signature of the wrong length and otherwise gives a minimal DER `SEQUENCE` that an X.690 reader written here reads back to `r` and `s`. `SignatureVerifier.verifyEcdsa` decides the shape before it looks at the key (CVE-2022-21449). |
| | `verdictsAgreeWithTheJdksFixedLengthEngine` | `FuzzedDataProvider` | `SignatureVerifier.verifyEcdsa` is `VALID` exactly when the JDK's fixed-length engine (`SHAxxxwithECDSAinP1363Format`, which the main code never uses) accepts a signature of the exact length with `r` and `s` in range, under a key on the curve. Signatures come from the fuzzer, or are signed here and damaged: `r` or `s` set to 0, 1, `n - 1`, `n`, `n + 1`, the field prime or all ones, the high-S twin (which is valid), swapped halves, a byte cut or added, halves padded to another curve's length, or the DER form. Curve and hash are chosen separately. |
| `CacheLifetimeFuzzTests` (`internal.http`) | `timeToLiveIsTotalClampedAndAgreesWithAnRfc9111Oracle` | header lines | `CacheLifetime.timeToLive` never throws, stays within its bounds, and equals an oracle for its RFC 9111 subset (list splitting with quoted strings, the `cache-directive` grammar, `no-store`, `no-cache`, `max-age` and its 2<sup>31</sup> cap, `Expires` minus `Date`, `Age`) for three receipt times and three sets of bounds. `HttpDate.parse` and `parseSingleField` agree with a regular-expression reading of RFC 9110 section 5.6.7's three forms and its two-digit-year rule. |
| `JwsSignerFuzzTests` (`jose`) | `signingMatchesIndependentGrammarAndSignature` | control bytes and data | Control bytes select the RSA signing algorithm, invalid grammar, a key-pair mismatch or an exhausted budget; the tail supplies bounded Latin-1 data. Accepted output follows the compact grammar, keeps the payload bytes unchanged, and verifies with the original JCA key. |
| `SigningProfilesFuzzTests` (`jose`) | `allSelectedAlgorithmsMatchIndependentJcaAndPreservePayload` | control bytes and data | Reaches all nine selected signing algorithms. Exact compact bytes are checked by a raw JCA oracle; EC verification uses the JDK's fixed-length engine without calling the product's converter. Same-family key mismatches and zero budgets release no credential. |
| `KeyImportsFuzzTests` (root) | `publicImportPathsAreBoundedAndAgreeWithArmor` | DER or PEM bytes | Arbitrary bounded DER and armor through the public import methods either yield a selected key profile, checked separately with JCA, or one fixed failure. Certificate parsing does not establish trust. |
| | `ordinaryFixturePairsAgreeWithIndependentJca` | control bytes | Ordinary OpenSSL fixtures supply RSA, P-256, P-384 and Ed25519 keys for the public pair methods; a key mismatch or a zero budget cannot pass a pair check. |

### OAuth, OIDC and resource server

| Class (package) | Method | Input | What it checks |
|---|---|---|---|
| `OAuthFuzzTests` (`oauth`) | `callbackKeepsSingletonsAndRedactsInput` | callback query bytes | An accepted callback has at most one of each protocol singleton, never both code and error, and redacts its input; malformed input yields a typed fixed-reason exception. |
| | `tokenJsonKeepsSecretsOutOfGenericMembers` | token JSON bytes | An accepted access token is printable ASCII, and token members never enter the generic JSON view; malformed or error bodies yield typed exceptions. |
| | `metadataRequiresExactIssuer` | metadata JSON bytes | An accepted document retains the configured issuer exactly; malformed or mismatched documents yield typed exceptions. Endpoint URI safety is checked when the client loads the document. |
| | `formBodyRoundTripsUnicodeAndReservedCharacters` | form value bytes | The OAuth writer and query decoder preserve arbitrary Latin-1 code points through UTF-8 form encoding without emitting raw line breaks. |
| `OidcFuzzTests` (`oidc`) | `signedClaimsRespectInitialAndRefreshProfiles` | JSON claim bytes | JDK HMAC signs every input to reach post-signature checks. A separate profile oracle checks exact issuer and single audience, subject, NumericDates/skew, nonce, ACR, authentication age, hashes and refresh continuity; only fixed OIDC exceptions escape. |
| | `metadataRequiresExactIssuerAndCapabilities` | metadata JSON bytes | Accepted remote metadata keeps exact issuer and required `code`/RS256/subject capabilities. No explicit defaults are applied; URI safety remains the client's separate outbound-policy check. |
| | `userInfoRequiresTheVerifiedSubject` | UserInfo JSON bytes | Acceptance agrees exactly with a separate check of the verified subject; malformed or different subjects produce fixed OIDC reasons. |
| | `sessionReferencesRoundTripWithoutCredentials` | reference JSON bytes | Accepted trusted-storage references stay within 64 KiB, round-trip canonically, retain only continuity fields and stay redacted. The current version's positive controls check the exact persisted `required_acr_values` set separately from continuity claims; older-version inputs are rejection inputs. This parser does not authenticate storage or create identity. |
| `EntraIssuerFuzzTests` (`oidc`) | `entraMatchesMetadataKeyTenantAndSessionModel` | control bytes and data | A finite model across trust roots, metadata shape, token and verifying-key issuer binding, tenant and session continuity, with refreshes signed separately by original JCA keys. |
| `ClientAssertionFuzzTests` (`oauth`) | `assertionMatchesEndpointClockBudgetAndSnapshot` | control bytes and data | Client assertions keep the right audience for each role, the original deadline, the clock and the key snapshot across key rotation. |
| `ResourceServerFuzzTests` (`oauth`) | `bearerPresentationMatchesTheHeaderGrammar` | Authorization field bytes | A separate RFC 6750 regexp oracle checks scheme, one to 58 spaces, b64token, trailing padding and configured 8 KiB credential/64-byte prefix caps. Empty, single and identical-duplicate lists exercise throwing and result APIs; no parsed credential is called verified. |
| | `challengesEscapeAndBoundTrustedParameters` | trusted parameter bytes | Separate printable-ASCII, description and quoted-string rendering rules check exact escaping and the 1 KiB post-expansion field cap. Input controls/non-ASCII and quote/backslash description values reject. |
| | `formPostMimeMatchesIndependentFieldGrammar` | raw MIME field bytes | A separate quote-aware field grammar checks one form field, empty parameters, case-insensitive names, duplicate parameters, quoted-pairs and absent/UTF-8 charset. A fixed synthetic callback isolates MIME from callback parsing; duplicate fields always reject. |
| | `metadataKeepsRolesAndRawResourceIdentifiers` | metadata JSON or resource URI bytes | Separate role projection rules check exact issuer, required role endpoint syntax and optional authentication-method typing/uniqueness. Configured protected-resource values retain raw path/query/case/dot segments, derive the well-known location without normalization, deduplicate configured lists and stay within the JSON cap. `HostClassifier` supplies the separately tested loopback classification; endpoint fetching, SSRF and DNS are outside this target. |
| | `signedAccessTokensRespectStrictAndUntypedProfiles` | JSON claim bytes | JDK Ed25519 signs arbitrary input under typed, absent, JWT and unrelated explicit profiles. A separate claim oracle checks issuer, audience, required typed claims, NumericDates and zero-skew edges, confirmation refusal, scope grammar, the extra compatibility claim and untyped identity-claim substitution. Both accepted and rejected verdicts are checked. |
| | `introspectionResponsesAreTypedAudienceCheckedAndUncached` | JSON response bytes | The public client uses an offline synthetic `HttpClient`, with no socket or executor. A separate oracle distinguishes malformed provider documents from local inactive/profile rejection and verified proof. Each syntactically valid first response is followed by a fresh inactive response to the same credential; two authenticated POSTs and an inactive second verdict prove the client did not reuse the first proof. |

The OIDC seeds under `com/revetsec/oidc/OidcFuzzTestsInputs` use test-only values and a fixed
2026-09-30 clock. The signed-claims target uses an explicit HMAC compatibility profile for speed;
the JOSE targets and core OIDC unit tests cover asymmetric signatures and signed UserInfo. It
signs arbitrary payload bytes and evaluates both initial and refresh profiles; it does not fuzz the
browser flow or call a network endpoint.

The resource-server seeds use only synthetic test values and a fixed 2026-10-01 clock. The Ed25519
key is ephemeral and generated within each target JVM; curated inputs hold claim bytes, never a
private key or a pre-signed production credential. The synthetic HTTP transport delivers bodies
directly to the normal public client's body subscriber without network requests, and records
method, endpoint, authentication presence and request count. Real TLS, provider clocks,
backoff/races and opaque-token revocation stay with the core regression and integration tests.

`JwsSignerFuzzTests`, `ClientAssertionFuzzTests` and `EntraIssuerFuzzTests` read unsigned control
bytes first (missing bytes are zero), and the remaining bytes supply bounded Latin-1 text. Their
keys are generated once per JVM and never saved, and they use no network.

### Authorization server

These targets drive the public issuer engine (`com.revetsec.oauth.server`) with a bounded atomic
test store that is process-local. They make no durability, distributed-store or external-network
claim. Signing keys are generated once per JVM and never saved, sealing keys are fuzz-only
constants, and no target uses a core test helper.
Inputs start with unsigned control bytes (missing bytes are zero) followed by a bounded tail.

| Class | Method | What it checks |
|---|---|---|
| `IssuerIngressFuzzTests` | `rawRequestsMatchIndependentGrammar` | Four endpoint grammars, raw header occurrences, aggregate caps, strict percent/UTF-8 decoding and query/body selection, against a separate split, byte-stream and JDK-decoder oracle. Its generated MIME variants are enumerated; this is not an arbitrary MIME differential. The tail is bounded to 8,192 bytes. |
| `IssuerCodeFuzzTests` | `codeTransitionsRespectBindingsAndSingleUse` | Consent and public or Basic confidential code redemption, two exact resources, scope narrowing, client/version/return/S256 binding, expiry, denial, conflict retry and consumed-code replay. Original JCA signatures and exact issued claims are checked. A wrong-binding replay leaves the winner active; a valid replay invalidates it and never returns a second credential. The tail is bounded to 256 bytes before a SHA-256 verifier derivation written in the target. |
| `CimdFuzzTests` | `metadataCachePeerAndFramingRemainBound` | Enumerated client ID metadata document (CIMD) JSON admission with authenticated cache address/version/expiry/namespace checks, plus an offline helper for copied public numeric answers, strict HTTP/1.1 response framing and conservative freshness. It performs no DNS lookup or socket operation. |
| `IssuerStoreFuzzTests` | `recordsAuthenticateNamespaceVersionRetentionAndPayload` | All seven record kinds, canonical stored-form reconstruction, issuer and subject namespace derivation, authenticated address/version/retention/ciphertext bindings, expiry, sealer separation and object-only payloads. |
| `IssuerRefreshFuzzTests` | `refreshFamilyAndStatusTransitionsRemainAtomic` | Rotation, exact client/resource/scope binding, request-only scope narrowing, policy continuation, expiry, conflict retry, endpoint and trusted revocation, used-token replay and fresh issuer/subject/grant status admission. Successful rotations preserve one family; a valid used-token replay terminates it. Wrong-owner and wrong-resource attempts do not consume the token or invalidate the legitimate family. Signed access tokens are checked only through public credential responses, and every proof through the uncached public access-token API. |
| `IssuerSigningFuzzTests` | `accessTokensMatchFixedProfileAndIndependentSignature` | Authorization-code and refresh issuance: the exact eight-claim access-token profile and JSON types, active key ID, fixed RS256/`at+jwt` header, sorted scope, lifetime arithmetic, strict UTF-8, unique rotation `jti`, online proof admission and the five-field token response. JCA verifies the exact compact signing input with the original active public key and rejects the retained key. The public JWKS is checked against the original RSA modulus/exponent and exact public-only fields for both active and retained keys. |

### SAML

| Class | Method | What it checks |
|---|---|---|
| `SamlFuzzTests` | `postBindingKeepsRawOctetsAndFixedRejections` | Raw HTTP-POST form bytes never release XML before exact form and Base64 parsing. |
| | `redirectBindingKeepsRawOctetsAndBoundedInflation` | Raw HTTP-Redirect query bytes exercise percent decoding, bounded inflation and signed-query framing. |
| | `metadataParsingCannotApproveAnUntrustedDescriptor` | Arbitrary XML either stays untrusted or yields bounded, locally parsed IdP metadata. The accepted-result oracle checks certificate count and size, entity ID and scope bounds, and HTTPS endpoint host, user-info and fragment constraints. |
| | `xmlParserAndWalkerRejectAmbiguousDocuments` | Arbitrary SAML XML cannot smuggle duplicate IDs through the single parser and response walker. |
| | `signedAndEncryptedResponsesNeverReleaseMutatedIdentity` | Structure-aware changes to signed and encrypted responses: unsigned wrapping content, signed-field edits and encrypted carriers cannot change the released identity. |
| | `encryptedCiphertextChangesCannotReleaseIdentity` | Byte changes to GCM encrypted-data and wrapped-key ciphertext cannot release a claimed identity. |
| `SamlLogoutFuzzTests` | `signedLogoutCasesNeverReleaseWrongSessionOrSuccess` | Selects one of 23 Python-signed Redirect logout queries, then tries it unchanged, with an equivalent RelayState encoding, with a duplicate SigAlg and with a changed signed octet. Only the unchanged valid request may release the fixed NameID/SessionIndex; only the unchanged valid response may complete the sealed pending logout. |
| | `signedPostLogoutCasesNeverReleaseWrongSessionOrSuccess` | Selects one of the 23 libxmlsec-signed POST cases, checks a valid control before each trial, then tries the original form, a duplicate message field or a changed XML signature byte. Successful controls retain the fixed NameID/SessionIndex or the correlated status and reject a second admission. |
| | `rawPostLogoutFormsNeverAdmitUnsignedProtocolMessages` | Parses arbitrary form bytes, checks replay denial for any accepted original, then removes every XML signature and requires rejection. |

The structure-aware target starts from scripted-IdP fixtures signed with a pinned test key and
requires every successful authentication to retain the fixture's exact subject, attributes,
signature coverage and encryption status. The ciphertext target starts from a GCM fixture produced
by a separate test encryptor and requires every changed carrier to reject before identity release.
Inputs select fixtures and mutations; verification certificates and the test decryption key remain
in the fixture tree.

All six `SamlFuzzTests` targets have curated seeds under
`com/revetsec/saml/SamlFuzzTestsInputs`, including accepted binding and metadata documents, XML
ambiguity cases and encrypted-carrier boundaries. The metadata corpus includes
`certificate-size-limit.xml`, a valid IdP descriptor with the certificate-only 24,576-byte DER
fixture (exactly 32,768 Base64 characters).

The logout targets use a fresh replay cache for each trial. For the two POST targets, structured
seed bytes select the case, the mutation (0 original, 1 duplicate message, 2 signature edit) and
the signature byte offset; missing control bytes are zero. Raw seeds include signed controls,
unsigned messages, conflicting form fields, invalid Base64 and malformed encoding. No SAML target
calls a network service.

### WebAuthn and TOTP

| Class (package) | Method | What it checks |
|---|---|---|
| `WebAuthnFuzzTests` (`internal.webauthn`) | `noneAttestationAcceptsOnlyTheExactBoundedCarrier` | Raw CBOR and bounded `none` attestation carriers built in both member orders: authenticator data is copied, and missing, non-minimal, indefinite, nonempty-statement, truncated and trailing forms are rejected. A carrier is never a proof. |
| | `clientDataBindsTheExactBrowserContext` | Derives fresh challenge bytes from each input and checks exact browser client-data binding for registration and authentication; altered type, origin, challenge, cross-origin and duplicate-key fields are rejected. |
| `WebAuthnCeremonyFuzzTests` (`webauthn`) | `registrationRejectsChangedBrowserEvidenceWithoutConsumingTheValidCeremony` | A rejected registration cannot consume the challenge or create a credential proof; the original ceremony stays usable and a confirmed success is single-use. |
| | `assertionBindsTheSignedInputsAndAuthoritativeCredentialState` | A changed assertion releases no proof. Replay, a stale nonzero signature counter, the account-pinned reauthentication purpose, a pending assertion after server-side credential removal, and permanent reservation of the removed credential ID are all checked. |
| | `allSupportedAlgorithmsBindTheCommittedKeyAndExactSignedBytes` | Selects ES256, Ed25519 or RS256 and builds the COSE public key from a JDK-generated test key. An incorrect reported algorithm is rejected before enrollment is accepted, a correctly encoded signature over different client-data bytes is rejected before the exact signed assertion is accepted, and replay is then rejected. |
| | `checkedReauthenticationPreservesEntryContextAndEffectClasses` | Runs real enrollment and completion through the checked facade, distinguishes all five result leaves, exact callback and effect counts, all six proof fields and deterministic entry-account mutation. |
| `TotpFuzzTests` (`totp`) | `changedRecoveryCodeNeverConsumesTheValidCode` | A changed copy of a newly issued recovery code is rejected, the unchanged control still succeeds, and replay fails. |
| | `malformedTotpCodeNeverConsumesTheValidStep` | A changed six-digit TOTP code is rejected, the unchanged control still succeeds, and replay fails. |

The ceremony targets use the public relying-party API and its bounded in-memory store, and build
ordinary browser JSON. The registration and assertion targets sign with an Ed25519 key generated
only in the target JVM. A corrupted Ed25519 signature may produce either `Rejected` or
`Unavailable` when the JDK reports provider failure, but never a proof. The reauthentication
target's controlled store loss and admission changes are local fault injections.

The TOTP targets use an explicitly initialized, volatile in-memory store and a fixed test recovery
gate. Their seeds cover invalid ASCII, Unicode lookalikes, missing or extra symbols and overlong
inputs.

None of these targets covers durable stores, cross-JVM behavior, deployed recovery, database
transactions, an independent authenticator or a physical security key. The unpublished PostgreSQL
fixtures under `examples/postgresql-pending-store` cover durable TOTP recovery admission
separately.

### SCIM

| Class | Method | What it checks |
|---|---|---|
| `ScimSyntaxFuzzTests` | `rawFiltersRemainBoundedAndRoundTrip` | Filters from a UTF-8 text view and a raw UTF-16 view (unpaired surrogate units included). Accepted syntax keeps its graph and literal bounds, serializes without length growth and reparses under the same limits; rejections carry fixed errors and bounded UTF-16 offsets. |
| | `rawPathsRemainBoundedAndRoundTrip` | The same properties for attribute paths, which also preserve their explicit parts. |
| `ScimM10FuzzTests` | `rawQueriesStayBoundedAndApproved` | Arbitrary raw GET query text yields a bounded, normalized approved query or a fixed error. |
| | `rawBodiesStayBoundedAndAtomic` | Header-aware create, PUT and SearchRequest bodies with integer lexical preservation cannot mutate the authoritative current resource on any outcome. |
| | `resourcesRenderWithoutNeverAttributesOrForeignSelections` | Approved response selections stay associated, and transient write-only data (a password generated at runtime) is stripped from every output. |
| `ScimM11FuzzTests` | `rawPatchBodiesStayBoundedAndAtomic` | Arbitrary PatchOp bodies through schema binding, ordered application and membership reduction have fixed outcomes and never mutate the current snapshot. |
| | `lateFailurePreservesMembershipAndMetadata` | A generated member addition followed by a forbidden final operation cannot publish the earlier Group membership update. |
| `ScimM12FuzzTests` | `evaluationsRebindPoliciesAndAgreeWithIndependentNullModel` | Arbitrary UTF-8 and raw UTF-16 filter trees under two receiving policies and limits, evaluated against assigned and unassigned scalar and multivalue data and compared with a hand-written default-null/any-element model. No input causes partial success or an implicit policy grant. |
| `ScimRc3IngressFuzzTests` | `physicalHeadersQueriesAndBodiesPreserveBoundsPrivacyAndProvenance` | Original physical headers and bounded query and resource ingress, with a separate GET/SearchRequest framing model. Hand-authored header expectations and JDK URL encoding supply the oracle; choice zero exercises ordinary query parsing. |

The PATCH targets check unchanged authoritative snapshots, metadata retention, fixed rejection
outcomes and request/result path provenance across strict, Entra and Okta configurations. Core
grammar tests supply separately written RFC acceptance and AST expectations. The syntax targets do
not check schema binding or policy enforcement, and none of the SCIM targets establishes query
permission, provider interoperability or persistence behavior.

### Invariants shared by every target

These follow the threat model's invariant rows in [docs/threat-model.md](../docs/threat-model.md).

- **Only the documented exception.** The one exception type each target allows is listed above.
  Anything else escaping, including `IllegalArgumentException` from `JsonCodec.parse`, a JDK
  exception, `ArithmeticException`, `StackOverflowError` or `OutOfMemoryError`, is a finding
  (INV-G1).
  - `StrictUtf8.encode`, `PercentDecoding.decode`, `FormUrlEncoding.encode`,
    `FormUrlEncoding.decode` and `QueryParameters.parse` throw `ArithmeticException` for inputs of
    hundreds of millions of characters, where a length would pass `Integer.MAX_VALUE` (see their
    Javadoc). Fuzz inputs are bounded by libFuzzer's `-max_len`, far below that, so no target
    allows it.
- **Only the documented exception, in JOSE.** Inside, `JoseFailure` and `SkippedKeyException`;
  at the public API, the `JoseException` subclass of the reason, and `IllegalArgumentException`
  only from `StaticJwksSource.fromJwks` for a set with no usable key. A static key
  source never throws `JwksUnavailableException`, so one would be a finding too.
- **Fixed messages, no input echo.** A checked failure's message must equal its Kind's own fixed
  message; a `JoseFailure` or `SkippedKeyException` message names only its reason, and a
  `JoseException` carries its reason's fixed message. The model's and the sealer's
  `IllegalArgumentException` messages must be the fixed message of the first failed check; for a
  seal lifetime, that is the `Limits` row's own message, which names the lifetime but never the
  plaintext or context. So no message can echo the input, and the check needs no sentinel.
- **Bounded work.** Every accepted JSON document is measured by a separate walker and number
  lexer and must stay inside its profile's limits; a document never yields more values than it
  has bytes. libFuzzer's `-timeout` stops a slow input:
  - locally, with `-timeout=30` as below, libFuzzer writes a `timeout-*` file and ends the test
    JVM, so the Maven run fails;
  - ClusterFuzzLite passes `-timeout=25`, but reports a timeout only when its `REPORT_TIMEOUTS`
    setting is on (here, the `REPORT_TIMEOUTS` environment variable of the workflows' `docker://`
    run step). It is off by default and none of the three workflows (`cflite_pr.yml`,
    `cflite_batch.yml`, `cflite_cron.yml`) sets it, so a slow input does not fail a
    ClusterFuzzLite job.
- **Oracles, not self-comparison.** Where a target predicts a result, the prediction comes from
  code written here from the specification: its own walker, ASCII fold, Base64 and
  percent-decoding, DER reader (X.690), and StateSealer v1 implementation. It never calls the code
  under test to decide what that code should do.
  - The JOSE targets parse JSON text with `JsonCodec` and certificates with `Pem`, which have
    targets of their own, and decide everything after those parses themselves: the compact split,
    base64url, the header rules, the twelve key rules in `BigInteger` arithmetic over the curve
    parameters the JDK names, RFC 7638, key selection, the claim rules and NumericDates.
  - Signature verdicts come from the JDK's own engines, never from `internal.crypto`, and a
    fixed-length ECDSA verdict from the JDK's `inP1363Format` engines, which the main code is
    banned from using.

### The sealer's independent v1 implementation

`StateSealerFuzzTests` opens every value that opens with the StateSealer v1 construction, written
in the target on the JDK's `HmacSHA256` and `AES/GCM/NoPadding`, apart from Revetsec's `Hkdf` and
`AesGcm`: PRK from the master key, the message key from the label and salt, and the additional
authenticated data from the header, the label and the context. A black-box check cannot see the
label in the key derivation, because the label is also in the additional authenticated data, so a
wrong label fails either way. This comparison sees it, for every fuzzed plaintext, context and
label, where `SealerV1Tests` pins four known-answer vectors.

### The JOSE validators and keys

`JwtValidatorFuzzTests` checks every token with three validators over one key set:

- one for `https://issuer.example.com` that allows the eleven asymmetric algorithms, expects
  `https://api.example.com`, requires `sub` and `client_id`, and allows the default 60 seconds of
  skew;
- one for a made-up Entra tenant that allows `RS256`, `ES256` and `EdDSA`, accepts any audience,
  requires `typ` from `JWT` and `at+jwt`, allows no skew and caps tokens at 8,192 characters;
- one for the same tenant spelled in upper case, with the defaults and any audience. The Entra
  `{tenantid}` template stands only for a lowercase `tid`, so it must never serve this issuer.

All three read the time from a clock fixed at 2026-09-27T12:00:00Z. The key set has twenty-one
slots (`JwtValidatorFuzzSupport.KEY_SLOTS`): the RSA-2048 key once per RSA algorithm, the
RSA-3072 key without `alg`, the three EC keys (two with an `x5c` certificate), the Ed25519 key
without `alg`, with `EdDSA` and with `Ed25519`, RSA keys whose JWK `issuer` is another issuer, the
Entra template or the exact Entra issuer, an EC key bound to the first validator's issuer, one key
without `kid`, and three keys that share one `kid` (the P-521 key with `ES512` and without `alg`,
and an RSA key with `RS384`). So the selection rules all apply: one RSA algorithm per key without
`alg` (INV-J3), each direction of the `EdDSA`/`Ed25519` alias between a key's `alg` and the
token's, ambiguity with and without `kid`, a shared `kid` that only one key fits,
`KEY_ISSUER_MISMATCH`, and the template.

- The first target verifies with the TEST ONLY fixture keys' public halves, which this module's
  `src/test/resources/com/revetsec/jose/fixture-key-set.json` holds as written by the seed
  generator (below).
- The second target signs its tokens itself, so it holds fuzz-only key pairs for the same slots,
  generated when the class loads from fixed `SHA1PRNG` seeds; no private key is committed.
  `EcdsaFuzzTests` generates its fuzz-only keys the same way.

### "Exact" name comparison and the SCIM profile

The SCIM target checks that whatever SCIM accepts, the exact-name profile also accepts. No type in
the code is called `EXACT`. The term is the "Names: exact" column of the profile table in
`JsonLimits`, meaning `isAsciiCaseVariantNamesRejected() == false`: only identical member names
are duplicates. That rule belongs to `protocolDocument`, `jose` and the maximum-cap profile. SCIM
also rejects names that differ only in ASCII case.

The profiles differ in their other limits too (protocol depth 32, SCIM depth 64), so comparing SCIM
with `protocolDocument` directly would be wrong. The target builds SCIM's exact-name twin instead:
the SCIM limits with exact names, through the package-private `JsonLimits` constructor. It then
checks both directions:

- SCIM accepts exactly when the twin accepts and no object holds ASCII case-variant names.
- A SCIM rejection that is not `DUPLICATE_MEMBER` is the twin's rejection, with the same Kind and
  offset.

### The tight profile

The real profiles' string limit is 1 Mi UTF-16 code units, which no fuzz input reaches, and their
depth, node and number limits need inputs of hundreds of bytes or more. So the codec targets also
parse under a synthetic profile far below every registry floor, built through the package-private
`JsonLimits` constructor (`JsonFuzzSupport.tightLimits()`): 64 KiB of input, depth 3, 12 nodes,
strings of 6 code units, numbers of 6 characters and exponents of magnitude 3, with exact names.
Every structural Kind is then a few bytes away, and the bound checks see both sides of each limit
on most inputs. No production path uses it.

### Coverage limits

- The key-set cache's own behavior (cooldowns, backoff, a removed key, stale keys) is outside the
  JOSE targets, which verify over static key sources; the core tests cover it.
- `Pem.parseCertificateDer` must turn any `RuntimeException` from the JDK's certificate factory
  into `PemException`, and the DER target reports anything else as a finding. Jazzer does not
  instrument the JDK's X.509 code, so coverage cannot steer toward such an exception, and no input
  is known that makes the JDK throw one. Narrowing that catch would not be caught by these targets.
- The targets use in-memory or synthetic stores and transports. They do not cover durable or
  distributed storage, real TLS, DNS, provider accounts, browsers or physical authenticators.
- Seed replay is a deterministic check of a finite corpus, not a fuzzing session.

## Seeds

Seeds live in each method's Jazzer inputs directory, `<package>/<SimpleClassName>Inputs/<method>/`
on the test class path. Jazzer replays every file there, including files in subdirectories. Three
sources fill it: corpora mapped in from the core tree, seeds written by the seed generator, and
hand-written seeds.

**Mapped corpora.** The fuzz pom copies these into the inputs directories through Maven resource
`targetPath`, so they are never duplicated in the tree. They exist only under
`fuzz/target/test-classes`.

| Source (core `src/test/resources/`) | Files | Mapped into |
|---|---|---|
| `com/revetsec/internal/json/corpus/parse/` and `round-trip/`: the 25 files ported from Soklet plus the protocol-shaped seeds, `.bin` files included | 30 | the five JSON-text methods (`parse/`, `round-trip/`) |
| `vectors/jsontestsuite/test_parsing/`: JSONTestSuite at `1ef36fa0`, one file name containing `#` | 318 | the same five methods (`jsontestsuite/`) |
| `com/revetsec/internal/json/corpus/`, `vectors/jsontestsuite/test_parsing/` (the same files) | 30 and 318 | the two JOSE JSON-text methods, `CompactJwsFuzzTests#headerChecksAgreeWithAnIndependentOracleForP3ToP8` and `JwkFuzzTests#keySetDocumentsSkipExactlyTheKeysAnIndependentOracleRefuses` |
| `com/revetsec/jose/entra/2026-09-27/*-keys.json`: the captured Entra key sets, with `x5c` chains and templated `issuer` members | 5 | `JwkFuzzTests#keySetDocumentsSkipExactlyTheKeysAnIndependentOracleRefuses` (`entra/`) |
| `com/revetsec/internal/json/corpus/`, `vectors/jsontestsuite/test_parsing/` | 30 and 318 | all four `OidcFuzzTests` methods and the `ResourceServerFuzzTests` role-metadata, signed-profile and introspection methods |
| `fixtures/pem/` and `fixtures/keys/`: the TEST ONLY PEM fixtures | 33 | `PemFuzzTests#pemParsersRejectOnlyWithPemExceptionAndAcceptAtMostOneLabel` (`fixtures-pem/`, `fixtures-keys/`) |

The core build checks the two JSON corpora against their SHA-256 manifests
(`JsonCorpusManifestTests`, `JsonTestSuiteTests`), so the fuzz module carries no second manifest
for them. The TEST ONLY PEM and key fixtures have no SHA-256 manifest. `PemTests` checks them only
through its parsing and key-pair assertions, so an edit to one of them changes the PEM target's
seeds without failing any test.

`FuzzSeedLayoutTests` checks the layout in the replay: every inputs directory belongs to a
`@FuzzTest` method of its class, every `@FuzzTest` method has at least one seed, every `byte[]`
target in a JSON package is mapped, and each mapped target holds every file of its mapped corpora,
unchanged (for a JSON-text method, all 30 core corpus files and all 318 JSONTestSuite files). The
JOSE packages hold targets of both kinds, so each of their `byte[]` targets must be on one of two
lists, JSON text (a decoded header, a JWK Set document) or not (a token, a signing program), and
the JSON-text ones are mapped like the JSON targets. It also requires that no method of a target
class names a record in its signature (see "Writing a target").
Renaming or moving a target therefore fails the replay, and the ClusterFuzzLite build, until its
`targetPath` entries and seed directory move with it.

**Generated seeds** (`generated-*`), and the fixture key set, come from
`com.revetsec.FuzzSeedGenerator` in this module, which reads the TEST ONLY fixture keys from the
core checkout (its `src/test/resources/fixtures/keys/` and `fixtures/pem/ed25519-*.pem`):

- tokens for the JwtValidator target, and some of them for the compact target: every algorithm
  with its key, the selection cases (each direction of the `EdDSA`/`Ed25519` alias, a shared
  `kid`), the time boundaries at 60 seconds of skew (`iat` at +60 and +61 seconds among them), the
  issuer, audience, required-claim and `cnf` cases (`cnf` of JSON `null` too), a `jti` that is not
  a string, damaged signatures (DER, `r = 0`, `r = n`, the high-S twin, 63, 65, 255 and 257
  octets, empty, another key's, a flipped bit, a changed payload, a padded segment, an HMAC keyed
  with the RSA public key's DER encoding), and the Entra cases, including tokens of exactly 8,192
  and 8,193 characters for the Entra validator's cap;
- key sets for the JWK Set target: the fixture key set, every fixture key with its certificate,
  certificates of other keys, and damaged copies (a leading zero octet, an even modulus,
  exponents 3, 65,535, 65,536 and 2<sup>32</sup> + 1, the RSA-1024 key, a coordinate one octet
  short, a point off the curve or at the field prime, the Ed25519 points of order 1, 2 and 4 and
  encodings that do not decode, and malformed optional members, among them `kid`s of 256 and 257
  characters). Keys computed by the generator sit at the key rules' bounds: moduli of 2,047,
  16,384 and 16,385 bits drawn from SHA-256, moduli that carry the ROCA fingerprint for every prime
  or for all but the first or the last, a point on each NIST curve whose `x` is written as the
  field prime, and Ed25519's four points of order 8. A seed that needs a private member carries a
  placeholder value, never a fixture's private key;
- `com/revetsec/jose/fixture-key-set.json`, the JwtValidator target's key set.

Generate them from the repository root, after `test-compile` (see "Running locally"):

```sh
java -cp "fuzz/target/test-classes:fuzz/target/classes" com.revetsec.FuzzSeedGenerator .
```

RSASSA-PKCS1-v1_5, Ed25519 and HMAC signatures are deterministic. RSASSA-PSS and ECDSA signing
draw from a `SHA1PRNG` seeded with a constant, which repeats on one JDK but not necessarily across
JDKs.

**Wycheproof-derived seeds** (`wycheproof-<file>-tc<tcId>-<field>`) each hold one field of the
vendored Wycheproof files (the core tree's `src/test/resources/vectors/wycheproof/testvectors_v1/`;
see NOTICE): JWS strings (`jws`), byte for byte, for the token targets, including the RFC 7520
examples and the base64 canonicality tests; group keys and key sets (`public`, `private`), the
same JSON values written as canonical JSON, for the JWK Set target, the ROCA key among them; and
fixed-length ECDSA signatures (`sig`), the octets their hex spells, for the ECDSA shape target.
The generator writes them too. Two of the `jws` seeds (Wycheproof JWS tcIds 13 and 30) are empty,
and libFuzzer leaves empty inputs out of its seed count.

`FuzzSeedProvenanceTests` checks both kinds in the replay, against the core checkout that
Surefire names:

- each `wycheproof-*` seed is still exactly the field its name gives, read from the vendored
  file by name, apart from the generator's selection;
- each `generated-*` seed and the fixture key set is what the generator makes now: byte for byte
  for the deterministic signatures and every key set; the same signing input and a signature that
  still verifies with its fixture key for a PSS or ECDSA token; the same signing input and
  signature length for a damaged one. A generated file the generator no longer makes fails too.

**Hand-written seeds**, in `src/test/resources/`:

- **JSON codec:** SCIM case variants (`id` with `ID`, escaped variants, nested variants), names that
  must stay distinct (`ıd` with `id`, the Kelvin sign with `k`), and numbers whose canonical form
  is just inside, or just outside, the 1,024-character number limit. The parse target also has
  seeds exactly one past a limit, each of which fails the replay if the matching codec check lets
  one more through: 33 and 65 nested arrays, 1,001 nodes (SCIM), a string of 7 code units and one
  of 4 supplementary characters (the tight profile), and numbers whose text (`1e000…01`, 1,025
  characters), written exponent (`100e-10001`, `100e-100001`), adjusted exponent (`10e10000`) or
  canonical form (plain and scientific, 1,025 characters) is one over.
- **RFC 7638:** one synthetic JWK per key type and one per failure: lowercase `kty`, a missing or
  non-string member, a value with a quote or a control character (U+0001, and U+001F, the last one
  JSON must escape), a value with a space and U+007F, which need no escape, and non-ASCII values.
- **StateSealer:** values sealed with the fuzz-only keys on the target's fixed clock.
  - Authentic values: empty, non-ASCII, at the 3,800-character maximum, under the verification
    key, and under the `PENDING_SAML` label.
  - Failures: an expired value, the wrong context, an unknown key ID, over-length (an authentic
    3,802-character value sealed under a 16,384-character maximum, which only unseal step 1
    rejects), padded, the standard alphabet, the wrong version, a key ID length over 64, shorter
    than the tag, non-zero trailing bits, and empty.
  - The target's clock never moves, so authentic seeds stay valid.
  - To regenerate them, seal with the same keys and clock as `StateSealerFuzzTests`, then write each
    value as ISO-8859-1.
- **PEM:** armor variants of the Ed25519 and RSA fixtures (CRLF, surrounding whitespace, an
  encryption header, two blocks, a mismatched END label, one body line, a space in the body, an
  empty body, a non-ASCII label, no final newline), and the Ed25519 PKCS#8 key with a byte after
  it or inside its `privateKey` octets. The DER target's seeds are the DER bodies of ten of the TEST
  ONLY fixtures (one of them the certificate fixture with a trailing byte), an empty input, an
  indefinite-length `SEQUENCE`, and three PKCS#8 keys made from the fixtures: Ed25519 with a byte
  after the key, and Ed25519 and EC P-256 with a byte inside the `privateKey` octets. The JDK
  ignores that inner byte for EdDSA, and for EC before JDK 27, so only `Pem`'s own check rejects it.
  When the fixtures under `src/test/resources/fixtures/pem/` or `fixtures/keys/` change, rebuild
  these seeds from the new fixtures in the same change.
- **Encoding:** RFC 4648 vectors and their non-canonical, padded, misplaced-padding and wrapped
  variants, and the RFC 6749 Appendix B vector with malformed, truncated, overlong, surrogate and
  non-ASCII-digit escapes, raw CESU-8 surrogates and repeated query parameters.
- **JOSE tokens** (the compact and JwtValidator targets): every spelling of `none` with empty and
  non-empty signatures; `rs256`, `ES256K`, `RSA-OAEP` and a numeric `alg`; the JSON
  serialization; five, four and two segments; an empty header; padding, the standard alphabet, a
  4n + 1 segment, non-canonical trailing bits and a space; `crit`, `b64`, `zip`, `jku` (the
  configured URI), `jwk`, `x5u`, an ignored `x5c` and `cty`; `typ` of another profile, with a
  parameter, or a number; `kid` empty, of 257 characters, or a number; a duplicate `alg`, a
  byte-order mark and invalid UTF-8; RS256, PS256 and ES256 signatures of impossible lengths with
  an unknown `kid`, which must fail before key selection; and the RFC 7515 appendix A and RFC 8037
  appendix A.4 examples. The compact target also has tokens of exactly 64 and 65 characters for
  its 64-character limit.
- **JOSE headers** (the header target): each P4 to P8 rejection, and five headers that each hold
  every rejection from one step on (from `b64`, `zip`, the key references, `typ` and `cty`), so
  that the replay pins the order of P5 to P8; `typ` spellings (lower case, `application/`,
  parameters, two slashes, empty, non-ASCII, the Kelvin sign), `kid` at 256 and 257 UTF-16 code
  units, in surrogate pairs too, and with control and bidirectional characters, a byte-order mark
  and a lone surrogate.
- **JWK Sets:** each document failure (`keys` missing, null, not an array, an element that is not
  an object, a duplicate `keys` member, more elements than the tight limit, and 101 keys against
  the default limit of 100, next to 100 keys), each skip reason in a small document, `kid` values
  that `Jwk.toString` must escape, and the RFC 7515 appendix A, RFC 7517 appendix A.1 and
  RFC 8037 appendix A.2 public keys.
- **ECDSA:** empty, all-zero, all-ones and single-bit signatures of each curve's length, and two
  P-521 signatures whose DER form has 127 and 128 content octets, on each side of the long form.
- **Cache lifetime:** `max-age` of 5 s and 999,999,999 s, one hour, the 2<sup>31</sup> cap, quoted
  and quoted-pair arguments, conflicting and repeated `max-age`, every malformed element form,
  `no-store`, `no-cache` with an argument, the ignored directives, directive names in upper case,
  `Expires` in all three date forms and with a wrong day name, 30 February, a leap second, another
  zone, year 0, the RFC 9110 section 5.6.7 example dates, the RFC 850 century boundary, and `Age`
  in lists, over several lines and past the lifetime.
- **Signing programs** (the second JwtValidator target): each algorithm and damage kind, claim
  types and time boundaries, `cnf`, the Entra template with a lowercase and an uppercase `tid`,
  and a bare header, which the target signs with the key its `kid` names.

**`FuzzedDataProvider` seeds.** The JSON model factory target and the sealer's seal target read
`FuzzedDataProvider` construction programs, not documents, so their seeds are programs chosen to
reach particular oracles:

- for the model factory target, a kept `BigDecimal` subclass (`lying-bigdecimal-subclass.bin`), an
  unpaired surrogate in a `fromMembers` name (`unpaired-surrogate-member-name-in-a-map.bin`), and a
  zero at the exponent cap (`zero-at-the-exponent-cap-rescaled.bin`). Zero's adjusted exponent is
  minus its scale, so `0E-100000` is inside the model's exponent cap but the equal `0E-100001` is
  not; the target therefore rescales zero toward scale 0;
- for the seal target, a context at the 256-character limit that starts with a surrogate pair
  (`context-at-the-limit-starting-with-a-surrogate-pair.bin`). The target's "other context" replaces
  the first code point, because cutting one code unit could leave an unpaired surrogate, which is
  an invalid context rather than a different one.

`JwkFuzzTests#keysBuiltFromFuzzedIntegersAgreeWithTheCurveAndThumbprintOracle` and
`EcdsaFuzzTests#verdictsAgreeWithTheJdksFixedLengthEngine` start from programs kept from earlier
fuzzing corpora: for each key kind and each skip reason or usable outcome (46), and for each curve,
signature form (raw, signed, signed and damaged), verifying key and verdict (33), the shortest input
that reaches it, named for them, such as `rsa-weak-key.bin` or `p-384-damaged-signer-key-valid.bin`
(the high-S twin). They were classified by replaying each corpus input through the target's own
choice sequence.

A change to how a target consumes its `FuzzedDataProvider` turns these seeds into other programs.
Regenerate them by fuzzing until each oracle is reached again, for example against a scratch copy
of the main code with the matching defect planted.

**Seed inventories.** Several targets keep an inventory of their authored seeds. A `.sha256` file
lists each seed's path and SHA-256; a JSON inventory also records each seed's control bytes and
meaning. Files at the top of `fuzz/` sit next to this README; the others are under
`src/test/resources/com/revetsec/`.

| Inventory | Targets | Checked in the replay by |
|---|---|---|
| `oidc/oidc-seeds.sha256` | `OidcFuzzTests` | `FuzzSeedProvenanceTests` |
| `oauth/resource-server-seeds.sha256` | `ResourceServerFuzzTests` | `FuzzSeedProvenanceTests` (complete path set and bytes) |
| `m6-seeds.sha256`, with controls and meanings in `fuzz/m6-semantic-seeds.json` | `JwsSignerFuzzTests`, `ClientAssertionFuzzTests`, `EntraIssuerFuzzTests` | `FuzzSeedProvenanceTests` (the `.sha256` file) |
| `fuzz/as1-semantic-seeds.json` | `IssuerIngressFuzzTests`, `IssuerCodeFuzzTests` | `FuzzSeedProvenanceTests` |
| `fuzz/as1-g2-semantic-seeds.json` | `CimdFuzzTests`, `IssuerStoreFuzzTests` | `FuzzSeedProvenanceTests` |
| `fuzz/as1-g3-semantic-seeds.json` | `IssuerRefreshFuzzTests` | `FuzzSeedProvenanceTests` |
| `fuzz/as1-g4-semantic-seeds.json` | `IssuerSigningFuzzTests` | `FuzzSeedProvenanceTests` |
| `fuzz/selected-feature-fuzz-seeds.json` | `KeyImportsFuzzTests`, `SigningProfilesFuzzTests`, `WebAuthnCeremonyFuzzTests#checkedReauthenticationPreservesEntryContextAndEffectClasses`, and the ordinary fixtures under core `src/test/resources/fixtures/key-import-profile/` | `FuzzSeedProvenanceTests` (exact path set, count and hashes) |
| `saml/saml-post-logout-seeds.sha256` | the two `SamlLogoutFuzzTests` POST targets | `FuzzSeedProvenanceTests` |
| `scim/scim-seeds.sha256`, documented in `scim/SCIM-SEEDS.md` | `ScimSyntaxFuzzTests` | `ScimSeedProvenanceTests` |
| `scim/scim-m10-seeds.sha256`, documented in `scim/SCIM-M10-SEEDS.md` | `ScimM10FuzzTests` | inventory only |
| `scim/scim-m11-seeds.sha256`, documented in `scim/SCIM-M11-SEEDS.md` | `ScimM11FuzzTests` | `ScimM11SeedProvenanceTests` |
| `scim/scim-m12-seeds.sha256`, documented in `scim/SCIM-M12-SEEDS.md` | `ScimM12FuzzTests` | `ScimM12SeedProvenanceTests` |
| `scim/rc3-ingress-seeds.sha256`, with meanings in `fuzz/scim-rc3-ingress-seeds.json` | `ScimRc3IngressFuzzTests` | `ScimRc3IngressFuzzTests#authoredIngressSeedsMatchTheirCompleteManifest` (the `.sha256` file) |

The SCIM seed provenance checks run in both the normal and the main-sources-only builds.
`SCIM-SEEDS.md` also records the provenance of the syntax seeds, including all 17 RFC 7644 Figure 2
examples, and the narrow `$ref` syntax choice. `ScimSeedProvenanceTests`,
`ScimM11SeedProvenanceTests` and `ScimM12SeedProvenanceTests` also read their seed documents.

`fuzz/.gitattributes` marks `src/test/resources/**` as `-text`, because seeds hold CR, LF, NUL,
invalid UTF-8 and DER, and git must never rewrite them.

## Writing a target

- Put the class in `fuzz/src/test/java`, in the package of the code it exercises.
- Name the class `*FuzzTests`. Surefire here runs only `**/*FuzzTests.java`,
  `FuzzSeedLayoutTests`, `FuzzSeedProvenanceTests`, `FuzzNullabilityContractTests` and
  `com/revetsec/scim/*SeedProvenanceTests`, because the core test tree is compiled into this
  module but its tests (the contract tests included) belong to the root build.
  `.clusterfuzzlite/build.sh` looks only for the `*FuzzTests` classes. For the same reason, no
  class in the core test tree may be named `*FuzzTests`. Helpers such as `JsonFuzzSupport`,
  `JwtValidatorFuzzSupport` and `FuzzSeedGenerator` take any other name.
- Each `@FuzzTest` method becomes one ClusterFuzzLite target, named
  `<SimpleClassName>_<method>`. Target names must be unique across packages.
- Put curated seeds in `src/test/resources/<package>/<SimpleClassName>Inputs/<method>/`, or map a
  corpus from the core tree there through a `testResource` with a `targetPath` in the fuzz pom.
  Every target needs at least one seed. Renaming a `@FuzzTest` method or moving its class means
  updating its `targetPath` entries and moving its seed directory; `FuzzSeedLayoutTests` fails
  the replay until both match. A new `byte[]` target in `jose` or `internal.jose` also goes on one
  of `FuzzSeedLayoutTests`' two JOSE lists.
- Seeds made from fixtures or vendored files come from `FuzzSeedGenerator`, never by hand, so that
  `FuzzSeedProvenanceTests` can check them: a `generated-*` or `wycheproof-*` file that the
  generator does not make fails the replay. For other authored seeds, consider an inventory with
  SHA-256 like the existing ones (see "Seeds").
- Keep choice 0 of a `FuzzedDataProvider` target on the ordinary path. An exhausted input gives
  the minimum of every range, so a rare branch at 0 would absorb most short inputs.
- Never name a main-code record (such as `VerificationKey` or `ParsedJwks`) in the signature of
  a method of a target class; take `Object` and cast inside. Jazzer finds a target by reflecting
  over its class's declared methods, which loads every type their signatures name before fuzzing
  starts, and in ClusterFuzzLite's base image (its own Jazzer on Temurin 17.0.16) a record loaded
  that early fails on its first construction with `NoSuchFieldError` on one of its own fields.
  Locally, with Jazzer 0.30.0, the same target runs; `FuzzSeedLayoutTests` fails the replay
  instead, so the ClusterFuzzLite build check is not the first to show it.
- Annotate every reference parameter and return type with explicit JSpecify nullability, including
  arrays, generic arguments, wildcard bounds, constructors and record components; primitive and
  void types are exempt. `FuzzNullabilityContractTests` attributes every authored fuzz Java source
  with the replay classpath and enforces this in both the normal and the main-sources-only builds.
- Carry the Apache-2.0 header, a jsr305 thread-safety marker and the `@author` line, as the
  existing targets do. Name each method as a sentence stating its invariant, and cite the RFC or
  threat-model INV row it checks.

## Running locally

Replay every seed (Jazzer's regression mode), as CI's `fuzz-regression` job does:

```sh
mvn -B -ntp -f fuzz/pom.xml clean verify
```

Fuzz one method:

```sh
JAZZER_FUZZ=1 mvn -B -ntp -f fuzz/pom.xml test \
  -Dtest='JsonCodecFuzzTests#scimAcceptsOnlyWhatTheExactNameProfileAccepts' \
  -Djazzer.max_duration=5m \
  -Djazzer.internal.basedir="$(mktemp -d)" \
  -Djazzer.internal.arg.0=fuzz -Djazzer.internal.arg.1=-timeout=30
```

- **One fuzzed method per JVM.** Jazzer's JUnit integration fuzzes only one `@FuzzTest` per JVM, so
  select one method per invocation.
- **Parallel runs.** Give each run its own copy of the tree (without `target/`). Two Maven runs
  that share `fuzz/target` race each other.
- **Keep generated files out of the tree.** `jazzer.internal.basedir` points Jazzer's working
  files outside the checkout: its generated corpus (`.cifuzz-corpus/`) and any crash, timeout or
  OOM file. Without it, the corpus lands in `fuzz/.cifuzz-corpus/`, and crash files land in the
  method's source inputs directory, or in `fuzz/` for a method without one. `fuzz/.gitignore`
  covers all of these.
- **libFuzzer flags.** `jazzer.internal.arg.<n>` passes flags to libFuzzer: `.0` is `argv[0]` and
  `.1` onward are flags.
- **Agent attachment.** Jazzer must be able to attach its agent to the test JVM, and the Surefire
  `argLine` allows it. A denied attachment is a harness failure, not evidence about the code under
  test.

The replay runs on JDK 17 and newer; CI's gating replay uses JDK 21. On JDK 27, Jazzer 0.30.0's
bundled ASM cannot read Java 27 class files (major version 71), so it logs `Failed to instrument`
warnings for the JDK classes it hooks, such as `java.util.regex`. Use JDK 17 to 25 for fuzzing
sessions until a Jazzer release supports 27.

If the core test tree doesn't compile (for example while a change to it is in flight), build
against the main sources alone. No target needs anything from the core test tree:

```sh
mvn -B -ntp -f fuzz/pom.xml -Drevetsec.fuzz.mainSourcesOnly clean verify
```

After a change to the fixture keys, the key slots, the generated tokens' claims or the Wycheproof
selection, regenerate the generated seeds and commit the result (see "Seeds"); the replay's
`FuzzSeedProvenanceTests` fails until they match. The generator writes files but never deletes
one, so remove a `generated-*` or `wycheproof-*` seed it no longer makes by hand:

```sh
mvn -B -ntp -f fuzz/pom.xml test-compile
java -cp "fuzz/target/test-classes:fuzz/target/classes" com.revetsec.FuzzSeedGenerator .
```

## Corpus policy

Inputs checked in under `src/test/resources/**/<Class>Inputs/<method>/` are curated regression
seeds. They are reviewed, named for the behavior they cover, and small enough to replay on every
push and PR.

Generated fuzzing output is ignored by `fuzz/.gitignore`:

- `fuzz/target/`;
- `fuzz/.cifuzz-corpus/`, Jazzer's generated corpus;
- raw `crash-*`, `timeout-*`, `slow-unit-*` and `oom-*` files.

When a target finds a real crash, do not commit the raw file. Confirm the root cause and fix it,
then promote the reproducer into one or both of:

- a focused unit or regression test next to the affected code;
- a named seed that describes the behavior, such as `number-plain-canonical-form-longer-than-its-text.json`.

Seeds must never contain captured production requests, tokens, assertions, secrets, credentials
or personal data. They are synthetic protocol values and published test vectors, apart from the
Entra key sets that the pom maps in, which are Microsoft's published public keys as the core tree
captured them. The keys in seeds are the public halves of the TEST ONLY fixtures under
`src/test/resources/fixtures/`, keys the seed generator computes, Wycheproof's test keys (their
`private` members included) and RFC example public keys (see NOTICE). Generated tokens are signed
with the TEST ONLY fixtures, the Wycheproof and RFC tokens carry their sources' signatures, and
the signing targets sign with fuzz-only key pairs that `JwtValidatorFuzzTests` and
`EcdsaFuzzTests` generate from fixed seeds when they load; the sealer target's keys are fuzz-only
constants. The SAML and key-import targets read TEST ONLY fixtures from the core tree; the other
targets use fuzz-only constants or generate their keys at runtime, and never save them.

Passing replay, and fuzzing without findings, are bounded evidence and not proof of the absence
of bugs. They are not an independent security audit.

## ClusterFuzzLite

[ClusterFuzzLite](https://google.github.io/clusterfuzzlite/) runs the same targets in GitHub
Actions:

| Workflow | Trigger | What it does |
|---|---|---|
| `ci.yml`, job `fuzz-regression` | push, PR | Gating seed replay: `mvn -B -ntp -f fuzz/pom.xml verify` on JDK 21 |
| `cflite_pr.yml` | PR | Builds every target and fuzzes them within a shared time budget (`code-change` mode), starting from the batch corpus |
| `cflite_batch.yml` | nightly, manual | Batch fuzzing within a shared time budget, keeping the corpus in a separate storage repository |
| `cflite_cron.yml` | nightly, manual | Corpus pruning in that storage repository |

`FUZZ_SECONDS` is one budget shared by every target: 1,200 seconds for a PR run and 3,600 seconds
for a nightly batch run, with unused time redistributed. Each target's share therefore shrinks as
targets are added, and signing and verification targets execute fewer inputs than codec targets in
the same time. The batch and pruning workflows skip with a notice until the corpus storage
repository described in `cflite_batch.yml` is configured, and PR fuzzing then starts from the seeds
alone.

The build integration lives in `.clusterfuzzlite/`:

- `project.yaml`: `language: jvm`. JVM projects support only the `address` and `undefined`
  sanitizers, and the workflows use `address` alone, because Revetsec has no native code.
- `Dockerfile`: `gcr.io/oss-fuzz-base/base-builder-jvm:v1`, pinned by digest, plus Maven 3.10.0
  from Maven Central with its SHA-512 checked. `Dockerfile.dockerignore` keeps build output out of
  the context.
- `build.sh`: compiles this module with Maven (`test-compile`), then asks Jazzer to list the
  `@FuzzTest` methods of every `*FuzzTests` class (Jazzer's `--list_fuzz_tests` takes a
  `:`-separated class list). For each one it writes an executable wrapper
  `$OUT/<SimpleClassName>_<method>`, which runs the method through the base image's Jazzer driver
  (`--target_class`, `--target_method`). It also packs the method's seeds as
  `$OUT/<SimpleClassName>_<method>_seed_corpus.zip`.
  - The zip is built from `fuzz/target/test-classes/<package>/<SimpleClassName>Inputs/<method>/`,
    because the mapped corpora exist only there. The zip keeps subdirectories: two corpora can
    share a file name (`parse/` and `round-trip/` both hold `surrogate-pair.json`), and libFuzzer
    reads corpus directories recursively. ClusterFuzzLite's own fuzzing step unpacks the zip into
    sequentially numbered files in one directory, so the subdirectories matter for `run_fuzzer`,
    which extracts the zip with `unzip`, and for local replay.
  - `build.sh` fails if a target has no seeds, or if a seed directory names a method that Jazzer
    does not list (a renamed or removed target), checks that each zip holds every seed file, and
    prints the count per target.

  At runtime the targets use the base image's Jazzer (driver, agent and JUnit integration), and
  Maven's copies of Jazzer are left out so that two Jazzer versions are never mixed. After the zips
  are built, the build removes the seed directories from the runtime classpath copy. ClusterFuzzLite
  supplies them through the zip, and its build check needs a `-runs=4` start-up run to execute
  exactly four inputs.

**JDK.** The pinned `base-builder-jvm` image and the `clusterfuzzlite-run-fuzzers:v1` runner image
ship Temurin 17.0.16 as `$JAVA_HOME`. The ClusterFuzzLite docs still say OpenJDK 15, which is
stale. No extra JDK is installed; `build.sh` fails if the image's JDK is older than 17.

**Pins.** The workflows do not use the google/clusterfuzzlite actions. `cflite_pr.yml`,
`cflite_batch.yml` and `cflite_cron.yml` run `gcr.io/oss-fuzz-base/clusterfuzzlite-build-fuzzers:v1`
and `clusterfuzzlite-run-fuzzers:v1` directly as `docker://` steps, pinned by digest, with the
environment that the v1 actions' `action.yml` passes (see the header of `cflite_batch.yml`).
Dependabot watches the `base-builder-jvm` digest in `.clusterfuzzlite/Dockerfile`, but not the
`docker://` step digests: move those by hand, in all three workflows, in the same PR as the
`base-builder-jvm` bump. Choose images outside the seven-day cooldown that `.github/dependabot.yml`
applies, rather than a floating tag's newest rebuild. Maven 4 release candidates are not used.

### Reproducing the ClusterFuzzLite build locally

JVM fuzzing in OSS-Fuzz and ClusterFuzzLite is x86_64 only. On an arm64 machine, pass
`--platform linux/amd64` and Docker runs the images under emulation. From the repository root:

```sh
# 1. Build the builder image (the context is the repository root).
docker build --platform linux/amd64 -t revetsec-cflite -f .clusterfuzzlite/Dockerfile .

# 2. Run the build, as ClusterFuzzLite's `compile` step does.
mkdir -p /tmp/revetsec-cflite-out
docker run --rm --platform linux/amd64 \
  -e FUZZING_ENGINE=libfuzzer -e SANITIZER=address -e FUZZING_LANGUAGE=jvm -e ARCHITECTURE=x86_64 \
  -v /tmp/revetsec-cflite-out:/out revetsec-cflite compile

# 3. Run ClusterFuzzLite's build checks, then fuzz one target for 20 seconds, in the runner image.
docker run --rm --platform linux/amd64 \
  -e FUZZING_ENGINE=libfuzzer -e SANITIZER=address -e FUZZING_LANGUAGE=jvm -e ARCHITECTURE=x86_64 \
  -e OUT=/out -e RUN_FUZZER_MODE=batch -e FUZZER_ARGS='-rss_limit_mb=2560 -timeout=25' \
  -v /tmp/revetsec-cflite-out:/out --entrypoint /bin/bash \
  gcr.io/oss-fuzz-base/clusterfuzzlite-run-fuzzers:v1 -c '
    python3 /usr/local/bin/test_all.py &&
    mkdir -p /tmp/corpus &&
    run_fuzzer JsonCodecFuzzTests_scimAcceptsOnlyWhatTheExactNameProfileAccepts \
      -max_total_time=20 /tmp/corpus'
```

- **Offline builds.** Step 1 downloads Maven. To build without network access, use an existing
  `base-builder-jvm` image, mount a host Maven installation at `/opt/maven` and a populated Maven
  repository read-only, and run `compile` with `--network none`,
  `-e MVN=/opt/maven/bin/mvn -e MAVEN_ARGS=-o`. Pass `--pull never` to keep Docker from fetching
  images.
- **Emulation timeouts.** Under emulation, `test_all.py` can time out several targets when it
  checks them all in parallel; it then retries them one at a time, and they pass.
- **Seed counts.** libFuzzer leaves empty seeds out of its count, so a target can report fewer
  seeds than its zip holds.
