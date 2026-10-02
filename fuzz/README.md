# Revetsec Fuzz Tests

This module holds Revetsec's [Jazzer](https://github.com/CodeIntelligenceTesting/jazzer) fuzz
targets. It has its own `pom.xml`, the root build never sees it, and it is never published: the
pom skips `install` and `deploy` and builds no jar. Fuzzing dependencies therefore stay out of the
published `com.revetsec:revetsec` artifact, which keeps zero runtime dependencies.

The module compiles Revetsec's sources directly, the same way Soklet's `fuzz/` does:

- `../src/main/java` as main sources;
- `../src/test/java` and `../src/test/resources` as test sources and resources, so targets can
  reuse test helpers, fixtures and (from M7) the SAML mutator. Two groups of files are left out:
  Failsafe integration tests (`**/*IT.java`), the Testcontainers-backed scripted-IdP classes
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

No target uses a core test helper, and neither do the seed generator and the two seed checks
(below), so the module also builds with `-Drevetsec.fuzz.mainSourcesOnly`.

Versions: Jazzer 0.30.0 (as in Soklet's `fuzz/`) and JUnit 6.1.3 through the JUnit BOM, on Java
17 or newer. The BOM aligns Jazzer's transitive JUnit Platform modules with the explicit API,
engine and launcher dependencies. Without it, older Platform classes stay on the test classpath
and a run can fail before any input executes.

## Targets

M1 deleted the M0 placeholder (`PlaceholderFuzzTests`, which exercised no Revetsec code) and added
six classes with twelve `@FuzzTest` methods. M2 added five classes with nine methods, for the JOSE
layer, the fixed-length ECDSA path and the key-set cache lifetime. M3 added four OAuth input targets,
M4 added four OIDC targets, and M5 adds six resource-server targets, so there are now fourteen classes and thirty-five methods. Each method is one ClusterFuzzLite target, named
`<SimpleClassName>_<method>`.

| Class (package) | Method | Input | What it checks |
|---|---|---|---|
| `JsonCodecFuzzTests` (`internal.json`) | `parseRejectsOnlyWithJsonParseExceptionAndAcceptsOnlyValuesInsideTheProfile` | JSON bytes | Under `protocolDocument` (4 MiB), `jose` (1 KiB), `scim` (10 MiB, 1,000 nodes), a tight profile (below) and the maximum-cap profile: only `JsonParseException`, with its Kind's message, no cause and an offset inside the input. `INPUT_SIZE`, `BOM` and `INVALID_UTF8` exactly when they apply, in that order, and `INVALID_UTF8` at the offset where the JDK's strict decoder stops. An accepted document is inside every limit of its profile, on the value (depth, nodes, string length, digits, canonical number length, adjusted exponent) and on the text (each number's length and written exponent, found by a lexer written here). It holds only exact `BigDecimal`s and well-formed strings, and equals what the maximum-cap profile parses. |
| | `acceptedValuesRoundTripUnderTheMaximumCapProfile` | JSON bytes | Whatever a profile accepts, `toJson()` parses back under the maximum-cap profile to an equal value with an equal hash, and the canonical text is a fixed point. It also parses under the accepting profile whenever it fits that profile's byte limit. |
| | `scimAcceptsOnlyWhatTheExactNameProfileAccepts` | JSON bytes | SCIM accepts exactly what its exact-name twin accepts without ASCII case-variant names (see below). Up to eight accepted objects are also retried, each with one added near-miss of the first member name that holds an ASCII letter: that letter with its case flipped, which SCIM must reject, and `ı`, `İ`, the Kelvin sign or the long s in its place, which SCIM must keep apart. |
| `JsonModelFuzzTests` (`json`) | `factoriesAcceptExactlyTheValuesInsideTheModelInvariants` | `FuzzedDataProvider` | Drives the public factories and `JsonObject.Builder` with unpaired surrogates, oversized numbers, lying `BigDecimal` subclasses, repeated builder names and nesting past 64. Each call succeeds exactly when an oracle for G7-6 says so, and otherwise throws `IllegalArgumentException` with the fixed message of the first failed check. Accepted values keep their invariants, equal a rebuilt copy with members reversed and numbers rescaled (with an equal hash), and round-trip through the codec unless a canonical number is over 4,096 characters, which is then `NUMBER_LENGTH`. |
| | `parsedValuesKeepEqualityUnderReorderingAndRescaling` | JSON bytes | For what the maximum-cap profile parses: equality and hashing ignore member order and number scale, a changed leaf breaks equality, arrays are ordered, `toString()` is redacted, and `find`, `findString`, `findLong`, `findBoolean` and `findStringList` agree with `getMembers()`. |
| `Rfc7638FuzzTests` (`internal.json`) | `canonicalJwkAgreesWithAnIndependentEncoder` | JSON bytes | For every object in the document, `canonicalJwk` gives exactly the bytes, or exactly the `JsonFieldException` Kind, of an encoder written from RFC 7638 section 3. The result ignores member order and is a fixed point. |
| `StateSealerFuzzTests` (root) | `unsealRejectsEverythingButAuthenticValuesWithOneFixedException` | sealed text | `StateSealer.unseal` throws only the one `InvalidSealedStateException` (fixed message, no cause, nothing suppressed, the same stack trace whichever step failed), and `SealedStateAccess` only `UnsealException`, `INVALID`, or `EXPIRED` for a value that opens at an earlier time. Nothing longer than the 3,800-character maximum opens. A value that opens is bound to its label, context, key and expiry, and one changed character makes it fail. It also opens, to the same plaintext, under an implementation of the v1 construction written in the target (see below). |
| | `sealedValuesOpenOnlyUnchangedUnderTheirOwnLabelContextAndTime` | `FuzzedDataProvider` | Seals fuzzed plaintexts under fuzzed contexts, labels, lifetimes and expiry instants. Each value has the v1 length and opens with the same plaintext until its notAfter, then reports `EXPIRED`, and the target's own v1 implementation opens it to the same plaintext and notAfter. It fails under every other label, under a longer context and under a different context of the same length, and after any edit, and it opens after the next rotation step only while its key is held. An invalid `seal` throws `IllegalArgumentException` with the first failed check's message, never the plaintext or context. |
| `PemFuzzTests` (`internal.pem`) | `pemParsersRejectOnlyWithPemExceptionAndAcceptAtMostOneLabel` | PEM text | The three parsers throw only `PemException` with its Kind's message. At most one of them accepts a text, and the other two reject it with `UNSUPPORTED_LABEL`. Accepted values re-parse from the JDK's own encoding. An accepted body is exactly one DER `SEQUENCE`, and a PKCS#8 body's `privateKey` octets hold exactly one element, both checked with a DER reader written in the target. |
| | `derParsersRejectOnlyWithPemExceptionAndAgreeWithTheirArmoredForms` | DER bytes | `parseCertificateDer` and all four labels over the same DER throw only `PemException`, and the certificate parser gives the same outcome with and without armor. Where the target's DER reader finds no minimal definite-length `SEQUENCE`, all five fail with `MALFORMED_DER`, and where bytes follow it, all five fail with `TRAILING_DATA`. An accepted PKCS#8 key's `privateKey` octets hold exactly one element. |
| `EncodingFuzzTests` (`internal.encoding`) | `base64DecodersAcceptExactlyTheCanonicalEncodings` | text and octets | `Base64Url`, `StandardBase64` and `SamlBase64` agree with an RFC 4648 oracle: the exact octets, or the exact Kind of the first failed check, so each octet string has one accepted encoding. Every encoding round-trips, and a line-wrapped one also round-trips through `SamlBase64`. |
| | `urlAndUtf8CodecsMatchTheirOraclesExactly` | octets, also read as text | `StrictUtf8`, `PercentDecoding`, `FormUrlEncoding` and `QueryParameters` agree with oracles written from RFC 3629, RFC 3986 and RFC 6749 Appendix B. `FormUrlEncoding` also agrees with `URLDecoder` where it accepts and with `URLEncoder` for well-formed input. Query parameters survive re-encoding. |
| `CompactJwsFuzzTests` (`internal.jose`) | `compactSerializationsSplitIntoThreeCanonicalSegmentsOrFailInStepOrder` | token text | `CompactJwsParser.parse` under two maximum lengths, then `JwtProcessor.prepare` under three header policies (M2 plan, "JOSE semantics" steps 1 to 5): the oracle's decoded segments and the received signing input, or the reason of the first failed step, from `TOKEN_TOO_LARGE` through `JSON_SERIALIZATION`, `TOKEN_SYNTAX`, `ENCRYPTED_TOKEN` and the header reasons to `SIGNATURE_MALFORMED`. An empty payload or signature passes the split (M2-6). Every `JoseFailure` names only its reason, with no cause and no stack trace. |
| | `headerChecksAgreeWithAnIndependentOracleForP3ToP8` | JSON bytes | `JoseHeaderPolicy.check` under three policies against a P3 to P8 oracle with its own table of `alg` wire values and its own `typ` normalization: `HEADER`, `ALGORITHM_NOT_ALLOWED` (every spelling of `none`), `CRITICAL_HEADER`, `UNENCODED_PAYLOAD`, `COMPRESSED_PAYLOAD`, `UNTRUSTED_KEY_REFERENCE`, `INVALID_TYPE` and `NESTED_TOKEN`, in that order, or the header's algorithm, `kid` and raw `typ`. For every string in the header, `normalizeType`, `allowsType` and `JwsAlgorithm.findByWireValue` agree with the oracle. |
| `JsonWebKeyFuzzTests` (`internal.jose`) | `keySetDocumentsSkipExactlyTheKeysAnIndependentOracleRefuses` | JSON bytes | `JwkSetParser` under the default and tight limits: `KEY_SET` exactly for the oracle's document failures, and otherwise every key kept or skipped with the reason of the first of the plan's twelve key rules it breaks, at its index (M2-7). Every object in the document also goes through `JwkParser` alone. A kept key has the oracle's `kid`, `kty`, `crv`, `alg`, `use`, JWK `issuer`, RFC 7638 thumbprint and JCA key values. `JsonWebKeySet.fromJson` agrees on the same text, escapes the `kid` in `toString`, and a `StaticJsonWebKeySource` needs one usable key. |
| | `keysBuiltFromFuzzedIntegersAgreeWithTheCurveAndThumbprintOracle` | `FuzzedDataProvider` | Builds the JWKs that byte mutation seldom reaches: RSA moduli of chosen sizes and parity, some built to carry the ROCA fingerprint for every prime or for all but one; exponents at their bounds; EC points computed on the curve, moved off it, or past the field prime; Ed25519 small-order points, `y` at or past the field prime, and `x = 0` with the sign bit; encodings that are not minimal or not the curve's length; every optional member, valid and invalid. `JwkParser`, and a one-key document through `JwkSetParser`, give the oracle's verdict. |
| `JwtValidatorFuzzTests` (`jose`) | `validateAcceptsOnlyWhatTheJdkVerifiersAccept` | token text | Three validators over the TEST ONLY fixture keys' public halves (see below). A token is accepted only if the JDK's own verifier for its algorithm accepts its signature with the one key the selection rules pick, and every header and claim rule passes; then it carries exactly the oracle's claims. A rejection has the reason of the oracle's first failed step, in that reason's exception class, with its fixed message, no cause, never transient, and `didFailToValidateJwt` gets the same instance. |
| | `signedTokensAreJudgedLikeTheOracleWhateverTheirHeaderAndClaims` | signing program | The same validators and oracle over fuzz-only keys. The input spells a header and a payload, which the target signs and may then damage (a flipped bit, a byte cut or added, a zeroed or emptied signature, the high-S twin, `r` of 0 or `n`, another key's signature, a changed payload, padding), so fuzzed headers and claims reach the checks after the signature. |
| `EcdsaFuzzTests` (`internal.crypto`) | `shapeCheckAndDerEncodingAgreeWithTheRangeRuleAndAnX690Reader` | signature octets | For each curve, `EcdsaSignatures.findShapeFailure` gives RFC 7518 section 3.4's verdict (the exact length, then `1 <= r, s <= n - 1` over the curve orders the JDK names). `toDer` refuses a signature of the wrong length and otherwise gives a minimal DER `SEQUENCE` that an X.690 reader written here reads back to `r` and `s`. `SignatureVerifier.verifyEcdsa` decides the shape before it looks at the key (G8-3, CVE-2022-21449). |
| | `verdictsAgreeWithTheJdksFixedLengthEngine` | `FuzzedDataProvider` | `SignatureVerifier.verifyEcdsa` is `VALID` exactly when the JDK's fixed-length engine (`SHAxxxwithECDSAinP1363Format`, which the main code never uses) accepts a signature of the exact length with `r` and `s` in range, under a key on the curve. Signatures come from the fuzzer, or are signed here and damaged: `r` or `s` set to 0, 1, `n - 1`, `n`, `n + 1`, the field prime or all ones, the high-S twin (which is valid), swapped halves, a byte cut or added, halves padded to another curve's length, or the DER form. Curve and hash are chosen separately. |
| `CacheLifetimeFuzzTests` (`internal.http`) | `timeToLiveIsTotalClampedAndAgreesWithAnRfc9111Oracle` | header lines | `CacheLifetime.timeToLive` never throws, stays within its bounds, and equals an oracle for its RFC 9111 subset (M2-8 "TTL": list splitting with quoted strings, the `cache-directive` grammar, `no-store`, `no-cache`, `max-age` and its 2<sup>31</sup> cap, `Expires` minus `Date`, `Age`) for three receipt times and three sets of bounds. `HttpDate.parse` and `parseSingleField` agree with a regular-expression reading of RFC 9110 section 5.6.7's three forms and its two-digit-year rule. |
| `OAuthFuzzTests` (`oauth`) | `callbackKeepsSingletonsAndRedactsInput` | callback query bytes | An accepted callback has at most one of each protocol singleton, never both code and error, and redacts its input; malformed input yields a typed fixed-reason exception. |
| | `tokenJsonKeepsSecretsOutOfGenericMembers` | token JSON bytes | An accepted access token is printable ASCII, and token members never enter the generic JSON view; malformed or error bodies yield typed exceptions. |
| | `metadataRequiresExactIssuer` | metadata JSON bytes | An accepted document retains the configured issuer exactly; malformed or mismatched documents yield typed exceptions. Endpoint URI safety is checked when the client loads the document. |
| | `formBodyRoundTripsUnicodeAndReservedCharacters` | form value bytes | The OAuth writer and query decoder preserve arbitrary Latin-1 code points through UTF-8 form encoding without emitting raw line breaks. |
| `OidcFuzzTests` (`oidc`) | `signedClaimsRespectInitialAndRefreshProfiles` | JSON claim bytes | JDK HMAC signs every input to reach post-signature checks. An independent profile oracle checks exact issuer and single audience, subject, NumericDates/skew, nonce, ACR, authentication age, hashes and refresh continuity; only fixed OIDC exceptions escape. |
| | `metadataRequiresExactIssuerAndCapabilities` | metadata JSON bytes | Accepted remote metadata keeps exact issuer and required `code`/RS256/subject capabilities. No explicit defaults are applied; URI safety remains the client's separate outbound-policy check. |
| | `userInfoRequiresTheVerifiedSubject` | UserInfo JSON bytes | Acceptance agrees exactly with a separate check of the verified subject; malformed or different subjects produce fixed OIDC reasons. |
| | `sessionReferencesRoundTripWithoutCredentials` | reference JSON bytes | Accepted trusted-storage references stay within 64 KiB, round-trip canonically, retain only continuity fields and stay redacted. This parser does not authenticate storage or create identity. |

| `ResourceServerFuzzTests` (`oauth`) | `bearerPresentationMatchesTheHeaderGrammar` | Authorization field bytes | A separate RFC 6750 regexp oracle checks scheme, one to 58 spaces, b64token, trailing padding and configured 8 KiB credential/64-byte prefix caps. Empty, single and identical-duplicate lists exercise throwing and result APIs; no parsed credential is called verified. |
| | `challengesEscapeAndBoundTrustedParameters` | trusted parameter bytes | Separate printable-ASCII, description and quoted-string rendering rules check exact escaping and the 1 KiB post-expansion field cap. Input controls/non-ASCII and quote/backslash description values reject. |
| | `formPostMimeMatchesIndependentFieldGrammar` | raw MIME field bytes | A separate quote-aware field grammar checks one form field, empty parameters, case-insensitive names, duplicate parameters, quoted-pairs and absent/UTF-8 charset. A fixed synthetic callback isolates MIME from callback parsing; duplicate fields always reject. |
| | `metadataKeepsRolesAndRawResourceIdentifiers` | metadata JSON or resource URI bytes | Separate role projection rules check exact issuer, required role endpoint syntax and optional authentication-method typing/uniqueness. Configured protected-resource values retain raw path/query/case/dot segments, derive the well-known location without normalization, deduplicate configured lists and stay within the JSON cap. Foundational `HostClassifier` supplies the separately tested loopback classification; endpoint fetching/SSRF/DNS are outside this target. |
| | `signedAccessTokensRespectStrictAndUntypedProfiles` | JSON claim bytes | JDK Ed25519 signs arbitrary input under typed, absent, JWT and unrelated explicit profiles. A separate claim oracle checks issuer, audience, required typed claims, NumericDates and zero-skew edges, confirmation refusal, scope grammar, the extra compatibility claim and untyped identity-claim substitution. Both accepted and rejected verdicts are checked. |
| | `introspectionResponsesAreTypedAudienceCheckedAndUncached` | JSON response bytes | The public client uses an offline synthetic `HttpClient`, with no socket or executor. A separate oracle distinguishes malformed provider documents from local inactive/profile rejection and verified proof. Each syntactically valid first response is followed by a fresh inactive response to the same credential; two authenticated POSTs and an inactive second verdict prove the client did not reuse the first proof. |

The M4 semantic seeds under `com/revetsec/oidc/OidcFuzzTestsInputs` use test-only values and a fixed
2026-09-30 clock. `oidc-seeds.sha256` inventories every authored seed and is checked by
`FuzzSeedProvenanceTests`. All four targets also receive the two core JSON corpora through Maven
resource mappings, checked by `FuzzSeedLayoutTests`. The signed-claims target uses an explicit
HMAC compatibility profile for speed; existing JOSE targets and M4 unit tests cover asymmetric
signatures and signed UserInfo. It signs arbitrary payload bytes and evaluates both initial
and refresh profiles; it does not fuzz the browser flow or call a network endpoint.


The M5 resource-server seeds use only synthetic test values and a fixed 2026-10-01 clock.
`com/revetsec/oauth/resource-server-seeds.sha256` inventories all 236 authored seeds; the complete
path set and bytes are checked by `FuzzSeedProvenanceTests`. The role-metadata, signed-profile and
introspection targets also receive both complete core JSON corpora through resource mappings,
checked by `FuzzSeedLayoutTests`. The Ed25519 key is ephemeral and generated within each target
JVM; curated inputs hold claim bytes, never a private key or a pre-signed production credential.
No core test helper is needed in the main-sources-only build. The synthetic HTTP transport delivers
bodies directly to the normal public client's body subscriber without network requests, and
records method, endpoint, authentication presence and request count. Real TLS, provider clocks,
backoff/races and opaque-token revocation remain core regression/integration checks.

### Invariants shared by every target

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
  only from `StaticJsonWebKeySource.fromJsonWebKeySet` for a set with no usable key. A static key
  source never throws `JsonWebKeySetUnavailableException`, so one would be a finding too.
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
    ClusterFuzzLite job today.
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

`StateSealerFuzzTests` opens every value that opens with the v1 construction as the M1 plan states
it ("StateSealer v1"), written in the target on the JDK's `HmacSHA256` and `AES/GCM/NoPadding`, apart
from Revetsec's `Hkdf` and `AesGcm`: PRK from the master key, the message key from the label and
salt, and the additional authenticated data from the header, the label and the context. A black-box
check cannot see the label in the key derivation, because the label is also in the additional
authenticated data, so a wrong label fails either way. This comparison sees it, for every fuzzed
plaintext, context and label, where `SealerV1Tests` pins four known-answer vectors.

### The JOSE validators and keys

`JwtValidatorFuzzTests` checks every token with three validators over one key set:

- one for `https://issuer.example.com` that allows the eleven asymmetric algorithms, expects
  `https://api.example.com`, requires `sub` and `client_id`, and allows the default 60 seconds of
  skew;
- one for a made-up Entra tenant that allows `RS256`, `ES256` and `EdDSA`, accepts any audience,
  requires `typ` from `JWT` and `at+jwt`, allows no skew and caps tokens at 8,192 characters;
- one for the same tenant spelled in upper case, with the defaults and any audience. The Entra
  `{tenantid}` template stands only for a lowercase `tid` (M2-11), so it must never serve this
  issuer.

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

The plan's wording is "whatever SCIM accepts, EXACT also accepts". No type in the code is called
`EXACT`. The term is the "Names: exact" column of the profile table in `JsonLimits`, meaning
`isAsciiCaseVariantNamesRejected() == false`: only identical member names are duplicates. That
rule belongs to `protocolDocument`, `jose` and the maximum-cap profile. SCIM also rejects names
that differ only in ASCII case (G7-7).

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

## Seeds

Seeds live in each method's Jazzer inputs directory, `<package>/<SimpleClassName>Inputs/<method>/`
on the test class path. Jazzer replays every file there, including files in subdirectories. Two
sources fill it.

**Mapped corpora.** The fuzz pom copies these into the inputs directories through Maven resource
`targetPath`, so they are never duplicated in the tree. They exist only under
`fuzz/target/test-classes`.

| Source (core `src/test/resources/`) | Files | Mapped into |
|---|---|---|
| `com/revetsec/internal/json/corpus/parse/` and `round-trip/`: the 25 files ported from Soklet plus the protocol-shaped seeds, `.bin` files included | 30 | the five JSON-text methods (`parse/`, `round-trip/`) |
| `vectors/jsontestsuite/test_parsing/`: JSONTestSuite at `1ef36fa0`, one file name containing `#` | 318 | the same five methods (`jsontestsuite/`) |
| `com/revetsec/internal/json/corpus/`, `vectors/jsontestsuite/test_parsing/` (the same files) | 30 and 318 | the two JOSE JSON-text methods, `CompactJwsFuzzTests#headerChecksAgreeWithAnIndependentOracleForP3ToP8` and `JsonWebKeyFuzzTests#keySetDocumentsSkipExactlyTheKeysAnIndependentOracleRefuses` |
| `com/revetsec/jose/entra/2026-09-27/*-keys.json`: the captured Entra key sets, with `x5c` chains and templated `issuer` members | 5 | `JsonWebKeyFuzzTests#keySetDocumentsSkipExactlyTheKeysAnIndependentOracleRefuses` (`entra/`) |
| `com/revetsec/internal/json/corpus/`, `vectors/jsontestsuite/test_parsing/` | 30 and 318 | all four OIDC JSON methods and the three M5 role-metadata, signed-profile and introspection JSON methods |
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

The tree's generated seeds were written on 2026-09-28 with Corretto 21.0.11, from the repository
root, after `test-compile`:

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
The generator writes them too.

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
  that `JsonWebKey.toString` must escape, and the RFC 7515 appendix A, RFC 7517 appendix A.1 and
  RFC 8037 appendix A.2 public keys.
- **ECDSA:** empty, all-zero, all-ones and single-bit signatures of each curve's length, and two
  P-521 signatures whose DER form has 127 and 128 content octets, on each side of the long form.
- **Cache lifetime:** exit criterion 15's `max-age` rows (5 s, 999,999,999 s), one hour, the
  2<sup>31</sup> cap, quoted and quoted-pair arguments, conflicting and repeated `max-age`, every
  malformed element form, `no-store`, `no-cache` with an argument, the ignored directives,
  directive names in upper case, `Expires` in all three date forms and with a wrong day name, 30
  February, a leap second, another zone, year 0, the RFC 9110 section 5.6.7 example dates, the
  RFC 850 century boundary, and `Age` in lists, over several lines and past the lifetime.
- **Signing programs** (the second JwtValidator target): each algorithm and damage kind, claim
  types and time boundaries, `cnf`, the Entra template with a lowercase and an uppercase `tid`,
  and a bare header, which the target signs with the key its `kid` names.

The JSON model factory target and the sealer's seal target read `FuzzedDataProvider` construction
programs, not documents, so their seeds are
reproducers: of the two target defects that the first fuzzing round found (see "M1 local
fuzzing"), and, for the model factory target, of two planted model defects (a kept `BigDecimal`
subclass, `lying-bigdecimal-subclass.bin`, and an unpaired surrogate in a `fromMembers` name,
`unpaired-surrogate-member-name-in-a-map.bin`), so that the replay reaches those oracles too. A
change to how a target consumes its `FuzzedDataProvider` turns these seeds into other programs;
regenerate them by fuzzing the planted defect again. The two M2 `FuzzedDataProvider` targets
(`JsonWebKeyFuzzTests#keysBuiltFromFuzzedIntegersAgreeWithTheCurveAndThumbprintOracle` and
`EcdsaFuzzTests#verdictsAgreeWithTheJdksFixedLengthEngine`) start from programs kept from their
2026-09-28 fuzzing sessions' corpora: for each key kind and each skip reason or usable outcome (46),
and for each curve, signature form (raw, signed, signed and damaged), verifying key and verdict
(33), the shortest input that reaches it, named for them, such as `rsa-weak-key.bin` or
`p-384-damaged-signer-key-valid.bin` (the high-S twin). They were classified by replaying each
corpus input through the target's own choice sequence.

`fuzz/.gitattributes` marks `src/test/resources/**` as `-text`, because seeds hold CR, LF, NUL,
invalid UTF-8 and DER, and git must never rewrite them.

## Writing a target

- Put the class in `fuzz/src/test/java`, in the package of the code it exercises.
- Name the class `*FuzzTests`. Surefire here runs only `**/*FuzzTests.java`,
  `FuzzSeedLayoutTests` and `FuzzSeedProvenanceTests`, because the core test tree is compiled into
  this module but its tests
  (the contract tests included) belong to the root build. `.clusterfuzzlite/build.sh` looks only
  for the `*FuzzTests` classes. For the same reason, no class in the core test tree may be named
  `*FuzzTests`. Helpers such as `JsonFuzzSupport`, `JwtValidatorFuzzSupport` and
  `FuzzSeedGenerator` take any other name.
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
  generator does not make fails the replay.
- Keep choice 0 of a `FuzzedDataProvider` target on the ordinary path. An exhausted input gives
  the minimum of every range, so a rare branch at 0 would absorb most short inputs.
- Never name a main-code record (such as `VerificationKey` or `ParsedKeySet`) in the signature of
  a method of a target class; take `Object` and cast inside. Jazzer finds a target by reflecting
  over its class's declared methods, which loads every type their signatures name before fuzzing
  starts, and in ClusterFuzzLite's base image (its own Jazzer on Temurin 17.0.16) a record loaded
  that early fails on its first construction with `NoSuchFieldError` on one of its own fields.
  Locally, with Jazzer 0.30.0, the same target runs; `FuzzSeedLayoutTests` fails the replay
  instead, so the ClusterFuzzLite build check is not the first to show it (see below).
- Carry the Apache-2.0 header, a jsr305 thread-safety marker and the `@author` line, as the
  existing targets do. Name each method as a sentence stating its invariant, and cite the plan
  item, RFC or INV row it checks.

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

Replay passes on JDK 17, 21, 25 and 27. On JDK 27, Jazzer 0.30.0's bundled ASM cannot read Java 27
class files (major version 71), so it logs `Failed to instrument` warnings for the JDK classes it
hooks, such as `java.util.regex`. Use JDK 17 to 25 for fuzzing sessions until a Jazzer release
supports 27.

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

### M1 local fuzzing

Every method was fuzzed in Jazzer fuzzing mode on arm64 macOS, each in its own copy of the tree,
with `-timeout=30` and Jazzer's working files outside the checkout. The first round (2026-09-24)
ran each method for 330 seconds on Corretto 21.0.11. The final round (2026-09-25) ran the targets
as they are now: 330 seconds per method on Corretto 21.0.11, all twelve at once, then 180 seconds
per method on Corretto 17.0.20.1.

| Target | First round, 21 | Final, 21 (330 s) | Final, 17 (180 s) |
|---|---:|---:|---:|
| `JsonCodecFuzzTests_parseRejectsOnlyWithJsonParseExceptionAndAcceptsOnlyValuesInsideTheProfile` | 8,587,371 | 2,189,151 | 1,258,960 |
| `JsonCodecFuzzTests_acceptedValuesRoundTripUnderTheMaximumCapProfile` | 9,213,110 | 2,537,587 | 1,287,610 |
| `JsonCodecFuzzTests_scimAcceptsOnlyWhatTheExactNameProfileAccepts` | 3,977,628 | 4,139,124 | 2,970,752 |
| `JsonModelFuzzTests_factoriesAcceptExactlyTheValuesInsideTheModelInvariants` | 5,730,769 | 3,099,783 | 1,836,723 |
| `JsonModelFuzzTests_parsedValuesKeepEqualityUnderReorderingAndRescaling` | 3,985,080 | 6,517,126 | 5,924,775 |
| `Rfc7638FuzzTests_canonicalJwkAgreesWithAnIndependentEncoder` | 2,329,286 | 5,231,574 | 1,404,121 |
| `StateSealerFuzzTests_unsealRejectsEverythingButAuthenticValuesWithOneFixedException` | 7,352,306 | 3,910,077 | 2,430,865 |
| `StateSealerFuzzTests_sealedValuesOpenOnlyUnchangedUnderTheirOwnLabelContextAndTime` | 3,835,580 | 1,461,468 | 810,506 |
| `PemFuzzTests_pemParsersRejectOnlyWithPemExceptionAndAcceptAtMostOneLabel` | 16,197,758 | 9,115,866 | 5,966,792 |
| `PemFuzzTests_derParsersRejectOnlyWithPemExceptionAndAgreeWithTheirArmoredForms` | 2,052,204 | 1,918,316 | 1,155,356 |
| `EncodingFuzzTests_base64DecodersAcceptExactlyTheCanonicalEncodings` | 11,224,171 | 7,168,504 | 4,027,074 |
| `EncodingFuzzTests_urlAndUtf8CodecsMatchTheirOraclesExactly` | 1,293,957 | 997,583 | 659,447 |

The numbers are executions. The final round found nothing, and no run found a defect in
Revetsec's main code. The first round found two defects in the targets themselves, both fixed, and
each reproducer is kept as a named seed:

- **The model target's rescaled copy.** Zero's adjusted exponent is minus its scale. So
  `0E-100000` is inside the model's exponent cap, but the equal `0E-100001` is not, and rescaling
  a zero away from scale 0 could leave the cap. The target now rescales zero toward scale 0
  (`zero-at-the-exponent-cap-rescaled.bin`). The model's behavior matches G7-6 as written.
- **The sealer target's "other context".** At the 256-character limit, the target cut the first
  code unit off a context, which could leave an unpaired surrogate: an invalid context, not a
  different one. It now replaces the first code point
  (`context-at-the-limit-starting-with-a-surrogate-pair.bin`).

**Planted defects.** To check that the targets detect what they claim to, defects were planted in
scratch copies of the main code, one at a time, and the seed replay was run against each:

- Before the first round, seven: a `JsonParseException` message that echoes the offset;
  `Base64Url` without its canonical-form check; `StateSealer.unseal` letting an internal failure
  escape; percent decoding that accepts non-ASCII digits; SCIM names compared exactly, or folded
  with `String.toLowerCase`; and the codec's canonical-number-length check removed. The replay
  failed on all seven, the last two only after the SCIM near-miss names and the number seeds were
  added.
- In review, 35 targeted defects: each codec limit letting one more through; the BOM, duplicate
  and SCIM name checks weakened; the model's caps, equality, copy, surrogate and builder-duplicate
  checks weakened; the RFC 7638 escape rule; the sealer's length and expiry checks and its single
  failure path; the label left out of the sealer's key derivation; the context left out of its
  additional authenticated data (by length, or by bytes); PEM's two trailing-data checks removed
  and one of its catches narrowed; and two encoding rules. The replay failed on 34. The tight profile, the number-text lexer, the
  one-past-a-limit seeds, the sealer's own v1 implementation and same-length context, and the PEM
  DER reader and PKCS#8 seeds were added for those.
- The survivor narrows the catch in `Pem.parseCertificateDer` to `CertificateException`, so a
  `RuntimeException` from the JDK's certificate factory would escape. No input is known that makes
  Corretto 17 or 21 throw one, and the DER target did not find one in 4.8 million inputs over 10
  minutes on 17 with the defect planted. Jazzer does not instrument the JDK's X.509 code, so
  coverage cannot steer toward one. The target still reports any exception other than
  `PemException` as a finding.

### M2 local fuzzing

Every M2 method was fuzzed the same way on 2026-09-28, each in its own copy of the tree: 330 seconds
per method on Corretto 21.0.11, all nine at once, then 210 seconds per method on Corretto 17.0.20.1.
Three targets were fuzzed again, and their rows give the last session: the two
`FuzzedDataProvider` targets after their choice order changed (choice 0, which an exhausted input
gives, now takes the ordinary path, where it had taken a rare one), and the two `JsonWebKeyFuzzTests`
targets after their helpers stopped naming records in their signatures (see "Writing a target").
In review, the two `JwtValidatorFuzzTests` targets were fuzzed once more the same way (all four
sessions at once), after their key set gained five slots, and their rows give that session. The
seeds the review added (see "Planted defects (M2)") changed no other target's code. The first
target now also starts from seeds of 8,192 and 8,193 characters, which raise libFuzzer's input
length limit from 4,096 bytes, so it runs fewer, longer inputs than before.

| Target | 21 (330 s) | 17 (210 s) |
|---|---:|---:|
| `CompactJwsFuzzTests_compactSerializationsSplitIntoThreeCanonicalSegmentsOrFailInStepOrder` | 11,403,269 | 8,932,078 |
| `CompactJwsFuzzTests_headerChecksAgreeWithAnIndependentOracleForP3ToP8` | 4,345,714 | 2,913,392 |
| `JsonWebKeyFuzzTests_keySetDocumentsSkipExactlyTheKeysAnIndependentOracleRefuses` | 621,287 | 374,124 |
| `JsonWebKeyFuzzTests_keysBuiltFromFuzzedIntegersAgreeWithTheCurveAndThumbprintOracle` | 2,889,353 | 1,929,494 |
| `JwtValidatorFuzzTests_validateAcceptsOnlyWhatTheJdkVerifiersAccept` | 4,124,988 | 2,767,915 |
| `JwtValidatorFuzzTests_signedTokensAreJudgedLikeTheOracleWhateverTheirHeaderAndClaims` | 411,064 | 236,196 |
| `EcdsaFuzzTests_shapeCheckAndDerEncodingAgreeWithTheRangeRuleAndAnX690Reader` | 29,372,437 | 19,157,972 |
| `EcdsaFuzzTests_verdictsAgreeWithTheJdksFixedLengthEngine` | 221,792 | 143,333 |
| `CacheLifetimeFuzzTests_timeToLiveIsTotalClampedAndAgreesWithAnRfc9111Oracle` | 1,004,951 | 790,303 |

The numbers are executions; the targets that sign, verify or build keys run slowest. No run found a
defect in Revetsec's main code or in a target, and no crash, timeout or out-of-memory file was
written.

**Planted defects (M2).** Forty-seven defects were planted in scratch copies of the main code, one
at a time, and the seed replay of the affected targets was run against each. On the final targets
and seeds it failed on all 47:

- compact serialization and header: `rs256` read as `RS256`; `none`, in any case, read as `RS256`;
  `jku` not treated as a key reference; base64url padding accepted; four dots not recognized as an
  encrypted token; an empty signature segment refused; a leading brace not recognized as the JSON
  serialization; `typ` parameters stripped before the comparison; a 257-character `kid` accepted;
  `cty` ignored; an empty `crit` array ignored;
- signature shape: the ECDSA range check skipped; a DER ECDSA signature passed to the JCA; the RSA
  length bound before key selection dropped; the exact RSA modulus length not checked; the DER
  `SEQUENCE` given the long form from 64 octets;
- key selection: an RSA key without `alg` fitting every RSA algorithm; the first of two candidate
  keys used; a key without `kid` matching every `kid`;
- claims: the audience check dropped; `exp` plus the skew still valid; `cnf` ignored; `iss`
  compared ignoring case; `aud: []` counted as absent; a required claim of JSON `null` counted as
  present; an uppercase `tid` substituted into the Entra template, which only the third validator
  (for an uppercase tenant) catches, and which survived until it was added;
- keys: the Ed25519 decoding skipped; the small-order check skipped; a JWK `issuer` that is not a
  string counted as absent; the ROCA check skipped; leading zero octets in `n` or `e` accepted; the
  exponent floor lowered to 3; the on-curve check skipped; an `x5c` certificate of another key
  accepted; `key_ops` without `verify` accepted; `use` not checked; `ES384` on a P-256 key accepted;
  one element over the key limit accepted;
- cache lifetime and dates: the first of two conflicting `max-age` values used; `no-cache`
  ignored; `Age` not subtracted; `Age`'s last list member used; the day name not checked against
  the date; no century fallback for an RFC 850 year; a leap second refused; a quoted-pair not
  unescaped; the 2<sup>31</sup> cap lowered by one.

In review, 36 more defects were planted the same way. The replay failed on 15 of them at once. The
other 21 survived it, because no seed reached them and, for the first five, no key in the
JwtValidator targets' key set could: the `EdDSA`/`Ed25519` alias between a key's `alg` and the
token's dropped, in either direction or both; a shared `kid` answered by its first fitting key, or
ambiguous even when only one key fits; `iat` at exactly the skew refused; a `cnf` of JSON `null`
ignored; a `jti` that is not a string accepted; a token of exactly the maximum length refused; a
validator's own maximum token length ignored for the default; the ROCA check without its first
or its last prime; moduli of 2,047 or 16,385 bits accepted; a JWK `kid` of 256 characters refused;
the small-order check blind to Ed25519's points of order 8; an EC coordinate equal to the field
prime accepted; `zip` checked before `b64`; `Cache-Control` directive names compared
case-sensitively; the DER `SEQUENCE` given the short form at 128 content octets; and
`JsonWebKeySet.fromJson` accepting 101 keys. The key slots and the seeds described above were
added for them, and the replay now fails on all 36, and still on the first 47.

The key-set cache's own behavior (cooldowns, backoff, a removed key, stale keys) is outside these
targets, which verify over static key sources; the core tests cover it.

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
constants.

Passing replay, and fuzzing without findings, are bounded evidence and not proof of the absence
of bugs.

## ClusterFuzzLite

[ClusterFuzzLite](https://google.github.io/clusterfuzzlite/) runs the same targets in GitHub
Actions:

| Workflow | Trigger | What it does |
|---|---|---|
| `ci.yml`, job `fuzz-regression` | push, PR | Gating seed replay: `mvn -B -ntp -f fuzz/pom.xml verify` on JDK 21 |
| `cflite_pr.yml` | PR | Builds every target and fuzzes them within a shared time budget (`code-change` mode), starting from the batch corpus |
| `cflite_batch.yml` | nightly, manual | Batch fuzzing within a shared time budget, keeping the corpus in a separate storage repository |
| `cflite_cron.yml` | nightly, manual | Corpus pruning in that storage repository |

`FUZZ_SECONDS` is one budget shared by every target. M0 set it for a single placeholder target,
and the workflows (`.github/`) raise it as targets are added: twelve in M1, twenty-one from M2. Each
target gets at least its share, so the M2 JOSE targets, which sign or verify, execute fewer inputs
in their share than the codec targets. The batch and pruning
workflows skip with a notice until the corpus storage repository described in `cflite_batch.yml`
is configured, and PR fuzzing then starts from the seeds alone.

The build integration lives in `.clusterfuzzlite/`:

- `project.yaml`: `language: jvm`. JVM projects support only the `address` and `undefined`
  sanitizers, and the workflows use `address` alone, because Revetsec has no native code.
- `Dockerfile`: `gcr.io/oss-fuzz-base/base-builder-jvm:v1`, pinned by digest, plus Maven 3.9.16
  from Maven Central with its SHA-512 checked. `Dockerfile.dockerignore` keeps build output out of
  the context.
- `build.sh`: compiles this module with Maven (`test-compile`), then asks Jazzer to list the
  `@FuzzTest` methods of every `*FuzzTests` class. For each one it writes an executable wrapper
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

**JDK.** On 2026-09-23 both `base-builder-jvm` (digest `sha256:5eaa9b0d…`) and the runner image
`clusterfuzzlite-run-fuzzers:v1` (digest `sha256:4c1febe9…`) shipped Temurin 17.0.16+8 as
`$JAVA_HOME`. The ClusterFuzzLite docs still say OpenJDK 15, which is stale. No extra JDK is
installed; `build.sh` fails if the image's JDK is older than 17.

**Pins.** The workflows do not use the google/clusterfuzzlite actions. `cflite_pr.yml`,
`cflite_batch.yml` and `cflite_cron.yml` run `gcr.io/oss-fuzz-base/clusterfuzzlite-build-fuzzers:v1`
and `clusterfuzzlite-run-fuzzers:v1` directly as `docker://` steps, pinned by digest, with the
environment that the v1 actions' `action.yml` passes (see the header of `cflite_batch.yml`).
Dependabot watches the `base-builder-jvm` digest in `.clusterfuzzlite/Dockerfile`, but not the
`docker://` step digests: move those by hand, in all three workflows, in the same PR as the
`base-builder-jvm` bump.

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

This build was also run offline on an arm64 Mac under emulation, in the local `base-builder-jvm`
image (digest `sha256:5eaa9b0d…`), on 2026-09-24 and again on 2026-09-25 with the final targets.
Step 1 downloads Maven, so it was replaced by mounting the host's Maven 3.9.16 at `/opt/maven` and
its Maven repository read-only, with `--network none`, `-e MVN=/opt/maven/bin/mvn -e MAVEN_ARGS=-o`
and `compile`. The results of the final run:

- `compile` built all twelve targets. The seed zips held 363, 352 and 354 seeds for the three
  `JsonCodecFuzzTests` targets, 348 and 362 for the other two JSON-text targets, 45 and 15 for PEM,
  17 and 1 for the sealer, 16 each for encoding, and 3 for the model factory target.
- The runtime copy held no inputs directories.
- `test_all.py` passed in the runner image (`clusterfuzzlite-run-fuzzers:v1`, `sha256:4c1febe9…`).
  Under emulation, five targets timed out when all twelve were checked in parallel, and passed when
  test_all retried them one at a time; the first run saw the same.
- A 30-second `run_fuzzer` of each run found nothing:
  `JsonCodecFuzzTests_scimAcceptsOnlyWhatTheExactNameProfileAccepts` on 2026-09-24 loaded all 354
  seeds from its zip and executed 320,815 inputs, and
  `PemFuzzTests_derParsersRejectOnlyWithPemExceptionAndAgreeWithTheirArmoredForms` on 2026-09-25
  loaded all 15 seeds from its zip and executed 95,702 inputs.

The first M1 run (2026-09-24) also found a defect that M0's single target had hidden. `build.sh`
passed the class list to `--list_fuzz_tests` separated by commas, but Jazzer splits that value on
`:`. With more than one class, Jazzer read the whole list as one class name and listed no targets,
so the build failed. `build.sh` now joins the list with `:`.

The same offline build was run on 2026-09-28 with the twenty-one M2 targets:

- `compile` built all twenty-one. The runtime copy held no inputs directories, and it kept
  `com/revetsec/jose/fixture-key-set.json`.
- The first run's `test_all.py` passed its threshold but reported one broken target: both JWK
  targets crashed on their first key with `NoSuchFieldError` on a field of `VerificationKey`, a
  record that the target's method signatures had made Jazzer load early (see "Writing a target").
  After the signatures changed, `test_all.py` reported no broken target; under emulation twelve
  targets timed out when all were checked in parallel, and passed when test_all retried them one
  at a time.
- A 20-second `run_fuzzer` of
  `JsonWebKeyFuzzTests_keysBuiltFromFuzzedIntegersAgreeWithTheCurveAndThumbprintOracle` loaded its
  seeds from its zip and executed 76,847 inputs, and one of
  `JwtValidatorFuzzTests_validateAcceptsOnlyWhatTheJdkVerifiersAccept` executed 109,373. Neither
  found anything.
- After the review's key slots and seeds, the build was run once more the same way, on the same
  day. `compile` built all twenty-one targets. The M2 seed zips held 153 and 396 seeds for the
  compact and header targets, 466 and 46 for the two JWK targets, 240 and 26 for the two
  JwtValidator targets, 61 and 33 for the two ECDSA targets, and 60 for the cache lifetime target.
  `test_all.py` passed with no broken target, again after retrying twelve targets one at a time,
  and 20-second `run_fuzzer` runs of the two JwtValidator targets executed 71,249 and 12,336
  inputs and found nothing. libFuzzer counted 238 seeds for the first of them, two fewer than its
  zip holds: the two it left out are empty, the `jws` values of Wycheproof's JWS tcIds 13 and 30.

### Explicit helper signatures

`FuzzNullabilityContractTests` attributes every authored fuzz Java source with the actual replay classpath. Both normal
and main-sources-only builds enforce explicit JSpecify on reference parameters and returns, including arrays, generic
arguments, wildcard bounds, constructors and record components. Nullable oracle alternatives and optional fixture
members retain their actual meaning. Primitive/void types are exempt. This guard is an ordinary regression test; the
35 semantic fuzz target inventory is unchanged.
