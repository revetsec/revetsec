# Revetsec Fuzz Tests

This module holds Revetsec's [Jazzer](https://github.com/CodeIntelligenceTesting/jazzer) fuzz
targets. It has its own `pom.xml`, the root build never sees it, and it is never published: the
pom skips `install` and `deploy` and builds no jar. Fuzzing dependencies therefore stay out of the
published `com.revetsec:revetsec` artifact, which keeps zero runtime dependencies.

The module compiles Revetsec's sources directly, the same way Soklet's `fuzz/` does:

- `../src/main/java` as main sources;
- `../src/test/java` and `../src/test/resources` as test sources and resources, so targets can
  reuse test helpers, fixtures and (from M7) the SAML mutator. Two groups of files are left out:
  Failsafe integration tests (`**/*IT.java`) and the Testcontainers-backed scripted-IdP classes
  (`com/revetsec/saml/ScriptedIdp*`). Nothing here needs Docker or Testcontainers.

`build-helper-maven-plugin` cannot filter the test sources it adds, so the compiler's
`testExcludes` does the filtering. The excluded files stay on javac's source path. If an included
file ever references one of them, javac compiles it implicitly and the build fails on the missing
Testcontainers classes. That failure is deliberate.

Because the targets sit in the packages they exercise, they can use package-private hooks. The M1
targets use these:

- `JsonLimits.maximumCaps()` and the `JsonLimits` constructor (for SCIM's exact-name twin and the
  tight profile), reached through the helper `com.revetsec.internal.json.JsonFuzzSupport` in this
  module;
- the input-size caps `JsonLimits.PROTOCOL_DOCUMENT_INPUT_BYTES_CAP` and `SCIM_INPUT_BYTES_CAP`;
- `JsonInvariants.depthOf` in `com.revetsec.json`.

None of the M1 targets uses a core test helper, so they also build with
`-Drevetsec.fuzz.mainSourcesOnly`.

Versions: Jazzer 0.30.0 (as in Soklet's `fuzz/`) and JUnit 6.1.3 through the JUnit BOM, on Java
17 or newer. The BOM aligns Jazzer's transitive JUnit Platform modules with the explicit API,
engine and launcher dependencies. Without it, older Platform classes stay on the test classpath
and a run can fail before any input executes.

## Targets

M1 deleted the M0 placeholder (`PlaceholderFuzzTests`, which exercised no Revetsec code) and added
six classes with twelve `@FuzzTest` methods. Each method is one ClusterFuzzLite target, named
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
- **Fixed messages, no input echo.** A checked failure's message must equal its Kind's own fixed
  message. The model's and the sealer's `IllegalArgumentException` messages must be the fixed
  message of the first failed check; for a seal lifetime, that is the `Limits` row's own message,
  which names the lifetime but never the plaintext or context. So no message can echo the input,
  and the check needs no sentinel.
- **Bounded work.** Every accepted JSON document is measured by a separate walker and number
  lexer and must stay inside its profile's limits; a document never yields more values than it
  has bytes. libFuzzer's `-timeout` stops a slow input:
  - locally, with `-timeout=30` as below, libFuzzer writes a `timeout-*` file and ends the test
    JVM, so the Maven run fails;
  - ClusterFuzzLite passes `-timeout=25`, but reports a timeout only when its `REPORT_TIMEOUTS`
    setting is on (here, the `REPORT_TIMEOUTS` environment variable of the workflows' `docker://`
    run step). It is off by default and the M1 workflows do not set it, so a slow input does not
    fail a ClusterFuzzLite job today.
- **Oracles, not self-comparison.** Where a target predicts a result, the prediction comes from
  code written here from the specification: its own walker, ASCII fold, Base64 and
  percent-decoding, DER reader (X.690), and StateSealer v1 implementation. It never calls the code
  under test to decide what that code should do.

### The sealer's independent v1 implementation

`StateSealerFuzzTests` opens every value that opens with the v1 construction as the M1 plan states
it ("StateSealer v1"), written in the target on the JDK's `HmacSHA256` and `AES/GCM/NoPadding`, apart
from Revetsec's `Hkdf` and `AesGcm`: PRK from the master key, the message key from the label and
salt, and the additional authenticated data from the header, the label and the context. A black-box
check cannot see the label in the key derivation, because the label is also in the additional
authenticated data, so a wrong label fails either way. This comparison sees it, for every fuzzed
plaintext, context and label, where `SealerV1Tests` pins four known-answer vectors.

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
| `fixtures/pem/` and `fixtures/keys/`: the TEST ONLY PEM fixtures | 33 | `PemFuzzTests#pemParsersRejectOnlyWithPemExceptionAndAcceptAtMostOneLabel` (`fixtures-pem/`, `fixtures-keys/`) |

The core build checks the two JSON corpora against their SHA-256 manifests
(`JsonCorpusManifestTests`, `JsonTestSuiteTests`), so the fuzz module carries no second manifest
for them. The TEST ONLY PEM and key fixtures have no SHA-256 manifest. `PemTests` checks them only
through its parsing and key-pair assertions, so an edit to one of them changes the PEM target's
seeds without failing any test.

`FuzzSeedLayoutTests` checks the layout in the replay: every inputs directory belongs to a
`@FuzzTest` method of its class, every `@FuzzTest` method has at least one seed, every `byte[]`
target in a JSON package is mapped, and each mapped target holds every file of its mapped corpora,
unchanged (for a JSON-text method, all 30 core corpus files and all 318 JSONTestSuite files).
Renaming or moving a target therefore fails the replay, and the ClusterFuzzLite build, until its
`targetPath` entries and seed directory move with it.

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

The two `FuzzedDataProvider` methods read construction programs, not documents, so their seeds are
reproducers: of the two target defects that the first fuzzing round found (see "M1 local
fuzzing"), and, for the model factory target, of two planted model defects (a kept `BigDecimal`
subclass, `lying-bigdecimal-subclass.bin`, and an unpaired surrogate in a `fromMembers` name,
`unpaired-surrogate-member-name-in-a-map.bin`), so that the replay reaches those oracles too. A
change to how a target consumes its `FuzzedDataProvider` turns these seeds into other programs;
regenerate them by fuzzing the planted defect again.

`fuzz/.gitattributes` marks `src/test/resources/**` as `-text`, because seeds hold CR, LF, NUL,
invalid UTF-8 and DER, and git must never rewrite them.

## Writing a target

- Put the class in `fuzz/src/test/java`, in the package of the code it exercises.
- Name the class `*FuzzTests`. Surefire here runs only `**/*FuzzTests.java` and
  `FuzzSeedLayoutTests`, because the core test tree is compiled into this module but its tests
  (the contract tests included) belong to the root build. `.clusterfuzzlite/build.sh` looks only
  for the `*FuzzTests` classes. For the same reason, no class in the core test tree may be named
  `*FuzzTests`. Helpers such as `JsonFuzzSupport` take any other name.
- Each `@FuzzTest` method becomes one ClusterFuzzLite target, named
  `<SimpleClassName>_<method>`. Target names must be unique across packages.
- Put curated seeds in `src/test/resources/<package>/<SimpleClassName>Inputs/<method>/`, or map a
  corpus from the core tree there through a `testResource` with a `targetPath` in the fuzz pom.
  Every target needs at least one seed. Renaming a `@FuzzTest` method or moving its class means
  updating its `targetPath` entries and moving its seed directory; `FuzzSeedLayoutTests` fails
  the replay until both match.
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
against the main sources alone. The M1 targets need nothing from the core test tree:

```sh
mvn -B -ntp -f fuzz/pom.xml -Drevetsec.fuzz.mainSourcesOnly clean verify
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

Seeds are synthetic protocol values only. They must never contain captured production requests,
tokens, assertions, secrets, credentials or personal data. Test keys come only from the test-only
material under `src/test/resources/fixtures/`, and the sealer target's keys are fuzz-only
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
and it is raised in the workflows (`.github/`) for the twelve M1 targets. The batch and pruning
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

The first run also found a defect that M0's single target had hidden. `build.sh` passed the class list
to `--list_fuzz_tests` separated by commas, but Jazzer splits that value on `:`. With more than one
class, Jazzer read the whole list as one class name and listed no targets, so the build failed.
`build.sh` now joins the list with `:`.
