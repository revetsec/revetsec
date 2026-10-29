# RC-1 comparator profiles and differences

Observed locally on 2026-10-14. This ledger describes the exact configured test
profiles; it does not assert that different libraries have identical defaults.
The Maven pins are test-only. RSA/EC verification shares JCA providers; Nimbus's
Ed25519 path uses Tink. The original protected header and signed input are never
rewritten to make an oracle accept a different algorithm.

These original observations are retained below. The
[2026-10-28 dependency refresh](#2026-10-28-dependency-refresh) records the current
pins and the two changed JSON corpus verdicts separately.

| Input or capability | Revetsec | Nimbus 10.10 | jose4j 0.9.7 | Disposition |
|---|---|---|---|---|
| RS256/384/512, PS256/384/512, ES256/384/512, EdDSA positive fixture | Accept | Accept | Accept | Same checked subject, issuer, audiences and expiry. |
| RFC 9864 `Ed25519` positive fixture | Accept | Accept | Reject | jose4j does not register this fully specified algorithm name. Its ordinary EdDSA path is tested separately; no protected-header alias is installed. |
| `jku`, `x5u` or embedded `jwk` header | Reject | Accept with the configured fixed key | Accept with the configured fixed key, except unsupported Ed25519 | Revetsec's JWT profile rejects header-selected key material/locations. Both oracle harnesses use the explicit trusted key and perform no URL lookup. |
| JWT `cnf` | Reject | Accept | Accept, except unsupported Ed25519 | Revetsec's bearer verifier excludes confirmation-bound credentials. The generic JWT oracle profiles do not enforce that bearer rule. |
| Present JSON-null `exp` | Reject | Accept | Reject | Nimbus's configured required-claim set checks claim presence, while its expiration-time accessor returns null and skips the time comparison. Revetsec requires a valid NumericDate; null never releases proof. |
| Changed signed input, wrong key, truncated/absent signature, extra/missing segments | Reject | Reject | Reject | Every original fixture receives every probe. |
| Wrong issuer/audience, expired/missing expiry, future nbf, unknown critical header, none, unallowed algorithm | Reject | Reject | Reject | Fixed-clock matched issuer/audience/expiry policies. |
| Duplicate protected alg or aud, wrong protected/payload root, string expiry, numeric issuer/audience | Reject | Reject | Reject | Duplicate names are rejected after unescaping; the original signed carrier is retained. |

Each of 32 JOSE fixtures receives 28 changes, in addition to its original checked
identity comparison. Two negative controls prove that the projection detects a
signature-verdict disagreement and a changed signed subject. Synthetic fixture
keys are public test keys; these are no account-backed provider observations.

The JSON corpus ledger is
[`json-corpus-verdicts.tsv`](src/test/resources/rc1/json-corpus-verdicts.tsv).
It covers all 318 vendored inputs. Of these, 298 have the same accept/reject
verdict; every shared acceptance has an equal typed tree. The 20 differences are
all Revetsec rejections and Jackson acceptances:

| Disposition | Inputs | Reason |
|---|---:|---|
| `BOUNDED_EXPONENT` | 3 | Revetsec's protocol profile bounds written and adjusted exponents to magnitude 10,000; Jackson can expose these numeric spellings as BigDecimal. |
| `UNICODE_SCALAR_MODEL` | 10 | Revetsec rejects unpaired escaped UTF-16 surrogates, including member names. Jackson exposes those UTF-16 code units. |
| `STRICT_UTF8_PROFILE` | 6 | Three UTF-16 auto-detection inputs and three invalid UTF-8 inputs (encoded surrogate, code point beyond Unicode range, overlong two-byte sequence). Revetsec validates UTF-8 before tokenization. |
| `UTF8_BOM_PROFILE` | 1 | Revetsec rejects a leading UTF-8 BOM; Jackson consumes it. |

For `n_structure_null-byte-outside-string.json` (`5b 00 5d`), adding a leading or
trailing NUL makes Jackson auto-detect UTF-16 and expose `[]`. Revetsec rejects
both carriers. Those two mutation verdicts are explicit; the remaining 952
framing mutations are rejected by both. No byte carrier is recoded for agreement.

The two upstream `y_` files containing duplicate object names are rejected by
both configured parsers, following Revetsec's existing `DEVIATIONS.txt` and
Jackson's explicit strict-duplicate setting. The six accepted upstream `i_`
large-number cases preserve exact BigDecimal values; no double conversion or
precision rounding is used. The vendored `I_DECISIONS.txt` retains Revetsec's
original intended profile decisions.

Primary pin sources checked on 2026-10-14: [Nimbus release metadata](https://repo.maven.apache.org/maven2/com/nimbusds/nimbus-jose-jwt/maven-metadata.xml),
[jose4j upstream tags](https://bitbucket.org/b_c/jose4j/downloads/?iframe=true&spa=0&tab=tags),
[Jackson 2.18.8 release](https://github.com/FasterXML/jackson/wiki/Jackson-Release-2.18.8),
[Tink 1.23.0 release](https://github.com/tink-crypto/tink-java/releases/tag/v1.23.0).
Nimbus's published POM selects optional Tink 1.23.0; the dedicated dependency
makes that verifier available without adding it to core.

## 2026-10-28 dependency refresh

The current standalone comparator pins Jackson-core 2.22.4 and Tink 1.24.0;
Nimbus 10.10 and jose4j 0.9.7 are unchanged. All 930 JOSE and 1,310 JSON cases
passed on JDK 17 and 21 with zero failures, errors or skips. The complete-case
report verifier passed on both JDKs.

Jackson 2.22.4 rejects two corpus inputs that Jackson 2.18.8 accepted:

| Input | Current Revetsec | Current Jackson | Disposition |
|---|---|---|---|
| `i_object_key_lone_2nd_surrogate.json` | Reject | Reject | An escaped unpaired surrogate in a member name is now rejected by both parsers. |
| `i_string_UTF8_surrogate_U+D800.json` | Reject | Reject | The UTF-8 byte sequence encoding a surrogate is now rejected by both parsers. |

The current TSV therefore has 300 shared verdicts and 18 differences: three
bounded-exponent inputs, nine Unicode-scalar model inputs, five strict-UTF-8
inputs and the BOM input. Explicit high- and low-surrogate member-name controls
also reject in both parsers. Jackson still exposes escaped unpaired UTF-16 units
in string values; that model difference remains asserted. No core parser policy
or accepted typed tree changed to obtain agreement.
