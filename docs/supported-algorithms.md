# Supported Algorithms

**Status: JWS verification.** Revetsec verifies signed JWTs (milestone M2), and this page covers the algorithms and keys that verification accepts. The other areas below are added as they land, and the page is complete before 1.0.0.

Algorithms come from allowlists configured on the validating object, never from the message being validated. Names are compared exactly: JOSE `alg` values case-sensitively, and XML Signature and XML Encryption algorithms as exact URIs.

Each table has three kinds of entry:

- **Default:** accepted without configuration.
- **Opt-in:** accepted only after the application names it explicitly, sometimes as a [compatibility mode](compatibility-modes.md).
- **Never:** rejected under every configuration.

## JWS signature algorithms (`JwtValidator`)

| `alg` | Status | Key | Verified as (JCA name) | Signature length |
|---|---|---|---|---|
| `RS256` | Default | RSA | `SHA256withRSA` | the key's modulus length |
| `RS384`, `RS512` | Opt-in | RSA | `SHA384withRSA`, `SHA512withRSA` | the key's modulus length |
| `PS256`, `PS384`, `PS512` | Opt-in | RSA | `RSASSA-PSS` with SHA-256, SHA-384 or SHA-512, MGF1 with the same hash, a salt of 32, 48 or 64 octets and trailer field 1 (RFC 7518 section 3.5) | the key's modulus length |
| `ES256`, `ES384`, `ES512` | Opt-in | EC on P-256, P-384 or P-521, one curve each | `SHA256withECDSA`, `SHA384withECDSA`, `SHA512withECDSA`, over a DER encoding that Revetsec builds from the JWS signature | exactly 64, 96 or 132 octets |
| `Ed25519` (RFC 9864), `EdDSA` (RFC 8037) | Opt-in | OKP on Ed25519 | `Ed25519` | exactly 64 octets |
| `HS256`, `HS384`, `HS512` | Never in `JwtValidator` | none | | |
| `none`, in any case, and any other value | Never | | | |

- **Opt-in** means naming the algorithm in `JwtValidator.Builder.allowedAlgorithms`, which replaces the default: `Set.of(JwsAlgorithm.RS256, JwsAlgorithm.ES256)` allows exactly those two. An empty set is refused. Allow only the algorithms your identity provider signs with.
- **Matching is exact.** `rs256` is not `RS256`. In the allowlist, `Ed25519` and `EdDSA` are two separate algorithms: allowing one does not allow the other. They are aliases only between a key's `alg` and the token's `alg`, on an Ed25519 key.
- **HMAC.** `JwtValidator` verifies only with public keys, so `build()` throws `IllegalArgumentException` for an allowlist that names an HMAC algorithm. `JwsAlgorithm` represents them for OpenID Connect ID tokens signed with a client secret, which are planned as an opt-in with a secret at least as long as the hash output (32, 48 or 64 octets; RFC 7518 section 3.2).
- **`none`** cannot be represented: there is no `JwsAlgorithm` for it, and a well-formed token with `alg: none` fails with `ALGORITHM_NOT_ALLOWED`, whether its signature segment is empty or not. So do `dir`, `RSA1_5`, the PBES2 algorithms, `ES256K` and every other value.
- **The signature's shape is checked before any key is looked up,** so a malformed signature never causes a key set fetch. An ECDSA signature must be exactly 64, 96 or 132 octets, with r and s from 1 to n - 1, the check for CVE-2022-21449; Revetsec makes it itself, on every Java runtime and with any provider. An Ed25519 signature must be 64 octets. An RSA signature must be 256 to 2,048 octets, the modulus lengths the key rules allow, and after the key is selected exactly its modulus length. Anything else is `SIGNATURE_MALFORMED`.
- **Why DER for ECDSA.** Revetsec checks the fixed-length form itself and then verifies through the standard `SHAxxxwithECDSA` names, which works with any JCA provider, including hardware-backed and approved-mode ones. The exact-length check is needed either way: the JDK's own fixed-length (P1363) verifier accepts some signatures that are too short, and without the check a zero-padded signature would verify through DER.

## Keys (JSON Web Keys)

A key set is parsed key by key. A key that breaks a rule is skipped, with a `JsonWebKeySkipReason` that a remote key source reports to `JoseObserver.didSkipJsonWebKey`, and is never used, not even for its public half. Only the document itself (not JSON, no `keys` array, an element of `keys` that is not an object, too large, too many keys) fails a key set.

| Key | Status | Rules |
|---|---|---|
| RSA (`kty: RSA`) | Accepted | A modulus of 2,048 to 16,384 bits, odd, and without the ROCA fingerprint (CVE-2017-15361). A public exponent `e` that is odd, at least 65,537 and below 2^32. `n` and `e` in minimal Base64urlUInt form, with no leading zero octet. |
| EC (`kty: EC`) | Accepted on P-256, P-384 and P-521 | Coordinates of exactly 32, 48 or 66 octets, each below the field prime, for a point on the curve, checked before the JCA builds the key, because the JCA accepts points off the curve. |
| OKP (`kty: OKP`) | Accepted on Ed25519 | `x` of 32 octets that decodes to a curve point (RFC 8032 section 5.1.3) of more than small order. |
| Symmetric (`kty: oct`) | Never | Skipped as `SYMMETRIC_KEY`. |
| Any key with private members (`d`, `p`, `q`, `dp`, `dq`, `qi`, `oth`, `k`) | Never | Skipped as `PRIVATE_KEY_MEMBERS`. |
| Other curves (such as secp256k1, Ed448, X25519 and X448) and other key types | Never | Skipped as `UNSUPPORTED_CURVE` or `UNSUPPORTED_KEY_TYPE`, unless an earlier rule gives another reason (below). |

A key is also skipped when its `use` is not `sig`, its `key_ops` does not include `verify`, its `alg` names an algorithm Revetsec does not have or one for another key type or curve, its `kid` is not a string of 1 to 256 characters, or its `x5c` certificate does not parse or holds another key. [`JsonWebKeySkipReason`](../src/main/java/com/revetsec/jose/JsonWebKeySkipReason.java) lists the 13 reasons and the fixed order in which the checks run. When a key breaks more than one rule, the first check that fails names the reason: `use` and `key_ops` come before `alg`, and `alg` before `crv`. So a secp256k1 key with `alg: ES256K` (RFC 8812), or an X25519 key with `alg: ECDH-ES`, is skipped as `UNSUPPORTED_ALGORITHM`, and an X25519 key with `use: enc` as `NOT_A_VERIFICATION_KEY`.

**The RSA exponent floor is 65,537.** RSA signature verification with a small exponent such as 3 is open to forgery in an implementation that parses the PKCS #1 v1.5 structure instead of re-encoding the expected value and comparing it (Bleichenbacher, 2006). The JDK's own provider re-encodes and compares, but Revetsec works with whatever JCA provider the runtime selects, so it refuses the setting instead: a key with `e` = 3, or any other exponent below 65,537, is skipped as `RSA_EXPONENT`. Revetsec knows of no identity provider that publishes such keys. A provider that publishes a modulus with a leading zero octet, or a small exponent, loses that key; Revetsec has no compatibility mode for either.

**Each RSA key serves one algorithm (RFC 8725 section 3.1).** A key whose `alg` is present verifies only that algorithm. An RSA key without `alg` verifies a token only while the validator's allowlist holds exactly one RSA algorithm (one of `RS256` to `RS512` and `PS256` to `PS512`), and only for that one. A token that names such a key by its `kid` while two RSA algorithms are allowed fails with `KEY_ALGORITHM_MISMATCH`, which never refreshes the key set. A token without `kid` for which no key fits counts as an unknown key instead: it fails with `UNKNOWN_KEY`, and a remote key source refreshes for it at most once per unknown-key cooldown. An application that must allow two RSA algorithms needs keys that carry `alg`. EC and Ed25519 keys are bound to one algorithm by their curve.

> **Microsoft Entra ID publishes RSA keys without `alg`.** Every key in the Entra key sets read on 2026-09-27 lacked it. Under the default allowlist, `RS256` alone, those keys verify Entra's RS256 tokens. Allowing a second RSA algorithm, for example `Set.of(JwsAlgorithm.RS256, JwsAlgorithm.PS256)`, makes every Entra key unusable, and every Entra token then fails with `KEY_ALGORITHM_MISMATCH`. Keep the allowlist at one RSA algorithm for an Entra issuer.

**A key's `issuer` member binds it to one issuer.** A key with an `issuer` member verifies a token only when the member equals the token's `iss` exactly; otherwise the token fails with `KEY_ISSUER_MISMATCH`, which never refreshes the key set. A member that is present but not a non-empty string (`null`, a number, an array or `""`) skips the key as `MALFORMED_KEY`, so it is never usable for any issuer. This check comes after the validator's own: `iss` must first equal the configured issuer, or the token fails with `ISSUER_MISMATCH`.

**Microsoft Entra ID's shared key sets use one templated `issuer`.** In the `common` and `organizations` v2.0 key sets, the keys carry the `issuer` member `https://login.microsoftonline.com/{tenantid}/v2.0` (and in `common`, three keys carry the consumer tenant's own issuer). A member exactly equal to that template is bound to the token's `iss` only when the token's `tid` claim is a lowercase GUID string (`8-4-4-4-12` hexadecimal digits) and `iss` is exactly `https://login.microsoftonline.com/` + `tid` + `/v2.0`. Since `iss` must still equal the configured issuer, the template lets Microsoft's shared keys verify tokens for that one issuer and no other. Everything else is compared literally and fails with `KEY_ISSUER_MISMATCH`: another host, such as the sovereign clouds (`login.microsoftonline.us`, `login.chinacloudapi.cn`) or External ID (`ciamlogin.com`); another placeholder spelling (`{TENANTID}`, `{tid}`); a doubled placeholder; or anything after `/v2.0`. A tenant's own v2.0 key set carries that tenant's exact issuer, and the v1.0 key sets carry no `issuer` member at all. This was checked against Microsoft's key sets as read on 2026-09-27 and against test tokens signed with keys shaped like them; no token signed by Entra itself has been verified yet. Validating Entra tokens for any tenant, with a configured `common` or `organizations` issuer, arrives with OpenID Connect.

**Entra's v1.0 and v2.0 tokens each need their own issuer and key set.** A v1.0 token, whose `iss` is `https://sts.windows.net/<tenant>/`, needs a validator with exactly that issuer and a source for the tenant's v1.0 key set, the `jwks_uri` of its v1.0 OpenID configuration. A v2.0 token needs the v2.0 issuer, `https://login.microsoftonline.com/<tenant>/v2.0`, and the v2.0 key set, the `jwks_uri` of `https://login.microsoftonline.com/<tenant>/v2.0/.well-known/openid-configuration`. The tenant's two key sets held the same keys when read, but only the v2.0 keys carry `issuer` members. None of them equals a v1.0 `iss`, and the template matches only a v2.0 `iss`, so a v1.0 token checked against any v2.0 key set, the tenant's own included, passes its signature check and then fails with `KEY_ISSUER_MISMATCH`. An application that accepts both versions needs a validator and a source for each.

## JCA providers and Java runtimes

Revetsec pins the JCA algorithm names in the table above and never names or passes a provider, so the JCA selects a provider as it always does. Revetsec's own tests run on the JDK's providers. Whether third-party and PKCS #11 providers verify DER-encoded ECDSA, RSASSA-PSS with fixed parameters, Ed25519 and RSA PKCS #1 v1.5 the way the JDK's providers do has not been tested. Revetsec's own checks (the signature shapes, the ECDSA range check, the key rules and the exponent floor above) run before any provider sees the signature or the key, whichever provider it is.

Known differences between Java runtimes:

- JDK 17's EC provider rejects a valid ECDSA signature whose x-coordinate of R is at least the group order n, which Java 21 and later accept. An honest signer produces one with probability below 2^-129, so this affects availability only.
- JDK 17's Ed25519 provider accepts a 65-octet signature. Revetsec's length check refuses it on every runtime.
- ECDSA signatures are malleable: when (r, s) verifies, so does (r, n - s), on every runtime. Never key a cache or a replay check on a token's signature bytes.

Remote key sources refuse to build on a runtime older than Java 17.0.3 (18.0.1 on Java 18), whose TLS and certificate checks are exposed to CVE-2022-21449, unless the application acknowledges it (see [compatibility modes](compatibility-modes.md)). A static key source does no I/O and has no such floor, and the ECDSA range check above protects its tokens on every runtime.

## Planned areas

- JWS for OpenID Connect ID tokens and JWT access tokens, with their own allowlists and the provider-advertised sets where a specification defines one
- JWS signing for client assertions
- XML Signature: SignatureMethod, DigestMethod, canonicalization and transforms
- SAML HTTP-Redirect binding signatures
- XML Encryption: content encryption and key transport
