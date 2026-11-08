# Bounded key imports

`KeyImports` loads ordinary application-owned JCA key material. It accepts RSA under the existing 2048–16384-bit modulus/exponent/ROCA policy, EC P-256/P-384 and canonical non-small-order Ed25519 public points. It does not establish certificate trust or authorize a key's application use.

| Input | Method |
| --- | --- |
| One certificate PEM block / DER certificate | `certificateFromPem` / `certificateFromDer` |
| One PUBLIC KEY PEM block / SPKI DER | `publicKeyFromPem` / `publicKeyFromSpkiDer` |
| Unencrypted PRIVATE KEY or RSA PRIVATE KEY PEM | `privateKeyFromPem` |
| PKCS#8 DER / two-prime RSA PKCS#1 DER | `privateKeyFromPkcs8Der` / `rsaPrivateKeyFromPkcs1Der` |
| Explicit agreement check | `checkKeyPair(privateKey, publicKey, remainingBudget)` |

DER is limited to 65,536 bytes and PEM to 98,304 characters. Both are checked before copying or decoding; PEM also has a decoded-DER ceiling checked before allocation. One exact block, matching label and canonical padded Base64 are required. Caller arrays remain unchanged. Owned private DER and challenge/signature buffers are erased; immutable strings and provider-owned key material/copies retain their normal ownership limits.

The private PKCS#8 profile is version 0 without attributes or an outer public-key field. EC's inner named parameters must match its outer curve. An embedded EC public hint must be structurally valid and on the selected curve, but import does not prove that it agrees with the scalar. Encrypted keys, SEC1 armor, multi-prime RSA, P-521, Ed448, XDH, RSA-PSS containers and private JWK import are outside this profile. General RSA key material can still be supplied to the selected PSS signers.

Call `checkKeyPair` separately when agreement matters. It reparses bounded canonical public SPKI, signs a fresh 32-byte noncredential challenge with the private key and checks the result through the existing independent verifier. It returns no signature. Public keys must be encodable; private keys may remain opaque and are never exported. One original monotonic budget covers provider/random initialization, signing and verification. Trusted synchronous providers must cooperate; a blocked provider cannot be forcibly preempted by these checks. No retry or fallback is performed.

`KeyImportException` exposes fixed reasons for malformed/oversized input, unsupported or rejected keys, pair mismatch, unavailable providers, exhausted budgets and cancellation. It retains no input, key, provider message, cause or suppressed exception. Interruption remains set. Certificate imports check bounded parsing and the embedded key profile; applications still own signature, chain, hostname, validity and revocation policy, and no full certificate-inner DER canonicality guarantee is added.

The [Java 17 example](../examples/key-import/README.md) shows bounded application file reads and explicit pair checking. Local JDK/provider checks do not establish hardware-provider compatibility or close final release/API acceptance.

Import, signing and publication use distinct profiles. A directly supplied typed/restricted PSS key may fit a selected PSS signer while remaining outside both import and `PublishedJwk` publication. See the [publication profile contract](jwks-publication.md). No generic typed-PSS-container compatibility is promised.
