# Test signing and encryption keys (TEST ONLY)

> **TEST ONLY. PUBLIC. NEVER USE ANYWHERE ELSE.**
>
> Every private key in this directory is committed to a public repository, so anyone can sign or decrypt with it.
> Use these keys only in Revetsec's own tests and local test containers, such as the scripted IdP. Never use them to
> sign, encrypt or protect anything real, never register their certificates with a real identity provider or service
> provider, and never copy them into another project.

These are the fixed SAML (and general signature) test keys: IdP signing keys, SP signing and encryption keys, and
negative keys that tests must reject. They are checked in rather than generated at test time, so fixtures signed
with them (for example the scripted IdP's minted corpus) still verify offline.

## Files

Each key has two files with stable names:

- `<name>-key.pem`: the private key, unencrypted PKCS#8 PEM (`-----BEGIN PRIVATE KEY-----`);
- `<name>-cert.pem`: a self-signed X.509 v3 certificate for that key, PEM.

| Name | Role | Key | Certificate signature | `keyUsage` (critical) | Serial |
|---|---|---|---|---|---|
| `idp-signing-rsa-2048` | IdP signing | RSA-2048 | `sha256WithRSAEncryption` | `digitalSignature` | 2001 |
| `idp-signing-rsa-3072` | IdP signing | RSA-3072 | `sha256WithRSAEncryption` | `digitalSignature` | 2002 |
| `idp-signing-ec-p256` | IdP signing | EC P-256 (`secp256r1`) | `ecdsa-with-SHA256` | `digitalSignature` | 2003 |
| `idp-signing-ec-p384` | IdP signing | EC P-384 (`secp384r1`) | `ecdsa-with-SHA384` | `digitalSignature` | 2004 |
| `idp-signing-ec-p521` | IdP signing | EC P-521 (`secp521r1`) | `ecdsa-with-SHA512` | `digitalSignature` | 2005 |
| `negative-attacker-rsa-2048` | Negative: a well-formed key that is never trusted (signature by the wrong key) | RSA-2048 | `sha256WithRSAEncryption` | `digitalSignature` | 2101 |
| `negative-rsa-1024` | Negative: below the RSA-2048 minimum | RSA-1024 | `sha256WithRSAEncryption` | `digitalSignature` | 2102 |
| `negative-unconfigured-ec-p256` | Negative: a valid EC key that no test configures as trusted | EC P-256 (`secp256r1`) | `ecdsa-with-SHA256` | `digitalSignature` | 2103 |
| `sp-signing-rsa-2048` | SP signing (AuthnRequest, logout messages, metadata) | RSA-2048 | `sha256WithRSAEncryption` | `digitalSignature` | 2201 |
| `sp-encryption-rsa-2048` | SP encryption (the IdP encrypts to it; the SP decrypts) | RSA-2048 | `sha256WithRSAEncryption` | `keyEncipherment` | 2202 |

The complete file list:

- `idp-signing-rsa-2048-key.pem`, `idp-signing-rsa-2048-cert.pem`
- `idp-signing-rsa-3072-key.pem`, `idp-signing-rsa-3072-cert.pem`
- `idp-signing-ec-p256-key.pem`, `idp-signing-ec-p256-cert.pem`
- `idp-signing-ec-p384-key.pem`, `idp-signing-ec-p384-cert.pem`
- `idp-signing-ec-p521-key.pem`, `idp-signing-ec-p521-cert.pem`
- `negative-attacker-rsa-2048-key.pem`, `negative-attacker-rsa-2048-cert.pem`
- `negative-rsa-1024-key.pem`, `negative-rsa-1024-cert.pem`
- `negative-unconfigured-ec-p256-key.pem`, `negative-unconfigured-ec-p256-cert.pem`
- `sp-signing-rsa-2048-key.pem`, `sp-signing-rsa-2048-cert.pem`
- `sp-encryption-rsa-2048-key.pem`, `sp-encryption-rsa-2048-cert.pem`

## Profile

- Every certificate is self-signed, with subject and issuer `CN=<description>, O=Revetsec test fixtures - TEST ONLY`.
- `basicConstraints` critical `CA:FALSE`; a subject key identifier; the `keyUsage` shown above.
- Every certificate is valid from `2026-01-01T00:00:00Z` to `2126-01-01T00:00:00Z` (100 years), so fixtures do not
  expire.
- RSA keys use the public exponent 65537. EC keys use named curves, never explicit parameters.
- The keys load with the JDK alone: `PKCS8EncodedKeySpec` with `KeyFactory.getInstance("RSA")` or
  `KeyFactory.getInstance("EC")`, and certificates with `CertificateFactory.getInstance("X.509")`.

## Regenerating (read this first)

Regenerating replaces every key here. **Every committed fixture that was signed with, or encrypted to, one of these
keys stops verifying or decrypting.** That includes the scripted IdP's minted corpus and any captured fixture that
targets these keys. Regenerate only on purpose, and re-mint or re-capture the dependent fixtures in the same change.

Fixtures derived from these keys go stale too. `../pem/` is made from `idp-signing-rsa-2048` and
`idp-signing-ec-p256`, and `PemTests` checks that its files match these keys, so re-run the commands in
`../pem/README.txt` in the same change. The hand-written PEM and DER seeds under
`fuzz/src/test/resources/com/revetsec/internal/pem/PemFuzzTestsInputs/` were made from those fixtures; rebuild them
as `fuzz/README.md` describes (Seeds, PEM), or they keep exercising the old keys' bytes. The fuzz module's generated
JOSE seeds (`generated-*` under `fuzz/src/test/resources/`) and
`fuzz/src/test/resources/com/revetsec/jose/fixture-key-set.json` are made from these keys too: re-run
`com.revetsec.FuzzSeedGenerator` as `fuzz/README.md` describes (Seeds, generated seeds), and remove by hand any
generated seed it no longer makes. `FuzzSeedProvenanceTests` fails the fuzz replay until they match.

```sh
scripts/regenerate-test-pki.sh check          # verify what is checked in (read-only; needs a JDK keytool)
scripts/regenerate-test-pki.sh keys --force   # replace every file listed above
```

Generating needs OpenSSL 3.4 or later, and `check` needs OpenSSL 3.0 or later (LibreSSL is not supported). The script
refuses to overwrite existing files without `--force`. It builds everything in a temporary directory, checks it, and
only then replaces the files here.

Later milestones may add other test keys to this directory, for example a dummy SP decryption key for a captured
fixture. Document each one in this README. The script neither generates nor touches them.
