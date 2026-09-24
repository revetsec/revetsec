# Test TLS PKI (TEST ONLY)

> **TEST ONLY. PUBLIC. NEVER USE ANYWHERE ELSE.**
>
> Every file in this directory, including every private key and the test CA's private key, is committed to a public
> repository. Anyone can read these keys and mint certificates with the test CA. Use them only in RevetSec's own tests
> and local test containers. Never use them to protect anything real, never deploy them, never copy them into another
> project, and never add `test-ca.pem` to an operating-system, browser or JDK trust store.

This directory holds the test CA and the TLS server certificate that RevetSec's in-process HTTPS test servers and
test containers use. HTTPS stays on in tests, so clients verify the server against this CA instead of turning
verification off.

## Files

Every PKCS#12 file uses the password **`changeit`**, for both the store and the key. PEM private keys are
unencrypted PKCS#8 (`-----BEGIN PRIVATE KEY-----`).

| File | Contents | Format |
|---|---|---|
| `test-ca.pem` | Test CA certificate (the trust anchor) | X.509, PEM |
| `test-ca-key.pem` | Test CA private key, RSA-3072 | PKCS#8, PEM, unencrypted |
| `test-ca.p12` | Test CA key and certificate, alias `test-ca` (`PrivateKeyEntry`) | PKCS#12, password `changeit` |
| `server.pem` | Server leaf certificate, issued by the test CA | X.509, PEM |
| `server-key.pem` | Server leaf private key, RSA-2048 | PKCS#8, PEM, unencrypted |
| `server.p12` | Server key with chain `[server, test-ca]`, alias `server` (`PrivateKeyEntry`) | PKCS#12, password `changeit` |
| `truststore.p12` | Test CA certificate only, alias `revetsec-test-ca` (`trustedCertEntry`) | PKCS#12, password `changeit` |

The PKCS#12 files use AES-256-CBC (PBES2) and an HMAC-SHA256 MAC, which every supported JDK (17.0.3 and later) reads.
They do not use PBMAC1, because JDK 17 cannot read it.

## Profile

Everything below is fixed by `scripts/regenerate-test-pki.sh`. Only the key material changes when it is regenerated.

- **Validity:** every certificate is valid from `2026-01-01T00:00:00Z` to `2126-01-01T00:00:00Z` (100 years), so the
  fixtures do not expire and fixed-`Clock` tests from 2026 onward see valid certificates.
- **Test CA** (`test-ca.pem`):
  - subject `CN=RevetSec Test CA - DO NOT TRUST, O=RevetSec test fixtures - TEST ONLY`, self-signed, serial 1000;
  - RSA-3072, `sha256WithRSAEncryption`;
  - `basicConstraints` critical `CA:TRUE, pathlen:0`; `keyUsage` critical `keyCertSign, cRLSign`;
  - `extendedKeyUsage` `serverAuth` only, so verifiers that apply a CA's extended key usage reject TLS client and
    S/MIME certificates issued by it. OpenSSL does not apply it to code signing (see the unprotected cases below);
  - **critical name constraints**, because the CA's private key is public. Every name in a leaf must fall inside
    these permitted subtrees:
    - DNS subtrees: `localhost`, `internal`, `test`, `example`, `local`, `home.arpa`;
    - IP ranges: `127.0.0.0/8`, `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `100.64.0.0/10`, `::1/128`,
      `fc00::/7`;
    - email addresses and URIs: only the reserved domain `invalid`, which no real address uses, so a leaf with any
      real email address or URI is rejected.

    There is deliberately no directory-name constraint. LibreSSL 3.3.6, which macOS's `/usr/bin/curl` uses, rejected
    every leaf under a permitted directory-name subtree, including leaves that OpenSSL accepted (observed 2026-09-23).

    This is damage limitation, not permission to trust the CA. Verifiers that apply a trust anchor's extended key usage
    and name constraints reject a TLS client or S/MIME leaf, and a leaf for any other DNS name, IP address, email
    address or URI. OpenSSL does: `scripts/regenerate-test-pki.sh check` signs throwaway probe leaves and confirms that
    `openssl verify` rejects each case. Python, Node and curl were observed applying the DNS and IP constraints.

    Two cases are **not protected**:

    - **Code signing, in OpenSSL.** OpenSSL's `codesign` purpose checks only that the issuer is a CA and ignores the
      CA's extended key usage, and with no directory-name constraint nothing restricts the subject. So OpenSSL accepts
      a code-signing leaf from this CA for any subject, such as `O=Big Bank, CN=Big Bank Code Signing`; only its SANs,
      and a CN that looks like a host name, are held to the name constraints. OpenSSL's `timestampsign` and
      `ocsphelper` purposes, and `openssl verify` without `-purpose`, ignore the CA's extended key usage too (observed
      with OpenSSL 3.6.3 on 2026-09-24). `check` prints a note for the code-signing case instead of failing.
    - **The JDK,** which applies neither a trust anchor's name constraints nor its extended key usage: Corretto 17, 21,
      25 and 27 accepted a test-CA leaf for `evil.com`, and all four accepted a TLS client leaf and a leaf with an
      email SAN (observed 2026-09-23). So a JDK trust store that contains this CA trusts it for every name and purpose.
- **Server leaf** (`server.pem`):
  - subject `CN=localhost, O=RevetSec test fixtures - TEST ONLY`, serial 1001;
  - RSA-2048, `sha256WithRSAEncryption`, issued by the test CA;
  - `subjectAltName`, in this order: `DNS:localhost`, `IP:127.0.0.1`, `DNS:host.testcontainers.internal`,
    `DNS:host.docker.internal`;
  - `basicConstraints` critical `CA:FALSE`; `keyUsage` critical `digitalSignature, keyEncipherment`;
    `extendedKeyUsage` `serverAuth`; subject and authority key identifiers.

## Using it

- **Java client:** load `truststore.p12` with `KeyStore.getInstance("PKCS12")` and `"changeit"`, and build the
  `SSLContext` from a `TrustManagerFactory`. Keep hostname verification on; connect to `localhost` or `127.0.0.1`.
- **Java server** (for example the JDK `HttpsServer`): load `server.p12` into a `KeyManagerFactory`.
- **PEM consumers** (Keycloak `KC_HTTPS_CERTIFICATE_FILE` / `KC_HTTPS_CERTIFICATE_KEY_FILE`, Node `https`, Python
  `ssl`, nginx): `server.pem` and `server-key.pem` for the server, and `test-ca.pem` as the client's CA file (for
  example `NODE_EXTRA_CA_CERTS`, `SSL_CERT_FILE` or `REQUESTS_CA_BUNDLE`).
- **Containers:** copy each file individually, read-only. Never bake these files into an image.

Apple platform TLS clients (Safari, `URLSession`) reject TLS server certificates that are valid for more than 825
days, so this leaf is not meant for browsers on macOS or iOS. RevetSec's tests use `java.net.http`, Python and Node
clients, which do not apply that limit.

## Remote Docker host

If Testcontainers reaches containers through a host name or address that the leaf does not cover, issue an extra
leaf from the same test CA into a directory outside the repository. Nothing in this directory changes:

```sh
scripts/regenerate-test-pki.sh leaf --out-dir /tmp/revetsec-remote-tls --san DNS:dockerhost.internal --san IP:192.168.1.20
```

The extra SANs must stay inside the CA's name constraints. A single-label name such as a bare `docker` is not
covered, so use a `*.test` or `*.internal` alias, or the host's IP address. The `leaf` subcommand accepts only DNS
and IP SANs.

## Regenerating

```sh
JAVA_HOME=/path/to/jdk scripts/regenerate-test-pki.sh check         # verify what is checked in (read-only)
JAVA_HOME=/path/to/jdk scripts/regenerate-test-pki.sh tls --force   # replace every file listed above
```

Generating needs OpenSSL 3.4 or later, and `check` needs OpenSSL 3.0 or later (LibreSSL is not supported). Both need
a JDK `keytool`. The script refuses to overwrite existing files without `--force`. It builds everything in a temporary
directory, checks it, and only then replaces the files here. Regenerating this directory changes only the TLS
material, because no committed fixture embeds it. The fixture signing keys are in `../fixtures/keys/` and are
regenerated separately.
