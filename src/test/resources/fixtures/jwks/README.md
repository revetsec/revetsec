# JWKS publication certificate fixtures

These certificates are TEST ONLY fixtures for `PublishedJwkTests`.
They reuse private keys already checked in under `fixtures/keys`; no new private
keys were generated. Never use these keys or certificates outside tests.

- `publisher-root.pem` is a self-signed CA certificate for the existing
  `sp-signing-rsa-2048-key.pem`, with `keyCertSign`, `cRLSign`, and a path-length
  constraint of one.
- `publisher-leaf.pem` contains the public key from the existing
  `idp-signing-rsa-2048-key.pem` and is signed by that root. It has no KeyUsage
  extension, covering the permitted absence of that extension.

The fixtures were generated with OpenSSL 3.6.3 on October 15, 2026 using these
commands from the repository root:

```sh
openssl req -new -x509 \
  -key src/test/resources/fixtures/keys/sp-signing-rsa-2048-key.pem \
  -out src/test/resources/fixtures/jwks/publisher-root.pem \
  -days 3650 -set_serial 53001 \
  -subj '/O=Revetsec TEST ONLY/CN=JWKS publisher test root' \
  -addext 'basicConstraints=critical,CA:TRUE,pathlen:1' \
  -addext 'keyUsage=critical,keyCertSign,cRLSign'

openssl req -new \
  -key src/test/resources/fixtures/keys/idp-signing-rsa-2048-key.pem \
  -out /tmp/revetsec-publisher-leaf.csr \
  -subj '/O=Revetsec TEST ONLY/CN=JWKS publisher test leaf'

openssl x509 -req -in /tmp/revetsec-publisher-leaf.csr \
  -CA src/test/resources/fixtures/jwks/publisher-root.pem \
  -CAkey src/test/resources/fixtures/keys/sp-signing-rsa-2048-key.pem \
  -set_serial 53002 -days 3650 \
  -out src/test/resources/fixtures/jwks/publisher-leaf.pem
```

The checks intentionally do not depend on the certificates' validity dates.
The chain's order, names, CA/key-usage constraints and signatures are exercised by
the tests, along with an altered leaf signature that must be rejected.
