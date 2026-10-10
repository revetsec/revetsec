# Independent SAML fixtures

These are expired bearer assertions for the dummy SP `https://sp.test/Selftest`.
They were minted on 2026-10-09 by the local `revetsec-scripted-idp:ci` image using
`python -m scripted_idp selftest --out /out`. The producer source is
`interop/scripted-idp/scripted_idp/selftest.py`; `versions.json` records its
library versions. Cases 1–6 use python-xmlsec/libxmlsec1 for XML signatures and
encryption; `extra-signxml-assertion-rsa-sha256.xml` uses signxml. The producer
checked its outputs with libxmlsec1 and pyca/cryptography before
they were copied here. The Java replay test uses a fixed 2026-09-01 clock.

The `keys/sp-rsa-2048.key` file is a disposable **test-only** decryption key
created for these fixtures. It is not an application or release signing key.
Each IdP key directory entry is a public certificate only. Re-running the
producer generates new random keys and ciphertext, so byte-for-byte fixture
reproduction is not expected.

The success cases exercise RSA and ECDSA signatures, two independent signing
stacks, EncryptedAssertion and EncryptedID. The RSA-SHA1 and RSA1_5 cases are
negative inputs. This corpus does not replace the required live IdP and
hostile-structure integration matrix.
