M-K key import fixtures — TEST ONLY, PUBLIC, NEVER USE FOR DEPLOYMENT

Generated offline on 2026-11-05 with OpenSSL 3.6.3 9 Jun 2026, arm64 macOS.
All private material comes from existing publicly committed test-only keys;
no private fixture was generated, exported or modified by these commands.
The certificate has a one-day lifetime only to make clear that import does
not establish validity, trust, hostname, a chain or a revocation result.
The tests also retain the older RSA/EC ordinary fixture certificates.

From the core checkout:
openssl req -new -x509 -key src/test/resources/fixtures/pem/ed25519-key.pem \
  -subj '/CN=Revetsec key import TEST ONLY' -set_serial 20261105 -days 1 \
  -out ed25519-cert.pem
openssl pkey -in src/test/resources/fixtures/keys/idp-signing-ec-p384-key.pem \
  -pubout -out ec-p384-public.pem

The certificate is parsing/key-profile evidence only. Its self-signature is
not used as a trust result, and the exact current wall time is not asserted.
