PEM test fixtures for com.revetsec.internal.pem.PemTests (TEST ONLY)
=====================================================================

TEST ONLY. PUBLIC. NEVER USE ANYWHERE ELSE. Every private key here is committed to a
public repository, so anyone can use it. Use these files only in Revetsec's own tests.

These fixtures hold the PEM forms that M0's fixtures/keys/ does not: PKCS#1, SEC1,
encrypted keys, bare public keys, Ed25519 and X25519 keys, explicit EC curve
parameters, and certificates with bytes after their DER. PemTests builds the remaining
malformed variants (bad armor, bad Base64, bad DER, unsupported parameters) in code
from these files and from fixtures/keys/.

They were generated once, offline, on 2026-09-24 with OpenSSL 3.6.3 (Homebrew,
arm64 macOS), from the M0 keys in ../keys/, which were only read. To regenerate, run
the commands below from this directory. The two encrypted keys and the Ed25519 and
X25519 keys come out different on every run (random salt, IV or key); the tests do
not depend on their exact bytes. The others are deterministic.

  K=../keys
  PASS=pass:revetsec-test-only

  # PKCS#1 "RSA PRIVATE KEY": the same key as idp-signing-rsa-2048-key.pem (accepted)
  openssl pkey -in $K/idp-signing-rsa-2048-key.pem -traditional -out rsa-2048-pkcs1-key.pem

  # SEC1 "EC PRIVATE KEY" (rejected: SEC1_PRIVATE_KEY)
  openssl ec -in $K/idp-signing-ec-p256-key.pem -out ec-p256-sec1-key.pem

  # PKCS#8 "ENCRYPTED PRIVATE KEY" (rejected: ENCRYPTED_PRIVATE_KEY)
  openssl pkcs8 -topk8 -in $K/idp-signing-rsa-2048-key.pem -v2 aes-256-cbc \
      -passout $PASS -out rsa-2048-encrypted-pkcs8-key.pem

  # Legacy "RSA PRIVATE KEY" with Proc-Type: 4,ENCRYPTED (rejected: ENCRYPTED_PRIVATE_KEY)
  openssl rsa -in $K/idp-signing-rsa-2048-key.pem -aes256 -traditional \
      -passout $PASS -out rsa-2048-encrypted-pkcs1-key.pem

  # "PUBLIC KEY" (SubjectPublicKeyInfo) for two M0 keys (accepted)
  openssl pkey -in $K/idp-signing-rsa-2048-key.pem -pubout -out rsa-2048-public.pem
  openssl pkey -in $K/idp-signing-ec-p256-key.pem -pubout -out ec-p256-public.pem

  # A new Ed25519 key pair (accepted), and an X25519 key (rejected: UNSUPPORTED_ALGORITHM)
  openssl genpkey -algorithm ed25519 -out ed25519-key.pem
  openssl pkey -in ed25519-key.pem -pubout -out ed25519-public.pem
  openssl genpkey -algorithm x25519 -out x25519-key.pem

  # EC P-256 with explicit curve parameters instead of a named curve
  # (rejected: UNSUPPORTED_ALGORITHM)
  openssl ec -in $K/idp-signing-ec-p256-key.pem -param_enc explicit \
      | openssl pkcs8 -topk8 -nocrypt -out ec-p256-explicit-parameters-key.pem
  openssl ec -in $K/idp-signing-ec-p256-key.pem -param_enc explicit -pubout \
      -out ec-p256-explicit-parameters-public.pem

  # A certificate followed by one zero byte, and by a second copy of itself, inside
  # one CERTIFICATE block (rejected: TRAILING_DATA; the JDK's CertificateFactory
  # accepts both and ignores the extra bytes)
  openssl x509 -in $K/idp-signing-rsa-2048-cert.pem -outform DER -out cert.der
  { cat cert.der; printf '\000'; } > cert-trailing-byte.der
  { echo '-----BEGIN CERTIFICATE-----'; openssl base64 -in cert-trailing-byte.der; \
    echo '-----END CERTIFICATE-----'; } > rsa-2048-cert-trailing-byte.pem
  cat cert.der cert.der > cert-twice.der
  { echo '-----BEGIN CERTIFICATE-----'; openssl base64 -in cert-twice.der; \
    echo '-----END CERTIFICATE-----'; } > rsa-2048-cert-appended-certificate.pem
  rm -f cert.der cert-trailing-byte.der cert-twice.der

The password of the two encrypted keys is revetsec-test-only; no test uses it.
