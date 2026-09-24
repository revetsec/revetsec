# Scripted-IdP spike results (M0)

Run on 2026-09-23 on a local arm64 Mac:
- Apple M5 Pro, macOS 27.0;
- Docker Desktop, Engine 29.6.1, with the containerd image store;
- Corretto JDKs 17.0.20.1, 21.0.11, 25.0.4.1 and 27+35.

Everything below was measured on this machine, from the files in this directory, with
`contentSha256` `9d14cb618d4652f29071bb6293a352dff86b181f51d57805c0cc8a14600ddf97`. The
`ubuntu-24.04` and `ubuntu-24.04-arm` CI legs have not run yet (see "Not covered").

Two changes came after that run:
- `spike/run_spike.py` now sets the modes of the throwaway TLS files for the startup
  measurement inside the container that writes them. On rootful Linux Docker the host user
  cannot chmod files that uid 65534 owns.
- Comments and docstrings were reworded in `Dockerfile`, `requirements.in`,
  `spike/Crosscheck.java` and `scripted_idp/`, with no code change. The `scripted_idp/`
  docstrings moved `contentSha256` to
  `3241b1b31d1716690212106d7be6b4905531e0a547682c755862d9ebba7d681a`.

`run_spike.py` was re-run with the changed files later the same day, on the same Mac, with
`--no-cache` and all four JDKs, and every check passed:
- the image built, and the selftest passed;
- the cross-check passed on every JDK, and the tampered copy failed exactly case 1 and
  case 4;
- `serve` answered `/health` 0.46 s after `docker run`.

The measurements below are from the original run.

## Decision

**Go: the python-xmlsec wheels.** This was the preferred engine binding; the other two
candidates were fallbacks (see "Not covered").
- All six go/no-go cases passed in the container on arm64.
- Each case was cross-checked separately, using only the JDK, on 17, 21, 25 and 27.
- No fallback was needed, so the Alpine `xmlsec1` CLI and the Node engine were not tried.

## Per-case results

Two tools checked every case:
- **Selftest** runs in the container (`python -m scripted_idp selftest`). It writes the XML,
  then parses those bytes back and verifies or decrypts them with libxmlsec1. For encrypted
  cases it also decrypts with pyca/cryptography and parses the plaintext standalone.
- **Crosscheck** is `java spike/Crosscheck.java <out>`. It uses JDK `javax.xml.crypto` with
  secure validation on and ID attributes registered, then decrypts by hand with JCA.

| # | Case | Selftest | JDK cross-check (17, 21, 25, 27) | Result |
|---|---|---|---|---|
| 1 | Signed Response and Assertion, RSA-SHA256, exclusive c14n, SHA-256 digest | both signatures verified | both signatures valid, secure validation on | **GO** |
| 2 | RSA-SHA1 signature with a SHA-1 digest, through the wheel's bundled OpenSSL 3.6.0 | signed and verified | valid with secure validation **off**. With it on, every JDK rejects the signature: "It is forbidden to use algorithm …#rsa-sha1 when secure validation is enabled" | **GO** for producing SHA-1 fixtures (see finding 1) |
| 3 | ECDSA P-256/SHA-256, P-384/SHA-384 and P-521/SHA-512 | verified; `SignatureValue` is raw r‖s of 64, 96 and 132 bytes | valid, secure validation on; the same r‖s lengths | **GO** |
| 4 | AES-256-GCM EncryptedAssertion, `xmlenc11#rsa-oaep` with `ds:DigestMethod` `xmlenc#sha256` and `xenc11:MGF` `mgf1sha256`, from a hand-built lxml template | decrypted by libxmlsec1 and by pyca; pyca's OAEP SHA-1/MGF1-SHA1 unwrap is rejected; the inner Assertion signature verifies | `RSA/ECB/OAEPPadding` with `OAEPParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, PSpecified.DEFAULT)` unwraps the key, and SHA-1 OAEP parameters fail. `AES/GCM/NoPadding` (12-byte IV, 128-bit tag) decrypts to a standalone `saml:Assertion` whose signature is valid | **GO** |
| 5 | AES-256-GCM EncryptedAssertion with an `rsa-1_5` EncryptedKey | decrypted by libxmlsec1 and by pyca (PKCS#1 v1.5) | `RSA/ECB/PKCS1Padding`, then AES-GCM; standalone Assertion, signature valid | **GO** |
| 6 | EncryptedID (AES-256-GCM, `xmlenc11#rsa-oaep` SHA-256/MGF1-SHA256) inside a signed Assertion | Assertion signature verified; EncryptedID decrypted by libxmlsec1 and by pyca | Assertion signature valid; decrypts to a standalone `saml:NameID` with the expected value | **GO** |
| — | Extra: signxml 5.1.0, the second signer. Signs an Assertion with RSA-SHA256 and exclusive c14n | verified by libxmlsec1 | valid, secure validation on | pass |

**The cross-check can fail.** `run_spike.py` alters one character in a copy of the outputs:
- case 1's signed NameID text;
- the first character of case 4's data `CipherValue`.

On all four JDKs, Crosscheck then fails exactly case 1 (`Reference` digest invalid) and
case 4 (`AEADBadTagException`), and passes every other case.

**The libxml2 pairing check can fail.** In a throwaway container from this image, lxml
was replaced with 6.0.1, which bundles libxml2 2.14.5. Both commands then exited 1:
- `selftest` reported `FAIL libxml2-pairing`;
- `serve` raised `RuntimeError: libxml2 mismatch` before binding its port.

python-xmlsec's own import check compares only major.minor, so it would not have caught
this.

**amd64 under emulation.** `docker buildx build --platform linux/amd64 --load --no-cache`
installed the x86_64 wheels from the same `requirements.txt`, so the x86_64 hashes resolve.
- The build-time selftest passed.
- A separate selftest run's outputs passed Crosscheck on JDK 17.
- This is emulation on the Mac, not the `ubuntu-24.04` runner.

## Measurements

| Metric | Value |
|---|---|
| Image build, cold: base image pulled and wheels downloaded during the build, `--no-cache` | 12.2 s (an earlier cold run took 9.9 s) |
| Image build, `--no-cache`, base image already local | 8.1 s (earlier 9.2 s). About 7 s of this is `pip install`, mostly wheel download |
| Image build, all layers cached | 0.3–0.5 s |
| Image size, `docker image inspect -f '{{.Size}}'` (the containerd store reports the compressed content size) | arm64 33,242,160 bytes (33.2 MB); amd64 32,788,472 bytes (32.8 MB) |
| Image size unpacked on disk (`docker images`, DISK USAGE) | 133 MB |
| Build-time selftest step | 0.7 s |
| `docker run … selftest`, end to end | 0.8–1.2 s |
| `serve` startup: `docker run -d` to the first `200` from `GET /health` over TLS | 0.54, 0.54, 0.55, 0.57, 0.65 s (final code); 0.46–0.53 s in earlier runs |
| `docker stop` (SIGTERM handled; no 10 s kill) | 0.21–0.22 s |
| amd64 build under emulation, `--no-cache` (not representative of CI) | 14.4 s |

The estimate before the spike was about 40–60 MB compressed and a startup under 2 s. The
measured values are below both.

## Versions

As reported by `GET /health` and `versions.json`. arm64 and amd64 report the same versions.

| Component | Version |
|---|---|
| Base image | `python:3.13-alpine3.24@sha256:79e7a9b9ff1cbceff819f856fb374477792a5967759d94df266de7b7b4120e6f` (index). Manifests: arm64 `sha256:ff547c46029c9cd2dbce2f1ce5873debb58b9ccfeeac2ded49f72d15f47273e2`, amd64 `sha256:f3ebba2ace255c93267a0278da88c7f1044432991abc4e6ad20d22e34dd0f8ee` |
| Python | 3.13.15 |
| Alpine | 3.24.2 |
| xmlsec (python-xmlsec) | 1.3.17 |
| libxmlsec1 | 1.3.9 |
| libxml2 | 2.14.6, in all four places: lxml runtime and compiled, xmlsec runtime and compiled |
| libxslt (lxml) | 1.1.43 |
| lxml | 6.0.2 |
| signxml | 5.1.0 |
| cryptography | 50.0.1 |
| cffi, pycparser, certifi | 2.1.1, 3.0, 2026.7.22 |
| OpenSSL, Python `ssl` (Alpine system library) | OpenSSL 3.5.8 25 Aug 2026 |
| OpenSSL, bundled in cryptography | OpenSSL 4.0.2 25 Aug 2026 |
| OpenSSL, linked statically into the xmlsec wheel | 3.6.0 (read from the default provider's version string in the binary; no OpenSSL symbols are exported) |

## Findings for later milestones

1. **The JDK rejects RSA-SHA1 under secure validation** on 17, 21, 25 and 27, through
   `jdk.xml.dsig.secureValidationPolicy`.
   - RevetSec's M7 `SHA1_SIGNATURES` compatibility mode therefore can't simply rely on
     `javax.xml.crypto` defaults.
   - Turning secure validation off drops all the other policy checks too.
   - This needs a design decision before M7, both in RevetSec's algorithm policy and in
     how it treats the JDK's XML Signature settings.
   - Producing SHA-1 fixtures is not a problem, because the wheel's OpenSSL signs SHA-1.
2. **Encrypted plaintext must declare its own namespaces.** libxmlsec1 encrypts the
   element's plain serialization (`xmlNodeDump`), which carries no inherited `xmlns`
   declarations. lxml, meanwhile, drops a child's redundant `xmlns:saml` when the child is
   appended under a parent that declares it.
   - The selftest therefore builds `EncryptedAssertion` and `EncryptedID` by parsing a
     standalone serialization of the Assertion or NameID.
   - libxmlsec1's decryptor parses plaintext in the context of the EncryptedData's
     parent, while the JDK cross-check parses it standalone.
   - RevetSec's M8 decryptor must choose one behavior, and the scripted IdP should be able
     to produce both shapes as test inputs.
3. **The three OpenSSL builds differ from the pre-spike assumption.** cryptography 50.0.1
   bundles OpenSSL **4.0.2**, not the 3.x release that was expected. Alpine's system OpenSSL
   is 3.5.8. The xmlsec wheel has 3.6.0, as expected. The M7 CVE inventory should list all
   three.
4. **The pairing check does not block an lxml bump.** lxml 6.1.3 also bundles libxml2
   2.14.6, and the pairing check compares libxml2 versions only.
   - So a bump to lxml 6.1.x would pass it.
   - Whether xmlsec 1.3.17 works with lxml 6.1.x was not tested.
   - The manual "lxml and xmlsec move together" rule, plus the Dependabot ignore entry,
     remain the guard.
5. **libxmlsec1 wraps base64 at 64 characters** in `SignatureValue`, `CipherValue` and
   `X509Certificate`. RevetSec's decoders must accept XML whitespace inside base64 content.
   The JDK MIME decoder accepts it.
6. **Digest URIs.** libxmlsec1 writes `xmlenc#sha256` and `xmlenc#sha512` for SHA-256 and
   SHA-512 digests, and `xmldsig-more#sha384` for SHA-384. The JDK accepts all three.

## Not covered

- The `ubuntu-24.04` and `ubuntu-24.04-arm` legs, which are the CI `scripted-idp-image`
  job (`.github/workflows/ci.yml`). Only the local arm64 build and an emulated amd64 build
  ran here.
- The fallback engines (the Alpine `xmlsec1` 1.3.11 CLI, and Node). They were not needed.
- `/health` reports `contentSha256`, which covers the app sources plus
  `requirements.txt`, but not the image digest, which it is planned to report too. The base
  image is pinned by digest in the `Dockerfile`.
- Everything scheduled from M7 on:
  - the control API;
  - the committed fixture keys;
  - the vendored XSDs;
  - the CVE inventory.

## Reproduce

```sh
cd interop/scripted-idp
python3 spike/run_spike.py --no-cache \
  --java-home "$JDK17_HOME" \
  --java-home "$JDK21_HOME" \
  --java-home "$JDK25_HOME" \
  --java-home "$JDK27_HOME"
```
