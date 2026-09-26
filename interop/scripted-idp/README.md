# Scripted IdP

Revetsec's own SAML test IdP, built to be the SAML partner in Revetsec's integration tests.
It signs and encrypts with **libxmlsec1** (through python-xmlsec) and **signxml**, neither of
which shares code with the JDK's XMLDSig (Apache Santuario). It is test tooling only, licensed
Apache-2.0.

**The image is never pushed to a registry.** Pushing would be publication, and it would
redistribute Alpine's GPL busybox and the LGPL libiconv that the xmlsec wheel links statically.
Build it locally, or in CI with `load: true` and `push: false`.

## Status (M0)

This is the M0 skeleton:

- `serve` starts an HTTPS server on port 8443 with a single endpoint, `GET /health`, which
  reports every library version.
- `selftest --out DIR` runs the M0 spike cases 1–6 plus a signxml smoke check, and writes
  each output XML to `DIR`.

The control API, a JSON-over-HTTPS interface through which tests register SPs and choose
the responses the IdP produces, arrives with M7.

## Build

```sh
docker build -t revetsec-scripted-idp interop/scripted-idp
```

The build runs the selftest as uid 65534, so a broken pin or a libxml2 mismatch between
lxml and xmlsec fails the build.

## Run

```sh
# Selftest into a host directory. The directory must be writable by uid 65534.
docker run --rm -v "$PWD/out:/out" revetsec-scripted-idp selftest --out /out

# Server. TLS is required: there is no plaintext fallback.
docker run --rm -p 127.0.0.1:8443:8443 -v "$PWD/tls:/run/tls:ro" \
  -e SCRIPTED_IDP_TLS_CERT=/run/tls/server.crt -e SCRIPTED_IDP_TLS_KEY=/run/tls/server.key \
  revetsec-scripted-idp serve
```

- `serve` prints `SCRIPTED_IDP_READY port=8443` once it is listening.
- It exits on SIGTERM.
- It refuses to start if the TLS files are missing or unreadable, or if lxml's and xmlsec's
  libxml2 differ in any version component.

## Keys

The M0 selftest generates throwaway keys on every run and writes their certificates, plus
the throwaway SP decryption key, to `DIR/keys/` for the JDK cross-check. From M7 the
container uses the committed test keys under `src/test/resources/fixtures/keys/`, copied in
file by file with mode `0444`. Keys are never baked into the image.

## Pins

- **Base image:** `python:3.13-alpine3.24`, pinned by multi-arch index digest in `Dockerfile`.
- **Python dependencies:** `requirements.in` lists the four direct pins. `requirements.txt`
  is their full closure. It is hash-locked to the cp313 `musllinux_1_2` aarch64 and x86_64
  wheels only (no sdists), and is installed with
  `pip install --require-hashes --only-binary=:all: --no-deps`.
- **lxml and xmlsec move together, in one manual PR.** The xmlsec 1.3.17 wheel statically
  links libxml2 2.14.6 and is built against lxml 6.0.2.

To regenerate the hashes after changing `requirements.in`:

```sh
for arch in aarch64 x86_64; do
  pip download --only-binary=:all: --platform "musllinux_1_2_$arch" --python-version 3.13 \
    --implementation cp --abi cp313 --abi abi3 --abi none -d "wheels/$arch" -r requirements.in
done
shasum -a 256 wheels/*/*.whl
```

Then check each hash against `https://pypi.org/pypi/<name>/<version>/json` and edit
`requirements.txt`.

## M0 spike

```sh
python3 spike/run_spike.py --java-home "$JAVA_17_HOME" [--java-home ...] [--no-cache]
java spike/Crosscheck.java <selftest-output-dir>   # JDK-only cross-check on its own
```

`run_spike.py` does the following:

1. Builds the image.
2. Runs the selftest into a temporary directory.
3. Cross-checks the outputs with each JDK, using `spike/Crosscheck.java`: `javax.xml.crypto`
   for signatures, and JCA for decryption.
4. Confirms that the cross-check fails on a tampered copy.
5. Times `serve` from `docker run` to the first good `/health`.

The results are in `SPIKE-RESULTS.md`.
