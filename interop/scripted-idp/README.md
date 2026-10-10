# Scripted IdP

Revetsec's own SAML test IdP, built to be the SAML partner in Revetsec's integration tests.
It signs and encrypts with **libxmlsec1** (through python-xmlsec) and **signxml**, neither of
which shares code with the JDK's XMLDSig (Apache Santuario). It is test tooling only, licensed
Apache-2.0.

**The image is never pushed to a registry.** Pushing would be publication, and it would
redistribute Alpine's GPL busybox and the LGPL libiconv that the xmlsec wheel links statically.
Build it locally, or in CI with `load: true` and `push: false`.

## Current scope

`serve` offers HTTPS endpoints for health, SP registration, metadata, stateless response minting,
armed Redirect/POST SSO, Redirect SLO in both directions, template signing/encryption, and
libxmlsec signature/decryption oracles. It checks Revetsec's AuthnRequests and supplied
SP metadata against pinned, offline OASIS/W3C XSDs. It verifies signed SP Redirect
queries over the received octets and POST AuthnRequests with libxmlsec1. The Java
`ScriptedIdpSsoIT` drives Revetsec's public SP API through SSO and SLO, and the fixed-key
offline corpus covers 120 fixed-key cases: the 54-case signature/digest/placement matrix,
36 additional GCM/OAEP/coverage combinations, five sibling-key cases, four signed
encryption negatives, and the original
RSA, ECDSA, signxml, GCM/OAEP and guarded CBC cases. `selftest --out DIR`
still runs the original M0 producer checks.

The broader hostile-structure and remaining encryption-negative matrix,
real-product captures, and RC-2 differential work remain open. This
test partner is not an identity service for applications.

## Template controls

The four controls accept strict JSON over HTTPS and require `clock.now` as a UTC instant.
Caller XML is capped at 256 KiB and parsed without DTD, entities or network access.
The controls deliberately do not apply SAML SP policy; `oracle/verify` reports only
libxmlsec's cryptographic verdict and whether the one Reference names the selected target.

- `POST /control/sign`: `{clock, xml, target_id, signing:{algorithm, digest?, engine?}}`.
  The selected `ID` must name one Assertion or Response. Algorithms are the named RSA
  and ECDSA fixture algorithms; `engine` is `xmlsec` or the RSA-SHA256 `signxml` seed.
- `POST /control/encrypt`: `{clock, xml, target_id, element, encryption:{data_algorithm,
  key_transport, key_placement?, extra_encrypted_keys?, variant?}}`. `target_id` names the Assertion. `element` is `Assertion` or its
  sole direct Subject/NameID. The recipient is the fixture SP's public certificate.
  Key placement can be inline, a sibling referenced by `RetrievalMethod`, or an implicit
  sibling; one or two deliberately unwrappable sibling candidates can precede the real key.
  Named variants can add an invalid MGF child, nonempty OAEPparams or a flipped content
  ciphertext bit before an enclosing Response is signed. `rsa-1_5` is produced only as a
  Revetsec default-reject fixture.
- `POST /control/oracle/verify`: `{clock, xml, target_id, credential}`. `credential`
  selects one pinned fixture IdP certificate. A bad signature gives `valid:false`.
- `POST /control/oracle/decrypt`: `{clock, xml}`. It requires exactly one EncryptedData
  and returns `valid` and the plaintext XML when decryption succeeds. The endpoint is
  available only when `SCRIPTED_IDP_ORACLE_DECRYPTION_KEY` points to the matching,
  read-only **test fixture** private key. Ordinary SSO containers omit this variable
  and never receive the SP private key; the separate local oracle probe enables it.

`probe_server.py` exercises both signers, RSA/ECDSA variants, tampering, GCM Assertion
encryption, CBC EncryptedID, OAEP parameter combinations, sibling-key placement and the
independent oracle outcomes.

`GET /metadata?now=<UTC>&variant=<name>` offers `default`, `rollover` (two signing
certificates), `aggregate` (entity selection), `expired`, `scopes` (one literal and one
ignored regexp scope), `no-slo`, `signed`, and `aggregate-signed`. The Java interop test
parses every variant and pins the signing key for both signed forms.

`PUT /control/sps` optionally accepts `metadata_xml`. The partner validates it offline
against the official SAML metadata XSD and checks its entity, ACS and SLO locations
against the registration. `/sso` checks every inbound AuthnRequest against the official
protocol XSD before accepting it. `GET /control/received` records `schema_valid:true`
for these checks. Vendored source URLs and hashes are in `schemas/SOURCES.md`.
`POST /control/logout-sign` signs supplied LogoutRequest or LogoutResponse XML
over the exact HTTP-Redirect query octets for hostile SP acceptance tests. It is
a test control, not an application logout endpoint.
`mint_slo_corpus.py` uses the same pinned signer and fixed test key to regenerate
the 14 offline Redirect queries compared with OpenSAML in `differential/`.
`mint_signed_structure_corpus.py` signs one clean and 14 deliberately ambiguous
Response templates, then verifies each with the libxmlsec oracle. The checked-in
fixtures live in `src/test/resources/fixtures/scripted-idp/signed-structure/`.
Run it in the pinned image with `/run/keys` and `/fixtures` mounted read-only,
and the destination mounted at `/out`; the script header lists the mount contract.
`mint_signed_assertion_corpus.py` applies the same signing and oracle boundary
to 23 malformed Assertions, five valid variants and a clean control. Its added
cases cover signed Assertion order, nilled container declarations and attribute
promotion through malformed AttributeStatement/Attribute elements;
its fixtures live beside the Response corpus in `signed-assertion-structure/`.
`mint_signed_attribute_corpus.py` signs scoped and ordinary AttributeValues with
XML Schema instance nil/type hints. Its 12 fixtures in `signed-attribute-values/`
check which values may become text or a stable scoped identifier after signature
verification; every signature is checked again by the libxmlsec oracle.
`mint_signed_identity_shape_corpus.py` signs 20 identity, audience, authentication
statement and Assertion-version variants in `signed-identity-shape/`. Thirteen
carry deliberately malformed SAML under a valid test-IdP signature; the oracle
checks signature coverage, while Revetsec's SP checks semantic acceptance.
`mint_signed_boundary_shape_corpus.py` signs 19 bearer-confirmation and Conditions
variants in `signed-boundary-shape/`: four valid controls and 15 malformed shapes.
The libxmlsec oracle verifies the signature on every fixture before it is saved.

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
  -v "$PWD/src/test/resources/fixtures/keys:/run/keys:ro" \
  -e SCRIPTED_IDP_TLS_CERT=/run/tls/server.crt -e SCRIPTED_IDP_TLS_KEY=/run/tls/server.key \
  -e SCRIPTED_IDP_KEYS_DIR=/run/keys \
  revetsec-scripted-idp serve
```

- `serve` prints `SCRIPTED_IDP_READY port=8443` once it is listening.
- It exits on SIGTERM.
- It refuses to start if the TLS files are missing or unreadable, or if lxml's and xmlsec's
  libxml2 differ in any version component.

## Playground browser smoke

`playground_browser_probe.mjs` drives the actual Soklet Playground UI in sandboxed Chromium. Its local fixture uses one Docker `--network none` namespace shared by the scripted IdP at `https://localhost:8443`, the Playground listeners at `127.0.0.1:8080/8081`, and the pinned Caddy edge at `https://localhost:9443`. Register the Playground's SP metadata through `/control/sps` with signed requests required before running the probe. The browser container runs as `pwuser` with all capabilities dropped, the derived Playwright seccomp profile and a private NSS database. Mount a disposable CA certificate at `/shared/ca.crt`, this directory at `/probe`, and `interop/inspector-auth/support` at `/support`; set `NODE_EXTRA_CA_CERTS=/shared/ca.crt` and run `node /probe/playground_browser_probe.mjs`. No certificate-error or browser-sandbox bypass is used.

From the core repository root, after starting that isolated fixture and setting `NAMESPACE_CONTAINER`, `PRIVATE_CA` and `BROWSER_SECCOMP` to its anchor container, CA certificate and [derived browser profile](../inspector-auth/linux/README.md), run:

```sh
docker run --rm --network "container:$NAMESPACE_CONTAINER" --user pwuser \
  --cap-drop ALL --security-opt no-new-privileges \
  --security-opt "seccomp=$BROWSER_SECCOMP" --shm-size 512m \
  -v "$PRIVATE_CA:/shared/ca.crt:ro" \
  -v "$PWD/interop/scripted-idp:/probe:ro" \
  -v "$PWD/interop/inspector-auth/support:/support:ro" \
  -e NODE_EXTRA_CA_CERTS=/shared/ca.crt \
  revetsec-interop/inspector-linux:m5-phase4-locked \
  node /probe/playground_browser_probe.mjs
```

The probe arms its own SSO/SLO responses, then checks two browser logins, SP-initiated logout, preservation of the app session for a verified LogoutRequest with a different `SessionIndex`, and termination for the matching index. It also checks the IdP's independent signature/schema receipts, private browser cleanup and secure session cookie. Output contains only redacted route/status and outcome facts. This local scripted-partner smoke does not close RC-2's independent-IdP, differential, fuzz, review or manual pentest gates.

## Keys

The M0 selftest generates throwaway keys on every run and writes their certificates, plus
the throwaway SP decryption key, to `DIR/keys/` for the JDK cross-check. Live mode loads
the test IdP's signing key and SP's public encryption certificate under
`src/test/resources/fixtures/keys/`, supplied through a read-only mount or copied in file
by file with mode `0444`. The Java integration test does not give the container the SP's
decryption private key. Keys are never baked into the image.

The fixed-key corpus is minted explicitly by running `mint_corpus.py` inside the pinned
image with `/run/keys` read-only and `/out` writable. Each XML is serialized once;
`capture.json` records the spec, tool versions, and SHA-256 digest. Revetsec replays the
corpus offline in its ordinary unit suite. The original 75 fixture bytes are retained;
new cases carry a per-case `producer_content_sha256` because the local image source
hash changed when their producer support was added.

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
