# SimpleSAMLphp 2.5.0 CBC response captures

Captured on 2026-10-11 from `cirrusid/simplesamlphp:v2.5.0` with image manifest
digest `sha256:9ae050473c68ce13c5451839cb64257eaa17be3a4d2c9a3f87996bbe0cebb0aa`.
The IdP ran on a loopback-only port with the disposable `student` exampleauth
account. The repository's test-only `keys/idp-signing-rsa-2048-*` credential
signed the Responses. No external account or production credential was used.

Revetsec generated the SP metadata and signed Redirect AuthnRequests for
`https://sp.test/SimpleCapture` and ACS `https://sp.example.test/acs`.
SimpleSAMLphp accepted those requests; changing the signed RelayState caused
its signature check to reject the request. The `*-redirect-url.txt` files
contain the exact signed requests, `*-request.xml` their inflated XML, and
`*-pending.txt` the matching request ID, RelayState, issue instant and expiry.

- `cbc-response-signed-response.xml` has a signed Response and an AES-128-CBC
  encrypted assertion with RSA-OAEP-MGF1P key transport.
- `cbc-assertion-signed-response.xml` has a signed assertion encrypted in an
  unsigned Response using the same algorithms. It is a negative fixture.

`SimpleSamlCapturedResponseTests` replays both at their recorded times. The
signed Response authenticates with explicit per-IdP CBC enablement and cannot
replay; the assertion-signed variant is rejected despite CBC enablement.
`capture-manifest.json` records SHA-256 hashes of the captured files.

The `slo/` directory contains separate real IdP-initiated and SP-initiated
logout exchanges. Each side accepts the other's signed Redirect message, and
Revetsec's offline tests replay both. Its own README and manifest describe the
provenance and checks.
