# SimpleSAMLphp 2.5.0 front-channel logout captures

Captured on 2026-10-11 from `cirrusid/simplesamlphp:v2.5.0`, pinned by the
manifest digest in `capture-manifest.json`. The IdP ran in Docker on a
loopback-only port with a disposable `student` exampleauth account and the
repository's test-only signing key. No external account or production secret
was used.

After accepting a signed Revetsec AuthnRequest, the IdP issued the encrypted,
Response-signed `login-response.xml`. The same browser then called the IdP's
`singleLogout` endpoint. The IdP returned a signed Redirect LogoutRequest for
`https://sp.example.test/slo`. Revetsec verified its raw query, issuer,
destination, NameID and session index, then generated a signed Success
LogoutResponse. The IdP accepted that response and redirected to the configured
`logout-final-url.txt`.
Before the valid reply, the capture script changed the signed RelayState in a
copy of the LogoutResponse URL. SimpleSAMLphp rejected that query and still
accepted the original response.

`SimpleSamlCapturedLogoutTests` replays the login and logout with a fixed clock,
compares the logout identifiers with the authenticated session, rejects a
tampered signed query and replay, and verifies both the generated and captured
outbound LogoutResponses. The live IdP acceptance is checked by
`interop/simplesamlphp/capture_slo.py`; an offline replay alone does not prove
that the product accepted the response.

The same script then starts a fresh SSO session and asks Revetsec to initiate
logout. The real IdP rejects a tampered signed LogoutRequest, accepts the
original request and returns a signed Redirect LogoutResponse. Revetsec accepts
that response. The `sp-initiated-*` files retain the request/response URLs,
response XML and session identifiers for an offline binding and replay test.
The capture-only sealed pending cookie is discarded with the temporary working
directory; it is not retained in this fixture.
