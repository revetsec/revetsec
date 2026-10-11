# Shibboleth IdP 5.2.3 encrypted response captures

Captured on 2026-10-11 from `i2incommon/shib-idp:5.2.3_20260824_rocky10_multiarch`
(pulled manifest digest `sha256:bb6bbf1cfe935d20cb2d312e121fc6540cd367d18eee40ea263592c873efc7e5`).
The unmodified image ran on a loopback published port with a test-only local password
validator. Its entity ID was `https://idp.example.org/idp/shibboleth`. No external
account or production credential was used.

The SP entity ID was `https://sp.test/ShibCapture`, with ACS
`https://sp.example.test/acs`. Revetsec generated the SP metadata and signed
HTTP-Redirect AuthnRequests. The existing test-only signing and encryption keys in
`../keys/` were used. The IdP accepted the requests and emitted each checked-in
Response after the dummy login. `*-request.xml` is the inflated outbound request;
`*-redirect-url.txt` records the exact signed outbound Redirect URL;
`*-pending.txt` contains its request ID, RelayState, issue instant and expiry.
`idp-signing.crt` is the public IdP signing certificate.
`capture-manifest.json` records SHA-256 hashes of the captured files.

- `gcm-sp-metadata.xml` is Revetsec's exact generated metadata. With the IdP's
  default GCM configuration, Shibboleth emitted a Response signature and an
  AES-128-GCM encrypted assertion with RSA-OAEP key transport.
- `cbc-sp-metadata.xml` derives from that generated metadata solely by removing
  its four `EncryptionMethod` algorithm hints. Shibboleth otherwise selected
  GCM even when `idp.encryption.config` was set to
  `shibboleth.EncryptionConfiguration.CBC`. With that CBC setting and the
  modified metadata, it emitted a Response signature and an AES-128-CBC
  encrypted assertion with RSA-OAEP-MGF1P key transport.

`ShibbolethCapturedResponseTests` replays both captures offline at their recorded
times, checks correlation and the IdP signature through normal SP completion,
requires explicit per-IdP CBC enablement, and confirms replay rejection. It also
checks that the retained SP metadata matches current Revetsec output and the
described CBC adjustment. The manual `shibboleth-capture.yml` workflow repeats
the capture and SP replay after the source is pushed; these fixtures record the
local run.
