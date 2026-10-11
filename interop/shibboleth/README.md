# Shibboleth IdP response capture

`capture.py` starts the pinned Shibboleth IdP 5.2.3 image on a loopback-only
Docker port. It uses a disposable local user and Revetsec's existing test-only
SP keys. Revetsec creates signed Redirect AuthnRequests and the SP metadata.
The script drives the IdP login and records its signed, encrypted GCM and CBC
Responses, plus the matching request and pending-state data. It checks the
image manifest digest and the selected content-encryption algorithm.

Run from the repository root after compiling the core:

```sh
mvn -B -ntp -Dmaven.javadoc.skip=true -DskipTests test-compile
docker pull i2incommon/shib-idp:5.2.3_20260824_rocky10_multiarch
python3 interop/shibboleth/capture.py --output /tmp/revetsec-shibboleth-capture
```

Set `JAVA_HOME` to JDK 17 locally. The output directory must be empty. The
script removes its temporary login credentials, cookies and containers after
each run. Its output contains the public IdP signing certificate, SP metadata,
signed Redirect URLs, requests, pending handles, Responses and a SHA-256
manifest. Inspect the
response before copying fixtures into
`src/test/resources/fixtures/shibboleth/`.

The manually dispatched `shibboleth-capture.yml` workflow performs the same
capture and immediately replays both fresh Responses through Revetsec's SP
using `-Drevetsec.shibboleth.fixtures=<capture-directory>`; it leaves the
checked-in regression fixtures untouched.
It uploads the evidence and test report. It does not update repository fixtures
or grant a release decision by itself.

Shibboleth selects GCM when Revetsec's generated metadata advertises GCM,
even with its CBC setting. For the CBC leg the script removes only the four
`EncryptionMethod` hints from the generated metadata and sets the IdP's CBC
configuration. Revetsec still requires explicit CBC enablement for that IdP
when consuming the Response.
