# SimpleSAMLphp CBC capture

`capture.py` runs the pinned `cirrusid/simplesamlphp:v2.5.0` test image on a
loopback-only Docker port. It creates a disposable exampleauth user, uses the
repository's test-only IdP key, and makes Revetsec generate signed Redirect
AuthnRequests and SP metadata. SimpleSAMLphp verifies the requests: the script
also changes a signed RelayState and requires the IdP to reject it.

The script captures two AES-128-CBC/RSA-OAEP-MGF1P Responses:

- a signed Response containing an encrypted assertion, which Revetsec accepts
  only with per-IdP CBC enabled;
- an unsigned Response containing an encrypted, signed assertion, which
  Revetsec rejects even with CBC enabled.

The capture restarts the IdP between signing modes because SimpleSAMLphp caches
remote SP metadata in the running process. Both modes are checked against fresh
container state.

Run from the repository root with `JAVA_HOME` selecting JDK 17:

```sh
mvn -B -ntp -Dmaven.javadoc.skip=true -DskipTests test-compile
docker pull cirrusid/simplesamlphp:v2.5.0
python3 interop/simplesamlphp/capture.py --output /tmp/revetsec-simplesamlphp-capture
```

The output directory must be empty. The script checks the image manifest
digest, removes its temporary login state and container, and writes the
public requests, Responses, metadata, pending handles, and SHA-256 manifest.
`simplesamlphp-capture.yml` runs this as a nightly advisory job and on manual
dispatch, replays fresh captures through the Revetsec SP, and uploads evidence.
The replay points the tests at the fresh directories with
`-Drevetsec.simplesamlphp.fixtures` and `-Drevetsec.simplesamlphp.slo.fixtures`;
it leaves the checked-in regression fixtures untouched.
The fixture provenance is in `src/test/resources/fixtures/simplesamlphp/README.md`.

`capture_slo.py` runs both logout directions after real SSO logins. First,
SimpleSAMLphp signs a Redirect LogoutRequest, Revetsec verifies it and signs a
LogoutResponse, and SimpleSAMLphp accepts that response. Then Revetsec signs an
SP-initiated LogoutRequest, SimpleSAMLphp accepts it and signs a LogoutResponse,
and Revetsec completes the logout. Run it with the same precompiled core and
pinned image:

```sh
python3 interop/simplesamlphp/capture_slo.py --output /tmp/revetsec-simplesaml-slo
```

The output includes both signed request and response URLs, inflated message
XML, login Responses and pending fields, final return URL, and a SHA-256
manifest. The workflow recaptures and replays these advisory SLO legs alongside
the CBC legs. In each direction it first sends a tampered signed query and
requires rejection; the valid query must still complete logout. The test-only
browser cookies, sealed pending state and credentials are deleted with the
container. See
`src/test/resources/fixtures/simplesamlphp/slo/README.md`.

The [SimpleSAMLphp SP remote metadata reference](https://github.com/simplesamlphp/simplesamlphp/blob/master/docs/simplesamlphp-reference-sp-remote.md)
documents Response signing and public-key assertion encryption settings.
