# Soklet passkey browser demo

This unpublished, disposable Soklet application exercises Revetsec's WebAuthn relying-party API: enrollment, discoverable sign-in, account-pinned reauthentication, listing and server-side removal. The app owns one demo account, the access-key enrollment decision, browser sessions, CSRF, the TLS edge and local storage. Revetsec owns ceremony options, response parsing, cryptographic verification and atomic credential transitions.

The default state is **single-process and volatile**. Each launch creates a fresh account handle, namespace, sealing key, session store and bounded InMemoryWebAuthnStore (1,024 entries and 8 MiB of sealed records). There is no eviction. Restarting loses all server-side passkeys and sessions; a credential still visible on a device cannot sign in to the new account. Do not use this launcher for an established account or a multi-node service. The PostgreSQL/Pyranid example shows the application-owned durable store; an established service also needs its external recovery admission barrier and managed sealing keys. This demo's fresh-process permit cannot authorize recovery after a restore.

`PasskeyApp` also has an injection constructor for an application-owned stable account handle, configured `WebAuthnRelyingParty` and application recovery gate. The app and relying party must receive the same reentrant gate instance so one permit spans verification and the subsequent browser-session change. The application supplies the store, namespace and sealing key through the relying party. It must bind that relying party to the same trusted RP ID and origin as the app and coordinate account disablement with the core account fence. This constructor keeps browser sessions in process memory: a new JVM can sign in using a persisted passkey, but an existing session does not roam between nodes or survive restart. The PostgreSQL fixture exercises this constructor across fresh JVMs, a real Chrome browser with two Soklet restarts and a primary outage, and a restore boundary. Its local file marker is test-only; production admission needs a durable cross-host recovery control stored outside the restorable database and a way to close every node after an uncertain write.

## Build against the pinned 4.0.0 artifact

Build the current Revetsec core JAR first. The build.py script compiles the example into a new private directory with warning-fatal Java 17 settings. It verifies the Soklet 4.0.0 artifact SHA-256 f7f62f967045a8eb8f943a90d49d499b4c5b755d20ab901e12a34fe1d004319b, runs route checks, and copies only core and Soklet JARs onto the runtime classpath. Annotation JARs are compile-time only.

~~~sh
python3 examples/passkeys-soklet/build.py \
  --work /absolute/new/private-passkey-build \
  --java-home /absolute/jdk17-or-newer \
  --core-jar /absolute/revetsec/target/revetsec-1.0.0-SNAPSHOT.jar \
  --soklet-jar /absolute/soklet-4.0.0.jar \
  --jspecify-jar /absolute/jspecify-1.0.1.jar \
  --jsr305-jar /absolute/jsr305-3.0.2.jar \
  --socket-check
~~~

The route checks use a test-only Ed25519 authenticator to exercise registration, discoverable sign-in, account-pinned reauthentication, one-use step-up, credential removal and denial of the removed credential. They also reject a wrong signature, registration replay and credential-ID reuse after removal. The optional socket check starts an actual loopback Soklet listener and checks session rotation and registration preparation through HTTP. It requires local socket permission.

## Prepare one exact HTTPS origin

Choose a lower-case DNS RP ID whose local name resolves to 127.0.0.1 in the browser and which you control for this test. The commands below use passkeys.example.test as a placeholder. WebAuthn requires the browser to load the exact HTTPS origin; HTTP loopback, numeric IP origins and a different subdomain are outside this Revetsec profile.

~~~sh
python3 examples/passkeys-soklet/prepare_tls.py \
  --work /absolute/new/private-passkey-tls \
  --openssl /absolute/path/to/openssl \
  --rp-id passkeys.example.test \
  --https-port 9443 --http-port 8093
~~~

The script requires an OpenSSL binary with `verify -verify_hostname` support (the tested binary was OpenSSL 3.6.3; macOS's `/usr/bin/openssl` lacks this option). It generates a two-day private CA, an exact DNS-SAN leaf certificate, checks matching and foreign hostnames, and writes a Caddyfile binding the HTTPS listener to loopback. It changes no trust store. Configure the browser's local DNS and trust for this disposable CA yourself, then run your pinned Caddy binary with /absolute/new/private-passkey-tls/Caddyfile. Remove the private CA, leaf keys, browser trust and test profile after use. The generated edge rejects comma-materialized sensitive header duplicates before forwarding. Keep the edge and app on the same host or private network; the backend is plain HTTP on 127.0.0.1:8093.

## Run the isolated browser check

`browser_check.mjs` exercises the actual page in Chrome with a CTAP2 virtual authenticator. It starts the built Soklet app, serves the exact DNS origin from a private Node HTTPS edge, maps that DNS name to loopback only in a disposable Chrome profile, and pins the test leaf's public key for Chrome without changing system trust. It checks browser registration, a deliberately bogus signed assertion rejected by Revetsec, discoverable sign-in, account-pinned reauthentication, one-use step-up, listing, server-side removal and rejection after removal. Node uses built-in modules only. The tested versions were Node 26.5.0 and Chrome 154 on macOS.

~~~sh
node examples/passkeys-soklet/browser_check.mjs \
  --classpath-file /absolute/new/private-passkey-build/CLASSPATH \
  --tls-dir /absolute/new/private-passkey-tls \
  --java /absolute/jdk17-or-newer/bin/java \
  --chrome '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome'
~~~

This check uses `leaf.crt` and `leaf.key` from `prepare_tls.py`; it does not run the generated Caddyfile. It removes its own temporary access key and Chrome profile. Remove the separate TLS and build directories after testing. A virtual authenticator proves browser/API integration, not a physical security key, PIN prompt, trusted browser profile or distributed deployment.

The PostgreSQL fixture can run the same Chrome flow against `DurablePasskeyPlayground`, a test-only launcher with one stable account handle, sealed PostgreSQL credential state and an external local marker. Pass its pinned Soklet JAR and absolute `--browser-node`, `--browser-chrome` and `--browser-openssl` paths to `run_webauthn.py`. It keeps Chrome's virtual authenticator alive while stopping and restarting the Soklet JVM after registration and again after removal. The browser starts with a new anonymous app session after each restart; its persisted credential signs in after the first restart and is rejected after the second. Between those steps, the fixture stops PostgreSQL after reauthentication: the account page and sensitive action return 503, and the unused step-up approval can be consumed exactly once after the same primary returns. The fixture owns and removes its PostgreSQL volume, Chrome profile, local TLS files and keys. See the PostgreSQL example README for the runner arguments and limits.

Create a private POSIX access-key file containing one fresh 43-character base64url value (optionally followed by a newline), mode 0600. This key is an application enrollment approval for the fixed demo account. It is never a WebAuthn credential or a Revetsec secret:

~~~sh
python3 -c 'import pathlib,secrets; p=pathlib.Path("/absolute/private/access-key"); p.write_text(secrets.token_urlsafe(32)+"\n"); p.chmod(0o600)'
~~~

Start the application with the exact same RP ID and origin as the TLS edge:

~~~sh
REVETSEC_PASSKEY_RP_ID=passkeys.example.test \
REVETSEC_PASSKEY_ORIGIN=https://passkeys.example.test:9443 \
REVETSEC_PASSKEY_HTTP_PORT=8093 \
REVETSEC_PASSKEY_ACCESS_KEY_FILE=/absolute/private/access-key \
  /absolute/jdk17-or-newer/bin/java \
  -cp "$(cat /absolute/new/private-passkey-build/CLASSPATH)" \
  example.passkeys.PasskeyPlayground
~~~

Open https://passkeys.example.test:9443/ in the trusted browser. Approve enrollment with the private demo key, register a passkey, sign out, sign in with that passkey, reauthenticate for the one-use sensitive action, list the credential and remove it. A removed credential may remain in the browser or security key, but the server will reject it on a later sign-in. The browser uses parseCreationOptionsFromJSON, parseRequestOptionsFromJSON and PublicKeyCredential.toJSON(); cancellation is only a browser UI outcome.

Every POST route checks the configured Host and exact Origin, a server-held session cookie and an independent CSRF header. Sign-in and access-key login rotate the session cookie, CSRF token and browser binding. The cookie is __Host-, Secure, HttpOnly and SameSite=Strict. A successful account-pinned reauthentication permits one sensitive action for one minute. The app holds its recovery permit through each route handler, including session-only actions and session rotation after a Revetsec proof. An uncertain WebAuthn write closes this disposable instance's route admission until a fresh restart. The app never turns caller-supplied credential IDs or handles into an authenticated account without a successful Revetsec result.

The route, loopback listener and virtual Chrome browser checks are separate. Trusted-edge deployment and the required physical discoverable UV-capable FIDO2 key remain separate release evidence.
