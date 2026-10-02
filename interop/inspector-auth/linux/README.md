# Isolated Linux browser route

The official Playwright 1.63.0-noble image and Linux arm64 manifest are pinned in `pins.json`; the image contains Node 24.20.0 and Chromium 153.0.8010.12. The exact released Inspector 2.9.0 dependency lock is installed without lifecycle scripts. The only added Ubuntu package is checksum-pinned libnss3-tools 2:3.98-1ubuntu0.2. No native browser profile, NSS database, private key or dependency tree belongs in source control.

Prepare a narrow new private build directory:

```sh
python3 interop/inspector-auth/linux/prepare-context.py --work-dir /absolute/new/private-browser-context
docker build --tag revetsec-interop/inspector-linux:local /absolute/new/private-browser-context
```

Preparation downloads only the exact public NSS package and baseline released Playwright seccomp JSON, verifies both SHA256 pins, and copies only package.json/package-lock.json/Dockerfile. The context excludes application sources, private research, credentials, profiles and trust stores. `artifacts/nss-tools.deb` is generated in this private context; no binary is committed. The Dockerfile performs `npm ci --ignore-scripts --no-audit --no-fund` from that exact lock.

Run the browser as pwuser (UID 1001), with `--network none --cap-drop ALL --security-opt no-new-privileges --security-opt seccomp=/absolute/private-browser-context/seccomp-browser-sandbox.json`. The baseline profile comes from the released Playwright source/hash. Its only two scoped derivations keep clone3 denied but return ENOSYS (38) for fallback and permit chroot used inside the browser sandbox user namespace. No capability or global Docker/kernel policy is added, and no browser sandbox is disabled. Verify Chrome's own Layer1Sandbox=Namespace, PID/network namespaces and Seccomp-BPF statuses before running OAuth.

On this host, existing Docker host-network mode could not reach a host127.0.0.1 listener. Therefore Caddy, Node provider, Inspector, JVM example and browser run inside one disposable Linux container with explicit127.0.0.1 listeners, no published port or outside network. Mount exact app/JDK/provider inputs read-only. Pass disposable TLS key material through bounded stdin only, write it to a new private container directory and remove it at shutdown. Import only its CA into a fresh private HOME/.pki/nssdb; Node gets only NODE_EXTRA_CA_CERTS and Java only a new explicit task truststore. Do not add global trust or disable hostname/certificate checks.

The actual Playground lane is cross-site for form_post because localhost and 127.0.0.1 are different sites. It uses provider https://127.0.0.1:9443, application HTTP 127.0.0.1:8080, MCP 127.0.0.1:8081, edge https://localhost:8443/mcp and unmodified Inspector http://127.0.0.1:6274. DCR registers its supported http://localhost:6274/oauth/callback. Request mcp:discover/mcp:whoami, then invoke whoami with tenant=local/object=self. Only the SafeViews checked issuer, p1_ partitioned subject, allowlistedscopes and fixed validation summary are eligible for result evidence. JWT and opaque/introspection modes are separate fresh runs. Normal flow success leaves the isolated generic 403 recovery item open.

## Run the packaged normal flow

Prepare TLS with `interop/local-https/prepare.py`. Stage only these private read-only inputs: `runtime/java` (Linux JDK 17), `runtime/caddy` (official pinned Caddy 2.11.4 binary), `app/` (the four packaged JARs below), and `provider/` (the pinned Node provider fixture plus its lock-installed dependencies). The application manifest is a four-row JSON array of `{name, sha256}`; its names are `playground-1.0.0-SNAPSHOT.jar`, `revetsec-1.0.0-SNAPSHOT.jar`, `revetsec-soklet-1.0.0-SNAPSHOT.jar`, and `soklet-4.0.0.jar`. Derive SHA256 from the actual Maven packaged artifacts after building the examples, and preserve their build evidence. The launcher verifies them before use.

The runtime can be extracted using a stopped task-owned container from the official pinned Caddy image and an exact locally verified `eclipse-temurin:17-jdk-noble` image: copy `/usr/bin/caddy` and `/opt/java/openjdk` into the private runtime directory, record both image identities and file hashes, then remove those stopped containers. No runtime binary is committed. The worker requires Linux arm64 inputs matching this pinned browser image.

```sh
python3 interop/inspector-auth/linux/run-local.py \
  --context /absolute/private-browser-context \
  --runtime /absolute/private/runtime --app /absolute/private/app \
  --app-manifest /absolute/private/packaged-apps.json \
  --provider /absolute/private/node-provider --tls /absolute/private/tls \
  --output /absolute/new/private-jwt-result --token-format jwt
```

Repeat with a new output directory and `--token-format opaque` for introspection. The image tag defaults to the preceding build command; `--image` can select that private derived image explicitly. The launcher uses `--init` to reap browser children and a container-private 512 MiB shared-memory mount for Chromium; host IPC is not shared. Its worker drives the released Inspector through OAuth and whoami, then checks application atomic/query and sealed/form_post browser login, secure HttpOnly host cookies and rotation, and the UI client-credentials probe. It keeps actual result checks strict; a failed selector or client flow is retained as a failure. Receipts contain bounded structure and booleans only; private TLS material travels through stdin and private trust stores/profiles are removed. Normal flow verification is independent of the generic 403 diagnostic.

The seccomp baseline's full released Apache 2.0 license is retained in `PLAYWRIGHT-LICENSE`; `pins.json` names its exact upstream URL and hash. The preparer preserves that license beside the private generated profile. The generated profile is a private input, not a checked-in upstream policy modification.
