# node-oidc-provider test OP (test-only)

A strict, spec-exact OpenID Provider for Revetsec's Tier-1 interop legs, gating from M5 in CI's `integration` job (see `.github/workflows/ci.yml`). It is built from:

- [`oidc-provider`](https://github.com/panva/node-oidc-provider) **9.12.2** (MIT, Copyright Filip Skokan), installed unmodified from registry.npmjs.org. `package-lock.json` pins it and its 39 transitive packages with integrity hashes;
- `server.js`, our own code (Apache-2.0): one test client, one test account, and an auto-login interaction handler;
- `Dockerfile`: `node:24.21.0-alpine3.24`, pinned by multi-arch index digest, `npm ci --omit=dev --ignore-scripts`, run as the `node` user.

The image is built locally or in CI with `--load` and is never pushed to a registry.

**Everything here is test-only.** The interaction handler logs every browser in as `test-user` and grants every requested scope without asking. That is what a headless test driver needs, and exactly what a real OP must never do. Never expose this server outside a throwaway test network.

| Item | Value |
|---|---|
| Client | `revetsec-test-client`, `client_secret_basic`, authorization-code + refresh-token grants, PKCE required for every client |
| Client secret | `test-only-client-secret-not-a-real-secret` (test-only) |
| Redirect URIs | `TEST_CLIENT_REDIRECT_URIS`, default `http://localhost:8080/callback,http://127.0.0.1:8080/callback` |
| Account | `test-user` (`test-user@example.test`) |
| Signing keys | RS256 and ES256, generated at every start; fetch the JWKS, never pin keys |
| Storage | oidc-provider's in-memory adapter; nothing survives a restart |

## Run

```sh
docker build -t revetsec-interop/node-oidc-provider:local interop/node-oidc-provider
# HTTPS with a PEM leaf and key for localhost (for example from the test CA):
docker create --name op -p 127.0.0.1:23443:3000 \
	-e ISSUER=https://localhost:23443 -e TLS_CERT_FILE=/tls/cert.pem -e TLS_KEY_FILE=/tls/key.pem \
	revetsec-interop/node-oidc-provider:local
docker cp path/to/tls-dir op:/tls    # cert.pem and key.pem, mode 644
docker start op
```

Without `TLS_CERT_FILE` and `TLS_KEY_FILE` it serves plain HTTP. `ISSUER` must be the URL the test driver uses, including the mapped host port. The server exits promptly on SIGTERM, so `docker stop` doesn't wait out the grace period.

## Updating the pins

- **oidc-provider:** change the exact version in `package.json`, run `npm install --package-lock-only --ignore-scripts`, and review the lockfile diff.
- **Base image:** change the tag and index digest on the `FROM` line.
- Either way, re-run `interop/spike/tier1-spike.sh --only node`, which builds the image and runs the headless code-flow smoke check.

M5 enables a separate test mode through `TEST_RESOURCE_MODE=m5`: resource indicators issue strict RFC 9068 JWT access tokens for the configured MCP resource and opaque tokens for a separate introspection resource. Code and client-credentials grants use the provider's real issuance paths. Signing keys rotate when the same local provider restarts; storage resets with that restart.

Node provider 9.12.2 rejects structured JWTs at its introspection and revocation endpoints. Tests preserve that rejection as a provider failure; audience-checked JSON introspection and revocation use the genuine opaque resource. Keycloak separately exercises JWT introspection. No provider implementation is patched or introspection audience check disabled. JWT introspection responses, PAR and DPoP remain later scope.

The separate `TEST_RESOURCE_MODE=playground` preset enables real public-client registration and the exact loopback HTTPS resource `TEST_PLAYGROUND_RESOURCE` (default `https://localhost:8443/mcp`). Only `mcp:discover` and `mcp:whoami` resource scopes are configured. `TEST_PLAYGROUND_TOKEN_FORMAT=jwt|opaque` selects actual provider JWT issuance or opaque issuance for audience-checked introspection. The fixed confidential test client may introspect tokens for that exact resource, including dynamically registered public clients; its authorization remains independent of the resource server's audience validation. Set `TEST_BIND_ADDRESS=127.0.0.1` when running Node directly on the host. Docker keeps its internal listener and must publish only an explicit loopback host port. Default OIDF and `m5` profiles are unchanged. See [the unpublished examples](../../examples/README.md) for startup and scoped HTTPS trust.

Integration tests start only under Maven's `integration` profile. Prepare both provider images before running the profile, including on a fresh Docker installation:

```sh
docker pull quay.io/keycloak/keycloak:26.7.4@sha256:82a77884f3af238beab1e7afd63b5f530e1b5c0590bd7aa60b40a40463e29b2c
docker build --pull=false -t revetsec-interop/node-oidc-provider:local interop/node-oidc-provider
mvn -Pintegration -Dmaven.javadoc.skip=true verify
```

The resource-provider fixtures refuse test-time pulls; CI prepares the same pinned image explicitly before Failsafe starts. To select another locally built node image, set `-Drevetsec.nodeProviderImage=<local-image>`; tests require the expected installed provider version. TLS uses a fresh SAN-correct test certificate and a scoped trust context. Loopback bindings and test-only credentials do not define a deployment authentication policy.
