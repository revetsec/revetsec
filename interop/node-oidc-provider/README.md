# node-oidc-provider test OP (test-only)

A strict, spec-exact OpenID Provider for Revetsec's Tier-1 interop legs, planned to gate from M5 in CI's `integration` job (see `.github/workflows/ci.yml`). It is built from:

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

The `features` block in `server.js` has placeholders for the M5/M6 strict-spec legs: RFC 9068 JWT access tokens through `resourceIndicators`, RFC 9701 JWT introspection, and PAR/DPoP policy variants.
