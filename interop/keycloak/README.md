# Keycloak test realm (test-only)

`revetsec-test-realm.json` is a minimal Keycloak realm for Revetsec's Tier-1 interop legs: self-hosted test partners for CI's gating `integration` job (see `.github/workflows/ci.yml`). Keycloak 26.7.x imports it at startup with `--import-realm` from `/opt/keycloak/data/import/`. The M0 spike in `../spike/` measures the import cost; see `../spike/TIER1-RESULTS.md`.

**Everything in this file is test-only.** The credentials below are fixed public values that protect nothing. Never import this realm into a Keycloak that is reachable from outside a throwaway test network, and never reuse these values anywhere else.

| Item | Value |
|---|---|
| Realm | `revetsec-test` |
| Confidential client | `revetsec-test-client`, `client_secret_basic`, standard (authorization-code) flow only, PKCE `S256` required, no consent screen |
| Client secret | `test-only-client-secret-not-a-real-secret` (test-only) |
| Redirect URIs | `http://localhost:8080/callback`, `http://127.0.0.1:8080/callback` |
| Test user | `test-user` / `test-user@example.test`, email verified, first and last name set, no required actions |
| Test user password | `test-only-password-not-a-secret` (test-only, clearly fake) |

The user has `emailVerified`, `firstName` and `lastName` set and no `requiredActions`. Without them Keycloak's user-profile checks put an "Update profile" or "Verify email" page into the headless login flow, which a driver that only submits the login form cannot get past.

Keycloak marks its login cookies `Secure` even over plain HTTP. A headless driver using `java.net.CookieManager` or Python's `CookieJar` therefore fails with `cookie_not_found` against a plain-HTTP Keycloak unless it treats loopback as a secure context, as browsers do. Run the gating legs over TLS from the test CA.

Moving the Keycloak pin (`../spike/tier1-spike.sh`, `KEYCLOAK_IMAGE`) is a deliberate change: re-run the spike and the headless login smoke check.

## OAuth and OIDC integration

`src/test/java/com/revetsec/oauth/KeycloakOAuthIT.java` starts Keycloak 26.7.4 at the pinned image digest, binds its published port to 127.0.0.1 only, and uses the checked-in test CA and imports this realm. Run it with `mvn -B -ntp -Pintegration -Dmaven.javadoc.skip=true verify`. Testcontainers and the provider are test-only; the artifact gains no runtime dependency. CI requires all ten named cases to execute with zero skips, failures or errors.

| Client | Tested behavior |
|---|---|
| `revetsec-test-client` | Basic/query and POST/form-post OIDC code flows, JSON UserInfo, persisted session reference and refresh; existing OAuth refresh/revocation |
| `revetsec-public-client` | Public OIDC form-post flow, JSON UserInfo and refresh; existing public OAuth code flow |
| `revetsec-service-client` | Existing OAuth client-credentials flow |
| `revetsec-signed-userinfo-client` | RSA ID tokens and RS256 signed UserInfo, exact issuer/subject binding and refresh |
| `revetsec-hmac-client` | Expected rejection of the pinned provider's HS256 ID token because it is signed with the realm MAC key |

The signed-UserInfo client's fixed test-only secret is `test-only-signed-userinfo-secret-not-a-real-secret`. Its Keycloak attribute is `user.info.response.signature.alg=RS256`. The HMAC client's test-only secret is `test-only-hmac-client-secret-not-a-real-secret-` followed by 19 `s` characters; its attribute is `id.token.signed.response.alg=HS256`. None of these values may be reused outside the disposable test realm.

**Pinned-provider HMAC limit:** Keycloak 26.7.4's `DefaultTokenManager.encode` selects the algorithm's `SignatureProvider.signer()`. Its MAC signer selects the realm's active signing key, rather than this client's secret. Revetsec's OIDC HMAC mode verifies with the exact request-authentication `client_secret` and rejects this token with `ID_TOKEN_SIGNATURE_INVALID`, without releasing identity or endpoint credentials. Use asymmetric ID tokens with this provider. This negative integration case supplements the positive client-secret HMAC cases in `OidcHmacTests`; it does not establish HMAC compatibility with Keycloak.

The headless test browser submits the real login form, handles secure session cookies over TLS and stops at the fixed registered callback. Query responses are parsed from Keycloak's redirect. Form-post responses are taken from Keycloak's actual HTML form, encoded into a UTF-8 POST body and passed to the core form-body parser; the harness checks the exact action and POST mode and never contacts the callback URL. The HTML parser is test-only and deliberately tied to the pinned theme. Separate negatives prove that a changed callback route sends no token POST, a changed authorization nonce rejects the provider-signed token, and configured signed UserInfo cannot downgrade to the provider's JSON response.

## SAML service provider integration

`KeycloakSamlIT` uses the same pinned, loopback-only TLS container and a test-only SAML
client with `https://sp.test/KeycloakSamlIT` as its entity ID. The client signs its
Responses, encrypts assertions to the public test SP certificate, and exposes Redirect
Single Logout at `https://sp.test/logout`. The corresponding private key remains in the
Revetsec test process; it is not mounted into Keycloak. The browser driver checks
SP-initiated and explicitly enabled IdP-initiated POST SSO, AES-256-GCM/RSA-OAEP
assertion decryption, and Redirect logout in both directions. It submits Keycloak's
actual login and logout confirmation forms and verifies the returned SAML messages
through the core service provider. The broader SAML release matrix is still open.

`run_playground_browser.sh` starts a disposable browser fixture after the current core
and Soklet adapter JARs and Playground classes have been built. Set `SOKLET_JAR` to the
checksum-pinned Soklet 4.0.0 JAR and `BROWSER_SECCOMP` to the private derived profile
from [the browser setup](../inspector-auth/linux/README.md), then run
`bash interop/keycloak/run_playground_browser.sh` from the core repository. The runner
uses only locally cached images, prints a bounded JSON result, and removes its owned
containers and temporary realm/metadata directory. `playground_browser_probe.mjs`
drives the actual app in sandboxed Chromium. Its `--network none` fixture uses
Keycloak at `https://localhost:8444`, Caddy at
`https://localhost:9443`, and the Playground on loopback HTTP behind Caddy. It adds a
**temporary copy** of the SAML client to the imported test realm with entity ID
`https://localhost:9443/saml/metadata`, POST ACS
`https://localhost:9443/saml/acs`, Redirect logout
`https://localhost:9443/saml/slo`, and `saml.client.signature=true`; the runner does
this without changing the shared realm fixture. It feeds Keycloak's HTTPS
metadata from that isolated namespace to the Playground as an approved local file,
using the test SP signing/decryption certificate and private key. Mount the same test
CA into Keycloak, the edge, a Java trust store and the browser's private NSS store.
The browser container uses the pinned Inspector image, nonroot `pwuser`, the derived
Playwright seccomp profile and no certificate or sandbox bypass. The probe checks two
encrypted POST logins,
the secure app session cookie, SP logout with a Keycloak SAMLResponse, and Keycloak
logout with a signed LogoutRequest and the app's SAMLResponse. It emits only bounded
route/status facts and cleans up its private browser profile.

Chromium 153 sends `Origin: null` on Keycloak's automatic cross-site POST to the
ACS. The Playground permits this opaque origin only on its SAML ACS, where the
sealed pending browser state and full response validation remain required. It does
not add `null` to the general CORS allowlist or to application form endpoints.
