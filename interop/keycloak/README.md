# Keycloak test realm (test-only)

`revetsec-test-realm.json` is a minimal Keycloak realm for Revetsec's Tier-1 interop legs: self-hosted test partners for CI's planned `integration` job (see `.github/workflows/ci.yml`). Keycloak 26.7.x imports it at startup with `--import-realm` from `/opt/keycloak/data/import/`. The M0 spike in `../spike/` measures the import cost; see `../spike/TIER1-RESULTS.md`.

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
