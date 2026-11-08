# Google and Apple ID tokens handed to a backend

This unpublished Java 17 application recipe implements the shared R9/R10 behavior
using public `JwtValidator` and JWKS APIs. It supplies a bounded application
handler, one-use login state, local session rotation and explicit account and
authorization callbacks. A valid ID token reaches those callbacks after the
provider and request checks; it does not create an account or grant application
permissions by itself.

Build after installing a matching core artifact:

```sh
mvn -B -ntp -f examples/provider-backend-tokens/pom.xml verify
```

The module is an integration recipe. Its carrier-neutral handler is the common
implementation for the [Soklet carrier](../provider-backend-tokens-soklet/README.md) and paired
[Jakarta](https://github.com/revetsec/revetsec-servlet-jakarta/blob/main/docs/provider-tokens.md)/
[javax](https://github.com/revetsec/revetsec-servlet-javax/blob/main/docs/provider-tokens.md) recipe sources.
Those local source/container components have separate receipts and profile limits. This directory adds no
native SDK or hosted-provider qualification; the Soklet carrier needs its declared trusted HTTPS/query-free edge.
The source is application code and adds no core API or standalone ID-token product.

## Wire the application boundary

```java
import example.provider.BackendApplication;
import java.net.URI;

final class ProviderBackendWiring {
    static BackendApplication configure(String googleWebClientId, String appleBundleId,
            BackendApplication.Accounts accounts, BackendApplication.Admission admission) {
        var configuration = new BackendApplication.Configuration(
                URI.create("https://app.example"), googleWebClientId, appleBundleId,
                null, 128, 65_536);
        return BackendApplication.create(configuration, accounts, admission);
    }
}
```

Use trusted startup configuration for the HTTPS origin and client IDs. The
production factory fixes Google's key URL to
`https://www.googleapis.com/oauth2/v3/certs` and Apple's to
`https://appleid.apple.com/auth/keys`. It permits **RS256 only**, requires
`iss`/`aud`/`exp` plus `sub`/`iat`/`nonce`, and explicitly uses zero JWT clock skew.
Operate a correctly synchronized application clock. Remote sources have a
one-second request timeout, eight-key/64-KiB limits and no expired-key staleness.
They retain the core runtime-patch and outbound-URI protections. Token `jku`,
`x5u` and embedded-key headers cannot select a source. Provider metadata is
configuration evidence, not a runtime token-directed discovery mechanism.

Build `BackendApplication.Request` from the actual carrier's bounded raw fields.
Retain duplicate header and cookie values; retain the presence of even an empty
query and the framework's discarded/oversized-body flag. Do not reconstruct a
successful-looking prefix after input truncation. Request limits are 32 headers,
8 KiB of header text, a 32-KiB complete form body, 16 form fields and an 8-KiB
compact token. The host must enforce its connection, request queue, body-read and
overall response deadlines before constructing this value. Supply trusted TLS and
socket-peer context; do not derive them from arbitrary forwarding headers.

All POSTs use `application/x-www-form-urlencoded` (optionally UTF-8 charset).
Duplicate decoded form names and malformed UTF-8 fail. Responses are fixed errors
or allowlisted application values with `no-store`; there are no permissive CORS
headers. Return the listed cookie strings as separate `Set-Cookie` fields and
serialize `Reply.fields()` as JSON with a normal JSON writer. Keep request bodies,
responses containing challenges/sessions, provider tokens and exceptions out of logs.

## Google browser POST flow

1. `GET /session` reads local session status and allocates nothing. Explicit
   `POST /google/begin` with `begin=1` requires the exact configured Origin.
   Existing authenticated browsers also send their session-bound `csrf` value.
   The admission callback runs before allocation. A successful begin returns a
   nonce and a host-only Secure/HttpOnly `__Host-provider-login` cookie.
2. Set GIS `data-nonce`/`nonce` to that exact nonce before requesting a credential.
   GIS delivers `credential` and `g_csrf_token` to `POST /google/complete`.
   The handler compares the nonempty `g_csrf_token` cookie and body values
   **before key lookup**, then reserves the matching pending cookie once.
   An Origin, when present, must be the configured origin or Google's exact
   `https://accounts.google.com` origin; missing Origin does not bypass the CSRF
   and server-nonce checks.
3. Two fixed validators accept exactly `https://accounts.google.com` and
   `accounts.google.com`. Only a local issuer mismatch invokes the second policy;
   a key-source failure is not retried. Each validator has its own trusted source
   instance. The single-browser-client profile accepts exactly the configured
   audience, rejects additional audiences, and requires a present `azp` to match
   that client. Hybrid presenters need a separately reviewed profile.
4. If `googleHostedDomain` is configured, `hd` must exactly match it. Email and its
   domain never select an account or establish organization membership. The
   account callback receives canonical Google issuer + case-sensitive `sub`;
   both documented issuer spellings map to that same account key.
5. Current account policy must authorize sign-in. Success replaces the old
   session atomically, returns a fresh host-only Secure/HttpOnly/SameSite=Lax
   `__Host-provider-session` cookie and deletes the pending cookie. The old ID
   stops authorizing requests. Failed validation/account policy produces no new
   session; a claimed pending attempt is discarded.

These checks follow Google's [server verification guidance](https://developers.google.com/identity/gsi/web/guides/verify-google-id-token),
[GIS HTML contract](https://developers.google.com/identity/gsi/web/reference/html-reference)
and [OpenID claim descriptions](https://developers.google.com/identity/openid-connect/openid-connect).
The recipe intentionally supports the bounded form contract, rather than every
GIS response transport or hybrid client configuration.

## Apple native token flow

1. The native client explicitly POSTs `begin=1` to `/apple/begin` over HTTPS.
   This native-only contract accepts no browser Origin or Cookie. Admission is
   still required. For an existing native app session, send its opaque app
   session as `Authorization: Bearer <session>` to bind subsequent rotation.
2. Keep the returned `request_id`, **private `request_binding`** and `nonce` in
   the current client transaction. Set Apple's authorization-request nonce to
   the exact server-provided nonce. This recipe supplies no native SDK code or
   implicit hash transformation. If a chosen SDK hashes nonce input, explicitly
   align the transmitted/expected value in a separately tested integration.
3. Send `request_id`, `request_binding` and `identity_token` as a form POST to
   `/apple/complete`. The server matches the provider, binding and live one-use
   attempt before validation. It checks Apple's exact issuer, the configured
   native bundle-ID audience, signature, expiry and exact signed nonce. A
   present `nonce_supported` must be boolean true; a missing nonce never selects
   a weaker legacy path. A present `azp` must match the configured audience.
4. Current account policy resolves Apple issuer + `sub`. Email, private-relay
   address, display name and untrusted request `client_id` do not map accounts.
   Success returns a fresh opaque **application** `session_token`, without a
   browser cookie. Use that session at `/native/session`,
   `/native/account/{tenant}/{account}` and `/native/logout`; never use the ID
   token as the application's API bearer credential.

Apple documents the [server verification checks](https://developer.apple.com/documentation/signinwithapple/verifying-a-user),
[server-session/nonce association](https://developer.apple.com/documentation/signinwithapple/authenticating-users-with-sign-in-with-apple)
and [request nonce](https://developer.apple.com/documentation/authenticationservices/asauthorizationopenidrequest/nonce).
Its [published discovery metadata](https://appleid.apple.com/.well-known/openid-configuration)
and [verification keys](https://appleid.apple.com/auth/keys), checked 2026-11-05,
advertise RS256 for ID tokens; that is this recipe's explicit verification policy.
Authorization-code exchange, refresh tokens, account-transfer migration,
server notifications and device credential-state APIs remain separate application
lifecycle integrations. A local signed fixture does not establish a real native
Apple sign-in or current provider account standing.

## Accounts, authorization, state and recovery

`Accounts.findAndAuthorizeLogin` performs a current, bounded, read-only lookup by
issuer + subject. Return an existing eligible local `Account`, or deny. Provision
and link accounts through an explicit separate application workflow; never link
by an email match. `Accounts.authorize` must consult current account policy on
every protected operation. The handler additionally enforces exact local
tenant/owner matching at `/account/{tenant}/{account}` and its native equivalent.
Local session status is not a substitute for those authorization checks.

`Admission` must implement source/global abuse policy using trusted peer context
and honor its supplied remaining budget. Apply account-specific limits in the
current account callback before authorizing sign-in. There are at most
eight validation/account workflows in flight. Pending attempts and sessions each
have the configured entry bound, and a conservative retained-string byte budget
accounts for referenced old sessions. Cleanup examines/rotates at most 16 entries
per map on an explicit begin; it never evicts a live row to obtain space.
Attempts last five minutes and sessions 30 minutes, with elapsed-time expiry
preventing revival after a wall-clock rollback. State is volatile and single
process: restart discards it; horizontal operation needs application-owned
durable atomic nonce/session transitions and recovery admission.

Every handler starts one four-second monotonic budget. It requires time for the
key source's bounded call, passes shrinking time to account/admission callbacks,
and withholds session creation after cancellation, late policy or token expiry. Callbacks must
honor that budget. There is no automatic retry, account mutation, hidden account
creation or read-based reconstruction of a withheld session. Start a fresh
user-initiated login after failure; infrastructure responses do not authorize a
blind retry loop. A pre-work busy refusal does not run the token/account phase.

Browser logout requires same Origin and session CSRF; native logout uses its
explicit app-session bearer and accepts no ambient cookies. Both end only the
application's local session. Disable/unlink current account mappings and apply
current policy to recovery/revocation separately from provider logout. Concurrent
logout or session loss during account lookup prevents publishing a replacement.

## Evidence boundary

Tests use deterministic **test-only** RSA/signature material, issued nonce/request
fixtures and fresh loopback JWKS endpoints through the actual public validators.
They cover issuer aliases, audience/presenter/domain policy, request multiplicity,
CSRF ordering, nonce replay/races, hostile signatures/key references, source
outage, account/tenant denial, rotation/logout, budgets, expiry, concurrency,
capacity and redaction. Test loopback opt-in and deterministic randomness are
package-private fixture wiring; the production factory exposes neither.

Hosted Google/browser and Apple account/device observations remain **unproven**.
Soklet and both Servlet namespace routing, real-container parity, distributed
sessions/recovery and the formal M12 tool pass require their own evidence.
