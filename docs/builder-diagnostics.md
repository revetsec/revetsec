# Builder configuration diagnostics

`TotpAuthenticator.Builder`, `WebAuthnRelyingParty.Builder` and
`OAuthAuthorizationServer.Builder` expose `configurationDiagnostics()` for the
current configuration snapshot. It returns an immutable list in a fixed order.
An empty list means the builder's construction-time checks pass; it does not
establish that storage, sealing keys, recovery admission, authenticators,
browsers or deployment infrastructure are ready.

Each `ConfigurationDiagnostic` is a fixed enum code. Its field and reason codes,
message and documentation reference are static. Every reference names a public
setter on one of the inspected builders. None includes a configured value, URI,
key, tenant or application exception. Configuration inspection does not call a
store, gate, provider, observer or network client.
The fixed catalog contains 57 codes: five TOTP and six WebAuthn required-setting
codes, plus nine required, 28 invalid and nine incompatible OAuth codes.
Validation timing remains
builder-specific: TOTP and WebAuthn setters reject malformed supplied values
immediately and preserve the last accepted value, while OAuth routes and
numeric, resource and combined settings retain their documented inspection and
build-time validation. `build()` keeps its existing `NullPointerException`
boundary and first-missing-field message for TOTP and WebAuthn. The issuer keeps
its `IllegalStateException` boundary for missing required configuration and
`IllegalArgumentException` for invalid routes, resources and settings.
Inspection never invokes the issuer's optional construction observer.

For TOTP, the required settings are `credentialNamespace`, `recoveryEpoch`,
`store`, `stateSealer` and `recoveryGate`. For WebAuthn, they are
`relyingPartyName`, `credentialNamespace`, `allowedOrigins`, `store`,
`stateSealer` and `recoveryGate`. The trusted issuer or RP ID is checked when the
builder is created. Invalid setting values are checked by their setters.

The OAuth issuer reports its nine missing required fields, refresh without a
revocation route, invalid or duplicate routes, invalid configured resources,
individual bounds for all 22 numeric settings, compatible-time and sealer-fit
rules, the numeric HTTP loopback opt-in and the CIMD runtime floor. Checks that
depend on an invalid parent setting are deferred until that setting is repaired;
independent issues are still reported together. Duplicate routes are attributed
to the later route in the fixed authorization, token, JWKS, revocation and
introspection order, regardless of setter call order. Across families, the issuer
reports required settings, the refresh/revocation dependency, individual numeric
bounds, combined timing and sealer-fit rules, resources, issuer scheme, routes and
the CIMD runtime floor in that order. Each returned list is a point-in-time
snapshot; later builder changes do not alter it. The issuer factory validates its
primary URI shape before returning a builder. Collection setters preserve their
existing immediate input validation.

Applications may present the fixed codes to their local configuration operator.
Do not expose them as a remote readiness endpoint or treat a syntactically valid
builder as authorization to admit traffic.

The [self-issued issuer](../examples/self-issued/src/main/java/example/issuer/IssuerResources.java)
and [passkey](../examples/passkeys-soklet/src/main/java/example/passkeys/PasskeyApp.java)
examples inspect their completed builders before construction. The
[TOTP integration guide](../examples/totp-soklet/README.md#configure-and-initialize)
shows the same check for an application-owned launcher; its compiled lifecycle
fixture exercises that pattern.
