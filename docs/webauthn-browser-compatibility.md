# WebAuthn browser and extension compatibility

This page describes the selected browser and extension profile. It is narrower than the set
of optional WebAuthn features. A browser exposing the JSON APIs is not by itself a qualified
browser/authenticator/provider combination. The application submits native
`PublicKeyCredential.toJSON()` output without deleting extension results or rewriting signed
client/authenticator data to make a response fit.

## Accepted and rejected outputs

| Surface | Current profile |
| --- | --- |
| Registration `clientExtensionResults` | Exactly `{"credProps":{"rk":true}}`. Missing/false/mistyped `rk`, missing/nonobject results and any additional member at either object level reject. |
| Authentication `clientExtensionResults` | Exactly `{}`. Any extra output, including `credProps`, PRF, large-blob or unknown results, rejects. |
| Registration authenticator extension data | No ED flag, or the bounded exact CBOR map `credProtect: 1`, `2` or `3`. Other keys, extra members, invalid values or malformed CBOR reject. This does not establish authenticator model trust or replace UV. |
| Authentication authenticator extension data | ED is not supported in this profile; unexpected extension/trailing bytes reject. |
| Attestation with conveyance `none` | Only the `none` format and empty `attStmt` are accepted. Packed self-attestation is not accepted by the current parser, even if returned in response to a `none` request. |

These are explicit library choices, not a claim that WebAuthn requires rejection of every
additional client output. Byte/node/decoded-data bounds, duplicate-key rejection, challenge,
exact configured origin, RP-ID hash, UP/UV, COSE/algorithm and authoritative commit/signature
checks still apply. The unsigned client `credProps` result alone is no proof or permission.
Synthetic negative cases verify that rejection leaves the original ceremony usable and stored
credential/counter state unchanged. The table concerns extension objects and consumed binary
structures; it is not a new universal allowlist for every JSON member.

The `credProps.authenticatorDisplayName` member came from an older draft:
the working group [removed it in November 2024](https://github.com/w3c/webauthn/pull/2194).
The [Level 3 Recommendation's credential-properties definition](https://www.w3.org/TR/webauthn-3/#sctn-authenticator-credential-properties-extension)
defines `rk`, not that display-name member. Current rejection of that historical field is pinned
by conformance tests, not a newly implemented Level 3 requirement. The broader forward-compatibility
limit remains real: legitimate extra outputs outside this selected profile still reject.
See also the standard's [JSON serialization contract](https://www.w3.org/TR/webauthn-3/#sctn-publickeycredential-tojson).

## Origin, binding and extension policy

A relying party accepts up to eight exact HTTPS origins on the RP host or a canonical
dot-delimited subdomain. For RP ID `example.com`, `https://login.example.com` is eligible,
but only an explicitly listed origin and port can complete a ceremony. Listing the parent does
not trust its children; listing a child does not trust its siblings, deeper children or another
port. Use lowercase ASCII DNS (punycode for internationalized names), omit the default HTTPS
port and configure nondefault ports explicitly. Existing aggregate pending-record byte budgets
still apply. Trusted application configuration chooses the RP ID and origins; request headers
do not choose trust. The app must control the selected registrable RP domain and each origin;
core does not perform a complete public-suffix-list lookup. This follows the standard
[RP-ID/origin relationship](https://www.w3.org/TR/2026/REC-webauthn-3-20260825/#relying-party-identifier);
exact origin verification remains a separate check. Related Origin Requests, HTTP/IP origins,
iframe/cross-origin and native-app profiles remain outside this scope.

Before constructing the relying party, `WebAuthnRelyingParty.Builder.configurationDiagnostics()`
can report every missing required setting as fixed, redacted codes. See
[builder configuration diagnostics](builder-diagnostics.md) for its construction-only scope; an
empty result does not verify browser compatibility, authenticator behavior or deployment readiness.

Update all participating readers before enabling child-origin configuration: the existing WAR2
codec format is unchanged, but older readers reject child-origin pending records. Existing
ceremonies keep their sealed origin snapshot; changing configuration does not retroactively add
or remove their origins. Coordinate configuration changes and pending-ceremony expiry accordingly.
No credential format, storage address or RP-ID hash changes, and no credential migration or
re-enrollment is required by this origin-policy change. Keep the same RP ID to retain that scope.

The six registration, sign-in and checked-reauthentication entry points take
[`OperationBinding`](https://javadoc.revetsec.com/com/revetsec/OperationBinding.html). WebAuthn
retains its narrower existing boundary: the emitted secret must be exactly 43 canonical unpadded
Base64URL characters decoding to 32 bytes. Generate it with `OperationBinding.fresh()` and retain
it in protected application session state. Do not turn a browser cookie or other request value
into a carrier with `fromTrustedPersistence`; compare request material to the retained session and
pass the retained carrier. The carrier correlates credential work only. It is not identity,
permission, freshness, uniqueness or a one-use action grant; the application still checks its
current session/account/purpose and atomically consumes its own pending action.

Provider behavior for `credProps.rk`, packed attestation under conveyance `none`,
platform/synced credentials and conditional sign-in is unproven for this profile. Accepting any
further extension output would require its own bounded grammar, trust meaning,
malformed/duplicate/oversized handling, and signature and store-mutation controls. Revetsec does
not silently ignore extra outputs.

Compatibility with a particular browser, physical key, platform authenticator or synced provider
is not established by this page. Test the combinations your users rely on; the
[reproducible browser harness](../verification/webauthn-browser-extensions/README.md) shows one
way to exercise native browser responses against the relying-party operations.
