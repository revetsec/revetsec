# WebAuthn browser and extension compatibility

This is the selected current-source profile, checked on 2026-11-03. It is narrower than the set
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

The October review's `credProps.authenticatorDisplayName` example referred to an older draft:
the working group [removed it in November 2024](https://github.com/w3c/webauthn/pull/2194).
The [Level 3 Recommendation's credential-properties definition](https://www.w3.org/TR/webauthn-3/#sctn-authenticator-credential-properties-extension)
defines `rk`, not that display-name member. Current rejection of that historical field is pinned
by conformance tests, not a newly implemented Level 3 requirement. The broader forward-compatibility
limit remains real: legitimate extra outputs outside this selected profile still reject.
See also the standard's [JSON serialization contract](https://www.w3.org/TR/webauthn-3/#sctn-publickeycredential-tojson).

## Dated target-browser evidence

The 2026-11-03 disposable run used macOS 27.0.1/arm64 and the current-source public relying-party
operations with controlled test-store authority time. Raw browser responses traveled through a
private stdin pipe to a test-only Java peer; receipts retain shapes and outcomes, not credentials,
keys, signatures, user handles or corresponding payload hashes.

| Browser/authenticator target | Observed evidence | Scope or remaining gap |
| --- | --- | --- |
| Installed Chrome 156.0.8078.80, CDP CTAP2.1 virtual USB with resident key and UV | Native JSON registration and discoverable sign-in succeeded at the exact HTTPS RP host and at its explicitly configured HTTPS child origin. Registration returned only `credProps.rk=true`; authentication returned `{}`. ES256, `none` attestation, flags 0x45/0x05, no authenticator ED. | Virtual desktop profile only; no physical key, platform authenticator, synced provider or conditional-autofill claim. |
| Bundled Chromium 149.0.7827.55, same virtual profile | Same native JSON shape and successful public API outcomes. | A second Chromium version, not a second independent browser engine. |
| Configured dot-delimited subdomain, both Chromium versions | Native registration/sign-in succeeded at `https://login.passkeys.example.test` with RP ID `passkeys.example.test` and a singleton exact origin allowlist. | Selected SR-2 parent/child virtual profile passes; other child origins remain untrusted unless explicitly listed. |
| Bundled Firefox 151.0 | JSON creation/request parsing and `toJSON()` were present; conditional-mediation capability returned true. | Capability probe only, with context-local TLS verification bypass. No ceremony, extension-output, physical/provider or Revetsec interoperability qualification. |
| Patched WebKit 26.5 | JSON APIs were present; conditional-mediation capability returned false. | Capability probe only under the same limited TLS setup. This is not installed Safari evidence. |
| Installed Safari 27.0.1; platform/synced providers; conditional autofill | No new ceremony evidence in this slice. | Explicitly unproven. API availability is not an autofill result. |
| Yubico Security Key C NFC, USB, Chrome 155.0.8059.40 on macOS 27.0.1, 2026-10-15 | The [historical physical-key flow](../../planning/records/webauthn/physical-key-2026-10-15/physical-key-report.json) covered registration, sign-in, reauthentication and rejection after removal. | Bound to its old browser/artifacts. It is not a fresh current-source extension-output capture or proof for another model/transport/provider. |

The Chromium runs used private browser profiles, an exact local DNS HTTPS edge, a private leaf
SPKI pin and the browser sandbox. They changed no system trust store. Twelve injected negatives
per successful profile (48 total across four profiles) rejected without mutation: historical
display-name output, extra client output, `rk=false`, unlisted child, suffix-lookalike, sibling
and another eligible-but-unlisted origin, wrong challenge, cross-origin/top-origin data, extra
authentication output and wrong RP-hash/signature bytes. These were deliberate mutations of
native response copies; the browsers did not natively emit those extra results.
Neither observed native profile returned packed attestation under conveyance `none`.

## SR-2/SR-5 handoff and policy changes

SR-2 is implemented for up to eight exact HTTPS origins on the RP host or a canonical
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

SR-5 still needs dated target-provider evidence for `credProps.rk`, any packed-under-`none`
behavior, platform/synced credentials and actual conditional sign-in, or precise unproven entries.
Before accepting another extension output, record a real browser/provider response shape and
decide its bounded grammar, trust meaning, malformed/duplicate/oversized handling, signature and
store-mutation controls. A parser widening needs its own implementation and qualification;
neither this policy nor the stale display-name example authorizes silently ignoring extra outputs.

The [reproducible browser harness](../verification/webauthn-browser-extensions/README.md) and the
[SR-2 slice evidence](../../planning/records/security/webauthn-sr2-origins-2026-11-03/HANDOFF.md)
bind source, runtime and browser identities. Physical-key/current-browser refresh, actual store
and witness/recovery behavior, hosted browser coverage and RC-WA/API/release approval remain open.
