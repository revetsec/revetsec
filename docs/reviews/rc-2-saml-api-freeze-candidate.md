# RC-2 SAML public API freeze candidate — 2026-10-12

**Status: proposed for maintainer review; not frozen.** This inventory is for
the current uncommitted checkout after importing the hosted Shibboleth
captures. It covers `com.revetsec.saml` in the core JAR. The current RC-2 code
change is confined to `com.revetsec.internal.xml`; no public SAML declaration
changed in this slice.

The package has 39 public top-level types: 22 final classes, 11 sealed result
interfaces, three extension interfaces, and three enums. The public entry
points center on `SamlServiceProvider`, `SamlIdentityProvider`, their metadata
types, raw POST/Redirect binding messages, and pending login/logout values.
Expected protocol outcomes use sealed result types, with checked identity
available only from success variants. The application owns users, account
linking, sessions, browser storage, and local authorization decisions.

The exact top-level inventory for the freeze review is:

| Area | Public types |
| --- | --- |
| SP and IdP configuration | `SamlServiceProvider`, `SamlIdentityProvider`, `SamlAuthenticationRequestOptions`, `SamlCompatibilityMode`, `SamlCredential`, `SamlServiceProviderMetadata`, `SamlIdentityProviderMetadata` |
| Login and identity values | `SamlAuthentication`, `SamlAttribute`, `SamlAttributeValue`, `SamlNameId`, `SamlSubjectKey`, `SamlSessionReference` |
| Pending state, replay and observation | `PendingSamlAuthentication`, `PendingSamlAuthenticationSource`, `PendingSamlAuthenticationStore`, `InMemoryPendingSamlAuthenticationStore`, `PendingSamlLogout`, `PendingSamlLogoutSource`, `SamlReplayCache`, `InMemorySamlReplayCache`, `SamlObserver` |
| Bindings, logout and wire values | `SamlPostBindingMessage`, `SamlRedirectBindingMessage`, `SamlPostForm`, `SamlLogoutRequest`, `SamlLogoutStatus` |
| Typed results | `SamlAuthenticationRequestResult`, `SamlAuthenticationResult`, `SamlIdentityProviderMetadataResult`, `SamlServiceProviderMetadataResult`, `SamlPostBindingParseResult`, `SamlRedirectBindingParseResult`, `SamlPendingConsumeResult`, `SamlPendingSaveResult`, `SamlLogoutRequestResult`, `SamlLogoutRedirectResult`, `SamlLogoutResponseRedirectResult`, `SamlLogoutResult` |

The three extension interfaces are `SamlReplayCache`,
`PendingSamlAuthenticationStore`, and `SamlObserver`. A multi-node application
must provide atomic shared replay and pending storage; the in-memory classes
serve one node. `connectionId` is the application-selected namespace for IdP
identity. `SamlSubjectKey.toStableString()` is the persistent key component;
new exact tests pin its length-prefixed encoding and all NameID qualifier and
scoped-identifier components.

An IdP connection permits one through eight trusted message-signing keys for
rollover. Metadata-signature verification retains its separate one-through-four
trust-anchor limit. The [integration guide](../saml-sp.md) describes these
limits, the CBC opt-in, pending-state rules, and login/logout ownership.

The current full core suite passed 17,685/17,685 tests on both Corretto 17
and 21, with one intentional locale skip per run. RC-2 still needs the manual
pentest disposition, PIT survivor review, differential cross-product, and
maintainer review of the `internal.xml` key-limit diff. The seven-target local
fuzz campaign and 91-seed replay are recorded in the mutation triage ledger.
This candidate does not claim those gates or the API freeze are complete.
