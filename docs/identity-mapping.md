# Identity Mapping

**Status: pre-release.** Revetsec validates OIDC and SAML identities, but the application owns account linking, local users and sessions.

Choosing which value identifies an account is the application's job, and the wrong choice leads to account takeover. These principles will shape the full guide:

- **OpenID Connect:** the account key is the issuer and subject pair (`iss`, `sub`). OpenID Connect Core 1.0 §5.7 names these as the only claims a relying party can rely on as a stable identifier. In a multi-tenant application, also include your own tenant or connection ID in the key, unless accounts are intentionally shared across tenants.
- **SAML:** key accounts on the pair `(authentication.getIdentityProviderConnectionId(), authentication.getSubjectKey().orElseThrow().toStableString())`. The subject key exists for a persistent NameID or a scope-authorized `subject-id` or `pairwise-id`; a transient NameID alone does not produce one. Never use the IdP `entityID` as the namespace across tenants: a tenant-uploaded metadata document can claim someone else's entityID. Configure a different application connection ID for each tenant connection, even if they use the same IdP.
- **Email is profile data, not an account key.** Link accounts by email only when the email is verified, your policy treats the issuer as authoritative for the email's domain, and preferably the user confirms interactively. Never link across tenants.

For SAML logout, retain `authentication.getSessionReference()` with the local session. When Revetsec validates a signed IdP LogoutRequest, match both its connection ID and its NameID qualifiers and SessionIndex against your stored references before ending a session. Revetsec identifies the request and signs a response; it does not terminate local sessions.
