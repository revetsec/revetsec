# Identity Mapping

**Status: skeleton.** RevetSec contains no protocol code yet. This guide is expanded, with application code, as the OpenID Connect and SAML areas land.

Choosing which value identifies an account is the application's job, and the wrong choice leads to account takeover. These principles will shape the full guide:

- **OpenID Connect:** the account key is the issuer and subject pair (`iss`, `sub`). OpenID Connect Core 1.0 §5.7 names these as the only claims a relying party can rely on as a stable identifier. In a multi-tenant application, also include your own tenant or connection ID in the key, unless accounts are intentionally shared across tenants.
- **SAML:** key accounts on your own identifier for the configured identity-provider connection, together with a persistent subject identifier. Never use the identity provider's entityID as a namespace across tenants: it comes from metadata that tenants upload, so a hostile tenant can claim another tenant's entityID. Transient NameIDs are never account keys.
- **Email is profile data, not an account key.** Link accounts by email only when the email is verified, your policy treats the issuer as authoritative for the email's domain, and preferably the user confirms interactively. Never link across tenants.
