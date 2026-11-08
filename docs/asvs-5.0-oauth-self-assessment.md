# OAuth and token responsibility map — 2026-10-14

This is an internal source/test responsibility map for the shipped library and examples. It is not an assessment of a deployed application. The references are OWASP ASVS [5.0.0 V9](https://github.com/OWASP/ASVS/blob/v5.0.0/5.0/en/0x18-V9-Self-contained-Tokens.md) and [V10](https://github.com/OWASP/ASVS/blob/v5.0.0/5.0/en/0x19-V10-OAuth-and-OIDC.md). Each identifier is retained, including unsupported and application-owned requirements. A test reference supplies bounded implementation evidence; deployment remains the application's responsibility.

Test names are relative to `src/test/java/com/revetsec`; example tests are labeled explicitly. The [threat model](threat-model.md) retains invariant mappings and limits. No ASVS level is claimed.

| V9 ID | Responsibility/evidence |
| --- | --- |
| 9.1.1 | Revetsec: `jose.JwtValidatorRfcVectorTests`, `jose.JwtValidatorRobustnessTests` |
| 9.1.2 | Revetsec: `jose.JwtValidatorAlgorithmConfusionTests`, `oidc.OidcHmacTests` |
| 9.1.3 | Revetsec: `jose.JwtValidatorHeaderTests`, `jose.JwtValidatorKeySelectionTests`; app configures trusted sources |
| 9.2.1 | Revetsec: `jose.JwtValidatorClaimsTests`, `oauth.ResourceServerAssuranceTests` |
| 9.2.2 | Revetsec: `jose.JwtValidatorHeaderTests`, `oauth.ResourceServerAssuranceTests`, `oidc.OidcAuthenticationFlowTests` |
| 9.2.3 | Revetsec: `jose.JwtValidatorClaimsTests`, `oauth.TokenIntrospectionClientTests` |
| 9.2.4 | Revetsec: `oauth.server.OAuthCodeRedemptionTests`; app controls resource registrations |

| V10 ID | Responsibility/evidence |
| --- | --- |
| 10.1.1 | App-owned: credential placement and BFF deployment; example `IssuerApplicationTests` exercises redacted responses |
| 10.1.2 | Revetsec/app binding: `oauth.PendingAuthorizationSourceTests`, `oidc.OidcAuthenticationFlowTests` |
| 10.2.1 | Revetsec: `oauth.PendingAuthorizationStoreTests`, `oidc.OidcAuthenticationFlowTests` |
| 10.2.2 | Revetsec: `oidc.OidcAuthenticationFlowTests`, `oauth.AuthorizationResponseTests` |
| 10.2.3 | App-owned scope selection; `oauth.AuthorizationRequestTests` checks request overrides |
| 10.3.1 | Revetsec: `oauth.ResourceServerAssuranceTests`, `oauth.TokenIntrospectionClientTests` |
| 10.3.2 | App-owned permissions; example `IssuerApplicationTests` exercises scope/tenant/object denial |
| 10.3.3 | App-owned identity mapping; checked issuer/subject facts: `oidc.OidcSessionReferenceTests` |
| 10.3.4 | App-owned resource strength policy; RP checks: `oidc.OidcAuthenticationFlowTests` |
| 10.3.5 | Unsupported: sender-constrained tokens; bearer deployments cannot satisfy this row through Revetsec |
| 10.4.1 | Revetsec/app registrations: `oauth.server.OAuthAuthorizationServerTests` |
| 10.4.2 | Revetsec/store contract: `oauth.server.OAuthCodeRedemptionTests` |
| 10.4.3 | Revetsec checked limits; app selects lifetime: `oauth.server.OAuthCodeRedemptionTests` |
| 10.4.4 | Revetsec/app client grants: `oauth.server.OAuthAuthorizationServerTests` |
| 10.4.5 | Revetsec/store contract: `oauth.server.OAuthRefreshRotationTests` |
| 10.4.6 | Revetsec: `oauth.server.OAuthCodeRedemptionTests` |
| 10.4.7 | N/A: dynamic client registration unsupported; CIMD has a separate bounded admission contract |
| 10.4.8 | Revetsec/store contract: `oauth.server.OAuthRefreshRotationTests` |
| 10.4.9 | App-owned revocation UI; core operations: `oauth.server.OAuthIssuerTokenStatusTests` |
| 10.4.10 | Revetsec/app credentials: `oauth.server.OAuthAuthorizationServerTests`; PAR unsupported |
| 10.4.11 | App-owned registered/requested/consented scopes; `oauth.server.OAuthCodeRedemptionTests` |
| 10.4.12 | Revetsec supports query responses; `oauth.server.OAuthAuthorizationServerTests` |
| 10.4.13 | Unsupported: PAR |
| 10.4.14 | Unsupported: sender-constrained issuance |
| 10.4.15 | N/A: RAR unsupported |
| 10.4.16 | Unsupported issuer authentication modes; client-side signer: `oauth.ClientAuthenticationTests` |
| 10.5.1 | Revetsec: `oidc.OidcAuthenticationFlowTests` |
| 10.5.2 | App-owned account continuity; checked subject continuity: `oidc.OidcRefreshTests`, `oidc.OidcSessionReferenceTests` |
| 10.5.3 | Revetsec: `oidc.OidcAuthenticationFlowTests` |
| 10.5.4 | Revetsec: `oidc.OidcAuthenticationFlowTests`, `oidc.OidcHmacTests` |
| 10.5.5 | N/A: OIDC back-channel logout unsupported |
| 10.6.1 | N/A: OpenID Provider unsupported |
| 10.6.2 | N/A: OpenID Provider unsupported |
| 10.7.1 | App-owned consent; example `IssuerApplicationTests` |
| 10.7.2 | App-owned consent presentation; example `IssuerApplicationTests` |
| 10.7.3 | App-owned consent management; core revocation: `oauth.server.OAuthIssuerTokenStatusTests` |

Store atomicity, persistence, restore coordination, keys, browser sessions, consent, authorization and operational policy require application evidence. The volatile self-issued example does not qualify a production deployment. Bearer tokens do not prove possession or prevent theft/replay by a credential holder. Current RC qualification records retain actual local observations and remaining gates separately.

## Selected pre-release changes — 2026-11-06

The original 43 V9/V10 identifiers and responsibility assignments above remain. The following source/test additions refine this map; they do not establish deployed-application assessment results or close release qualification.

| Surface | Responsibility and current source/test inputs |
| --- | --- |
| Selected signing algorithms (9.1.2 and client credentials in 10.4.10) | The [signing profile](supported-algorithms.md#bounded-signing-jwssigner) separates general signing, client assertions and the RS256-only issuer. `jose.JwsSignerRsaExpansionTests`, `jose.JwsSignerEcExpansionTests` and `jose.JwsSignerEd25519ExpansionTests` cover selected software profiles. Applications select trusted registration, key/provider and exact algorithm; a local provider fixture does not establish hosted-provider or hardware acceptance. |
| Per-flow assurance (10.3.4 and 10.5.2) | [Ordered request preferences and local acceptance](oidc-flow-assurance.md) are separate. `oidc.OidcAcrPreferenceTests` and `oidc.OidcPerFlowAssuranceTests` cover saved required ACR values on refresh and strict version-2 references. Applications clear unsupported version-1 references and require authentication again; no missing policy is inferred from defaults. |
| Browser pending state (10.1.2 and 10.2.1) | [Pending-state storage](oauth-client.md) requires exact correlation and the selected atomic store contract. Cookie-only and atomic-store profiles have different concurrent-consumption guarantees. Store uncertainty does not authorize replay or establish that earlier work had no effects. |
| RP-Initiated Logout (additional selected capability) | [Logout](oidc-logout.md) and `oidc.OidcLogoutFlowTests`, `oidc.OidcLogoutEdgeTests` and `oidc.OidcLogoutHintTests` cover checked hints, pending correlation and withheld output. The [local-first recipe](../examples/rp-initiated-logout/README.md) makes local POST/CSRF authorization and session closure application responsibilities. Provider return correlation grants no sign-in identity or session restoration. This capability does not satisfy the unsupported back-channel logout row 10.5.5. |
| Import-only key utilities (supporting input boundary) | [Key imports](key-imports.md) provide bounded parsing and a separate budgeted pair check. They establish no certificate-chain trust, private-key export permission, provider readiness or application key-rotation policy. |

The API declaration snapshot and [compatibility policy](../COMPATIBILITY.md) are separate from this responsibility map. Final source/member, claims, adversary, browser/provider, operating-profile and owner acceptance checks remain required. New API declarations or stronger integration types do not substitute for their runtime/effect evidence.
