# Current public type inventory

Measured **2026-11-03** from the uncommitted **1.0.0-SNAPSHOT** core source. Revetsec remains pre-release, with no compatibility promise before 1.0.0. See the [compatibility policy](../COMPATIBILITY.md) for what is API and how changes are treated.

## Counting rules

- Include public top-level declarations in the 11 exported core packages, then their public or protected member types recursively, provided every enclosing type is exported. This follows [ContractSupport.exportedTypes](../src/test/java/com/revetsec/ContractSupport.java) and the [public API contract checks](../src/test/java/com/revetsec/PublicApiContractTests.java).
- Count each declaration once, under its declaring top-level type. Nested builders, result variants and enums are explicit in the lists. Inherited references to a nested type do not create another declaration. Implicitly public member types of interfaces are included.
- Exclude internal packages, package-private/private types, types hidden by a non-exported enclosing type, local/anonymous/synthetic classes, and adapter/test/tooling artifacts. Methods, constructors, fields, enum constants and compiler-generated methods are not type declarations.
- Inclusion does not mean applications can construct or extend a type. Restricted carriers and result variants retain their documented construction and success-only payload rules. No protected nested declarations occur in this snapshot; all listed types are public.

The attributed source inventory (`--release 17`) and compiled accessible declarations agree exactly on **677 types: 327 top-level and 350 nested**, measured on JDK 21. These are declaration counts, not a member-level compatibility diff, API freeze, runtime/provider qualification or release acceptance. Public/protected members, including inherited members, and behavior/default/storage changes require separate review. The existing contract tests enforce API shape; they do not automatically keep this Markdown snapshot synchronized. Refresh the counts and complete lists whenever exported declarations change, and remeasure the final release candidate.

## Package totals

| Package | Top-level | Nested | Total |
| --- | ---: | ---: | ---: |
| [`com.revetsec`](#comrevetsec) | 11 | 5 | 16 |
| [`com.revetsec.jose`](#comrevetsecjose) | 26 | 13 | 39 |
| [`com.revetsec.json`](#comrevetsecjson) | 7 | 1 | 8 |
| [`com.revetsec.oauth`](#comrevetsecoauth) | 52 | 37 | 89 |
| [`com.revetsec.oauth.server`](#comrevetsecoauthserver) | 39 | 28 | 67 |
| [`com.revetsec.oidc`](#comrevetsecoidc) | 18 | 21 | 39 |
| [`com.revetsec.password`](#comrevetsecpassword) | 15 | 12 | 27 |
| [`com.revetsec.saml`](#comrevetsecsaml) | 43 | 63 | 106 |
| [`com.revetsec.scim`](#comrevetsecscim) | 58 | 59 | 117 |
| [`com.revetsec.totp`](#comrevetsectotp) | 34 | 67 | 101 |
| [`com.revetsec.webauthn`](#comrevetsecwebauthn) | 24 | 44 | 68 |
| **Total** | **327** | **350** | **677** |

## com.revetsec

11 top-level + 5 nested = **16 types**. Names link to the declaring source file.

| Top-level declaration | Kind | Accessible nested declarations |
| --- | --- | --- |
| [`ErrorCategory`](../src/main/java/com/revetsec/ErrorCategory.java) | enum | — |
| [`InvalidSealedStateException`](../src/main/java/com/revetsec/InvalidSealedStateException.java) | class | — |
| [`OutboundUriPolicy`](../src/main/java/com/revetsec/OutboundUriPolicy.java) | class | — |
| [`RevetsecException`](../src/main/java/com/revetsec/RevetsecException.java) | class | — |
| [`SealingKey`](../src/main/java/com/revetsec/SealingKey.java) | class | — |
| [`StateSealer`](../src/main/java/com/revetsec/StateSealer.java) | class | [`StateSealer.Builder`](../src/main/java/com/revetsec/StateSealer.java) |
| [`StateUnsealResult`](../src/main/java/com/revetsec/StateUnsealResult.java) | class | [`StateUnsealResult.Rejected`](../src/main/java/com/revetsec/StateUnsealResult.java), [`StateUnsealResult.Succeeded`](../src/main/java/com/revetsec/StateUnsealResult.java) |
| [`StoreAdmission`](../src/main/java/com/revetsec/StoreAdmission.java) | class | — |
| [`StoreCommitTiming`](../src/main/java/com/revetsec/StoreCommitTiming.java) | class | — |
| [`StoreTemporalCondition`](../src/main/java/com/revetsec/StoreTemporalCondition.java) | class | — |
| [`StoreTimeObservation`](../src/main/java/com/revetsec/StoreTimeObservation.java) | interface | [`StoreTimeObservation.Healthy`](../src/main/java/com/revetsec/StoreTimeObservation.java), [`StoreTimeObservation.Unavailable`](../src/main/java/com/revetsec/StoreTimeObservation.java) |

## com.revetsec.jose

26 top-level + 13 nested = **39 types**. Names link to the declaring source file.

| Top-level declaration | Kind | Accessible nested declarations |
| --- | --- | --- |
| [`JoseException`](../src/main/java/com/revetsec/jose/JoseException.java) | class | [`JoseException.Reason`](../src/main/java/com/revetsec/jose/JoseException.java) |
| [`JoseObserver`](../src/main/java/com/revetsec/jose/JoseObserver.java) | interface | — |
| [`Jwk`](../src/main/java/com/revetsec/jose/Jwk.java) | class | — |
| [`JwkSkipReason`](../src/main/java/com/revetsec/jose/JwkSkipReason.java) | enum | — |
| [`Jwks`](../src/main/java/com/revetsec/jose/Jwks.java) | class | — |
| [`JwksParseResult`](../src/main/java/com/revetsec/jose/JwksParseResult.java) | class | [`JwksParseResult.Rejected`](../src/main/java/com/revetsec/jose/JwksParseResult.java), [`JwksParseResult.Succeeded`](../src/main/java/com/revetsec/jose/JwksParseResult.java) |
| [`JwksPublisher`](../src/main/java/com/revetsec/jose/JwksPublisher.java) | class | [`JwksPublisher.Builder`](../src/main/java/com/revetsec/jose/JwksPublisher.java) |
| [`JwksResponse`](../src/main/java/com/revetsec/jose/JwksResponse.java) | class | — |
| [`JwksSource`](../src/main/java/com/revetsec/jose/JwksSource.java) | interface | — |
| [`JwksUnavailableException`](../src/main/java/com/revetsec/jose/JwksUnavailableException.java) | class | — |
| [`JwsAlgorithm`](../src/main/java/com/revetsec/jose/JwsAlgorithm.java) | enum | — |
| [`JwsSigner`](../src/main/java/com/revetsec/jose/JwsSigner.java) | class | [`JwsSigner.Builder`](../src/main/java/com/revetsec/jose/JwsSigner.java) |
| [`JwsSigningException`](../src/main/java/com/revetsec/jose/JwsSigningException.java) | class | [`JwsSigningException.Reason`](../src/main/java/com/revetsec/jose/JwsSigningException.java) |
| [`Jwt`](../src/main/java/com/revetsec/jose/Jwt.java) | class | — |
| [`JwtClaims`](../src/main/java/com/revetsec/jose/JwtClaims.java) | class | — |
| [`JwtClaimsSet`](../src/main/java/com/revetsec/jose/JwtClaimsSet.java) | class | [`JwtClaimsSet.Builder`](../src/main/java/com/revetsec/jose/JwtClaimsSet.java) |
| [`JwtSigningHeader`](../src/main/java/com/revetsec/jose/JwtSigningHeader.java) | class | [`JwtSigningHeader.Builder`](../src/main/java/com/revetsec/jose/JwtSigningHeader.java) |
| [`JwtType`](../src/main/java/com/revetsec/jose/JwtType.java) | enum | — |
| [`JwtValidationException`](../src/main/java/com/revetsec/jose/JwtValidationException.java) | class | — |
| [`JwtValidationResult`](../src/main/java/com/revetsec/jose/JwtValidationResult.java) | class | [`JwtValidationResult.Rejected`](../src/main/java/com/revetsec/jose/JwtValidationResult.java), [`JwtValidationResult.Succeeded`](../src/main/java/com/revetsec/jose/JwtValidationResult.java) |
| [`JwtValidator`](../src/main/java/com/revetsec/jose/JwtValidator.java) | class | [`JwtValidator.Builder`](../src/main/java/com/revetsec/jose/JwtValidator.java) |
| [`MalformedJoseInputException`](../src/main/java/com/revetsec/jose/MalformedJoseInputException.java) | class | — |
| [`PublishedJwk`](../src/main/java/com/revetsec/jose/PublishedJwk.java) | class | [`PublishedJwk.Builder`](../src/main/java/com/revetsec/jose/PublishedJwk.java) |
| [`RemoteJwksSource`](../src/main/java/com/revetsec/jose/RemoteJwksSource.java) | class | [`RemoteJwksSource.Builder`](../src/main/java/com/revetsec/jose/RemoteJwksSource.java) |
| [`StaticJwksSource`](../src/main/java/com/revetsec/jose/StaticJwksSource.java) | class | — |
| [`UnsupportedJoseFeatureException`](../src/main/java/com/revetsec/jose/UnsupportedJoseFeatureException.java) | class | — |

## com.revetsec.json

7 top-level + 1 nested = **8 types**. Names link to the declaring source file.

| Top-level declaration | Kind | Accessible nested declarations |
| --- | --- | --- |
| [`JsonArray`](../src/main/java/com/revetsec/json/JsonArray.java) | class | — |
| [`JsonBoolean`](../src/main/java/com/revetsec/json/JsonBoolean.java) | class | — |
| [`JsonNull`](../src/main/java/com/revetsec/json/JsonNull.java) | class | — |
| [`JsonNumber`](../src/main/java/com/revetsec/json/JsonNumber.java) | class | — |
| [`JsonObject`](../src/main/java/com/revetsec/json/JsonObject.java) | class | [`JsonObject.Builder`](../src/main/java/com/revetsec/json/JsonObject.java) |
| [`JsonString`](../src/main/java/com/revetsec/json/JsonString.java) | class | — |
| [`JsonValue`](../src/main/java/com/revetsec/json/JsonValue.java) | interface | — |

## com.revetsec.oauth

52 top-level + 37 nested = **89 types**. Names link to the declaring source file.

| Top-level declaration | Kind | Accessible nested declarations |
| --- | --- | --- |
| [`AccessToken`](../src/main/java/com/revetsec/oauth/AccessToken.java) | class | — |
| [`AccessTokenAcquisitionResult`](../src/main/java/com/revetsec/oauth/AccessTokenAcquisitionResult.java) | class | [`AccessTokenAcquisitionResult.Rejected`](../src/main/java/com/revetsec/oauth/AccessTokenAcquisitionResult.java), [`AccessTokenAcquisitionResult.Succeeded`](../src/main/java/com/revetsec/oauth/AccessTokenAcquisitionResult.java) |
| [`AccessTokenCompatibilityMode`](../src/main/java/com/revetsec/oauth/AccessTokenCompatibilityMode.java) | enum | — |
| [`AccessTokenObserver`](../src/main/java/com/revetsec/oauth/AccessTokenObserver.java) | interface | — |
| [`AccessTokenValidationException`](../src/main/java/com/revetsec/oauth/AccessTokenValidationException.java) | class | [`AccessTokenValidationException.Reason`](../src/main/java/com/revetsec/oauth/AccessTokenValidationException.java) |
| [`AccessTokenValidationResult`](../src/main/java/com/revetsec/oauth/AccessTokenValidationResult.java) | class | [`AccessTokenValidationResult.Rejected`](../src/main/java/com/revetsec/oauth/AccessTokenValidationResult.java), [`AccessTokenValidationResult.RejectedEndpoint`](../src/main/java/com/revetsec/oauth/AccessTokenValidationResult.java), [`AccessTokenValidationResult.Succeeded`](../src/main/java/com/revetsec/oauth/AccessTokenValidationResult.java) |
| [`AccessTokenValidator`](../src/main/java/com/revetsec/oauth/AccessTokenValidator.java) | interface | — |
| [`AuthorizationCompletionResult`](../src/main/java/com/revetsec/oauth/AuthorizationCompletionResult.java) | class | [`AuthorizationCompletionResult.Denied`](../src/main/java/com/revetsec/oauth/AuthorizationCompletionResult.java), [`AuthorizationCompletionResult.Failed`](../src/main/java/com/revetsec/oauth/AuthorizationCompletionResult.java), [`AuthorizationCompletionResult.Rejected`](../src/main/java/com/revetsec/oauth/AuthorizationCompletionResult.java), [`AuthorizationCompletionResult.RejectedAuthorizationError`](../src/main/java/com/revetsec/oauth/AuthorizationCompletionResult.java), [`AuthorizationCompletionResult.RejectedEndpoint`](../src/main/java/com/revetsec/oauth/AuthorizationCompletionResult.java), [`AuthorizationCompletionResult.Succeeded`](../src/main/java/com/revetsec/oauth/AuthorizationCompletionResult.java) |
| [`AuthorizationErrorException`](../src/main/java/com/revetsec/oauth/AuthorizationErrorException.java) | class | — |
| [`AuthorizationRedirect`](../src/main/java/com/revetsec/oauth/AuthorizationRedirect.java) | class | — |
| [`AuthorizationRequestOptions`](../src/main/java/com/revetsec/oauth/AuthorizationRequestOptions.java) | class | [`AuthorizationRequestOptions.Builder`](../src/main/java/com/revetsec/oauth/AuthorizationRequestOptions.java), [`AuthorizationRequestOptions.ResponseMode`](../src/main/java/com/revetsec/oauth/AuthorizationRequestOptions.java) |
| [`AuthorizationResponse`](../src/main/java/com/revetsec/oauth/AuthorizationResponse.java) | class | — |
| [`AuthorizationResponseParseResult`](../src/main/java/com/revetsec/oauth/AuthorizationResponseParseResult.java) | class | [`AuthorizationResponseParseResult.Rejected`](../src/main/java/com/revetsec/oauth/AuthorizationResponseParseResult.java), [`AuthorizationResponseParseResult.Succeeded`](../src/main/java/com/revetsec/oauth/AuthorizationResponseParseResult.java) |
| [`AuthorizationServerMetadata`](../src/main/java/com/revetsec/oauth/AuthorizationServerMetadata.java) | class | [`AuthorizationServerMetadata.Builder`](../src/main/java/com/revetsec/oauth/AuthorizationServerMetadata.java) |
| [`AuthorizationServerMetadataParseResult`](../src/main/java/com/revetsec/oauth/AuthorizationServerMetadataParseResult.java) | class | [`AuthorizationServerMetadataParseResult.Rejected`](../src/main/java/com/revetsec/oauth/AuthorizationServerMetadataParseResult.java), [`AuthorizationServerMetadataParseResult.Succeeded`](../src/main/java/com/revetsec/oauth/AuthorizationServerMetadataParseResult.java) |
| [`BearerChallenge`](../src/main/java/com/revetsec/oauth/BearerChallenge.java) | class | [`BearerChallenge.Builder`](../src/main/java/com/revetsec/oauth/BearerChallenge.java) |
| [`BearerError`](../src/main/java/com/revetsec/oauth/BearerError.java) | enum | — |
| [`BearerToken`](../src/main/java/com/revetsec/oauth/BearerToken.java) | class | — |
| [`BearerTokenResult`](../src/main/java/com/revetsec/oauth/BearerTokenResult.java) | class | [`BearerTokenResult.Absent`](../src/main/java/com/revetsec/oauth/BearerTokenResult.java), [`BearerTokenResult.Malformed`](../src/main/java/com/revetsec/oauth/BearerTokenResult.java), [`BearerTokenResult.Present`](../src/main/java/com/revetsec/oauth/BearerTokenResult.java) |
| [`ClientAssertionAudience`](../src/main/java/com/revetsec/oauth/ClientAssertionAudience.java) | enum | — |
| [`ClientAssertionKeyProvider`](../src/main/java/com/revetsec/oauth/ClientAssertionKeyProvider.java) | interface | — |
| [`ClientAssertionSigningKey`](../src/main/java/com/revetsec/oauth/ClientAssertionSigningKey.java) | class | [`ClientAssertionSigningKey.Builder`](../src/main/java/com/revetsec/oauth/ClientAssertionSigningKey.java) |
| [`ClientAuthentication`](../src/main/java/com/revetsec/oauth/ClientAuthentication.java) | class | [`ClientAuthentication.PrivateKeyJwtBuilder`](../src/main/java/com/revetsec/oauth/ClientAuthentication.java) |
| [`ClientCredentialsTokenSource`](../src/main/java/com/revetsec/oauth/ClientCredentialsTokenSource.java) | class | [`ClientCredentialsTokenSource.Builder`](../src/main/java/com/revetsec/oauth/ClientCredentialsTokenSource.java) |
| [`ClientSecretBasicEncoding`](../src/main/java/com/revetsec/oauth/ClientSecretBasicEncoding.java) | enum | — |
| [`InMemoryPendingAuthorizationStore`](../src/main/java/com/revetsec/oauth/InMemoryPendingAuthorizationStore.java) | class | [`InMemoryPendingAuthorizationStore.Builder`](../src/main/java/com/revetsec/oauth/InMemoryPendingAuthorizationStore.java) |
| [`IssuerParameterPolicy`](../src/main/java/com/revetsec/oauth/IssuerParameterPolicy.java) | enum | — |
| [`JwtAccessTokenValidator`](../src/main/java/com/revetsec/oauth/JwtAccessTokenValidator.java) | class | [`JwtAccessTokenValidator.Builder`](../src/main/java/com/revetsec/oauth/JwtAccessTokenValidator.java) |
| [`OAuthClient`](../src/main/java/com/revetsec/oauth/OAuthClient.java) | class | [`OAuthClient.Builder`](../src/main/java/com/revetsec/oauth/OAuthClient.java) |
| [`OAuthConfigurationException`](../src/main/java/com/revetsec/oauth/OAuthConfigurationException.java) | class | — |
| [`OAuthEndpoint`](../src/main/java/com/revetsec/oauth/OAuthEndpoint.java) | enum | — |
| [`OAuthEndpointError`](../src/main/java/com/revetsec/oauth/OAuthEndpointError.java) | enum | — |
| [`OAuthErrorResponseException`](../src/main/java/com/revetsec/oauth/OAuthErrorResponseException.java) | class | — |
| [`OAuthException`](../src/main/java/com/revetsec/oauth/OAuthException.java) | class | [`OAuthException.Reason`](../src/main/java/com/revetsec/oauth/OAuthException.java) |
| [`OAuthObserver`](../src/main/java/com/revetsec/oauth/OAuthObserver.java) | interface | — |
| [`OAuthResponseException`](../src/main/java/com/revetsec/oauth/OAuthResponseException.java) | class | — |
| [`OAuthRevocationResult`](../src/main/java/com/revetsec/oauth/OAuthRevocationResult.java) | class | [`OAuthRevocationResult.Rejected`](../src/main/java/com/revetsec/oauth/OAuthRevocationResult.java), [`OAuthRevocationResult.Succeeded`](../src/main/java/com/revetsec/oauth/OAuthRevocationResult.java) |
| [`OAuthTokenRequestResult`](../src/main/java/com/revetsec/oauth/OAuthTokenRequestResult.java) | class | [`OAuthTokenRequestResult.Rejected`](../src/main/java/com/revetsec/oauth/OAuthTokenRequestResult.java), [`OAuthTokenRequestResult.Succeeded`](../src/main/java/com/revetsec/oauth/OAuthTokenRequestResult.java) |
| [`OAuthTransportException`](../src/main/java/com/revetsec/oauth/OAuthTransportException.java) | class | — |
| [`OAuthValidationException`](../src/main/java/com/revetsec/oauth/OAuthValidationException.java) | class | — |
| [`PendingAuthorization`](../src/main/java/com/revetsec/oauth/PendingAuthorization.java) | class | — |
| [`PendingAuthorizationSaveResult`](../src/main/java/com/revetsec/oauth/PendingAuthorizationSaveResult.java) | enum | — |
| [`PendingAuthorizationSource`](../src/main/java/com/revetsec/oauth/PendingAuthorizationSource.java) | class | — |
| [`PendingAuthorizationStore`](../src/main/java/com/revetsec/oauth/PendingAuthorizationStore.java) | interface | — |
| [`PendingAuthorizationStoreException`](../src/main/java/com/revetsec/oauth/PendingAuthorizationStoreException.java) | class | — |
| [`ProtectedResourceMetadata`](../src/main/java/com/revetsec/oauth/ProtectedResourceMetadata.java) | class | [`ProtectedResourceMetadata.Builder`](../src/main/java/com/revetsec/oauth/ProtectedResourceMetadata.java) |
| [`RefreshToken`](../src/main/java/com/revetsec/oauth/RefreshToken.java) | class | — |
| [`TokenIntrospectionClient`](../src/main/java/com/revetsec/oauth/TokenIntrospectionClient.java) | class | [`TokenIntrospectionClient.Builder`](../src/main/java/com/revetsec/oauth/TokenIntrospectionClient.java) |
| [`TokenRequestOptions`](../src/main/java/com/revetsec/oauth/TokenRequestOptions.java) | class | [`TokenRequestOptions.Builder`](../src/main/java/com/revetsec/oauth/TokenRequestOptions.java) |
| [`TokenResponse`](../src/main/java/com/revetsec/oauth/TokenResponse.java) | class | — |
| [`TokenTypeHint`](../src/main/java/com/revetsec/oauth/TokenTypeHint.java) | enum | — |
| [`VerifiedAccessToken`](../src/main/java/com/revetsec/oauth/VerifiedAccessToken.java) | class | — |

## com.revetsec.oauth.server

39 top-level + 28 nested = **67 types**. Names link to the declaring source file.

| Top-level declaration | Kind | Accessible nested declarations |
| --- | --- | --- |
| [`InMemoryOAuthClientMetadataCache`](../src/main/java/com/revetsec/oauth/server/InMemoryOAuthClientMetadataCache.java) | class | — |
| [`OAuthAuthorizationDecision`](../src/main/java/com/revetsec/oauth/server/OAuthAuthorizationDecision.java) | class | [`OAuthAuthorizationDecision.Builder`](../src/main/java/com/revetsec/oauth/server/OAuthAuthorizationDecision.java) |
| [`OAuthAuthorizationResult`](../src/main/java/com/revetsec/oauth/server/OAuthAuthorizationResult.java) | class | [`OAuthAuthorizationResult.Completed`](../src/main/java/com/revetsec/oauth/server/OAuthAuthorizationResult.java), [`OAuthAuthorizationResult.Denied`](../src/main/java/com/revetsec/oauth/server/OAuthAuthorizationResult.java), [`OAuthAuthorizationResult.InteractionRequired`](../src/main/java/com/revetsec/oauth/server/OAuthAuthorizationResult.java), [`OAuthAuthorizationResult.Rejected`](../src/main/java/com/revetsec/oauth/server/OAuthAuthorizationResult.java) |
| [`OAuthAuthorizationServer`](../src/main/java/com/revetsec/oauth/server/OAuthAuthorizationServer.java) | class | [`OAuthAuthorizationServer.Builder`](../src/main/java/com/revetsec/oauth/server/OAuthAuthorizationServer.java) |
| [`OAuthAuthorizationServerStore`](../src/main/java/com/revetsec/oauth/server/OAuthAuthorizationServerStore.java) | interface | — |
| [`OAuthClientMetadataAddressResolver`](../src/main/java/com/revetsec/oauth/server/OAuthClientMetadataAddressResolver.java) | interface | — |
| [`OAuthClientMetadataCache`](../src/main/java/com/revetsec/oauth/server/OAuthClientMetadataCache.java) | interface | — |
| [`OAuthClientMetadataCacheEntry`](../src/main/java/com/revetsec/oauth/server/OAuthClientMetadataCacheEntry.java) | class | — |
| [`OAuthClientMetadataCacheException`](../src/main/java/com/revetsec/oauth/server/OAuthClientMetadataCacheException.java) | class | [`OAuthClientMetadataCacheException.Reason`](../src/main/java/com/revetsec/oauth/server/OAuthClientMetadataCacheException.java) |
| [`OAuthClientMetadataCacheKey`](../src/main/java/com/revetsec/oauth/server/OAuthClientMetadataCacheKey.java) | class | — |
| [`OAuthClientMetadataPolicy`](../src/main/java/com/revetsec/oauth/server/OAuthClientMetadataPolicy.java) | class | [`OAuthClientMetadataPolicy.Builder`](../src/main/java/com/revetsec/oauth/server/OAuthClientMetadataPolicy.java) |
| [`OAuthClientSecretVerifier`](../src/main/java/com/revetsec/oauth/server/OAuthClientSecretVerifier.java) | interface | — |
| [`OAuthGrantContext`](../src/main/java/com/revetsec/oauth/server/OAuthGrantContext.java) | class | — |
| [`OAuthGrantPolicy`](../src/main/java/com/revetsec/oauth/server/OAuthGrantPolicy.java) | interface | — |
| [`OAuthIntrospectionResult`](../src/main/java/com/revetsec/oauth/server/OAuthIntrospectionResult.java) | class | [`OAuthIntrospectionResult.Rejected`](../src/main/java/com/revetsec/oauth/server/OAuthIntrospectionResult.java), [`OAuthIntrospectionResult.Succeeded`](../src/main/java/com/revetsec/oauth/server/OAuthIntrospectionResult.java) |
| [`OAuthIssuerAccessTokenResult`](../src/main/java/com/revetsec/oauth/server/OAuthIssuerAccessTokenResult.java) | class | [`OAuthIssuerAccessTokenResult.Rejected`](../src/main/java/com/revetsec/oauth/server/OAuthIssuerAccessTokenResult.java), [`OAuthIssuerAccessTokenResult.Succeeded`](../src/main/java/com/revetsec/oauth/server/OAuthIssuerAccessTokenResult.java) |
| [`OAuthIssuerKeyProvider`](../src/main/java/com/revetsec/oauth/server/OAuthIssuerKeyProvider.java) | interface | — |
| [`OAuthIssuerKeySnapshot`](../src/main/java/com/revetsec/oauth/server/OAuthIssuerKeySnapshot.java) | class | [`OAuthIssuerKeySnapshot.Builder`](../src/main/java/com/revetsec/oauth/server/OAuthIssuerKeySnapshot.java) |
| [`OAuthIssuerSigningKey`](../src/main/java/com/revetsec/oauth/server/OAuthIssuerSigningKey.java) | class | — |
| [`OAuthRevocationResult`](../src/main/java/com/revetsec/oauth/server/OAuthRevocationResult.java) | class | [`OAuthRevocationResult.Rejected`](../src/main/java/com/revetsec/oauth/server/OAuthRevocationResult.java), [`OAuthRevocationResult.Succeeded`](../src/main/java/com/revetsec/oauth/server/OAuthRevocationResult.java) |
| [`OAuthServerClientAuthentication`](../src/main/java/com/revetsec/oauth/server/OAuthServerClientAuthentication.java) | class | — |
| [`OAuthServerClientRegistration`](../src/main/java/com/revetsec/oauth/server/OAuthServerClientRegistration.java) | class | [`OAuthServerClientRegistration.Builder`](../src/main/java/com/revetsec/oauth/server/OAuthServerClientRegistration.java) |
| [`OAuthServerClientRepository`](../src/main/java/com/revetsec/oauth/server/OAuthServerClientRepository.java) | interface | — |
| [`OAuthServerConfigurationException`](../src/main/java/com/revetsec/oauth/server/OAuthServerConfigurationException.java) | class | — |
| [`OAuthServerException`](../src/main/java/com/revetsec/oauth/server/OAuthServerException.java) | class | [`OAuthServerException.Reason`](../src/main/java/com/revetsec/oauth/server/OAuthServerException.java) |
| [`OAuthServerInteraction`](../src/main/java/com/revetsec/oauth/server/OAuthServerInteraction.java) | class | — |
| [`OAuthServerObserver`](../src/main/java/com/revetsec/oauth/server/OAuthServerObserver.java) | interface | [`OAuthServerObserver.Endpoint`](../src/main/java/com/revetsec/oauth/server/OAuthServerObserver.java) |
| [`OAuthServerResponse`](../src/main/java/com/revetsec/oauth/server/OAuthServerResponse.java) | class | — |
| [`OAuthServerSigningException`](../src/main/java/com/revetsec/oauth/server/OAuthServerSigningException.java) | class | — |
| [`OAuthServerStoreException`](../src/main/java/com/revetsec/oauth/server/OAuthServerStoreException.java) | class | — |
| [`OAuthServerTransportException`](../src/main/java/com/revetsec/oauth/server/OAuthServerTransportException.java) | class | — |
| [`OAuthServerValidationException`](../src/main/java/com/revetsec/oauth/server/OAuthServerValidationException.java) | class | — |
| [`OAuthStoreCommitReceipt`](../src/main/java/com/revetsec/oauth/server/OAuthStoreCommitReceipt.java) | class | — |
| [`OAuthStoreCommitStatus`](../src/main/java/com/revetsec/oauth/server/OAuthStoreCommitStatus.java) | enum | — |
| [`OAuthStoreEntry`](../src/main/java/com/revetsec/oauth/server/OAuthStoreEntry.java) | class | — |
| [`OAuthStoreKey`](../src/main/java/com/revetsec/oauth/server/OAuthStoreKey.java) | class | [`OAuthStoreKey.Kind`](../src/main/java/com/revetsec/oauth/server/OAuthStoreKey.java) |
| [`OAuthStoreReadResult`](../src/main/java/com/revetsec/oauth/server/OAuthStoreReadResult.java) | interface | [`OAuthStoreReadResult.Available`](../src/main/java/com/revetsec/oauth/server/OAuthStoreReadResult.java), [`OAuthStoreReadResult.Fenced`](../src/main/java/com/revetsec/oauth/server/OAuthStoreReadResult.java), [`OAuthStoreReadResult.Unavailable`](../src/main/java/com/revetsec/oauth/server/OAuthStoreReadResult.java) |
| [`OAuthStoreTransaction`](../src/main/java/com/revetsec/oauth/server/OAuthStoreTransaction.java) | class | [`OAuthStoreTransaction.Condition`](../src/main/java/com/revetsec/oauth/server/OAuthStoreTransaction.java), [`OAuthStoreTransaction.Mutation`](../src/main/java/com/revetsec/oauth/server/OAuthStoreTransaction.java), [`OAuthStoreTransaction.Mutation.Kind`](../src/main/java/com/revetsec/oauth/server/OAuthStoreTransaction.java), [`OAuthStoreTransaction.Purpose`](../src/main/java/com/revetsec/oauth/server/OAuthStoreTransaction.java) |
| [`OAuthTokenResult`](../src/main/java/com/revetsec/oauth/server/OAuthTokenResult.java) | class | [`OAuthTokenResult.Rejected`](../src/main/java/com/revetsec/oauth/server/OAuthTokenResult.java), [`OAuthTokenResult.Succeeded`](../src/main/java/com/revetsec/oauth/server/OAuthTokenResult.java) |

## com.revetsec.oidc

18 top-level + 21 nested = **39 types**. Names link to the declaring source file.

| Top-level declaration | Kind | Accessible nested declarations |
| --- | --- | --- |
| [`IdToken`](../src/main/java/com/revetsec/oidc/IdToken.java) | class | — |
| [`OidcAuthentication`](../src/main/java/com/revetsec/oidc/OidcAuthentication.java) | class | — |
| [`OidcAuthenticationOptions`](../src/main/java/com/revetsec/oidc/OidcAuthenticationOptions.java) | class | [`OidcAuthenticationOptions.Builder`](../src/main/java/com/revetsec/oidc/OidcAuthenticationOptions.java) |
| [`OidcAuthenticationResult`](../src/main/java/com/revetsec/oidc/OidcAuthenticationResult.java) | class | [`OidcAuthenticationResult.Denied`](../src/main/java/com/revetsec/oidc/OidcAuthenticationResult.java), [`OidcAuthenticationResult.Failed`](../src/main/java/com/revetsec/oidc/OidcAuthenticationResult.java), [`OidcAuthenticationResult.RejectedAuthorization`](../src/main/java/com/revetsec/oidc/OidcAuthenticationResult.java), [`OidcAuthenticationResult.RejectedAuthorizationError`](../src/main/java/com/revetsec/oidc/OidcAuthenticationResult.java), [`OidcAuthenticationResult.RejectedEndpoint`](../src/main/java/com/revetsec/oidc/OidcAuthenticationResult.java), [`OidcAuthenticationResult.RejectedIdToken`](../src/main/java/com/revetsec/oidc/OidcAuthenticationResult.java), [`OidcAuthenticationResult.Succeeded`](../src/main/java/com/revetsec/oidc/OidcAuthenticationResult.java) |
| [`OidcClient`](../src/main/java/com/revetsec/oidc/OidcClient.java) | class | [`OidcClient.Builder`](../src/main/java/com/revetsec/oidc/OidcClient.java) |
| [`OidcCompatibilityMode`](../src/main/java/com/revetsec/oidc/OidcCompatibilityMode.java) | enum | — |
| [`OidcException`](../src/main/java/com/revetsec/oidc/OidcException.java) | class | — |
| [`OidcIssuerPolicy`](../src/main/java/com/revetsec/oidc/OidcIssuerPolicy.java) | class | — |
| [`OidcObserver`](../src/main/java/com/revetsec/oidc/OidcObserver.java) | interface | — |
| [`OidcProviderMetadata`](../src/main/java/com/revetsec/oidc/OidcProviderMetadata.java) | class | [`OidcProviderMetadata.Builder`](../src/main/java/com/revetsec/oidc/OidcProviderMetadata.java) |
| [`OidcProviderMetadataParseResult`](../src/main/java/com/revetsec/oidc/OidcProviderMetadataParseResult.java) | class | [`OidcProviderMetadataParseResult.Rejected`](../src/main/java/com/revetsec/oidc/OidcProviderMetadataParseResult.java), [`OidcProviderMetadataParseResult.Succeeded`](../src/main/java/com/revetsec/oidc/OidcProviderMetadataParseResult.java) |
| [`OidcRefreshOutcome`](../src/main/java/com/revetsec/oidc/OidcRefreshOutcome.java) | class | [`OidcRefreshOutcome.Rejected`](../src/main/java/com/revetsec/oidc/OidcRefreshOutcome.java), [`OidcRefreshOutcome.RejectedEndpoint`](../src/main/java/com/revetsec/oidc/OidcRefreshOutcome.java), [`OidcRefreshOutcome.Succeeded`](../src/main/java/com/revetsec/oidc/OidcRefreshOutcome.java) |
| [`OidcRefreshResult`](../src/main/java/com/revetsec/oidc/OidcRefreshResult.java) | class | — |
| [`OidcSessionReference`](../src/main/java/com/revetsec/oidc/OidcSessionReference.java) | class | — |
| [`OidcSessionReferenceParseResult`](../src/main/java/com/revetsec/oidc/OidcSessionReferenceParseResult.java) | class | [`OidcSessionReferenceParseResult.Rejected`](../src/main/java/com/revetsec/oidc/OidcSessionReferenceParseResult.java), [`OidcSessionReferenceParseResult.Succeeded`](../src/main/java/com/revetsec/oidc/OidcSessionReferenceParseResult.java) |
| [`OidcUserInfo`](../src/main/java/com/revetsec/oidc/OidcUserInfo.java) | class | — |
| [`OidcUserInfoResult`](../src/main/java/com/revetsec/oidc/OidcUserInfoResult.java) | class | [`OidcUserInfoResult.Rejected`](../src/main/java/com/revetsec/oidc/OidcUserInfoResult.java), [`OidcUserInfoResult.RejectedEndpoint`](../src/main/java/com/revetsec/oidc/OidcUserInfoResult.java), [`OidcUserInfoResult.Succeeded`](../src/main/java/com/revetsec/oidc/OidcUserInfoResult.java) |
| [`OidcValidationException`](../src/main/java/com/revetsec/oidc/OidcValidationException.java) | class | [`OidcValidationException.Reason`](../src/main/java/com/revetsec/oidc/OidcValidationException.java) |

## com.revetsec.password

15 top-level + 12 nested = **27 types**. Names link to the declaring source file.

| Top-level declaration | Kind | Accessible nested declarations |
| --- | --- | --- |
| [`Argon2idParameters`](../src/main/java/com/revetsec/password/Argon2idParameters.java) | class | — |
| [`LegacyPasswordPreparation`](../src/main/java/com/revetsec/password/LegacyPasswordPreparation.java) | enum | — |
| [`PasswordHash`](../src/main/java/com/revetsec/password/PasswordHash.java) | class | — |
| [`PasswordHashResult`](../src/main/java/com/revetsec/password/PasswordHashResult.java) | class | [`PasswordHashResult.Rejected`](../src/main/java/com/revetsec/password/PasswordHashResult.java), [`PasswordHashResult.Succeeded`](../src/main/java/com/revetsec/password/PasswordHashResult.java), [`PasswordHashResult.Unavailable`](../src/main/java/com/revetsec/password/PasswordHashResult.java) |
| [`PasswordHasher`](../src/main/java/com/revetsec/password/PasswordHasher.java) | class | [`PasswordHasher.Builder`](../src/main/java/com/revetsec/password/PasswordHasher.java) |
| [`PasswordPepperKey`](../src/main/java/com/revetsec/password/PasswordPepperKey.java) | class | — |
| [`PasswordPepperSnapshot`](../src/main/java/com/revetsec/password/PasswordPepperSnapshot.java) | class | [`PasswordPepperSnapshot.Builder`](../src/main/java/com/revetsec/password/PasswordPepperSnapshot.java) |
| [`PasswordPepperSnapshotResult`](../src/main/java/com/revetsec/password/PasswordPepperSnapshotResult.java) | class | [`PasswordPepperSnapshotResult.Available`](../src/main/java/com/revetsec/password/PasswordPepperSnapshotResult.java), [`PasswordPepperSnapshotResult.Unavailable`](../src/main/java/com/revetsec/password/PasswordPepperSnapshotResult.java) |
| [`PasswordPepperSource`](../src/main/java/com/revetsec/password/PasswordPepperSource.java) | interface | — |
| [`PasswordRejectionReason`](../src/main/java/com/revetsec/password/PasswordRejectionReason.java) | enum | — |
| [`PasswordUnavailableReason`](../src/main/java/com/revetsec/password/PasswordUnavailableReason.java) | enum | — |
| [`PasswordVerificationLimits`](../src/main/java/com/revetsec/password/PasswordVerificationLimits.java) | class | [`PasswordVerificationLimits.Builder`](../src/main/java/com/revetsec/password/PasswordVerificationLimits.java) |
| [`PasswordVerificationResult`](../src/main/java/com/revetsec/password/PasswordVerificationResult.java) | class | [`PasswordVerificationResult.Matched`](../src/main/java/com/revetsec/password/PasswordVerificationResult.java), [`PasswordVerificationResult.NotMatched`](../src/main/java/com/revetsec/password/PasswordVerificationResult.java), [`PasswordVerificationResult.Rejected`](../src/main/java/com/revetsec/password/PasswordVerificationResult.java), [`PasswordVerificationResult.Unavailable`](../src/main/java/com/revetsec/password/PasswordVerificationResult.java) |
| [`PasswordWorkGate`](../src/main/java/com/revetsec/password/PasswordWorkGate.java) | class | — |
| [`Pbkdf2Hmac`](../src/main/java/com/revetsec/password/Pbkdf2Hmac.java) | enum | — |

## com.revetsec.saml

43 top-level + 63 nested = **106 types**. Names link to the declaring source file.

| Top-level declaration | Kind | Accessible nested declarations |
| --- | --- | --- |
| [`InMemoryPendingSamlAuthenticationStore`](../src/main/java/com/revetsec/saml/InMemoryPendingSamlAuthenticationStore.java) | class | — |
| [`InMemorySamlReplayCache`](../src/main/java/com/revetsec/saml/InMemorySamlReplayCache.java) | class | — |
| [`PendingSamlAuthentication`](../src/main/java/com/revetsec/saml/PendingSamlAuthentication.java) | class | — |
| [`PendingSamlAuthenticationSource`](../src/main/java/com/revetsec/saml/PendingSamlAuthenticationSource.java) | class | — |
| [`PendingSamlAuthenticationStore`](../src/main/java/com/revetsec/saml/PendingSamlAuthenticationStore.java) | interface | — |
| [`PendingSamlLogout`](../src/main/java/com/revetsec/saml/PendingSamlLogout.java) | class | — |
| [`PendingSamlLogoutSource`](../src/main/java/com/revetsec/saml/PendingSamlLogoutSource.java) | class | — |
| [`SamlAttribute`](../src/main/java/com/revetsec/saml/SamlAttribute.java) | class | — |
| [`SamlAttributeValue`](../src/main/java/com/revetsec/saml/SamlAttributeValue.java) | class | [`SamlAttributeValue.Kind`](../src/main/java/com/revetsec/saml/SamlAttributeValue.java) |
| [`SamlAuthentication`](../src/main/java/com/revetsec/saml/SamlAuthentication.java) | class | — |
| [`SamlAuthenticationRequestOptions`](../src/main/java/com/revetsec/saml/SamlAuthenticationRequestOptions.java) | class | [`SamlAuthenticationRequestOptions.Builder`](../src/main/java/com/revetsec/saml/SamlAuthenticationRequestOptions.java) |
| [`SamlAuthenticationRequestResult`](../src/main/java/com/revetsec/saml/SamlAuthenticationRequestResult.java) | interface | [`SamlAuthenticationRequestResult.PostPrepared`](../src/main/java/com/revetsec/saml/SamlAuthenticationRequestResult.java), [`SamlAuthenticationRequestResult.Prepared`](../src/main/java/com/revetsec/saml/SamlAuthenticationRequestResult.java), [`SamlAuthenticationRequestResult.Rejected`](../src/main/java/com/revetsec/saml/SamlAuthenticationRequestResult.java), [`SamlAuthenticationRequestResult.Unavailable`](../src/main/java/com/revetsec/saml/SamlAuthenticationRequestResult.java) |
| [`SamlAuthenticationResult`](../src/main/java/com/revetsec/saml/SamlAuthenticationResult.java) | interface | [`SamlAuthenticationResult.Indeterminate`](../src/main/java/com/revetsec/saml/SamlAuthenticationResult.java), [`SamlAuthenticationResult.Reason`](../src/main/java/com/revetsec/saml/SamlAuthenticationResult.java), [`SamlAuthenticationResult.Rejected`](../src/main/java/com/revetsec/saml/SamlAuthenticationResult.java), [`SamlAuthenticationResult.StatusCode`](../src/main/java/com/revetsec/saml/SamlAuthenticationResult.java), [`SamlAuthenticationResult.StatusReceived`](../src/main/java/com/revetsec/saml/SamlAuthenticationResult.java), [`SamlAuthenticationResult.Succeeded`](../src/main/java/com/revetsec/saml/SamlAuthenticationResult.java), [`SamlAuthenticationResult.Unavailable`](../src/main/java/com/revetsec/saml/SamlAuthenticationResult.java) |
| [`SamlCompatibilityMode`](../src/main/java/com/revetsec/saml/SamlCompatibilityMode.java) | enum | — |
| [`SamlCredential`](../src/main/java/com/revetsec/saml/SamlCredential.java) | class | — |
| [`SamlIdentityProvider`](../src/main/java/com/revetsec/saml/SamlIdentityProvider.java) | class | [`SamlIdentityProvider.Builder`](../src/main/java/com/revetsec/saml/SamlIdentityProvider.java) |
| [`SamlIdentityProviderMetadata`](../src/main/java/com/revetsec/saml/SamlIdentityProviderMetadata.java) | class | — |
| [`SamlIdentityProviderMetadataResult`](../src/main/java/com/revetsec/saml/SamlIdentityProviderMetadataResult.java) | interface | [`SamlIdentityProviderMetadataResult.Parsed`](../src/main/java/com/revetsec/saml/SamlIdentityProviderMetadataResult.java), [`SamlIdentityProviderMetadataResult.Rejected`](../src/main/java/com/revetsec/saml/SamlIdentityProviderMetadataResult.java), [`SamlIdentityProviderMetadataResult.Unavailable`](../src/main/java/com/revetsec/saml/SamlIdentityProviderMetadataResult.java) |
| [`SamlLogoutPostResult`](../src/main/java/com/revetsec/saml/SamlLogoutPostResult.java) | interface | [`SamlLogoutPostResult.Prepared`](../src/main/java/com/revetsec/saml/SamlLogoutPostResult.java), [`SamlLogoutPostResult.Rejected`](../src/main/java/com/revetsec/saml/SamlLogoutPostResult.java), [`SamlLogoutPostResult.Unavailable`](../src/main/java/com/revetsec/saml/SamlLogoutPostResult.java) |
| [`SamlLogoutRedirectResult`](../src/main/java/com/revetsec/saml/SamlLogoutRedirectResult.java) | interface | [`SamlLogoutRedirectResult.Prepared`](../src/main/java/com/revetsec/saml/SamlLogoutRedirectResult.java), [`SamlLogoutRedirectResult.Rejected`](../src/main/java/com/revetsec/saml/SamlLogoutRedirectResult.java), [`SamlLogoutRedirectResult.Unavailable`](../src/main/java/com/revetsec/saml/SamlLogoutRedirectResult.java) |
| [`SamlLogoutRequest`](../src/main/java/com/revetsec/saml/SamlLogoutRequest.java) | class | — |
| [`SamlLogoutRequestResult`](../src/main/java/com/revetsec/saml/SamlLogoutRequestResult.java) | interface | [`SamlLogoutRequestResult.Accepted`](../src/main/java/com/revetsec/saml/SamlLogoutRequestResult.java), [`SamlLogoutRequestResult.Indeterminate`](../src/main/java/com/revetsec/saml/SamlLogoutRequestResult.java), [`SamlLogoutRequestResult.Rejected`](../src/main/java/com/revetsec/saml/SamlLogoutRequestResult.java), [`SamlLogoutRequestResult.Unavailable`](../src/main/java/com/revetsec/saml/SamlLogoutRequestResult.java) |
| [`SamlLogoutResponsePostResult`](../src/main/java/com/revetsec/saml/SamlLogoutResponsePostResult.java) | interface | [`SamlLogoutResponsePostResult.Prepared`](../src/main/java/com/revetsec/saml/SamlLogoutResponsePostResult.java), [`SamlLogoutResponsePostResult.Rejected`](../src/main/java/com/revetsec/saml/SamlLogoutResponsePostResult.java), [`SamlLogoutResponsePostResult.Unavailable`](../src/main/java/com/revetsec/saml/SamlLogoutResponsePostResult.java) |
| [`SamlLogoutResponseRedirectResult`](../src/main/java/com/revetsec/saml/SamlLogoutResponseRedirectResult.java) | interface | [`SamlLogoutResponseRedirectResult.Prepared`](../src/main/java/com/revetsec/saml/SamlLogoutResponseRedirectResult.java), [`SamlLogoutResponseRedirectResult.Rejected`](../src/main/java/com/revetsec/saml/SamlLogoutResponseRedirectResult.java), [`SamlLogoutResponseRedirectResult.Unavailable`](../src/main/java/com/revetsec/saml/SamlLogoutResponseRedirectResult.java) |
| [`SamlLogoutResult`](../src/main/java/com/revetsec/saml/SamlLogoutResult.java) | interface | [`SamlLogoutResult.Indeterminate`](../src/main/java/com/revetsec/saml/SamlLogoutResult.java), [`SamlLogoutResult.Rejected`](../src/main/java/com/revetsec/saml/SamlLogoutResult.java), [`SamlLogoutResult.StatusReceived`](../src/main/java/com/revetsec/saml/SamlLogoutResult.java), [`SamlLogoutResult.Succeeded`](../src/main/java/com/revetsec/saml/SamlLogoutResult.java), [`SamlLogoutResult.Unavailable`](../src/main/java/com/revetsec/saml/SamlLogoutResult.java) |
| [`SamlLogoutStatus`](../src/main/java/com/revetsec/saml/SamlLogoutStatus.java) | enum | — |
| [`SamlNameId`](../src/main/java/com/revetsec/saml/SamlNameId.java) | class | — |
| [`SamlObserver`](../src/main/java/com/revetsec/saml/SamlObserver.java) | interface | [`SamlObserver.Operation`](../src/main/java/com/revetsec/saml/SamlObserver.java), [`SamlObserver.Outcome`](../src/main/java/com/revetsec/saml/SamlObserver.java) |
| [`SamlPendingConsumeResult`](../src/main/java/com/revetsec/saml/SamlPendingConsumeResult.java) | interface | [`SamlPendingConsumeResult.Consumed`](../src/main/java/com/revetsec/saml/SamlPendingConsumeResult.java), [`SamlPendingConsumeResult.Indeterminate`](../src/main/java/com/revetsec/saml/SamlPendingConsumeResult.java), [`SamlPendingConsumeResult.Missing`](../src/main/java/com/revetsec/saml/SamlPendingConsumeResult.java), [`SamlPendingConsumeResult.Unavailable`](../src/main/java/com/revetsec/saml/SamlPendingConsumeResult.java) |
| [`SamlPendingSaveResult`](../src/main/java/com/revetsec/saml/SamlPendingSaveResult.java) | enum | — |
| [`SamlPostBindingMessage`](../src/main/java/com/revetsec/saml/SamlPostBindingMessage.java) | class | [`SamlPostBindingMessage.Kind`](../src/main/java/com/revetsec/saml/SamlPostBindingMessage.java) |
| [`SamlPostBindingParseResult`](../src/main/java/com/revetsec/saml/SamlPostBindingParseResult.java) | interface | [`SamlPostBindingParseResult.Parsed`](../src/main/java/com/revetsec/saml/SamlPostBindingParseResult.java), [`SamlPostBindingParseResult.Reason`](../src/main/java/com/revetsec/saml/SamlPostBindingParseResult.java), [`SamlPostBindingParseResult.Rejected`](../src/main/java/com/revetsec/saml/SamlPostBindingParseResult.java) |
| [`SamlPostForm`](../src/main/java/com/revetsec/saml/SamlPostForm.java) | class | — |
| [`SamlRedirectBindingMessage`](../src/main/java/com/revetsec/saml/SamlRedirectBindingMessage.java) | class | [`SamlRedirectBindingMessage.Kind`](../src/main/java/com/revetsec/saml/SamlRedirectBindingMessage.java) |
| [`SamlRedirectBindingParseResult`](../src/main/java/com/revetsec/saml/SamlRedirectBindingParseResult.java) | interface | [`SamlRedirectBindingParseResult.Parsed`](../src/main/java/com/revetsec/saml/SamlRedirectBindingParseResult.java), [`SamlRedirectBindingParseResult.Rejected`](../src/main/java/com/revetsec/saml/SamlRedirectBindingParseResult.java) |
| [`SamlReplayCache`](../src/main/java/com/revetsec/saml/SamlReplayCache.java) | interface | [`SamlReplayCache.MarkResult`](../src/main/java/com/revetsec/saml/SamlReplayCache.java) |
| [`SamlServiceProvider`](../src/main/java/com/revetsec/saml/SamlServiceProvider.java) | class | [`SamlServiceProvider.Builder`](../src/main/java/com/revetsec/saml/SamlServiceProvider.java) |
| [`SamlServiceProviderMetadata`](../src/main/java/com/revetsec/saml/SamlServiceProviderMetadata.java) | class | — |
| [`SamlServiceProviderMetadataResult`](../src/main/java/com/revetsec/saml/SamlServiceProviderMetadataResult.java) | interface | [`SamlServiceProviderMetadataResult.Generated`](../src/main/java/com/revetsec/saml/SamlServiceProviderMetadataResult.java), [`SamlServiceProviderMetadataResult.Rejected`](../src/main/java/com/revetsec/saml/SamlServiceProviderMetadataResult.java), [`SamlServiceProviderMetadataResult.Unavailable`](../src/main/java/com/revetsec/saml/SamlServiceProviderMetadataResult.java) |
| [`SamlSessionReference`](../src/main/java/com/revetsec/saml/SamlSessionReference.java) | class | — |
| [`SamlSessionReferenceParseResult`](../src/main/java/com/revetsec/saml/SamlSessionReferenceParseResult.java) | class | [`SamlSessionReferenceParseResult.Reason`](../src/main/java/com/revetsec/saml/SamlSessionReferenceParseResult.java), [`SamlSessionReferenceParseResult.Rejected`](../src/main/java/com/revetsec/saml/SamlSessionReferenceParseResult.java), [`SamlSessionReferenceParseResult.RejectedSealedState`](../src/main/java/com/revetsec/saml/SamlSessionReferenceParseResult.java), [`SamlSessionReferenceParseResult.Succeeded`](../src/main/java/com/revetsec/saml/SamlSessionReferenceParseResult.java) |
| [`SamlSessionReferenceSealResult`](../src/main/java/com/revetsec/saml/SamlSessionReferenceSealResult.java) | interface | [`SamlSessionReferenceSealResult.Succeeded`](../src/main/java/com/revetsec/saml/SamlSessionReferenceSealResult.java), [`SamlSessionReferenceSealResult.TooLarge`](../src/main/java/com/revetsec/saml/SamlSessionReferenceSealResult.java), [`SamlSessionReferenceSealResult.Unavailable`](../src/main/java/com/revetsec/saml/SamlSessionReferenceSealResult.java) |
| [`SamlSubjectKey`](../src/main/java/com/revetsec/saml/SamlSubjectKey.java) | class | — |

## com.revetsec.scim

58 top-level + 59 nested = **117 types**. Names link to the declaring source file.

| Top-level declaration | Kind | Accessible nested declarations |
| --- | --- | --- |
| [`ScimAttributeDefinition`](../src/main/java/com/revetsec/scim/ScimAttributeDefinition.java) | class | [`ScimAttributeDefinition.Builder`](../src/main/java/com/revetsec/scim/ScimAttributeDefinition.java) |
| [`ScimAttributePath`](../src/main/java/com/revetsec/scim/ScimAttributePath.java) | class | — |
| [`ScimAttributePathParseResult`](../src/main/java/com/revetsec/scim/ScimAttributePathParseResult.java) | interface | [`ScimAttributePathParseResult.Rejected`](../src/main/java/com/revetsec/scim/ScimAttributePathParseResult.java), [`ScimAttributePathParseResult.Succeeded`](../src/main/java/com/revetsec/scim/ScimAttributePathParseResult.java) |
| [`ScimAttributeSelection`](../src/main/java/com/revetsec/scim/ScimAttributeSelection.java) | class | — |
| [`ScimAttributeSelectionResult`](../src/main/java/com/revetsec/scim/ScimAttributeSelectionResult.java) | interface | [`ScimAttributeSelectionResult.Rejected`](../src/main/java/com/revetsec/scim/ScimAttributeSelectionResult.java), [`ScimAttributeSelectionResult.Succeeded`](../src/main/java/com/revetsec/scim/ScimAttributeSelectionResult.java) |
| [`ScimAttributeType`](../src/main/java/com/revetsec/scim/ScimAttributeType.java) | enum | — |
| [`ScimAuthenticationScheme`](../src/main/java/com/revetsec/scim/ScimAuthenticationScheme.java) | class | [`ScimAuthenticationScheme.Builder`](../src/main/java/com/revetsec/scim/ScimAuthenticationScheme.java) |
| [`ScimComparisonOperator`](../src/main/java/com/revetsec/scim/ScimComparisonOperator.java) | enum | — |
| [`ScimCompatibility`](../src/main/java/com/revetsec/scim/ScimCompatibility.java) | class | [`ScimCompatibility.Builder`](../src/main/java/com/revetsec/scim/ScimCompatibility.java) |
| [`ScimCompatibilityFeature`](../src/main/java/com/revetsec/scim/ScimCompatibilityFeature.java) | enum | — |
| [`ScimContentTypeResult`](../src/main/java/com/revetsec/scim/ScimContentTypeResult.java) | interface | [`ScimContentTypeResult.Accepted`](../src/main/java/com/revetsec/scim/ScimContentTypeResult.java), [`ScimContentTypeResult.Rejected`](../src/main/java/com/revetsec/scim/ScimContentTypeResult.java) |
| [`ScimEnterpriseUser`](../src/main/java/com/revetsec/scim/ScimEnterpriseUser.java) | class | — |
| [`ScimError`](../src/main/java/com/revetsec/scim/ScimError.java) | class | — |
| [`ScimErrorType`](../src/main/java/com/revetsec/scim/ScimErrorType.java) | enum | — |
| [`ScimFilter`](../src/main/java/com/revetsec/scim/ScimFilter.java) | interface | [`ScimFilter.And`](../src/main/java/com/revetsec/scim/ScimFilter.java), [`ScimFilter.Comparison`](../src/main/java/com/revetsec/scim/ScimFilter.java), [`ScimFilter.Not`](../src/main/java/com/revetsec/scim/ScimFilter.java), [`ScimFilter.Or`](../src/main/java/com/revetsec/scim/ScimFilter.java), [`ScimFilter.Present`](../src/main/java/com/revetsec/scim/ScimFilter.java), [`ScimFilter.ValuePath`](../src/main/java/com/revetsec/scim/ScimFilter.java) |
| [`ScimFilterEvaluationResult`](../src/main/java/com/revetsec/scim/ScimFilterEvaluationResult.java) | interface | [`ScimFilterEvaluationResult.Rejected`](../src/main/java/com/revetsec/scim/ScimFilterEvaluationResult.java), [`ScimFilterEvaluationResult.Succeeded`](../src/main/java/com/revetsec/scim/ScimFilterEvaluationResult.java) |
| [`ScimFilterEvaluator`](../src/main/java/com/revetsec/scim/ScimFilterEvaluator.java) | class | — |
| [`ScimFilterLimits`](../src/main/java/com/revetsec/scim/ScimFilterLimits.java) | class | [`ScimFilterLimits.Builder`](../src/main/java/com/revetsec/scim/ScimFilterLimits.java) |
| [`ScimFilterParseResult`](../src/main/java/com/revetsec/scim/ScimFilterParseResult.java) | interface | [`ScimFilterParseResult.Rejected`](../src/main/java/com/revetsec/scim/ScimFilterParseResult.java), [`ScimFilterParseResult.Succeeded`](../src/main/java/com/revetsec/scim/ScimFilterParseResult.java) |
| [`ScimFilterPolicy`](../src/main/java/com/revetsec/scim/ScimFilterPolicy.java) | class | [`ScimFilterPolicy.Builder`](../src/main/java/com/revetsec/scim/ScimFilterPolicy.java) |
| [`ScimFilterValue`](../src/main/java/com/revetsec/scim/ScimFilterValue.java) | interface | [`ScimFilterValue.BooleanValue`](../src/main/java/com/revetsec/scim/ScimFilterValue.java), [`ScimFilterValue.NullValue`](../src/main/java/com/revetsec/scim/ScimFilterValue.java), [`ScimFilterValue.NumberValue`](../src/main/java/com/revetsec/scim/ScimFilterValue.java), [`ScimFilterValue.StringValue`](../src/main/java/com/revetsec/scim/ScimFilterValue.java) |
| [`ScimFilterVisitor`](../src/main/java/com/revetsec/scim/ScimFilterVisitor.java) | interface | — |
| [`ScimGroup`](../src/main/java/com/revetsec/scim/ScimGroup.java) | class | — |
| [`ScimIfMatchResult`](../src/main/java/com/revetsec/scim/ScimIfMatchResult.java) | interface | [`ScimIfMatchResult.Rejected`](../src/main/java/com/revetsec/scim/ScimIfMatchResult.java), [`ScimIfMatchResult.Satisfied`](../src/main/java/com/revetsec/scim/ScimIfMatchResult.java) |
| [`ScimIfNoneMatchResult`](../src/main/java/com/revetsec/scim/ScimIfNoneMatchResult.java) | interface | [`ScimIfNoneMatchResult.NotModified`](../src/main/java/com/revetsec/scim/ScimIfNoneMatchResult.java), [`ScimIfNoneMatchResult.Proceed`](../src/main/java/com/revetsec/scim/ScimIfNoneMatchResult.java), [`ScimIfNoneMatchResult.Rejected`](../src/main/java/com/revetsec/scim/ScimIfNoneMatchResult.java) |
| [`ScimLimits`](../src/main/java/com/revetsec/scim/ScimLimits.java) | class | [`ScimLimits.Builder`](../src/main/java/com/revetsec/scim/ScimLimits.java) |
| [`ScimListPage`](../src/main/java/com/revetsec/scim/ScimListPage.java) | class | [`ScimListPage.Builder`](../src/main/java/com/revetsec/scim/ScimListPage.java) |
| [`ScimLogicalOperator`](../src/main/java/com/revetsec/scim/ScimLogicalOperator.java) | enum | — |
| [`ScimMembershipPatch`](../src/main/java/com/revetsec/scim/ScimMembershipPatch.java) | class | [`ScimMembershipPatch.Kind`](../src/main/java/com/revetsec/scim/ScimMembershipPatch.java), [`ScimMembershipPatch.Step`](../src/main/java/com/revetsec/scim/ScimMembershipPatch.java) |
| [`ScimMembershipPatchResult`](../src/main/java/com/revetsec/scim/ScimMembershipPatchResult.java) | interface | [`ScimMembershipPatchResult.Reduced`](../src/main/java/com/revetsec/scim/ScimMembershipPatchResult.java), [`ScimMembershipPatchResult.Rejected`](../src/main/java/com/revetsec/scim/ScimMembershipPatchResult.java), [`ScimMembershipPatchResult.RequiresFullEvaluation`](../src/main/java/com/revetsec/scim/ScimMembershipPatchResult.java) |
| [`ScimMutability`](../src/main/java/com/revetsec/scim/ScimMutability.java) | enum | — |
| [`ScimObserver`](../src/main/java/com/revetsec/scim/ScimObserver.java) | interface | [`ScimObserver.Operation`](../src/main/java/com/revetsec/scim/ScimObserver.java), [`ScimObserver.Outcome`](../src/main/java/com/revetsec/scim/ScimObserver.java) |
| [`ScimPaginationConfig`](../src/main/java/com/revetsec/scim/ScimPaginationConfig.java) | class | [`ScimPaginationConfig.Builder`](../src/main/java/com/revetsec/scim/ScimPaginationConfig.java) |
| [`ScimPaginationMethod`](../src/main/java/com/revetsec/scim/ScimPaginationMethod.java) | enum | — |
| [`ScimPatchApplicationResult`](../src/main/java/com/revetsec/scim/ScimPatchApplicationResult.java) | interface | [`ScimPatchApplicationResult.Rejected`](../src/main/java/com/revetsec/scim/ScimPatchApplicationResult.java), [`ScimPatchApplicationResult.Succeeded`](../src/main/java/com/revetsec/scim/ScimPatchApplicationResult.java) |
| [`ScimPatchOperation`](../src/main/java/com/revetsec/scim/ScimPatchOperation.java) | class | — |
| [`ScimPatchOperationType`](../src/main/java/com/revetsec/scim/ScimPatchOperationType.java) | enum | — |
| [`ScimPatchParseResult`](../src/main/java/com/revetsec/scim/ScimPatchParseResult.java) | interface | [`ScimPatchParseResult.Rejected`](../src/main/java/com/revetsec/scim/ScimPatchParseResult.java), [`ScimPatchParseResult.Succeeded`](../src/main/java/com/revetsec/scim/ScimPatchParseResult.java) |
| [`ScimPatchRequest`](../src/main/java/com/revetsec/scim/ScimPatchRequest.java) | class | — |
| [`ScimPatchResult`](../src/main/java/com/revetsec/scim/ScimPatchResult.java) | class | — |
| [`ScimQuery`](../src/main/java/com/revetsec/scim/ScimQuery.java) | class | — |
| [`ScimQueryParseResult`](../src/main/java/com/revetsec/scim/ScimQueryParseResult.java) | interface | [`ScimQueryParseResult.Rejected`](../src/main/java/com/revetsec/scim/ScimQueryParseResult.java), [`ScimQueryParseResult.Succeeded`](../src/main/java/com/revetsec/scim/ScimQueryParseResult.java) |
| [`ScimResource`](../src/main/java/com/revetsec/scim/ScimResource.java) | class | [`ScimResource.Builder`](../src/main/java/com/revetsec/scim/ScimResource.java), [`ScimResource.Copier`](../src/main/java/com/revetsec/scim/ScimResource.java) |
| [`ScimResourceParseResult`](../src/main/java/com/revetsec/scim/ScimResourceParseResult.java) | interface | [`ScimResourceParseResult.Rejected`](../src/main/java/com/revetsec/scim/ScimResourceParseResult.java), [`ScimResourceParseResult.Succeeded`](../src/main/java/com/revetsec/scim/ScimResourceParseResult.java) |
| [`ScimResourceType`](../src/main/java/com/revetsec/scim/ScimResourceType.java) | class | [`ScimResourceType.Builder`](../src/main/java/com/revetsec/scim/ScimResourceType.java) |
| [`ScimResourceWorkLimitException`](../src/main/java/com/revetsec/scim/ScimResourceWorkLimitException.java) | class | — |
| [`ScimResponse`](../src/main/java/com/revetsec/scim/ScimResponse.java) | class | — |
| [`ScimResponseResult`](../src/main/java/com/revetsec/scim/ScimResponseResult.java) | interface | [`ScimResponseResult.Prepared`](../src/main/java/com/revetsec/scim/ScimResponseResult.java), [`ScimResponseResult.Rejected`](../src/main/java/com/revetsec/scim/ScimResponseResult.java) |
| [`ScimReturned`](../src/main/java/com/revetsec/scim/ScimReturned.java) | enum | — |
| [`ScimSchema`](../src/main/java/com/revetsec/scim/ScimSchema.java) | class | [`ScimSchema.Builder`](../src/main/java/com/revetsec/scim/ScimSchema.java) |
| [`ScimSchemaExtension`](../src/main/java/com/revetsec/scim/ScimSchemaExtension.java) | class | — |
| [`ScimServiceProvider`](../src/main/java/com/revetsec/scim/ScimServiceProvider.java) | class | [`ScimServiceProvider.Builder`](../src/main/java/com/revetsec/scim/ScimServiceProvider.java), [`ScimServiceProvider.Copier`](../src/main/java/com/revetsec/scim/ScimServiceProvider.java) |
| [`ScimServiceProviderConfig`](../src/main/java/com/revetsec/scim/ScimServiceProviderConfig.java) | class | [`ScimServiceProviderConfig.Builder`](../src/main/java/com/revetsec/scim/ScimServiceProviderConfig.java) |
| [`ScimSortOrder`](../src/main/java/com/revetsec/scim/ScimSortOrder.java) | enum | — |
| [`ScimStringMatchResult`](../src/main/java/com/revetsec/scim/ScimStringMatchResult.java) | interface | [`ScimStringMatchResult.Matched`](../src/main/java/com/revetsec/scim/ScimStringMatchResult.java), [`ScimStringMatchResult.Unsupported`](../src/main/java/com/revetsec/scim/ScimStringMatchResult.java) |
| [`ScimStringMatching`](../src/main/java/com/revetsec/scim/ScimStringMatching.java) | interface | — |
| [`ScimUniqueness`](../src/main/java/com/revetsec/scim/ScimUniqueness.java) | enum | — |
| [`ScimUser`](../src/main/java/com/revetsec/scim/ScimUser.java) | class | — |

## com.revetsec.totp

34 top-level + 67 nested = **101 types**. Names link to the declaring source file.

| Top-level declaration | Kind | Accessible nested declarations |
| --- | --- | --- |
| [`InMemoryTotpStore`](../src/main/java/com/revetsec/totp/InMemoryTotpStore.java) | class | [`InMemoryTotpStore.Builder`](../src/main/java/com/revetsec/totp/InMemoryTotpStore.java) |
| [`RecoveryCodeRotationResult`](../src/main/java/com/revetsec/totp/RecoveryCodeRotationResult.java) | class | [`RecoveryCodeRotationResult.Indeterminate`](../src/main/java/com/revetsec/totp/RecoveryCodeRotationResult.java), [`RecoveryCodeRotationResult.ReconciliationRequired`](../src/main/java/com/revetsec/totp/RecoveryCodeRotationResult.java), [`RecoveryCodeRotationResult.Rejected`](../src/main/java/com/revetsec/totp/RecoveryCodeRotationResult.java), [`RecoveryCodeRotationResult.Succeeded`](../src/main/java/com/revetsec/totp/RecoveryCodeRotationResult.java), [`RecoveryCodeRotationResult.Unavailable`](../src/main/java/com/revetsec/totp/RecoveryCodeRotationResult.java) |
| [`RecoveryCodeUse`](../src/main/java/com/revetsec/totp/RecoveryCodeUse.java) | class | — |
| [`RecoveryCodeUseResult`](../src/main/java/com/revetsec/totp/RecoveryCodeUseResult.java) | class | [`RecoveryCodeUseResult.Indeterminate`](../src/main/java/com/revetsec/totp/RecoveryCodeUseResult.java), [`RecoveryCodeUseResult.ReconciliationRequired`](../src/main/java/com/revetsec/totp/RecoveryCodeUseResult.java), [`RecoveryCodeUseResult.Rejected`](../src/main/java/com/revetsec/totp/RecoveryCodeUseResult.java), [`RecoveryCodeUseResult.Succeeded`](../src/main/java/com/revetsec/totp/RecoveryCodeUseResult.java), [`RecoveryCodeUseResult.Throttled`](../src/main/java/com/revetsec/totp/RecoveryCodeUseResult.java), [`RecoveryCodeUseResult.Unavailable`](../src/main/java/com/revetsec/totp/RecoveryCodeUseResult.java) |
| [`RecoveryCodes`](../src/main/java/com/revetsec/totp/RecoveryCodes.java) | class | — |
| [`TotpAuthenticationMethod`](../src/main/java/com/revetsec/totp/TotpAuthenticationMethod.java) | enum | — |
| [`TotpAuthenticator`](../src/main/java/com/revetsec/totp/TotpAuthenticator.java) | class | [`TotpAuthenticator.Builder`](../src/main/java/com/revetsec/totp/TotpAuthenticator.java) |
| [`TotpEnrollment`](../src/main/java/com/revetsec/totp/TotpEnrollment.java) | class | — |
| [`TotpEnrollmentCancellationResult`](../src/main/java/com/revetsec/totp/TotpEnrollmentCancellationResult.java) | class | [`TotpEnrollmentCancellationResult.Indeterminate`](../src/main/java/com/revetsec/totp/TotpEnrollmentCancellationResult.java), [`TotpEnrollmentCancellationResult.ReconciliationRequired`](../src/main/java/com/revetsec/totp/TotpEnrollmentCancellationResult.java), [`TotpEnrollmentCancellationResult.Rejected`](../src/main/java/com/revetsec/totp/TotpEnrollmentCancellationResult.java), [`TotpEnrollmentCancellationResult.Succeeded`](../src/main/java/com/revetsec/totp/TotpEnrollmentCancellationResult.java), [`TotpEnrollmentCancellationResult.Unavailable`](../src/main/java/com/revetsec/totp/TotpEnrollmentCancellationResult.java) |
| [`TotpEnrollmentOptions`](../src/main/java/com/revetsec/totp/TotpEnrollmentOptions.java) | class | [`TotpEnrollmentOptions.Builder`](../src/main/java/com/revetsec/totp/TotpEnrollmentOptions.java) |
| [`TotpEnrollmentRequestResult`](../src/main/java/com/revetsec/totp/TotpEnrollmentRequestResult.java) | class | [`TotpEnrollmentRequestResult.Indeterminate`](../src/main/java/com/revetsec/totp/TotpEnrollmentRequestResult.java), [`TotpEnrollmentRequestResult.Prepared`](../src/main/java/com/revetsec/totp/TotpEnrollmentRequestResult.java), [`TotpEnrollmentRequestResult.ReconciliationRequired`](../src/main/java/com/revetsec/totp/TotpEnrollmentRequestResult.java), [`TotpEnrollmentRequestResult.Rejected`](../src/main/java/com/revetsec/totp/TotpEnrollmentRequestResult.java), [`TotpEnrollmentRequestResult.Throttled`](../src/main/java/com/revetsec/totp/TotpEnrollmentRequestResult.java), [`TotpEnrollmentRequestResult.Unavailable`](../src/main/java/com/revetsec/totp/TotpEnrollmentRequestResult.java) |
| [`TotpEnrollmentResult`](../src/main/java/com/revetsec/totp/TotpEnrollmentResult.java) | class | [`TotpEnrollmentResult.Indeterminate`](../src/main/java/com/revetsec/totp/TotpEnrollmentResult.java), [`TotpEnrollmentResult.ReconciliationRequired`](../src/main/java/com/revetsec/totp/TotpEnrollmentResult.java), [`TotpEnrollmentResult.Rejected`](../src/main/java/com/revetsec/totp/TotpEnrollmentResult.java), [`TotpEnrollmentResult.Succeeded`](../src/main/java/com/revetsec/totp/TotpEnrollmentResult.java), [`TotpEnrollmentResult.Throttled`](../src/main/java/com/revetsec/totp/TotpEnrollmentResult.java), [`TotpEnrollmentResult.Unavailable`](../src/main/java/com/revetsec/totp/TotpEnrollmentResult.java) |
| [`TotpFactor`](../src/main/java/com/revetsec/totp/TotpFactor.java) | class | — |
| [`TotpFactorRemovalResult`](../src/main/java/com/revetsec/totp/TotpFactorRemovalResult.java) | class | [`TotpFactorRemovalResult.Indeterminate`](../src/main/java/com/revetsec/totp/TotpFactorRemovalResult.java), [`TotpFactorRemovalResult.ReconciliationRequired`](../src/main/java/com/revetsec/totp/TotpFactorRemovalResult.java), [`TotpFactorRemovalResult.Rejected`](../src/main/java/com/revetsec/totp/TotpFactorRemovalResult.java), [`TotpFactorRemovalResult.Succeeded`](../src/main/java/com/revetsec/totp/TotpFactorRemovalResult.java), [`TotpFactorRemovalResult.Unavailable`](../src/main/java/com/revetsec/totp/TotpFactorRemovalResult.java) |
| [`TotpNamespaceInitializationResult`](../src/main/java/com/revetsec/totp/TotpNamespaceInitializationResult.java) | class | [`TotpNamespaceInitializationResult.AlreadyInitialized`](../src/main/java/com/revetsec/totp/TotpNamespaceInitializationResult.java), [`TotpNamespaceInitializationResult.Indeterminate`](../src/main/java/com/revetsec/totp/TotpNamespaceInitializationResult.java), [`TotpNamespaceInitializationResult.Initialized`](../src/main/java/com/revetsec/totp/TotpNamespaceInitializationResult.java), [`TotpNamespaceInitializationResult.ReconciliationRequired`](../src/main/java/com/revetsec/totp/TotpNamespaceInitializationResult.java), [`TotpNamespaceInitializationResult.Unavailable`](../src/main/java/com/revetsec/totp/TotpNamespaceInitializationResult.java) |
| [`TotpPendingEnrollment`](../src/main/java/com/revetsec/totp/TotpPendingEnrollment.java) | class | — |
| [`TotpRecoveryContext`](../src/main/java/com/revetsec/totp/TotpRecoveryContext.java) | class | [`TotpRecoveryContext.Purpose`](../src/main/java/com/revetsec/totp/TotpRecoveryContext.java) |
| [`TotpRecoveryGate`](../src/main/java/com/revetsec/totp/TotpRecoveryGate.java) | interface | [`TotpRecoveryGate.Permit`](../src/main/java/com/revetsec/totp/TotpRecoveryGate.java) |
| [`TotpRejectionReason`](../src/main/java/com/revetsec/totp/TotpRejectionReason.java) | enum | — |
| [`TotpStatus`](../src/main/java/com/revetsec/totp/TotpStatus.java) | class | — |
| [`TotpStatusResult`](../src/main/java/com/revetsec/totp/TotpStatusResult.java) | class | [`TotpStatusResult.Absent`](../src/main/java/com/revetsec/totp/TotpStatusResult.java), [`TotpStatusResult.Present`](../src/main/java/com/revetsec/totp/TotpStatusResult.java), [`TotpStatusResult.Unavailable`](../src/main/java/com/revetsec/totp/TotpStatusResult.java) |
| [`TotpStore`](../src/main/java/com/revetsec/totp/TotpStore.java) | interface | — |
| [`TotpStoreCommitReceipt`](../src/main/java/com/revetsec/totp/TotpStoreCommitReceipt.java) | class | — |
| [`TotpStoreCommitResult`](../src/main/java/com/revetsec/totp/TotpStoreCommitResult.java) | enum | — |
| [`TotpStoreEntry`](../src/main/java/com/revetsec/totp/TotpStoreEntry.java) | interface | [`TotpStoreEntry.Absent`](../src/main/java/com/revetsec/totp/TotpStoreEntry.java), [`TotpStoreEntry.Present`](../src/main/java/com/revetsec/totp/TotpStoreEntry.java) |
| [`TotpStoreKey`](../src/main/java/com/revetsec/totp/TotpStoreKey.java) | class | [`TotpStoreKey.Kind`](../src/main/java/com/revetsec/totp/TotpStoreKey.java) |
| [`TotpStoreReadResult`](../src/main/java/com/revetsec/totp/TotpStoreReadResult.java) | interface | [`TotpStoreReadResult.Available`](../src/main/java/com/revetsec/totp/TotpStoreReadResult.java), [`TotpStoreReadResult.Fenced`](../src/main/java/com/revetsec/totp/TotpStoreReadResult.java), [`TotpStoreReadResult.Unavailable`](../src/main/java/com/revetsec/totp/TotpStoreReadResult.java) |
| [`TotpStoreRecord`](../src/main/java/com/revetsec/totp/TotpStoreRecord.java) | class | — |
| [`TotpStoreResealResult`](../src/main/java/com/revetsec/totp/TotpStoreResealResult.java) | class | [`TotpStoreResealResult.Absent`](../src/main/java/com/revetsec/totp/TotpStoreResealResult.java), [`TotpStoreResealResult.AlreadyCurrent`](../src/main/java/com/revetsec/totp/TotpStoreResealResult.java), [`TotpStoreResealResult.Indeterminate`](../src/main/java/com/revetsec/totp/TotpStoreResealResult.java), [`TotpStoreResealResult.ReconciliationRequired`](../src/main/java/com/revetsec/totp/TotpStoreResealResult.java), [`TotpStoreResealResult.Resealed`](../src/main/java/com/revetsec/totp/TotpStoreResealResult.java), [`TotpStoreResealResult.Unavailable`](../src/main/java/com/revetsec/totp/TotpStoreResealResult.java) |
| [`TotpStoreSnapshot`](../src/main/java/com/revetsec/totp/TotpStoreSnapshot.java) | class | — |
| [`TotpStoreWrite`](../src/main/java/com/revetsec/totp/TotpStoreWrite.java) | class | [`TotpStoreWrite.Mutation`](../src/main/java/com/revetsec/totp/TotpStoreWrite.java), [`TotpStoreWrite.Mutation.Kind`](../src/main/java/com/revetsec/totp/TotpStoreWrite.java), [`TotpStoreWrite.Purpose`](../src/main/java/com/revetsec/totp/TotpStoreWrite.java) |
| [`TotpUnavailableReason`](../src/main/java/com/revetsec/totp/TotpUnavailableReason.java) | enum | — |
| [`TotpVerification`](../src/main/java/com/revetsec/totp/TotpVerification.java) | class | — |
| [`TotpVerificationResult`](../src/main/java/com/revetsec/totp/TotpVerificationResult.java) | class | [`TotpVerificationResult.Indeterminate`](../src/main/java/com/revetsec/totp/TotpVerificationResult.java), [`TotpVerificationResult.ReconciliationRequired`](../src/main/java/com/revetsec/totp/TotpVerificationResult.java), [`TotpVerificationResult.Rejected`](../src/main/java/com/revetsec/totp/TotpVerificationResult.java), [`TotpVerificationResult.Succeeded`](../src/main/java/com/revetsec/totp/TotpVerificationResult.java), [`TotpVerificationResult.Throttled`](../src/main/java/com/revetsec/totp/TotpVerificationResult.java), [`TotpVerificationResult.Unavailable`](../src/main/java/com/revetsec/totp/TotpVerificationResult.java) |

## com.revetsec.webauthn

24 top-level + 44 nested = **68 types**. Names link to the declaring source file.

| Top-level declaration | Kind | Accessible nested declarations |
| --- | --- | --- |
| [`InMemoryWebAuthnStore`](../src/main/java/com/revetsec/webauthn/InMemoryWebAuthnStore.java) | class | — |
| [`WebAuthnAccountDisableResult`](../src/main/java/com/revetsec/webauthn/WebAuthnAccountDisableResult.java) | class | [`WebAuthnAccountDisableResult.Disabled`](../src/main/java/com/revetsec/webauthn/WebAuthnAccountDisableResult.java), [`WebAuthnAccountDisableResult.Indeterminate`](../src/main/java/com/revetsec/webauthn/WebAuthnAccountDisableResult.java), [`WebAuthnAccountDisableResult.ReconciliationRequired`](../src/main/java/com/revetsec/webauthn/WebAuthnAccountDisableResult.java), [`WebAuthnAccountDisableResult.Unavailable`](../src/main/java/com/revetsec/webauthn/WebAuthnAccountDisableResult.java) |
| [`WebAuthnAuthentication`](../src/main/java/com/revetsec/webauthn/WebAuthnAuthentication.java) | class | [`WebAuthnAuthentication.Kind`](../src/main/java/com/revetsec/webauthn/WebAuthnAuthentication.java) |
| [`WebAuthnAuthenticationRequestResult`](../src/main/java/com/revetsec/webauthn/WebAuthnAuthenticationRequestResult.java) | class | [`WebAuthnAuthenticationRequestResult.Indeterminate`](../src/main/java/com/revetsec/webauthn/WebAuthnAuthenticationRequestResult.java), [`WebAuthnAuthenticationRequestResult.Prepared`](../src/main/java/com/revetsec/webauthn/WebAuthnAuthenticationRequestResult.java), [`WebAuthnAuthenticationRequestResult.ReconciliationRequired`](../src/main/java/com/revetsec/webauthn/WebAuthnAuthenticationRequestResult.java), [`WebAuthnAuthenticationRequestResult.Rejected`](../src/main/java/com/revetsec/webauthn/WebAuthnAuthenticationRequestResult.java), [`WebAuthnAuthenticationRequestResult.Unavailable`](../src/main/java/com/revetsec/webauthn/WebAuthnAuthenticationRequestResult.java) |
| [`WebAuthnAuthenticationResult`](../src/main/java/com/revetsec/webauthn/WebAuthnAuthenticationResult.java) | class | [`WebAuthnAuthenticationResult.Indeterminate`](../src/main/java/com/revetsec/webauthn/WebAuthnAuthenticationResult.java), [`WebAuthnAuthenticationResult.ReconciliationRequired`](../src/main/java/com/revetsec/webauthn/WebAuthnAuthenticationResult.java), [`WebAuthnAuthenticationResult.Rejected`](../src/main/java/com/revetsec/webauthn/WebAuthnAuthenticationResult.java), [`WebAuthnAuthenticationResult.Succeeded`](../src/main/java/com/revetsec/webauthn/WebAuthnAuthenticationResult.java), [`WebAuthnAuthenticationResult.Unavailable`](../src/main/java/com/revetsec/webauthn/WebAuthnAuthenticationResult.java) |
| [`WebAuthnBrowserRequest`](../src/main/java/com/revetsec/webauthn/WebAuthnBrowserRequest.java) | class | — |
| [`WebAuthnCredentialListResult`](../src/main/java/com/revetsec/webauthn/WebAuthnCredentialListResult.java) | class | [`WebAuthnCredentialListResult.Listed`](../src/main/java/com/revetsec/webauthn/WebAuthnCredentialListResult.java), [`WebAuthnCredentialListResult.Unavailable`](../src/main/java/com/revetsec/webauthn/WebAuthnCredentialListResult.java) |
| [`WebAuthnCredentialRemovalResult`](../src/main/java/com/revetsec/webauthn/WebAuthnCredentialRemovalResult.java) | class | [`WebAuthnCredentialRemovalResult.Absent`](../src/main/java/com/revetsec/webauthn/WebAuthnCredentialRemovalResult.java), [`WebAuthnCredentialRemovalResult.Indeterminate`](../src/main/java/com/revetsec/webauthn/WebAuthnCredentialRemovalResult.java), [`WebAuthnCredentialRemovalResult.ReconciliationRequired`](../src/main/java/com/revetsec/webauthn/WebAuthnCredentialRemovalResult.java), [`WebAuthnCredentialRemovalResult.Removed`](../src/main/java/com/revetsec/webauthn/WebAuthnCredentialRemovalResult.java), [`WebAuthnCredentialRemovalResult.Unavailable`](../src/main/java/com/revetsec/webauthn/WebAuthnCredentialRemovalResult.java) |
| [`WebAuthnRecoveryGate`](../src/main/java/com/revetsec/webauthn/WebAuthnRecoveryGate.java) | interface | [`WebAuthnRecoveryGate.Permit`](../src/main/java/com/revetsec/webauthn/WebAuthnRecoveryGate.java) |
| [`WebAuthnRegistration`](../src/main/java/com/revetsec/webauthn/WebAuthnRegistration.java) | class | — |
| [`WebAuthnRegistrationOptions`](../src/main/java/com/revetsec/webauthn/WebAuthnRegistrationOptions.java) | class | [`WebAuthnRegistrationOptions.Builder`](../src/main/java/com/revetsec/webauthn/WebAuthnRegistrationOptions.java) |
| [`WebAuthnRegistrationRequestResult`](../src/main/java/com/revetsec/webauthn/WebAuthnRegistrationRequestResult.java) | class | [`WebAuthnRegistrationRequestResult.Indeterminate`](../src/main/java/com/revetsec/webauthn/WebAuthnRegistrationRequestResult.java), [`WebAuthnRegistrationRequestResult.Prepared`](../src/main/java/com/revetsec/webauthn/WebAuthnRegistrationRequestResult.java), [`WebAuthnRegistrationRequestResult.ReconciliationRequired`](../src/main/java/com/revetsec/webauthn/WebAuthnRegistrationRequestResult.java), [`WebAuthnRegistrationRequestResult.Rejected`](../src/main/java/com/revetsec/webauthn/WebAuthnRegistrationRequestResult.java), [`WebAuthnRegistrationRequestResult.Unavailable`](../src/main/java/com/revetsec/webauthn/WebAuthnRegistrationRequestResult.java) |
| [`WebAuthnRegistrationResult`](../src/main/java/com/revetsec/webauthn/WebAuthnRegistrationResult.java) | class | [`WebAuthnRegistrationResult.Indeterminate`](../src/main/java/com/revetsec/webauthn/WebAuthnRegistrationResult.java), [`WebAuthnRegistrationResult.ReconciliationRequired`](../src/main/java/com/revetsec/webauthn/WebAuthnRegistrationResult.java), [`WebAuthnRegistrationResult.Rejected`](../src/main/java/com/revetsec/webauthn/WebAuthnRegistrationResult.java), [`WebAuthnRegistrationResult.Succeeded`](../src/main/java/com/revetsec/webauthn/WebAuthnRegistrationResult.java), [`WebAuthnRegistrationResult.Unavailable`](../src/main/java/com/revetsec/webauthn/WebAuthnRegistrationResult.java) |
| [`WebAuthnRejectionReason`](../src/main/java/com/revetsec/webauthn/WebAuthnRejectionReason.java) | enum | — |
| [`WebAuthnRelyingParty`](../src/main/java/com/revetsec/webauthn/WebAuthnRelyingParty.java) | class | [`WebAuthnRelyingParty.Builder`](../src/main/java/com/revetsec/webauthn/WebAuthnRelyingParty.java) |
| [`WebAuthnSettings`](../src/main/java/com/revetsec/webauthn/WebAuthnSettings.java) | class | [`WebAuthnSettings.Builder`](../src/main/java/com/revetsec/webauthn/WebAuthnSettings.java) |
| [`WebAuthnStore`](../src/main/java/com/revetsec/webauthn/WebAuthnStore.java) | interface | — |
| [`WebAuthnStoreCommitReceipt`](../src/main/java/com/revetsec/webauthn/WebAuthnStoreCommitReceipt.java) | class | — |
| [`WebAuthnStoreCommitResult`](../src/main/java/com/revetsec/webauthn/WebAuthnStoreCommitResult.java) | enum | — |
| [`WebAuthnStoreEntry`](../src/main/java/com/revetsec/webauthn/WebAuthnStoreEntry.java) | interface | [`WebAuthnStoreEntry.Absent`](../src/main/java/com/revetsec/webauthn/WebAuthnStoreEntry.java), [`WebAuthnStoreEntry.Present`](../src/main/java/com/revetsec/webauthn/WebAuthnStoreEntry.java) |
| [`WebAuthnStoreKey`](../src/main/java/com/revetsec/webauthn/WebAuthnStoreKey.java) | class | [`WebAuthnStoreKey.Kind`](../src/main/java/com/revetsec/webauthn/WebAuthnStoreKey.java) |
| [`WebAuthnStoreReadResult`](../src/main/java/com/revetsec/webauthn/WebAuthnStoreReadResult.java) | interface | [`WebAuthnStoreReadResult.Available`](../src/main/java/com/revetsec/webauthn/WebAuthnStoreReadResult.java), [`WebAuthnStoreReadResult.Fenced`](../src/main/java/com/revetsec/webauthn/WebAuthnStoreReadResult.java), [`WebAuthnStoreReadResult.Unavailable`](../src/main/java/com/revetsec/webauthn/WebAuthnStoreReadResult.java) |
| [`WebAuthnStoreSnapshot`](../src/main/java/com/revetsec/webauthn/WebAuthnStoreSnapshot.java) | class | — |
| [`WebAuthnStoreWrite`](../src/main/java/com/revetsec/webauthn/WebAuthnStoreWrite.java) | class | [`WebAuthnStoreWrite.Mutation`](../src/main/java/com/revetsec/webauthn/WebAuthnStoreWrite.java), [`WebAuthnStoreWrite.Mutation.Kind`](../src/main/java/com/revetsec/webauthn/WebAuthnStoreWrite.java) |
