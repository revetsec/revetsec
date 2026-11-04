/*
 * Copyright 2026 Revetware LLC.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.revetsec.oauth.server;

import com.revetsec.internal.ObserverDispatch;
import java.util.concurrent.atomic.AtomicBoolean;
import com.revetsec.StateSealer;
import com.revetsec.OutboundUriPolicy;
import com.revetsec.internal.crypto.SealedStateAccess;
import com.revetsec.internal.http.Deadline;
import com.revetsec.internal.http.RuntimeFloor;
import com.revetsec.internal.oauth.OidcTransactionAccess;
import com.revetsec.jose.JwsAlgorithm;
import com.revetsec.jose.StaticJwksSource;
import com.revetsec.oauth.BearerToken;
import com.revetsec.oauth.JwtAccessTokenValidator;
import com.revetsec.oauth.VerifiedAccessToken;
import com.revetsec.oauth.AccessTokenValidationException;
import com.revetsec.oauth.OAuthTransportException;
import com.google.errorprone.annotations.CheckReturnValue;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import javax.annotation.concurrent.ThreadSafe;
import javax.annotation.concurrent.NotThreadSafe;
import java.net.URI;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.HashSet;
import java.util.function.Function;
import static java.util.Objects.requireNonNull;
import static com.revetsec.oauth.server.OAuthServerException.Reason.*;
import static com.revetsec.oauth.server.OAuthServerObserver.Endpoint.*;

/**
 * Caller-thread OAuth code issuer with authoritative online grant status. Applications supply users, consent,
 * atomic durable storage, admitted store time, healthy worker clocks, keys and authorization policy. Register the exact configured
 * routes; request headers never select issuer authority. Protect completion with the app's session and CSRF
 * controls. Infrastructure faults remain exceptions; expected remote rejection is a restricted result.
 * Construction performs no application data callbacks, network I/O, signing or thread startup; the builder documents
 * its explicit observer notification. No positive grant-status cache.
 * Revetsec has not been independently audited.
 * @since 1.0.0
 */
@ThreadSafe
public final class OAuthAuthorizationServer {
 private final @NonNull String issuer;
 private final @NonNull URI authorizationEndpoint, tokenEndpoint, jwksEndpoint;
 private final @Nullable URI revocationEndpoint, introspectionEndpoint;
 private final @NonNull OAuthServerSettings settings;
 private final @NonNull OAuthServerIngressLimits limits;
 private final @NonNull Map<@NonNull String, @NonNull Set<@NonNull String>> resources;
 private final @NonNull OAuthServerClientRepository repository;
 private final @NonNull OAuthGrantPolicy policy;
 private final @NonNull OAuthServerObserver observer;
 private final @NonNull Clock clock;
 private final boolean nativeLoopback, localhost, localhostAnyPort, refresh;
 private final @NonNull OAuthServerClientSelection clients;
 private final @NonNull OAuthStoreCoordinator coordinator;
 private final @NonNull OAuthAuthorizationLedger ledger;
 private final @NonNull OAuthAuthorizationResponseEncoder authorizationEncoder;
 private final @NonNull OAuthCodeRedemption codes;
 private final @NonNull OAuthRefreshRotation rotations;
 private final @NonNull OAuthIssuerKeyLifecycle keys;
 private final @NonNull OAuthIssuerTokenStatus status;
 private final @NonNull OAuthGrantRevocation revocation;
 private final @NonNull OAuthResourceIntrospection introspection;
 private final @NonNull OAuthIssuerMetadata metadata;
 private OAuthAuthorizationServer(@NonNull Builder b) { this(b, Runtime.version()); }
 private OAuthAuthorizationServer(@NonNull Builder b, Runtime.@NonNull Version runtimeVersion) {
  this.issuer=b.issuer; this.authorizationEndpoint=required(b.authorizationEndpoint); this.tokenEndpoint=required(b.tokenEndpoint);
  this.jwksEndpoint=required(b.jwksEndpoint); this.revocationEndpoint=b.revocationEndpoint; this.introspectionEndpoint=b.introspectionEndpoint;
  this.repository=required(b.clientRepository); this.policy=required(b.grantPolicy); OAuthAuthorizationServerStore store=required(b.store);
  OAuthIssuerKeyProvider provider=required(b.signingKeys); StateSealer sealer=required(b.stateSealer);
  this.refresh=b.refreshTokensEnabled;
  if (this.refresh && this.revocationEndpoint==null) throw new IllegalStateException("Refresh requires a revocation endpoint.");
  this.settings=b.settings.build(this.refresh,SealedStateAccess.get().getMaximumSealedLength(sealer)); this.limits=this.settings.ingress();
  this.resources=OAuthServerAuthorizationAdmission.checkedServerResources(required(b.resources),this.limits);
  this.clock=b.clock; this.observer=b.observer; this.nativeLoopback=b.allowNativeLoopbackRedirects; this.localhost=b.allowLocalhostRedirects; this.localhostAnyPort=b.allowLocalhostAnyPortRedirects;
  URI issuerUri=endpoint(URI.create(this.issuer),b.allowInsecureLoopback);
  Set<String> routes=new HashSet<>();
  for (URI route:List.of(this.authorizationEndpoint,this.tokenEndpoint,this.jwksEndpoint)) checkRoute(issuerUri,route,b.allowInsecureLoopback,routes);
  if(this.revocationEndpoint!=null) checkRoute(issuerUri,this.revocationEndpoint,b.allowInsecureLoopback,routes);
  if(this.introspectionEndpoint!=null) checkRoute(issuerUri,this.introspectionEndpoint,b.allowInsecureLoopback,routes);
  OAuthClientMetadataPolicy metadataPolicy=b.clientMetadataPolicy;
  if(metadataPolicy.getEnabled()) RuntimeFloor.require(runtimeVersion,b.acknowledgeUnpatchedRuntime);
  OAuthClientMetadataFetcher fetcher=metadataPolicy.getEnabled() ? new OAuthClientMetadataFetcher(this.issuer,sealer,metadataPolicy,this.limits,
   this.nativeLoopback,this.localhost,this.localhostAnyPort,b.outboundUriPolicy,this.clock,this.settings.requestTimeout) : null;
  this.clients=new OAuthServerClientSelection(this.repository,this.limits,fetcher,true);
  OAuthStoreRecordCodec codec=new OAuthStoreRecordCodec(this.issuer,sealer,this.settings.maximumStoreRecordBytes);
  this.coordinator=new OAuthStoreCoordinator(store,codec,this.clock,this.settings.clockSkew,this.settings.maximumStoreCommitAttempts,this.settings.maximumSubjectLength);
  this.ledger=new OAuthAuthorizationLedger(this.coordinator,codec,this.limits,this.settings.authorizationInteractionLifetime,
   this.settings.authorizationCodeLifetime,this.settings.maximumStoreCommitAttempts,this.settings.maximumSubjectLength,this.refresh);
  OAuthGrantRetention retention=new OAuthGrantRetention(this.settings.accessTokenLifetime,this.settings.clockSkew,this.settings.totalDeadline,this.settings.publicMetadataHttpCacheMaxAge);
  this.keys=new OAuthIssuerKeyLifecycle(provider,this.clock,this.settings.publicMetadataHttpCacheMaxAge,retention,true);
  OAuthTokenResponse.Encoder encoder=new OAuthTokenResponse.Encoder(this.issuer,this.keys,this.settings.maximumResponseBodyBytes,this.settings.maximumHeaderBytes);
  this.codes=new OAuthCodeRedemption(this.coordinator,codec,this.limits,retention,encoder,this.settings.accessTokenLifetime,this.refresh,
   this.settings.refreshTokenIdleLifetime,this.settings.refreshTokenAbsoluteLifetime,this.settings.maximumStoreCommitAttempts,this.settings.maximumSubjectLength);
  this.rotations=new OAuthRefreshRotation(this.coordinator,codec,this.limits,retention,encoder,this.settings.accessTokenLifetime,this.refresh,
   this.settings.refreshTokenIdleLifetime,this.settings.maximumStoreCommitAttempts,this.settings.maximumSubjectLength);
  this.authorizationEncoder=new OAuthAuthorizationResponseEncoder(issuerUri,b.allowInsecureLoopback,this.settings.maximumResponseBodyBytes,this.settings.maximumHeaderBytes,this.settings.maximumStateLength);
  this.status=new OAuthIssuerTokenStatus(this.coordinator,codec,this.limits,this.clock,this.settings.clockSkew,this.settings.maximumStoreCommitAttempts,this.settings.maximumSubjectLength,this.settings.maximumRequestBodyBytes);
  this.revocation=new OAuthGrantRevocation(this.coordinator,codec,this.status,this.limits,this.settings.maximumStoreCommitAttempts,this.settings.maximumSubjectLength,this.settings.maximumResponseBodyBytes,this.settings.maximumHeaderBytes);
  this.introspection=new OAuthResourceIntrospection(this.status,this.limits,this.settings.maximumResponseBodyBytes,this.settings.maximumHeaderBytes);
  Set<String> scopes=new HashSet<>(); for(Set<String> values:this.resources.values()) scopes.addAll(values);
  this.metadata=new OAuthIssuerMetadata(issuerUri,this.authorizationEndpoint,this.tokenEndpoint,this.jwksEndpoint,this.revocationEndpoint,this.introspectionEndpoint,
   this.refresh,b.allowInsecureLoopback,scopes,this.settings.publicMetadataHttpCacheMaxAge,this.settings.maximumResponseBodyBytes,this.settings.maximumHeaderBytes,metadataPolicy.getEnabled());
  if(this.localhostAnyPort) ObserverDispatch.dispatch(this.observer,OAuthServerObserver::didEnableLocalhostAnyPortRedirects);
 }
 /**
  * Starts configuration with an exact issuer identity, retained for the lifetime of the builder/server.
  * The primary argument is required and cannot be cleared. This factory checks its URI shape; numeric
  * HTTP loopback is admitted provisionally but still requires {@link Builder#allowInsecureLoopback(Boolean)}
  * at build. Localhost HTTP issuers are not supported. No endpoint routes are inferred or network calls made.
  * @param issuer absolute HTTPS issuer, or a numeric HTTP loopback issuer for explicit local opt-in
  * @return an otherwise unconfigured builder
  * @throws NullPointerException if issuer is null
  * @throws IllegalArgumentException if issuer is not a permitted absolute issuer URI
  * @since 1.0.0
  */
 @CheckReturnValue public static @NonNull Builder withIssuer(@NonNull String issuer) { return new Builder(issuer); }
 /** Admits a GET authorization request and creates a browser-bound interaction.
  * @param httpMethod materialized method
  * @param rawQuery original query or absence
  * @param rawBody materialized body
  * @param rawHeaderValues original header names and all occurrences
  * @param browserBinding independent app-owned canonical random binding
  * @return interaction or fixed local rejection
  * @since 1.0.0
  */
 @CheckReturnValue public @NonNull OAuthAuthorizationResult beginAuthorizationResult(@NonNull String httpMethod,@Nullable String rawQuery,
   byte @NonNull [] rawBody,@NonNull Map<@NonNull String,@NonNull List<@NonNull String>> rawHeaderValues,@NonNull String browserBinding) {
  inputs(httpMethod,rawBody,rawHeaderValues); requireNonNull(browserBinding);
  return execute(AUTHORIZATION,d->{
   OAuthServerRequest request=parse(OAuthServerRequest.Endpoint.AUTHORIZATION,httpMethod,rawQuery,rawBody,rawHeaderValues);
   binding(browserBinding);
   AtomicBoolean reported=new AtomicBoolean();
   return this.ledger.beginResult(()->OAuthServerAuthorizationAdmission.admit(request,this.clients,d,this.resources,this.limits,this.nativeLoopback,this.localhost,this.localhostAnyPort,
    ()->{if(reported.compareAndSet(false,true)) ObserverDispatch.dispatch(this.observer,OAuthServerObserver::didUseLocalhostAnyPortRedirects);}),browserBinding,d);
  },r->OAuthAuthorizationResult.fromRejection(r,rejection(OAuthServerRequest.Endpoint.AUTHORIZATION,r,false)));
 }
 /** Rechecks a continuation before rendering consent; this does not authenticate a user.
  * @param interactionValue secret continuation
  * @param browserBinding independent app-owned binding
  * @return checked restricted interaction or rejection
  * @since 1.0.0
  */
 @CheckReturnValue public @NonNull OAuthAuthorizationResult resumeAuthorizationResult(@NonNull String interactionValue,@NonNull String browserBinding) {
  requireNonNull(interactionValue); requireNonNull(browserBinding);
  return execute(AUTHORIZATION,d->{binding(interactionValue);binding(browserBinding);
   return interaction(interactionValue,browserBinding,selected(interactionValue,browserBinding,d),d);
  },r->OAuthAuthorizationResult.fromRejection(r,rejection(OAuthServerRequest.Endpoint.AUTHORIZATION,r,false)));
 }
 /** Completes app-protected consent once, with a fresh narrowing policy check before commit.
  * @param interactionValue secret continuation
  * @param browserBinding independent app-owned binding
  * @param decision trusted server-side app decision
  * @return retained committed redirect or rejection
  * @since 1.0.0
  */
 @CheckReturnValue public @NonNull OAuthAuthorizationResult completeAuthorizationResult(@NonNull String interactionValue,@NonNull String browserBinding,@NonNull OAuthAuthorizationDecision decision) {
  requireNonNull(interactionValue);requireNonNull(browserBinding);requireNonNull(decision);
  return execute(AUTHORIZATION,d->{binding(interactionValue);binding(browserBinding);
   return this.ledger.completeResult(interactionValue,browserBinding,()->selected(interactionValue,browserBinding,d),this.resources,decision,this.policy,this.authorizationEncoder,d);
  },r->OAuthAuthorizationResult.fromRejection(r,rejection(OAuthServerRequest.Endpoint.AUTHORIZATION,r,false)));
 }
 /** Handles one bounded token form request on its configured route.
  * @param httpMethod materialized method
  * @param rawQuery original query or absence
  * @param rawBody materialized body
  * @param rawHeaderValues original names and every occurrence
  * @return committed response or fixed local rejection
  * @since 1.0.0
  */
 @CheckReturnValue public @NonNull OAuthTokenResult tokenResult(@NonNull String httpMethod,@Nullable String rawQuery,
   byte @NonNull [] rawBody,@NonNull Map<@NonNull String,@NonNull List<@NonNull String>> rawHeaderValues) {
  inputs(httpMethod,rawBody,rawHeaderValues);
  boolean[] basic={false};
  return execute(TOKEN,d->{
   OAuthServerRequest request=parse(OAuthServerRequest.Endpoint.TOKEN,httpMethod,rawQuery,rawBody,rawHeaderValues);basic[0]=request.authorization()!=null;
   String grant=request.required("grant_type");
   OAuthTokenResponse response;
   if(grant.equals("authorization_code")) response=this.codes.redeem(request,this.clients,this.resources,this.policy,d);
   else if(grant.equals("refresh_token") && this.refresh) response=this.rotations.rotate(request,this.clients,this.resources,this.policy,d);
   else throw OAuthServerValidationException.fromReason(UNSUPPORTED_GRANT_TYPE);
   return OAuthTokenResult.fromSucceeded(response.response());
  },r->OAuthTokenResult.fromRejection(r,rejection(OAuthServerRequest.Endpoint.TOKEN,r,basic[0])));
 }
 /** Handles one bounded revocation form request on its configured route.
  * @param httpMethod materialized method
  * @param rawQuery original query or absence
  * @param rawBody materialized body
  * @param rawHeaderValues original names and every occurrence
  * @return committed response or fixed local rejection
  * @since 1.0.0
  */
 @CheckReturnValue public @NonNull OAuthRevocationResult revokeResult(@NonNull String httpMethod,@Nullable String rawQuery,
   byte @NonNull [] rawBody,@NonNull Map<@NonNull String,@NonNull List<@NonNull String>> rawHeaderValues) {
  inputs(httpMethod,rawBody,rawHeaderValues);
  if(this.revocationEndpoint==null) throw new IllegalStateException("The endpoint is disabled.");
  boolean[] basic={false};
  return execute(REVOCATION,d->{
   OAuthServerRequest request=parse(OAuthServerRequest.Endpoint.REVOCATION,httpMethod,rawQuery,rawBody,rawHeaderValues);basic[0]=request.authorization()!=null;
   return OAuthRevocationResult.fromSucceeded(this.revocation.revoke(request,this.clients,this.resources,this.keys,d).response());
  },r->OAuthRevocationResult.fromRejection(r,rejection(OAuthServerRequest.Endpoint.REVOCATION,r,basic[0])));
 }
 /** Handles one bounded introspection form request on its configured route.
  * @param httpMethod materialized method
  * @param rawQuery original query or absence
  * @param rawBody materialized body
  * @param rawHeaderValues original names and every occurrence
  * @return committed response or fixed local rejection
  * @since 1.0.0
  */
 @CheckReturnValue public @NonNull OAuthIntrospectionResult introspectionResult(@NonNull String httpMethod,@Nullable String rawQuery,
   byte @NonNull [] rawBody,@NonNull Map<@NonNull String,@NonNull List<@NonNull String>> rawHeaderValues) {
  inputs(httpMethod,rawBody,rawHeaderValues);
  if(this.introspectionEndpoint==null) throw new IllegalStateException("The endpoint is disabled.");
  boolean[] basic={false};
  return execute(INTROSPECTION,d->{
   OAuthServerRequest request=parse(OAuthServerRequest.Endpoint.INTROSPECTION,httpMethod,rawQuery,rawBody,rawHeaderValues);basic[0]=request.authorization()!=null;
   String resource=request.value("resource");
   if(resource==null) { if(this.resources.size()!=1) throw OAuthServerValidationException.fromReason(INVALID_RESOURCE); resource=this.resources.keySet().iterator().next(); }
   if(!this.resources.containsKey(resource)) throw OAuthServerValidationException.fromReason(INVALID_RESOURCE);
   return OAuthIntrospectionResult.fromSucceeded(this.introspection.introspect(request,this.repository,resource,this.keys,d).response());
  },r->OAuthIntrospectionResult.fromRejection(r,rejection(OAuthServerRequest.Endpoint.INTROSPECTION,r,basic[0])));
 }
 /** Validates local M5 signature/profile facts and uncached authoritative issuer status before proof release.
  * @param token unverified bearer credential
  * @param resource exact configured application resource
  * @return restricted checked proof or fixed rejection
  * @since 1.0.0
  */
 @CheckReturnValue public @NonNull OAuthIssuerAccessTokenResult validateAccessTokenResult(@NonNull BearerToken token,@NonNull String resource) {
  requireNonNull(token);OAuthServerConfiguration.resource(resource);
  if(!this.resources.containsKey(resource)) throw OAuthServerConfiguration.invalid();
  return execute(ACCESS_TOKEN_VALIDATION,d->{
   if(OidcTransactionAccess.get().bearerValue(token).length()>this.settings.maximumRequestBodyBytes) return OAuthIssuerAccessTokenResult.fromRejection(MALFORMED_REQUEST,null,null);
   StaticJwksSource snapshot=this.keys.recognitionKeys(d);
   com.revetsec.json.JsonObject claims;
   try{claims=this.status.recognizeForProof(OidcTransactionAccess.get().bearerValue(token),resource,snapshot,d);}
   catch(OAuthIssuerTokenStatus.RecognitionFailure rejected){return rejected.result();}
   return this.status.validateProof(claims,resource,d,session->{
    StaticJwksSource admittedKeys=this.keys.verificationKeys(d,session::authorityNow);
    Clock authorityClock=Clock.fixed(session.effectiveNow(),java.time.ZoneOffset.UTC);
    try {
     OAuthServerClientAdmission.remaining(d);
     JwtAccessTokenValidator validator=JwtAccessTokenValidator.withIssuer(this.issuer).jwksSource(admittedKeys).expectedAudiences(Set.of(resource))
      .allowedAlgorithms(Set.of(JwsAlgorithm.RS256)).clock(authorityClock).clockSkew(this.settings.clockSkew)
      .maximumTokenLength(Math.max(8192,this.settings.maximumRequestBodyBytes)).requestTimeout(Duration.ofSeconds(1)).totalDeadline(this.settings.totalDeadline).build();
     VerifiedAccessToken proof=OidcTransactionAccess.get().validateAccessToken(validator,token,d);
     return OAuthIssuerAccessTokenResult.fromSucceeded(proof);
    }catch(AccessTokenValidationException rejected){
     OAuthServerClientAdmission.remaining(d);
     return OAuthIssuerAccessTokenResult.fromRejection(TOKEN_REVOKED,rejected.getReason(),rejected.getJoseReason().orElse(null));
    }
   });
  },r->OAuthIssuerAccessTokenResult.fromRejection(r,null,null));
 }
 /** Revokes a trusted grant reference monotonically.
  * @param grantValue trusted management identity
  * @since 1.0.0
  */
 public void revokeGrant(@NonNull String grantValue) { OAuthStoreFormat.nonce(grantValue);
  execute(GRANT_REVOCATION,d->{this.revocation.revokeGrant(grantValue,d);return Boolean.TRUE;},r->{throw OAuthServerValidationException.fromReason(r);});
 }
 /** Advances an established subject fence; UNKNOWN requires reconciliation.
  * @param subject trusted management identity
  * @since 1.0.0
  */
 public void revokeSubject(@NonNull String subject) { OAuthServerConfiguration.text(subject,this.settings.maximumSubjectLength);
  execute(SUBJECT_REVOCATION,d->{this.coordinator.revokeSubject(subject,d);return Boolean.TRUE;},r->{throw OAuthServerValidationException.fromReason(r);});
 }
 /** Advances the established issuer fence; UNKNOWN requires reconciliation.
  * @since 1.0.0
  */
 public void revokeAllGrants() { 
  execute(ISSUER_REVOCATION,d->{this.coordinator.revokeAll(d);return Boolean.TRUE;},r->{throw OAuthServerValidationException.fromReason(r);});
 }
 /** Explicitly registers a never-used subject; never use this to repair lost permanent fences.
  * @param subject trusted management identity
  * @since 1.0.0
  */
 public void establishNewSubject(@NonNull String subject) { OAuthServerConfiguration.text(subject,this.settings.maximumSubjectLength);
  execute(SUBJECT_REGISTRATION,d->{this.coordinator.establishNewSubject(subject,d);return Boolean.TRUE;},r->{throw OAuthServerValidationException.fromReason(r);});
 }
 /** Explicitly initializes a namespace the operator knows has never been used or restored.
  * Existing state yields CONFLICT. UNKNOWN never means ready; reconcile before traffic or retry.
  * @return one authoritative initialization outcome
  * @since 1.0.0
  */
 @CheckReturnValue public @NonNull OAuthStoreCommitReceipt initializeFreshIssuer() {
  return execute(ISSUER_INITIALIZATION,this.coordinator::initializeFreshIssuerResult,r->{throw OAuthServerValidationException.fromReason(r);});
 }
 /** Attempts one authenticated reseal CAS without changing grant authority or retention.
  * @param key privileged namespace-bound maintenance key
  * @return COMMITTED, CONFLICT for absence/race/expired row, or UNKNOWN requiring reconciliation
  * @since 1.0.0
  */
 @CheckReturnValue public @NonNull OAuthStoreCommitReceipt resealStoreEntry(@NonNull OAuthStoreKey key) {
  requireNonNull(key);
  return execute(STORE_RESEAL,d->this.coordinator.reseal(key,d),r->{throw OAuthServerValidationException.fromReason(r);});
 }
 /** Prepares bounded public metadata for GET or HEAD.
  * @param httpMethod exact method
  * @return safe public response, including method rejection
  * @throws OAuthServerConfigurationException if the configured representation exceeds publication capacity
  * @since 1.0.0
  */
 @CheckReturnValue public @NonNull OAuthServerResponse metadataResponse(@NonNull String httpMethod) {
  requireNonNull(httpMethod);
  return execute(METADATA,d->this.metadata.metadata(httpMethod,d).response(),r->{throw OAuthServerValidationException.fromReason(r);});
 }
 /** Prepares bounded public json web key set for GET or HEAD.
  * @param httpMethod exact method
  * @return safe public response, including method rejection
  * @throws OAuthServerConfigurationException if the configured representation exceeds publication capacity
  * @since 1.0.0
  */
 @CheckReturnValue public @NonNull OAuthServerResponse jwksResponse(@NonNull String httpMethod) {
  requireNonNull(httpMethod);
  return execute(JWKS,d->this.metadata.jwks(httpMethod,this.keys,d).response(),r->{throw OAuthServerValidationException.fromReason(r);});
 }
 /** Translates a caught infrastructure exception to a fixed, bounded local503 response.
  * @param failure restricted issuer failure
  * @return safe response with no redirect or reflected descriptions
  * @since 1.0.0
  */
 @CheckReturnValue public @NonNull OAuthServerResponse responseForFailure(@NonNull OAuthServerException failure) {
  return OAuthServerFailureBoundary.failure(failure,this.settings.maximumResponseBodyBytes,this.settings.maximumHeaderBytes);
 }
 /** Checks configured signing keys and the established issuer fence on one shrinking caller budget.
  * Never initializes missing state or fetches arbitrary client metadata.
  * @since 1.0.0
  */
 public void warmUp() {
  try { Deadline d=Deadline.fromNow(this.settings.totalDeadline);
   for(int n=0;n<this.settings.maximumStoreCommitAttempts;n++){
    OAuthStoreCoordinator.Session session=this.coordinator.begin(d);this.keys.warmUp(d,session::authorityNow);
    if(session.barrier()==OAuthStoreCommitStatus.COMMITTED)return;
   }
   throw OAuthServerStoreException.fromReason(STORE_UNAVAILABLE,false);
  } catch(OAuthStoreFailure f) {throw OAuthServerFailureBoundary.store(f);}
  catch(OAuthServerAdmissionFailure f) {throw OAuthServerFailureBoundary.admission(f);}
 }
 /** Returns configured Issuer.
  * @return exact setting or optional absence
  * @since 1.0.0
  */
 @CheckReturnValue public @NonNull String getIssuer() {return this.issuer;}
 /** Returns configured AuthorizationEndpoint.
  * @return exact setting or optional absence
  * @since 1.0.0
  */
 @CheckReturnValue public @NonNull URI getAuthorizationEndpoint() {return this.authorizationEndpoint;}
 /** Returns configured TokenEndpoint.
  * @return exact setting or optional absence
  * @since 1.0.0
  */
 @CheckReturnValue public @NonNull URI getTokenEndpoint() {return this.tokenEndpoint;}
 /** Returns configured JwksEndpoint.
  * @return exact setting or optional absence
  * @since 1.0.0
  */
 @CheckReturnValue public @NonNull URI getJwksEndpoint() {return this.jwksEndpoint;}
 /** Returns configured RevocationEndpoint.
  * @return exact setting or optional absence
  * @since 1.0.0
  */
 @CheckReturnValue public @NonNull Optional<@NonNull URI> getRevocationEndpoint() {return Optional.ofNullable(this.revocationEndpoint);}
 /** Returns configured IntrospectionEndpoint.
  * @return exact setting or optional absence
  * @since 1.0.0
  */
 @CheckReturnValue public @NonNull Optional<@NonNull URI> getIntrospectionEndpoint() {return Optional.ofNullable(this.introspectionEndpoint);}
 /** Returns a fixed description without configuration or credentials.
  * @return redacted description
  * @since 1.0.0
  */
 @Override public @NonNull String toString() {return "OAuthAuthorizationServer{<redacted>}";}
 private OAuthServerClientSelection.@NonNull Selected selected(@NonNull String interaction,@NonNull String browser,@NonNull Deadline d) {
  return this.clients.authorization(this.ledger.clientId(interaction,browser,d),this.resources,d);
 }
 private @NonNull OAuthAuthorizationResult interaction(@NonNull String handle,@NonNull String browser,OAuthServerClientSelection.@NonNull Selected selected,@NonNull Deadline d) {
  OAuthAuthorizationRecord record=this.ledger.resume(handle,browser,selected,d);
  return OAuthAuthorizationResult.fromInteractionRequired(OAuthServerInteraction.fromRecord(handle,record,selected.client().getClientName().orElse(null),this.limits));
 }
 private static void binding(@NonNull String value) {
  try {OAuthAuthorizationRecord.credentialDigest(value);} catch(IllegalArgumentException f) {throw OAuthServerValidationException.fromReason(MALFORMED_REQUEST);}
 }
 private static void inputs(@NonNull String method,byte @NonNull [] body,@NonNull Map<@NonNull String,@NonNull List<@NonNull String>> headers) {
  requireNonNull(method);requireNonNull(body);requireNonNull(headers);
 }
 private @NonNull OAuthServerRequest parse(OAuthServerRequest.@NonNull Endpoint endpoint,@NonNull String method,@Nullable String query,
   byte @NonNull [] body,@NonNull Map<@NonNull String,@NonNull List<@NonNull String>> headers) {
  return OAuthServerRequest.parseForServer(endpoint,method,query,body,headers,this.limits);
 }
 private @NonNull OAuthServerResponse rejection(OAuthServerRequest.@NonNull Endpoint endpoint,OAuthServerException.@NonNull Reason reason,boolean basic) {
  return OAuthServerFailureBoundary.rejection(endpoint,reason,basic,this.settings.maximumResponseBodyBytes,this.settings.maximumHeaderBytes);
 }
 private <T> @NonNull T execute(OAuthServerObserver.@NonNull Endpoint endpoint,@NonNull Function<@NonNull Deadline,@NonNull T> work,
   @NonNull Function<OAuthServerException.@NonNull Reason,@NonNull T> reject) {
  Deadline d=Deadline.fromNow(this.settings.totalDeadline);OAuthServerObservation observation=new OAuthServerObservation(this.observer,endpoint);
  T result;
  try (OAuthStoreCoordinator.Operation scope=this.coordinator.operation(d)) {
  try {result=work.apply(d);}
  catch(OAuthTransportException f) {rethrowEffect(scope,observation,false);OAuthServerException translated=OAuthServerStoreException.fromReason(STORE_UNAVAILABLE,true);observation.failed(translated);throw translated;}
  catch(OAuthStoreFailure f) {rethrowEffect(scope,observation,false);OAuthServerException translated=OAuthServerFailureBoundary.store(f);observation.failed(translated);throw translated;}
  catch(OAuthServerAdmissionFailure f) {
   OAuthServerException translated=OAuthServerFailureBoundary.admission(f);
   rethrowEffect(scope,observation,translated instanceof OAuthServerValidationException);
   if(translated instanceof OAuthServerValidationException) result=rejectionResult(reject,translated.getReason(),observation);
   else {observation.failed(translated);throw translated;}
  }
  catch(OAuthServerValidationException rejected) {rethrowEffect(scope,observation,true);result=rejectionResult(reject,rejected.getReason(),observation);}
  catch(OAuthServerException f) {rethrowEffect(scope,observation,false);observation.failed(f);throw f;}
  catch(IllegalArgumentException f) {rethrowEffect(scope,observation,true);result=rejectionResult(reject,MALFORMED_REQUEST,observation);}
  try{scope.release();}catch(OAuthStoreFailure failure){OAuthServerException translated=OAuthServerFailureBoundary.store(failure);observation.failed(translated);throw translated;}
  OAuthServerException.Reason rejected=reason(result);Integer statusCode=statusCode(result);
  if(rejected==null) observation.succeeded(statusCode);else observation.rejected(rejected,statusCode);
  try{scope.release();}catch(OAuthStoreFailure failure){throw OAuthServerFailureBoundary.store(failure);}
  return result;
  }
 }
 /** Throwing rejection adapters are non-HTTP management paths; finish before their fixed exception escapes. */
 private static <T> @NonNull T rejectionResult(@NonNull Function<OAuthServerException.@NonNull Reason,@NonNull T> reject,
   OAuthServerException.@NonNull Reason reason,@NonNull OAuthServerObservation observation){
  try{return reject.apply(reason);}
  catch(OAuthServerValidationException rejected){observation.rejected(rejected.getReason(),null);throw rejected;}
 }
 private static void rethrowEffect(OAuthStoreCoordinator.@NonNull Operation scope,@NonNull OAuthServerObservation observation,boolean rejection){
  try{if(rejection)scope.rethrowRejectionEffect();else scope.rethrowEffect();}
  catch(OAuthStoreFailure failure){OAuthServerException translated=OAuthServerFailureBoundary.store(failure);observation.failed(translated);throw translated;}
 }
 private static OAuthServerException.@Nullable Reason reason(@NonNull Object result) {
  if(result instanceof OAuthAuthorizationResult.Rejected r) return r.getReason();
  if(result instanceof OAuthAuthorizationResult.Denied) return ACCESS_DENIED;
  if(result instanceof OAuthTokenResult.Rejected r) return r.getReason();
  if(result instanceof OAuthRevocationResult.Rejected r) return r.getReason();
  if(result instanceof OAuthIntrospectionResult.Rejected r) return r.getReason();
  if(result instanceof OAuthIssuerAccessTokenResult.Rejected r) return r.getReason();
  if(result instanceof OAuthServerResponse r && r.getStatusCode()==405) return METHOD_NOT_ALLOWED;
  return null;
 }
 private static @Nullable Integer statusCode(@NonNull Object result) {
  if(result instanceof OAuthAuthorizationResult.InteractionRequired) return 200;
  if(result instanceof OAuthAuthorizationResult.Completed r) return r.getResponse().getStatusCode();
  if(result instanceof OAuthAuthorizationResult.Denied r) return r.getResponse().getStatusCode();
  if(result instanceof OAuthAuthorizationResult.Rejected r) return r.getResponse().getStatusCode();
  if(result instanceof OAuthTokenResult.Succeeded r) return r.getResponse().getStatusCode();
  if(result instanceof OAuthTokenResult.Rejected r) return r.getResponse().getStatusCode();
  if(result instanceof OAuthRevocationResult.Succeeded r) return r.getResponse().getStatusCode();
  if(result instanceof OAuthRevocationResult.Rejected r) return r.getResponse().getStatusCode();
  if(result instanceof OAuthIntrospectionResult.Succeeded r) return r.getResponse().getStatusCode();
  if(result instanceof OAuthIntrospectionResult.Rejected r) return r.getResponse().getStatusCode();
  if(result instanceof OAuthServerResponse r) return r.getStatusCode();
  return null;
 }
 private static <T> @NonNull T required(@Nullable T value) {
  if(value==null) throw new IllegalStateException("Required authorization-server configuration is absent.");return value;
 }
 private static @NonNull URI endpoint(@NonNull URI uri,boolean insecure) {
  OAuthServerConfiguration.text(uri.toString(),2048);
  boolean loopback="http".equalsIgnoreCase(uri.getScheme()) && ("127.0.0.1".equals(uri.getHost()) || "[::1]".equals(uri.getHost()));
  if(uri.isOpaque() || uri.getHost()==null || uri.getRawUserInfo()!=null || uri.getRawQuery()!=null || uri.getRawFragment()!=null
    || uri.getPort()==0 || uri.getPort()>65535 || !("https".equalsIgnoreCase(uri.getScheme()) || insecure && loopback)) throw OAuthServerConfiguration.invalid();
  return uri;
 }
 private static void checkRoute(@NonNull URI issuer,@NonNull URI route,boolean insecure,@NonNull Set<@NonNull String> routes) {
  endpoint(route,insecure);
  if(!issuer.getScheme().equalsIgnoreCase(route.getScheme()) || !issuer.getRawAuthority().equals(route.getRawAuthority())
    || !routes.add(route.toString())) throw OAuthServerConfiguration.invalid();
 }
 /**
  * Mutable, non-thread-safe issuer configuration. Keep the builder on one configuring thread; each
  * {@link #build()} snapshots its values so later setters do not change an already-built server.
  * Application collaborators remain retained references and must satisfy their thread-safety, budget
  * and lifetime contracts; the server does not copy or close them.
  * <p>
  * Required configuration has no inferred defaults: authorization, token and JWKS routes, client
  * repository, authoritative store, signing-key provider, state sealer, grant policy and resource map.
  * Null clears those required values. Revocation and introspection routes default absent; refresh
  * defaults off and requires a revocation route when enabled. Collection setters replace complete
  * values; {@link #resources(Map)} snapshots the map and its scope sets rather than merging them.
  * <p>
  * Numeric setters accept a nullable value and defer bounds to build. In addition to each documented
  * inclusive interval, code lifetime must not exceed interaction lifetime; with refresh enabled,
  * access lifetime must not exceed idle lifetime, which must not exceed absolute lifetime. Skew must
  * not exceed half the access lifetime, request timeout must not exceed total deadline, and the sealed
  * record cap must fit the sealer. Resource counts and scope limits are checked against the copied map.
  * <p>
  * Configuration and construction do not call the repository, store, signing-key provider, grant policy
  * or address resolver, sample the worker clock, perform network I/O/signing, or start owned threads.
  * The explicit construction-time observer exception is
  * {@link OAuthServerObserver#didEnableLocalhostAnyPortRedirects()} when that option is enabled.
  * Build neither initializes persistence nor opens serving/recovery admission. The application owns
  * trusted startup time, durable store qualification, keys, user authentication, consent, sessions/CSRF
  * and HTTP routing. Construction success does not qualify that deployment.
  * @since 1.0.0
  */
 @NotThreadSafe @CheckReturnValue
 public static final class Builder {
  private final @NonNull String issuer;
  private @Nullable URI authorizationEndpoint,tokenEndpoint,jwksEndpoint,revocationEndpoint,introspectionEndpoint;
  private @Nullable OAuthServerClientRepository clientRepository;
  private @Nullable OAuthAuthorizationServerStore store;
  private @Nullable OAuthIssuerKeyProvider signingKeys;
  private @Nullable StateSealer stateSealer;
  private @Nullable OAuthGrantPolicy grantPolicy;
  private @Nullable Map<@NonNull String,@NonNull Set<@NonNull String>> resources;
  private @NonNull OAuthClientMetadataPolicy clientMetadataPolicy=OAuthClientMetadataPolicy.disabledInstance();
  private @NonNull Clock clock=Clock.systemUTC();
  private @NonNull OutboundUriPolicy outboundUriPolicy=OutboundUriPolicy.publicAddressesOnlyInstance();
  private @NonNull OAuthServerObserver observer=OAuthServerObserver.disabledInstance();
  private boolean refreshTokensEnabled,allowInsecureLoopback,allowNativeLoopbackRedirects,allowLocalhostRedirects,allowLocalhostAnyPortRedirects,acknowledgeUnpatchedRuntime;
  private final OAuthServerSettings.@NonNull Builder settings=OAuthServerSettings.builder();
  private Builder(@NonNull String issuer) {this.issuer=endpoint(URI.create(requireNonNull(issuer)),true).toString();}
  /**
   * Sets the required browser authorization route; there is no default.
   * Null clears the required route, so the next build fails until it is supplied again.
   * The route must use the issuer's scheme and exact raw authority, be distinct from every other configured
   * route, and contain no user info, query or fragment. It is not inferred from the issuer or request headers.
   * These checks run at {@link #build()}; the application owns HTTP routing and TLS termination.
   * @param value the exact absolute endpoint URI, or null to clear it
   * @return this builder
   * @since 1.0.0
   */
  @CheckReturnValue public @NonNull Builder authorizationEndpoint(@Nullable URI value) {this.authorizationEndpoint=value;return this;}
  /**
   * Sets the required code-exchange and refresh token route; there is no default.
   * Null clears the required route, so the next build fails until it is supplied again.
   * The route must use the issuer's scheme and exact raw authority, be distinct from every other configured
   * route, and contain no user info, query or fragment. It is not inferred from the issuer or request headers.
   * These checks run at {@link #build()}; the application owns HTTP routing and TLS termination.
   * @param value the exact absolute endpoint URI, or null to clear it
   * @return this builder
   * @since 1.0.0
   */
  @CheckReturnValue public @NonNull Builder tokenEndpoint(@Nullable URI value) {this.tokenEndpoint=value;return this;}
  /**
   * Sets the required public verification-key publication route; there is no default.
   * Null clears the required route, so the next build fails until it is supplied again.
   * The route must use the issuer's scheme and exact raw authority, be distinct from every other configured
   * route, and contain no user info, query or fragment. It is not inferred from the issuer or request headers.
   * These checks run at {@link #build()}; the application owns HTTP routing and TLS termination.
   * @param value the exact absolute endpoint URI, or null to clear it
   * @return this builder
   * @since 1.0.0
   */
  @CheckReturnValue public @NonNull Builder jwksEndpoint(@Nullable URI value) {this.jwksEndpoint=value;return this;}
  /**
   * Sets the optional token-revocation route; the default and null mean absent.
   * A route is required when {@link #refreshTokensEnabled(Boolean)} is true. Without it, revocation is
   * not advertised and the public revocation operation is unavailable; null does not select another route.
   * The route must use the issuer's scheme and exact raw authority, be distinct from every other configured
   * route, and contain no user info, query or fragment. It is not inferred from the issuer or request headers.
   * These checks run at {@link #build()}; the application owns HTTP routing and TLS termination.
   * @param value the exact absolute revocation URI, or null for no route
   * @return this builder
   * @since 1.0.0
   */
  @CheckReturnValue public @NonNull Builder revocationEndpoint(@Nullable URI value) {this.revocationEndpoint=value;return this;}
  /**
   * Sets the optional resource-only introspection route; the default and null mean absent.
   * Without it, introspection is not advertised and the public introspection operation is unavailable.
   * The route must use the issuer's scheme and exact raw authority, be distinct from every other configured
   * route, and contain no user info, query or fragment. It is not inferred from the issuer or request headers.
   * These checks run at {@link #build()}; the application owns HTTP routing and TLS termination.
   * @param value the exact absolute introspection URI, or null for no route
   * @return this builder
   * @since 1.0.0
   */
  @CheckReturnValue public @NonNull Builder introspectionEndpoint(@Nullable URI value) {this.introspectionEndpoint=value;return this;}
  /**
   * Sets the required application-owned registered-client lookup; there is no default.
   * Null clears it and makes the next build fail. The reference is retained, not copied or called during
   * construction. It must be thread-safe and honor each operation's remaining cooperative budget.
   * Exact registrations are consulted before opt-in client-ID metadata; a backend failure must not be
   * reported as an unknown client. See {@link OAuthServerClientRepository}.
   * @param value the registered-client repository, or null to clear it
   * @return this builder
   * @since 1.0.0
   */
  @CheckReturnValue public @NonNull Builder clientRepository(@Nullable OAuthServerClientRepository value) {this.clientRepository=value;return this;}
  /**
   * Sets the required application-owned authoritative store; there is no default.
   * Null clears it and makes the next build fail. The reference is retained without reading, writing or
   * initializing a namespace during construction. The implementation must supply the coherent admitted
   * time, atomic exact predicates, durability, recovery admission and permanent/replay retention required
   * by {@link OAuthAuthorizationServerStore}; this setter supplies none of those deployment guarantees.
   * @param value the authoritative issuer store, or null to clear it
   * @return this builder
   * @since 1.0.0
   */
  @CheckReturnValue public @NonNull Builder store(@Nullable OAuthAuthorizationServerStore value) {this.store=value;return this;}
  /**
   * Sets the required application-owned signing-key snapshot provider; there is no default.
   * Null clears it and makes the next build fail. Construction retains the provider without invoking it,
   * looking up keys or signing. Operations require coherent lifecycle snapshots and the issuer's RS256
   * profile. The application owns private-key protection, publication, rollover and retirement; changing
   * the provider reference is not a key-migration or retention procedure. See {@link OAuthIssuerKeyProvider}.
   * @param value the signing-key provider, or null to clear it
   * @return this builder
   * @since 1.0.0
   */
  @CheckReturnValue public @NonNull Builder signingKeys(@Nullable OAuthIssuerKeyProvider value) {this.signingKeys=value;return this;}
  /**
   * Sets the required application-owned state sealer; there is no default.
   * Null clears it and makes the next build fail. The immutable sealer reference is retained. At build,
   * {@link #maximumStoreRecordBytes(Integer)} must not exceed its configured maximum sealed length.
   * Sealing keys, old-key retention and coordinated rotation across writers remain application-owned;
   * replacing the sealer does not migrate stored records or repair missing fences.
   * @param value the configured state sealer, or null to clear it
   * @return this builder
   * @since 1.0.0
   */
  @CheckReturnValue public @NonNull Builder stateSealer(@Nullable StateSealer value) {this.stateSealer=value;return this;}
  /**
   * Sets the required application-owned continuing authorization policy; there is no default.
   * Null clears it and makes the next build fail. Construction retains the thread-safe callback without
   * invoking it. Approval, code exchange and refresh recheck current permissions under the remaining
   * cooperative budget. A decision can deny or narrow authority; it cannot replace application login,
   * session/CSRF protection or consent. See {@link OAuthGrantPolicy}.
   * @param value the continuing grant policy, or null to clear it
   * @return this builder
   * @since 1.0.0
   */
  @CheckReturnValue public @NonNull Builder grantPolicy(@Nullable OAuthGrantPolicy value) {this.grantPolicy=value;return this;}
  /**
   * Replaces the required complete map of exact resource identifiers to allowed scope sets.
   * There is no default; null clears the required map. Non-null maps and their scope sets are validated
   * and defensively copied when set, rather than merged or retained. Resource identifiers are absolute,
   * fragment-free URI spellings compared exactly and never fetched. The map must be nonempty; an empty
   * scope set grants no authority. Carrier/aggregate ceilings are checked here; the selected
   * {@link #maximumResources(Integer)}, {@link #maximumScopesPerResource(Integer)} and
   * {@link #maximumScopeLength(Integer)} are checked at build. Per-client and grant policy can only narrow
   * this configuration.
   * @param value the complete resource/scope map, or null to clear it
   * @return this builder
   * @throws IllegalArgumentException if the non-null replacement violates resource/scope carrier limits
   * @throws NullPointerException if a non-null map contains a null key, scope set or scope
   * @since 1.0.0
   */
  @CheckReturnValue public @NonNull Builder resources(@Nullable Map<@NonNull String,@NonNull Set<@NonNull String>> value) {this.resources=value==null ? null : OAuthServerConfiguration.resources(value,1024);return this;}
  /**
   * Selects opt-in client-ID metadata document (CIMD) policy.
   * The default and null are {@link OAuthClientMetadataPolicy#disabledInstance()}; null disables CIMD,
   * not registered clients. An enabled immutable policy retains its application resolver and explicit
   * cache selection. Construction performs no resolution, cache access or HTTP fetch. Enabled CIMD
   * requires the runtime floor described by {@link #acknowledgeUnpatchedRuntime(Boolean)} and uses
   * {@link #outboundUriPolicy(OutboundUriPolicy)}. Cache reuse is not authoritative credential storage
   * or shared-deployment qualification. Exact registered clients still take precedence.
   * @param value the complete metadata policy, or null to disable CIMD
   * @return this builder
   * @since 1.0.0
   */
  @CheckReturnValue public @NonNull Builder clientMetadataPolicy(@Nullable OAuthClientMetadataPolicy value) {this.clientMetadataPolicy=value==null ? OAuthClientMetadataPolicy.disabledInstance() : value;return this;}
  /**
   * Sets the worker wall clock; the default and null select {@link Clock#systemUTC()}.
   * The reference is retained without sampling it during construction. Operations use it for worker
   * health checks, provisional key-lifecycle preparation and optional metadata-cache freshness. Timed
   * authoritative state transitions use admitted store time and authenticated floors, not this clock as
   * a fallback. Changing this clock neither establishes trusted startup time nor resets durable floors.
   * @param value the application worker clock, or null to restore the system UTC clock
   * @return this builder
   * @since 1.0.0
   */
  @CheckReturnValue public @NonNull Builder clock(@Nullable Clock value) {this.clock=value==null ? Clock.systemUTC() : value;return this;}
  /**
   * Selects the immutable outbound URI policy for opt-in CIMD address admission.
   * The default and null select {@link OutboundUriPolicy#publicAddressesOnlyInstance()}. This is a
   * restriction on approved metadata requests, not permission to fetch arbitrary client URLs. The pinned
   * transport still enforces its address, redirect and TLS/hostname rules. This setting does not change
   * issuer endpoint authority or any of the separate redirect/loopback options.
   * @param value the outbound metadata URI policy, or null to restore the public-address policy
   * @return this builder
   * @since 1.0.0
   */
  @CheckReturnValue public @NonNull Builder outboundUriPolicy(@Nullable OutboundUriPolicy value) {this.outboundUriPolicy=value==null ? OutboundUriPolicy.publicAddressesOnlyInstance() : value;return this;}
  /**
   * Sets the application-owned synchronous issuer observer.
   * The default and null select {@link OAuthServerObserver#disabledInstance()}. The reference is retained;
   * hooks must be fast and thread-safe and follow the interface's failure-containment contract. Successful
   * construction with {@link #allowLocalhostAnyPortRedirects(Boolean)} enabled calls
   * {@link OAuthServerObserver#didEnableLocalhostAnyPortRedirects()}; construction otherwise performs no
   * issuer observer notification. This interface has no runtime-acknowledgment hook, and operation success
   * events are checkpoints rather than credential-delivery receipts.
   * @param value the issuer observer, or null to restore the disabled observer
   * @return this builder
   * @since 1.0.0
   */
  @CheckReturnValue public @NonNull Builder observer(@Nullable OAuthServerObserver value) {this.observer=value==null ? OAuthServerObserver.disabledInstance() : value;return this;}
  /**
   * Enables server-side refresh-token issuance and rotation; the default is false.
   * False or null disables refresh. Enabling it requires a configured {@link #revocationEndpoint(URI)}
   * at build and per-client and current grant-policy refresh permission at operation time. It does not
   * override either permission or extend an existing family's pinned lifetime. With refresh enabled,
   * access lifetime must not exceed refresh idle lifetime, which must not exceed refresh absolute lifetime.
   * @param value true to enable refresh; false or null to disable it
   * @return this builder
   * @since 1.0.0
   */
  @CheckReturnValue public @NonNull Builder refreshTokensEnabled(@Nullable Boolean value) {this.refreshTokensEnabled=Boolean.TRUE.equals(value);return this;}
  /**
   * Permits a numeric HTTP loopback issuer and its same-authority server routes for local development.
   * The default is false; false or null restores HTTPS-only issuer routes. The HTTP host must be exactly
   * {@code 127.0.0.1} or {@code [::1]}, not {@code localhost}. This option neither admits client redirects
   * nor enables the other loopback options, and it does not weaken CIMD transport or token validation.
   * @param value true to allow numeric HTTP loopback issuer routes; false or null to disable
   * @return this builder
   * @since 1.0.0
   */
  @CheckReturnValue public @NonNull Builder allowInsecureLoopback(@Nullable Boolean value) {this.allowInsecureLoopback=Boolean.TRUE.equals(value);return this;}
  /**
   * Enables HTTP IP-loopback client redirects with the native port exception; the default is false.
   * False or null disables the exception. Literal {@code 127.0.0.1} or {@code [::1]} redirects may vary
   * the port while retaining the other checked components; code redemption must use the actual admitted
   * redirect. CIMD uses this explicit policy regardless of its {@code application_type} declaration.
   * It does not enable HTTP issuer routes or localhost redirects; see
   * {@link #allowInsecureLoopback(Boolean)}, {@link #allowLocalhostRedirects(Boolean)} and
   * {@link #allowLocalhostAnyPortRedirects(Boolean)}.
   * @param value true to enable the IP-loopback redirect port exception; false or null to disable
   * @return this builder
   * @since 1.0.0
   */
  @CheckReturnValue public @NonNull Builder allowNativeLoopbackRedirects(@Nullable Boolean value) {this.allowNativeLoopbackRedirects=Boolean.TRUE.equals(value);return this;}
  /**
   * Enables exact HTTP localhost client redirects; the default is false.
   * False or null disables this profile. Every component, including the configured port spelling, stays
   * exact. This does not enable numeric-loopback redirects, an HTTP issuer, or port-less any-port matching;
   * the latter requires {@link #allowLocalhostAnyPortRedirects(Boolean)} separately.
   * @param value true to enable exact HTTP localhost redirects; false or null to disable
   * @return this builder
   * @since 1.0.0
   */
  @CheckReturnValue public @NonNull Builder allowLocalhostRedirects(@Nullable Boolean value) {this.allowLocalhostRedirects=Boolean.TRUE.equals(value);return this;}
  /**
   * Enables any-port matching for port-less HTTP localhost client registrations; the default is false.
   * False or null disables it. The registered authority must be exactly {@code localhost}; scheme, host,
   * raw path and query stay exact. Fixed-port registrations still require
   * {@link #allowLocalhostRedirects(Boolean)} and remain exact. No other loopback option is implied.
   * Code redemption requires the actual admitted redirect. A successful build emits
   * {@link OAuthServerObserver#didEnableLocalhostAnyPortRedirects()}, and an authorization operation that
   * relies on this exception emits {@link OAuthServerObserver#didUseLocalhostAnyPortRedirects()} even if
   * a later check rejects it. Exact matches under the separate exact-localhost profile do not use it.
   * @param value true to enable port-less localhost any-port matching; false or null to disable
   * @return this builder
   * @since 1.0.0
   */
  @CheckReturnValue public @NonNull Builder allowLocalhostAnyPortRedirects(@Nullable Boolean value) {this.allowLocalhostAnyPortRedirects=Boolean.TRUE.equals(value);return this;}
  /**
   * Acknowledges the runtime TLS risk when opt-in CIMD requires network access; the default is false.
   * False or null restores refusal on runtimes below 17.0.3 on Java 17 or 18.0.1 on Java 18. The guard is
   * checked at build only when {@link #clientMetadataPolicy(OAuthClientMetadataPolicy)} enables CIMD;
   * Java 19 and later pass this guard. The flag does not patch TLS or alter signature, claim, address or
   * peer-verification policy. The issuer observer has no acknowledgment event. With CIMD disabled it has
   * no runtime-floor effect on issuer construction.
   * @param value true to accept the runtime risk for CIMD; false or null to restore refusal
   * @return this builder
   * @since 1.0.0
   */
  @CheckReturnValue public @NonNull Builder acknowledgeUnpatchedRuntime(@Nullable Boolean value) {this.acknowledgeUnpatchedRuntime=Boolean.TRUE.equals(value);return this;}
  /**
   * Sets the maximum lifetime of a browser-bound authorization interaction.
   * Default: 15 minutes; inclusive range: 1 minute through 1 hour. Null restores the default.
   * Bounds and combined constraints are checked by {@link #build()}, not by this setter.
   * Authorization-code lifetime must not exceed this lifetime.
   * @param value the setting in duration units, or null to restore the default
   * @return this builder
   * @since 1.0.0
   */
  @CheckReturnValue public @NonNull Builder authorizationInteractionLifetime(@Nullable Duration value) {this.settings.authorizationInteractionLifetime(value);return this;}
  /**
   * Sets the lifetime of a one-use authorization code.
   * Default: 2 minutes; inclusive range: 30 seconds through 10 minutes. Null restores the default.
   * Bounds and combined constraints are checked by {@link #build()}, not by this setter.
   * Must not exceed {@link #authorizationInteractionLifetime(Duration)}; a longer code policy does not revive an expired or consumed code.
   * @param value the setting in duration units, or null to restore the default
   * @return this builder
   * @since 1.0.0
   */
  @CheckReturnValue public @NonNull Builder authorizationCodeLifetime(@Nullable Duration value) {this.settings.authorizationCodeLifetime(value);return this;}
  /**
   * Sets the maximum issued access-token lifetime.
   * Default: 5 minutes; inclusive range: 30 seconds through 15 minutes. Null restores the default.
   * Bounds and combined constraints are checked by {@link #build()}, not by this setter.
   * With refresh enabled, must not exceed refresh idle lifetime; clock skew must not exceed half this value. Existing families keep their pinned maximum. Raising this value beyond a family pin causes its next refresh to revoke it rather than enlarge the pin.
   * @param value the setting in duration units, or null to restore the default
   * @return this builder
   * @since 1.0.0
   */
  @CheckReturnValue public @NonNull Builder accessTokenLifetime(@Nullable Duration value) {this.settings.accessTokenLifetime(value);return this;}
  /**
   * Sets the refresh-family idle lifetime used for initial issuance and rotation.
   * Default: 24 hours; inclusive range: 5 minutes through 7 days. Null restores the default.
   * Bounds and combined constraints are checked by {@link #build()}, not by this setter.
   * When refresh is enabled, access lifetime must not exceed this value, which must not exceed refresh absolute lifetime. Existing families retain their original idle-lifetime pin; increasing this setting does not extend it.
   * @param value the setting in duration units, or null to restore the default
   * @return this builder
   * @since 1.0.0
   */
  @CheckReturnValue public @NonNull Builder refreshTokenIdleLifetime(@Nullable Duration value) {this.settings.refreshTokenIdleLifetime(value);return this;}
  /**
   * Sets the refresh-family absolute lifetime at initial issuance.
   * Default: 7 days; inclusive range: 1 hour through 30 days. Null restores the default.
   * Bounds and combined constraints are checked by {@link #build()}, not by this setter.
   * With refresh enabled, must be at least refresh idle lifetime. Rotation does not reset the original family absolute expiry, and later configuration does not extend it.
   * @param value the setting in duration units, or null to restore the default
   * @return this builder
   * @since 1.0.0
   */
  @CheckReturnValue public @NonNull Builder refreshTokenAbsoluteLifetime(@Nullable Duration value) {this.settings.refreshTokenAbsoluteLifetime(value);return this;}
  /**
   * Sets issuer JWT-validation skew and its contribution to physical retention.
   * Default: 30 seconds; inclusive range: zero through 60 seconds. Null restores the default.
   * Bounds and combined constraints are checked by {@link #build()}, not by this setter.
   * Must not exceed half the access-token lifetime. This does not reserve durable clock time or advance entity floors; authoritative temporal predicates use admitted store time. Together with total deadline and public metadata cache age it contributes to retained grant horizons. A combined policy beyond a stored family horizon causes its next refresh to revoke it; coordinate revocation and new authorization across nodes.
   * @param value the setting in duration units, or null to restore the default
   * @return this builder
   * @since 1.0.0
   */
  @CheckReturnValue public @NonNull Builder clockSkew(@Nullable Duration value) {this.settings.clockSkew(value);return this;}
  /**
   * Sets the original monotonic budget for a public issuer operation.
   * Default: 10 seconds; inclusive range: 1 second through 60 seconds. Null restores the default.
   * Bounds and combined constraints are checked by {@link #build()}, not by this setter.
   * Preparation, callbacks, contention retries, store work and final admission share this budget; retries do not restart it. Request timeout must not exceed it. Synchronous application callbacks must cooperate because the library cannot forcibly preempt them. It also contributes to the retention margin described by {@link #clockSkew(Duration)}.
   * @param value the setting in duration units, or null to restore the default
   * @return this builder
   * @since 1.0.0
   */
  @CheckReturnValue public @NonNull Builder totalDeadline(@Nullable Duration value) {this.settings.totalDeadline(value);return this;}
  /**
   * Sets the per-request timeout for outbound CIMD HTTP work.
   * Default: 5 seconds; inclusive range: 1 second through 30 seconds. Null restores the default.
   * Bounds and combined constraints are checked by {@link #build()}, not by this setter.
   * Must not exceed {@link #totalDeadline(Duration)}; the original remaining operation budget can shorten a request further. This does not set the host application HTTP-server timeout or preempt arbitrary application callbacks.
   * @param value the setting in duration units, or null to restore the default
   * @return this builder
   * @since 1.0.0
   */
  @CheckReturnValue public @NonNull Builder requestTimeout(@Nullable Duration value) {this.settings.requestTimeout(value);return this;}
  /**
   * Sets the HTTP Cache-Control max-age for public issuer metadata and JWKS responses.
   * Default: 60 seconds; inclusive range: zero through 5 minutes. Null restores the default.
   * Bounds and combined constraints are checked by {@link #build()}, not by this setter.
   * The header uses whole seconds from {@link Duration#toSeconds()}, while the full configured duration governs new-key publication wait and contributes to grant/verification-key retention. A combined policy beyond an existing family horizon causes its next refresh to revoke it; coordinate revocation and new authorization when changing this policy.
   * @param value the setting in duration units, or null to restore the default
   * @return this builder
   * @since 1.0.0
   */
  @CheckReturnValue public @NonNull Builder publicMetadataHttpCacheMaxAge(@Nullable Duration value) {this.settings.publicMetadataHttpCacheMaxAge(value);return this;}
  /**
   * Sets the maximum admitted materialized endpoint request-body size in bytes.
   * Default: 16384 bytes; inclusive range: 1024 bytes through 65536 bytes. Null restores the default.
   * Bounds and combined constraints are checked by {@link #build()}, not by this setter.
   * This is a library admission bound, not permission for a transport adapter or host server to allocate an unbounded body before calling the issuer. Query, header, token and result bounds still apply separately.
   * @param value the setting in the units described above, or null to restore the default
   * @return this builder
   * @since 1.0.0
   */
  @CheckReturnValue public @NonNull Builder maximumRequestBodyBytes(@Nullable Integer value) {this.settings.maximumRequestBodyBytes(value);return this;}
  /**
   * Sets the maximum raw query length in UTF-16 code units before form decoding.
   * Default: 16384 code units; inclusive range: 1024 code units through 65536 code units. Null restores the default.
   * Bounds and combined constraints are checked by {@link #build()}, not by this setter.
   * Encoded spelling consumes this budget separately from the decoded state/client/scope limits. The host must also bound acquisition of the original query.
   * @param value the setting in the units described above, or null to restore the default
   * @return this builder
   * @since 1.0.0
   */
  @CheckReturnValue public @NonNull Builder maximumRawQueryLength(@Nullable Integer value) {this.settings.maximumRawQueryLength(value);return this;}
  /**
   * Sets the aggregate request-header and prepared response-header budget in bytes.
   * Default: 16384 bytes; inclusive range: 1024 bytes through 65536 bytes. Null restores the default.
   * Bounds and combined constraints are checked by {@link #build()}, not by this setter.
   * Admitted request names, values and framing are charged together; separate header-name/occurrence caps and duplicate-security-header rules remain. This does not change the container or adapter read limits.
   * @param value the setting in the units described above, or null to restore the default
   * @return this builder
   * @since 1.0.0
   */
  @CheckReturnValue public @NonNull Builder maximumHeaderBytes(@Nullable Integer value) {this.settings.maximumHeaderBytes(value);return this;}
  /**
   * Sets the maximum prepared issuer response-body size in bytes.
   * Default: 32768 bytes; inclusive range: 4096 bytes through 131072 bytes. Null restores the default.
   * Bounds and combined constraints are checked by {@link #build()}, not by this setter.
   * Responses are bounded before credential-bearing output or the relevant transition is committed. Request/header/store budgets remain separate; a valid grant need not fit every smaller response policy.
   * @param value the setting in the units described above, or null to restore the default
   * @return this builder
   * @since 1.0.0
   */
  @CheckReturnValue public @NonNull Builder maximumResponseBodyBytes(@Nullable Integer value) {this.settings.maximumResponseBodyBytes(value);return this;}
  /**
   * Sets the maximum ASCII sealed store-record size in bytes, not plaintext payload size.
   * Default: 3800 bytes; inclusive range: 1024 bytes through 16384 bytes. Null restores the default.
   * Bounds and combined constraints are checked by {@link #build()}, not by this setter.
   * Must not exceed the configured {@link #stateSealer(StateSealer)} maximum sealed length. Envelope, authentication and encoding overhead reduce usable payload capacity. Raising another admission limit does not prove a resulting record fits; this setter neither enlarges the sealer nor migrates existing records.
   * @param value the setting in the units described above, or null to restore the default
   * @return this builder
   * @since 1.0.0
   */
  @CheckReturnValue public @NonNull Builder maximumStoreRecordBytes(@Nullable Integer value) {this.settings.maximumStoreRecordBytes(value);return this;}
  /**
   * Sets the maximum attempts for bounded store-conflict retry loops.
   * Default: 3 attempts; inclusive range: 1 attempt through 8 attempts. Null restores the default.
   * Bounds and combined constraints are checked by {@link #build()}, not by this setter.
   * Attempts share the original total deadline; this is not a global cap on every store callback in a composite operation. Only a definite zero-effect conflict permits retry. Unknown mutation outcomes and confirmed commitments requiring reconciliation stop automatic retry.
   * @param value the setting in the units described above, or null to restore the default
   * @return this builder
   * @since 1.0.0
   */
  @CheckReturnValue public @NonNull Builder maximumStoreCommitAttempts(@Nullable Integer value) {this.settings.maximumStoreCommitAttempts(value);return this;}
  /**
   * Sets the maximum resource entries accepted by configured issuer resource maps and client admission.
   * Default: 64 resources; inclusive range: 1 resource through 1024 resources. Null restores the default.
   * Bounds and combined constraints are checked by {@link #build()}, not by this setter.
   * The configured server map is checked at build; client maps are checked when selected. It is a count bound, not a collection of wildcard audiences or permission to fetch resource identifiers.
   * @param value the setting in the units described above, or null to restore the default
   * @return this builder
   * @since 1.0.0
   */
  @CheckReturnValue public @NonNull Builder maximumResources(@Nullable Integer value) {this.settings.maximumResources(value);return this;}
  /**
   * Sets the maximum redirect registrations accepted from a selected client.
   * Default: 32 redirects; inclusive range: 1 redirect through 64 redirects. Null restores the default.
   * Bounds and combined constraints are checked by {@link #build()}, not by this setter.
   * Selection applies this bound without changing exact redirect validation or the separately opted-in loopback profiles. Build does not fetch clients to pre-validate their registrations.
   * @param value the setting in the units described above, or null to restore the default
   * @return this builder
   * @since 1.0.0
   */
  @CheckReturnValue public @NonNull Builder maximumRedirectUris(@Nullable Integer value) {this.settings.maximumRedirectUris(value);return this;}
  /**
   * Sets the maximum scope count per resource in issuer configuration and client admission.
   * Default: 32 scopes; inclusive range: 1 scope through 128 scopes. Null restores the default.
   * Bounds and combined constraints are checked by {@link #build()}, not by this setter.
   * The server resource map is checked at build and selected clients at admission. This does not grant a scope absent from the client/server intersection or current grant policy.
   * @param value the setting in the units described above, or null to restore the default
   * @return this builder
   * @since 1.0.0
   */
  @CheckReturnValue public @NonNull Builder maximumScopesPerResource(@Nullable Integer value) {this.settings.maximumScopesPerResource(value);return this;}
  /**
   * Sets the maximum length of each ASCII scope token.
   * Default: 128 characters; inclusive range: 1 character through 128 characters. Null restores the default.
   * Bounds and combined constraints are checked by {@link #build()}, not by this setter.
   * The scope grammar remains strict; changing a length bound does not admit whitespace, quotes or backslashes or widen granted scopes.
   * @param value the setting in the units described above, or null to restore the default
   * @return this builder
   * @since 1.0.0
   */
  @CheckReturnValue public @NonNull Builder maximumScopeLength(@Nullable Integer value) {this.settings.maximumScopeLength(value);return this;}
  /**
   * Sets the maximum decoded authorization state length in UTF-16 code units.
   * Default: 1024 code units; inclusive range: 128 code units through 4096 code units. Null restores the default.
   * Bounds and combined constraints are checked by {@link #build()}, not by this setter.
   * Raw query/body and encoded redirect/response budgets still apply separately. State is reflected only after the request and registered redirect are admitted; it is not application session or CSRF authentication.
   * @param value the setting in the units described above, or null to restore the default
   * @return this builder
   * @since 1.0.0
   */
  @CheckReturnValue public @NonNull Builder maximumStateLength(@Nullable Integer value) {this.settings.maximumStateLength(value);return this;}
  /**
   * Sets the maximum client-identifier length in UTF-16 code units at issuer ingress.
   * Default: 2048 code units; inclusive range: 256 code units through 4096 code units. Null restores the default.
   * Bounds and combined constraints are checked by {@link #build()}, not by this setter.
   * Exact registered and CIMD identifiers remain subject to their profile and aggregate request limits. This bound does not normalize client identifiers or authorize metadata fetching.
   * @param value the setting in the units described above, or null to restore the default
   * @return this builder
   * @since 1.0.0
   */
  @CheckReturnValue public @NonNull Builder maximumClientIdLength(@Nullable Integer value) {this.settings.maximumClientIdLength(value);return this;}
  /**
   * Sets the maximum application subject length in UTF-16 code units.
   * Default: 255 code units; inclusive range: 16 code units through 1024 code units. Null restores the default.
   * Bounds and combined constraints are checked by {@link #build()}, not by this setter.
   * The interval bounds this maximum setting, not a minimum accepted subject length. Subjects remain exact application identifiers, separately scoped by issuer; this does not create accounts or authorize a user.
   * @param value the setting in the units described above, or null to restore the default
   * @return this builder
   * @since 1.0.0
   */
  @CheckReturnValue public @NonNull Builder maximumSubjectLength(@Nullable Integer value) {this.settings.maximumSubjectLength(value);return this;}
  /**
   * Validates the complete configuration and returns an issuer retaining the selected application collaborators.
   * Missing required values, refresh without revocation, unsafe/duplicate/cross-authority routes, invalid
   * numeric/combined limits and a CIMD runtime below the unacknowledged floor fail construction.
   * No client/store/key/policy/resolver callback, clock sampling, network I/O, signing or owned thread is
   * started. Enabling localhost any-port redirects does synchronously notify the configured observer as
   * described by {@link #observer(OAuthServerObserver)}; its documented failure rules apply.
   * This does not initialize an issuer namespace, verify deployment recovery/witness readiness or authorize
   * credential release. Later builder changes do not alter this server; retained application collaborators
   * continue to follow their own lifecycle contracts.
   * @return the configured server, without persistence initialization or serving admission
   * @throws IllegalStateException if required configuration is missing, refresh lacks revocation, or CIMD requires an unacknowledged runtime floor
   * @throws IllegalArgumentException if endpoint, resource, numeric or combined configuration is invalid
   * @since 1.0.0
   */
  @CheckReturnValue public @NonNull OAuthAuthorizationServer build() {return new OAuthAuthorizationServer(this);}
  /** Returns a fixed redacted description.
   * @return description
   * @since 1.0.0
   */
  @Override public @NonNull String toString() {return "OAuthAuthorizationServer.Builder{<redacted>}";}
 }
}
