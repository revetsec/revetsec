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

import com.revetsec.StateSealer;
import com.revetsec.OutboundUriPolicy;
import com.revetsec.internal.crypto.SealedStateAccess;
import com.revetsec.internal.http.Deadline;
import com.revetsec.internal.http.RuntimeFloor;
import com.revetsec.internal.oauth.OidcTransactionAccess;
import com.revetsec.jose.JwsAlgorithm;
import com.revetsec.jose.StaticJsonWebKeySource;
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
 * atomic durable storage, synchronized clocks, keys and authorization policy. Register the exact configured
 * routes; request headers never select issuer authority. Protect completion with the app's session and CSRF
 * controls. Infrastructure faults remain exceptions; expected remote rejection is a restricted result.
 * Construction performs no callbacks, network I/O, signing or thread startup. No positive grant-status cache.
 * Revetsec has not been independently audited.
 * @since 1.0.0
 */
@ThreadSafe
public final class OAuthAuthorizationServer {
 private final @NonNull String issuer;
 private final @NonNull URI authorizationEndpoint, tokenEndpoint, jsonWebKeySetEndpoint;
 private final @Nullable URI revocationEndpoint, introspectionEndpoint;
 private final @NonNull OAuthServerSettings settings;
 private final @NonNull OAuthServerIngressLimits limits;
 private final @NonNull Map<@NonNull String, @NonNull Set<@NonNull String>> resources;
 private final @NonNull OAuthServerClientRepository repository;
 private final @NonNull OAuthGrantPolicy policy;
 private final @NonNull OAuthServerObserver observer;
 private final @NonNull Clock clock;
 private final boolean nativeLoopback, localhost, refresh;
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
 private OAuthAuthorizationServer(@NonNull Builder b) {
  this.issuer=b.issuer; this.authorizationEndpoint=required(b.authorizationEndpoint); this.tokenEndpoint=required(b.tokenEndpoint);
  this.jsonWebKeySetEndpoint=required(b.jsonWebKeySetEndpoint); this.revocationEndpoint=b.revocationEndpoint; this.introspectionEndpoint=b.introspectionEndpoint;
  this.repository=required(b.clientRepository); this.policy=required(b.grantPolicy); OAuthAuthorizationServerStore store=required(b.store);
  OAuthIssuerKeyProvider provider=required(b.signingKeys); StateSealer sealer=required(b.stateSealer);
  this.refresh=b.refreshTokensEnabled;
  if (this.refresh && this.revocationEndpoint==null) throw new IllegalStateException("Refresh requires a revocation endpoint.");
  this.settings=b.settings.build(this.refresh,SealedStateAccess.get().getMaximumSealedLength(sealer)); this.limits=this.settings.ingress();
  this.resources=OAuthServerAuthorizationAdmission.checkedServerResources(required(b.resources),this.limits);
  this.clock=b.clock; this.observer=b.observer; this.nativeLoopback=b.allowNativeLoopbackRedirects; this.localhost=b.allowLocalhostRedirects;
  URI issuerUri=endpoint(URI.create(this.issuer),b.allowInsecureLoopback);
  Set<String> routes=new HashSet<>();
  for (URI route:List.of(this.authorizationEndpoint,this.tokenEndpoint,this.jsonWebKeySetEndpoint)) checkRoute(issuerUri,route,b.allowInsecureLoopback,routes);
  if(this.revocationEndpoint!=null) checkRoute(issuerUri,this.revocationEndpoint,b.allowInsecureLoopback,routes);
  if(this.introspectionEndpoint!=null) checkRoute(issuerUri,this.introspectionEndpoint,b.allowInsecureLoopback,routes);
  OAuthClientMetadataPolicy metadataPolicy=b.clientMetadataPolicy;
  if(metadataPolicy.getEnabled()) RuntimeFloor.require(b.acknowledgeUnpatchedRuntime);
  OAuthClientMetadataFetcher fetcher=metadataPolicy.getEnabled() ? new OAuthClientMetadataFetcher(this.issuer,sealer,metadataPolicy,this.limits,
   this.nativeLoopback,this.localhost,b.outboundUriPolicy,this.clock,this.settings.requestTimeout) : null;
  this.clients=new OAuthServerClientSelection(this.repository,this.limits,fetcher,true);
  OAuthStoreRecordCodec codec=new OAuthStoreRecordCodec(this.issuer,sealer,this.settings.maximumStoreRecordBytes);
  this.coordinator=new OAuthStoreCoordinator(store,codec,this.clock,this.settings.maximumStoreCommitAttempts,this.settings.maximumSubjectLength);
  this.ledger=new OAuthAuthorizationLedger(this.coordinator,codec,this.limits,this.settings.authorizationInteractionLifetime,
   this.settings.authorizationCodeLifetime,this.settings.maximumStoreCommitAttempts,this.settings.maximumSubjectLength,this.refresh);
  OAuthGrantRetention retention=new OAuthGrantRetention(this.settings.accessTokenLifetime,this.settings.clockSkew,this.settings.totalDeadline,this.settings.publicMetadataFreshness);
  this.keys=new OAuthIssuerKeyLifecycle(provider,this.clock,this.settings.publicMetadataFreshness,retention,true);
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
  this.metadata=new OAuthIssuerMetadata(issuerUri,this.authorizationEndpoint,this.tokenEndpoint,this.jsonWebKeySetEndpoint,this.revocationEndpoint,this.introspectionEndpoint,
   this.refresh,b.allowInsecureLoopback,scopes,this.settings.publicMetadataFreshness,this.settings.maximumResponseBodyBytes,this.settings.maximumHeaderBytes,metadataPolicy.getEnabled());
 }
 /** Starts configuration with the exact issuer identity.
  * @param issuer absolute HTTPS issuer, or an explicitly enabled numeric HTTP loopback issuer
  * @return builder
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
   OAuthServerAuthorizationAdmission admission=OAuthServerAuthorizationAdmission.admit(request,this.clients,d,this.resources,this.limits,this.nativeLoopback,this.localhost);
   String interaction=this.ledger.begin(admission,browserBinding,d);
   OAuthServerClientSelection.Selected selected=this.clients.authorization(admission.client().getClientId(),this.resources,d);
   return interaction(interaction,browserBinding,selected,d);
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
   return OAuthRevocationResult.fromSucceeded(this.revocation.revoke(request,this.clients,this.resources,this.keys.verificationKeys(d),d).response());
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
   return OAuthIntrospectionResult.fromSucceeded(this.introspection.introspect(request,this.repository,resource,this.keys.verificationKeys(d),d).response());
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
   StaticJsonWebKeySource snapshot=this.keys.verificationKeys(d);
   VerifiedAccessToken proof;
   try {
    OAuthServerClientAdmission.remaining(d);
    JwtAccessTokenValidator validator=JwtAccessTokenValidator.withIssuer(this.issuer).jsonWebKeySource(snapshot).expectedAudiences(Set.of(resource))
     .allowedAlgorithms(Set.of(JwsAlgorithm.RS256)).clock(this.clock).clockSkew(this.settings.clockSkew)
     .maximumTokenLength(Math.max(8192,this.settings.maximumRequestBodyBytes)).requestTimeout(Duration.ofSeconds(1)).totalDeadline(this.settings.totalDeadline).build();
    proof=OidcTransactionAccess.get().validateAccessToken(validator,token,d);
   } catch(AccessTokenValidationException rejected) {
    OAuthServerClientAdmission.remaining(d);
    return OAuthIssuerAccessTokenResult.fromRejection(TOKEN_REVOKED,rejected.getReason(),rejected.getJoseReason().orElse(null));
   }
   OAuthServerClientAdmission.remaining(d);
   return this.status.validate(OidcTransactionAccess.get().bearerValue(token),resource,snapshot,d,c->OAuthIssuerAccessTokenResult.fromSucceeded(proof));
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
 @CheckReturnValue public @NonNull OAuthStoreCommitStatus initializeFreshIssuer() {
  return execute(ISSUER_INITIALIZATION,this.coordinator::initializeFreshIssuerResult,r->{throw OAuthServerValidationException.fromReason(r);});
 }
 /** Attempts one authenticated reseal CAS without changing grant authority or retention.
  * @param key privileged namespace-bound maintenance key
  * @return COMMITTED, CONFLICT for absence/race/expired row, or UNKNOWN requiring reconciliation
  * @since 1.0.0
  */
 @CheckReturnValue public @NonNull OAuthStoreCommitStatus resealStoreEntry(@NonNull OAuthStoreKey key) {
  requireNonNull(key);
  return execute(STORE_RESEAL,d->this.coordinator.reseal(key,d),r->{throw OAuthServerValidationException.fromReason(r);});
 }
 /** Prepares bounded public metadata for GET or HEAD.
  * @param httpMethod exact method
  * @return safe public response, including method rejection
  * @since 1.0.0
  */
 @CheckReturnValue public @NonNull OAuthServerResponse metadataResponse(@NonNull String httpMethod) {
  requireNonNull(httpMethod);
  return execute(METADATA,d->this.metadata.metadata(httpMethod,d).response(),r->{throw OAuthServerValidationException.fromReason(r);});
 }
 /** Prepares bounded public json web key set for GET or HEAD.
  * @param httpMethod exact method
  * @return safe public response, including method rejection
  * @since 1.0.0
  */
 @CheckReturnValue public @NonNull OAuthServerResponse jsonWebKeySetResponse(@NonNull String httpMethod) {
  requireNonNull(httpMethod);
  return execute(JSON_WEB_KEY_SET,d->this.metadata.jwks(httpMethod,this.keys,d).response(),r->{throw OAuthServerValidationException.fromReason(r);});
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
  try { Deadline d=Deadline.fromNow(this.settings.totalDeadline); this.keys.warmUp(d);
   for(int n=0;n<this.settings.maximumStoreCommitAttempts;n++) if(this.coordinator.begin(d).barrier()==OAuthStoreCommitStatus.COMMITTED) return;
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
 /** Returns configured JsonWebKeySetEndpoint.
  * @return exact setting or optional absence
  * @since 1.0.0
  */
 @CheckReturnValue public @NonNull URI getJsonWebKeySetEndpoint() {return this.jsonWebKeySetEndpoint;}
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
  try {result=work.apply(d);}
  catch(OAuthTransportException f) {OAuthServerException translated=OAuthServerStoreException.fromReason(STORE_UNAVAILABLE,true);observation.failed(translated);throw translated;}
  catch(OAuthStoreFailure f) {OAuthServerException translated=OAuthServerFailureBoundary.store(f);observation.failed(translated);throw translated;}
  catch(OAuthServerAdmissionFailure f) {
   OAuthServerException translated=OAuthServerFailureBoundary.admission(f);
   if(translated instanceof OAuthServerValidationException) result=reject.apply(translated.getReason());
   else {observation.failed(translated);throw translated;}
  }
  catch(OAuthServerValidationException rejected) {result=reject.apply(rejected.getReason());}
  catch(OAuthServerException f) {observation.failed(f);throw f;}
  catch(IllegalArgumentException f) {result=reject.apply(MALFORMED_REQUEST);}
  OAuthServerException.Reason rejected=reason(result);Integer statusCode=statusCode(result);
  if(rejected==null) observation.succeeded(statusCode);else observation.rejected(rejected,statusCode);
  return result;
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
 /** Mutable pure configuration. Null clears required values or restores documented defaults; collection setters
  * replace and snapshot complete values. See the issuer limits registry for numeric defaults/ranges.
  * @since 1.0.0
  */
 @NotThreadSafe @CheckReturnValue
 public static final class Builder {
  private final @NonNull String issuer;
  private @Nullable URI authorizationEndpoint,tokenEndpoint,jsonWebKeySetEndpoint,revocationEndpoint,introspectionEndpoint;
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
  private boolean refreshTokensEnabled,allowInsecureLoopback,allowNativeLoopbackRedirects,allowLocalhostRedirects,acknowledgeUnpatchedRuntime;
  private final OAuthServerSettings.@NonNull Builder settings=OAuthServerSettings.builder();
  private Builder(@NonNull String issuer) {this.issuer=endpoint(URI.create(requireNonNull(issuer)),true).toString();}
  /** Sets authorizationEndpoint; null restores its default or clears a required setting.
   * @param value complete replacement or null
   * @return this builder
   * @since 1.0.0
   */
  @CheckReturnValue public @NonNull Builder authorizationEndpoint(@Nullable URI value) {this.authorizationEndpoint=value;return this;}
  /** Sets tokenEndpoint; null restores its default or clears a required setting.
   * @param value complete replacement or null
   * @return this builder
   * @since 1.0.0
   */
  @CheckReturnValue public @NonNull Builder tokenEndpoint(@Nullable URI value) {this.tokenEndpoint=value;return this;}
  /** Sets jsonWebKeySetEndpoint; null restores its default or clears a required setting.
   * @param value complete replacement or null
   * @return this builder
   * @since 1.0.0
   */
  @CheckReturnValue public @NonNull Builder jsonWebKeySetEndpoint(@Nullable URI value) {this.jsonWebKeySetEndpoint=value;return this;}
  /** Sets revocationEndpoint; null restores its default or clears a required setting.
   * @param value complete replacement or null
   * @return this builder
   * @since 1.0.0
   */
  @CheckReturnValue public @NonNull Builder revocationEndpoint(@Nullable URI value) {this.revocationEndpoint=value;return this;}
  /** Sets introspectionEndpoint; null restores its default or clears a required setting.
   * @param value complete replacement or null
   * @return this builder
   * @since 1.0.0
   */
  @CheckReturnValue public @NonNull Builder introspectionEndpoint(@Nullable URI value) {this.introspectionEndpoint=value;return this;}
  /** Sets clientRepository; null restores its default or clears a required setting.
   * @param value complete replacement or null
   * @return this builder
   * @since 1.0.0
   */
  @CheckReturnValue public @NonNull Builder clientRepository(@Nullable OAuthServerClientRepository value) {this.clientRepository=value;return this;}
  /** Sets store; null restores its default or clears a required setting.
   * @param value complete replacement or null
   * @return this builder
   * @since 1.0.0
   */
  @CheckReturnValue public @NonNull Builder store(@Nullable OAuthAuthorizationServerStore value) {this.store=value;return this;}
  /** Sets signingKeys; null restores its default or clears a required setting.
   * @param value complete replacement or null
   * @return this builder
   * @since 1.0.0
   */
  @CheckReturnValue public @NonNull Builder signingKeys(@Nullable OAuthIssuerKeyProvider value) {this.signingKeys=value;return this;}
  /** Sets stateSealer; null restores its default or clears a required setting.
   * @param value complete replacement or null
   * @return this builder
   * @since 1.0.0
   */
  @CheckReturnValue public @NonNull Builder stateSealer(@Nullable StateSealer value) {this.stateSealer=value;return this;}
  /** Sets grantPolicy; null restores its default or clears a required setting.
   * @param value complete replacement or null
   * @return this builder
   * @since 1.0.0
   */
  @CheckReturnValue public @NonNull Builder grantPolicy(@Nullable OAuthGrantPolicy value) {this.grantPolicy=value;return this;}
  /** Sets resources; null restores its default or clears a required setting.
   * @param value complete replacement or null
   * @return this builder
   * @since 1.0.0
   */
  @CheckReturnValue public @NonNull Builder resources(@Nullable Map<@NonNull String,@NonNull Set<@NonNull String>> value) {this.resources=value==null ? null : OAuthServerConfiguration.resources(value,1024);return this;}
  /** Sets clientMetadataPolicy; null restores its default or clears a required setting.
   * @param value complete replacement or null
   * @return this builder
   * @since 1.0.0
   */
  @CheckReturnValue public @NonNull Builder clientMetadataPolicy(@Nullable OAuthClientMetadataPolicy value) {this.clientMetadataPolicy=value==null ? OAuthClientMetadataPolicy.disabledInstance() : value;return this;}
  /** Sets clock; null restores its default or clears a required setting.
   * @param value complete replacement or null
   * @return this builder
   * @since 1.0.0
   */
  @CheckReturnValue public @NonNull Builder clock(@Nullable Clock value) {this.clock=value==null ? Clock.systemUTC() : value;return this;}
  /** Sets outboundUriPolicy; null restores its default or clears a required setting.
   * @param value complete replacement or null
   * @return this builder
   * @since 1.0.0
   */
  @CheckReturnValue public @NonNull Builder outboundUriPolicy(@Nullable OutboundUriPolicy value) {this.outboundUriPolicy=value==null ? OutboundUriPolicy.publicAddressesOnlyInstance() : value;return this;}
  /** Sets observer; null restores its default or clears a required setting.
   * @param value complete replacement or null
   * @return this builder
   * @since 1.0.0
   */
  @CheckReturnValue public @NonNull Builder observer(@Nullable OAuthServerObserver value) {this.observer=value==null ? OAuthServerObserver.disabledInstance() : value;return this;}
  /** Sets refreshTokensEnabled; null restores its default or clears a required setting.
   * @param value complete replacement or null
   * @return this builder
   * @since 1.0.0
   */
  @CheckReturnValue public @NonNull Builder refreshTokensEnabled(@Nullable Boolean value) {this.refreshTokensEnabled=Boolean.TRUE.equals(value);return this;}
  /** Sets allowInsecureLoopback; null restores its default or clears a required setting.
   * @param value complete replacement or null
   * @return this builder
   * @since 1.0.0
   */
  @CheckReturnValue public @NonNull Builder allowInsecureLoopback(@Nullable Boolean value) {this.allowInsecureLoopback=Boolean.TRUE.equals(value);return this;}
  /** Sets allowNativeLoopbackRedirects; null restores its default or clears a required setting.
   * @param value complete replacement or null
   * @return this builder
   * @since 1.0.0
   */
  @CheckReturnValue public @NonNull Builder allowNativeLoopbackRedirects(@Nullable Boolean value) {this.allowNativeLoopbackRedirects=Boolean.TRUE.equals(value);return this;}
  /** Sets allowLocalhostRedirects; null restores its default or clears a required setting.
   * @param value complete replacement or null
   * @return this builder
   * @since 1.0.0
   */
  @CheckReturnValue public @NonNull Builder allowLocalhostRedirects(@Nullable Boolean value) {this.allowLocalhostRedirects=Boolean.TRUE.equals(value);return this;}
  /** Sets acknowledgeUnpatchedRuntime; null restores its default or clears a required setting.
   * @param value complete replacement or null
   * @return this builder
   * @since 1.0.0
   */
  @CheckReturnValue public @NonNull Builder acknowledgeUnpatchedRuntime(@Nullable Boolean value) {this.acknowledgeUnpatchedRuntime=Boolean.TRUE.equals(value);return this;}
  /** Sets authorizationInteractionLifetime; null restores the issuer registry default. Bounds are checked at build.
   * @param value setting or null
   * @return this builder
   * @since 1.0.0
   */
  @CheckReturnValue public @NonNull Builder authorizationInteractionLifetime(@Nullable Duration value) {this.settings.authorizationInteractionLifetime(value);return this;}
  /** Sets authorizationCodeLifetime; null restores the issuer registry default. Bounds are checked at build.
   * @param value setting or null
   * @return this builder
   * @since 1.0.0
   */
  @CheckReturnValue public @NonNull Builder authorizationCodeLifetime(@Nullable Duration value) {this.settings.authorizationCodeLifetime(value);return this;}
  /** Sets accessTokenLifetime; null restores the issuer registry default. Bounds are checked at build.
   * @param value setting or null
   * @return this builder
   * @since 1.0.0
   */
  @CheckReturnValue public @NonNull Builder accessTokenLifetime(@Nullable Duration value) {this.settings.accessTokenLifetime(value);return this;}
  /** Sets refreshTokenIdleLifetime; null restores the issuer registry default. Bounds are checked at build.
   * @param value setting or null
   * @return this builder
   * @since 1.0.0
   */
  @CheckReturnValue public @NonNull Builder refreshTokenIdleLifetime(@Nullable Duration value) {this.settings.refreshTokenIdleLifetime(value);return this;}
  /** Sets refreshTokenAbsoluteLifetime; null restores the issuer registry default. Bounds are checked at build.
   * @param value setting or null
   * @return this builder
   * @since 1.0.0
   */
  @CheckReturnValue public @NonNull Builder refreshTokenAbsoluteLifetime(@Nullable Duration value) {this.settings.refreshTokenAbsoluteLifetime(value);return this;}
  /** Sets clockSkew; null restores the issuer registry default. Bounds are checked at build.
   * @param value setting or null
   * @return this builder
   * @since 1.0.0
   */
  @CheckReturnValue public @NonNull Builder clockSkew(@Nullable Duration value) {this.settings.clockSkew(value);return this;}
  /** Sets totalDeadline; null restores the issuer registry default. Bounds are checked at build.
   * @param value setting or null
   * @return this builder
   * @since 1.0.0
   */
  @CheckReturnValue public @NonNull Builder totalDeadline(@Nullable Duration value) {this.settings.totalDeadline(value);return this;}
  /** Sets requestTimeout; null restores the issuer registry default. Bounds are checked at build.
   * @param value setting or null
   * @return this builder
   * @since 1.0.0
   */
  @CheckReturnValue public @NonNull Builder requestTimeout(@Nullable Duration value) {this.settings.requestTimeout(value);return this;}
  /** Sets publicMetadataFreshness; null restores the issuer registry default. Bounds are checked at build.
   * @param value setting or null
   * @return this builder
   * @since 1.0.0
   */
  @CheckReturnValue public @NonNull Builder publicMetadataFreshness(@Nullable Duration value) {this.settings.publicMetadataFreshness(value);return this;}
  /** Sets maximumRequestBodyBytes; null restores the issuer registry default. Bounds are checked at build.
   * @param value setting or null
   * @return this builder
   * @since 1.0.0
   */
  @CheckReturnValue public @NonNull Builder maximumRequestBodyBytes(@Nullable Integer value) {this.settings.maximumRequestBodyBytes(value);return this;}
  /** Sets maximumRawQueryLength; null restores the issuer registry default. Bounds are checked at build.
   * @param value setting or null
   * @return this builder
   * @since 1.0.0
   */
  @CheckReturnValue public @NonNull Builder maximumRawQueryLength(@Nullable Integer value) {this.settings.maximumRawQueryLength(value);return this;}
  /** Sets maximumHeaderBytes; null restores the issuer registry default. Bounds are checked at build.
   * @param value setting or null
   * @return this builder
   * @since 1.0.0
   */
  @CheckReturnValue public @NonNull Builder maximumHeaderBytes(@Nullable Integer value) {this.settings.maximumHeaderBytes(value);return this;}
  /** Sets maximumResponseBodyBytes; null restores the issuer registry default. Bounds are checked at build.
   * @param value setting or null
   * @return this builder
   * @since 1.0.0
   */
  @CheckReturnValue public @NonNull Builder maximumResponseBodyBytes(@Nullable Integer value) {this.settings.maximumResponseBodyBytes(value);return this;}
  /** Sets maximumStoreRecordBytes; null restores the issuer registry default. Bounds are checked at build.
   * @param value setting or null
   * @return this builder
   * @since 1.0.0
   */
  @CheckReturnValue public @NonNull Builder maximumStoreRecordBytes(@Nullable Integer value) {this.settings.maximumStoreRecordBytes(value);return this;}
  /** Sets maximumStoreCommitAttempts; null restores the issuer registry default. Bounds are checked at build.
   * @param value setting or null
   * @return this builder
   * @since 1.0.0
   */
  @CheckReturnValue public @NonNull Builder maximumStoreCommitAttempts(@Nullable Integer value) {this.settings.maximumStoreCommitAttempts(value);return this;}
  /** Sets maximumResources; null restores the issuer registry default. Bounds are checked at build.
   * @param value setting or null
   * @return this builder
   * @since 1.0.0
   */
  @CheckReturnValue public @NonNull Builder maximumResources(@Nullable Integer value) {this.settings.maximumResources(value);return this;}
  /** Sets maximumRedirectUris; null restores the issuer registry default. Bounds are checked at build.
   * @param value setting or null
   * @return this builder
   * @since 1.0.0
   */
  @CheckReturnValue public @NonNull Builder maximumRedirectUris(@Nullable Integer value) {this.settings.maximumRedirectUris(value);return this;}
  /** Sets maximumScopesPerResource; null restores the issuer registry default. Bounds are checked at build.
   * @param value setting or null
   * @return this builder
   * @since 1.0.0
   */
  @CheckReturnValue public @NonNull Builder maximumScopesPerResource(@Nullable Integer value) {this.settings.maximumScopesPerResource(value);return this;}
  /** Sets maximumScopeLength; null restores the issuer registry default. Bounds are checked at build.
   * @param value setting or null
   * @return this builder
   * @since 1.0.0
   */
  @CheckReturnValue public @NonNull Builder maximumScopeLength(@Nullable Integer value) {this.settings.maximumScopeLength(value);return this;}
  /** Sets maximumStateLength; null restores the issuer registry default. Bounds are checked at build.
   * @param value setting or null
   * @return this builder
   * @since 1.0.0
   */
  @CheckReturnValue public @NonNull Builder maximumStateLength(@Nullable Integer value) {this.settings.maximumStateLength(value);return this;}
  /** Sets maximumClientIdLength; null restores the issuer registry default. Bounds are checked at build.
   * @param value setting or null
   * @return this builder
   * @since 1.0.0
   */
  @CheckReturnValue public @NonNull Builder maximumClientIdLength(@Nullable Integer value) {this.settings.maximumClientIdLength(value);return this;}
  /** Sets maximumSubjectLength; null restores the issuer registry default. Bounds are checked at build.
   * @param value setting or null
   * @return this builder
   * @since 1.0.0
   */
  @CheckReturnValue public @NonNull Builder maximumSubjectLength(@Nullable Integer value) {this.settings.maximumSubjectLength(value);return this;}
  /** Builds a snapshot without callbacks, I/O, signing or owned threads.
   * @return server
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
