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

import com.revetsec.SealingKey;
import com.revetsec.StateSealer;
import com.revetsec.OutboundUriPolicy;
import com.revetsec.internal.encoding.FormUrlEncoding;
import com.revetsec.internal.http.Deadline;
import com.revetsec.internal.http.RawResponse;
import com.revetsec.internal.json.JsonCodec;
import com.revetsec.internal.json.JsonLimits;
import com.revetsec.json.*;
import com.revetsec.jose.JwsAlgorithm;
import com.revetsec.jose.JwsSigner;
import com.revetsec.testing.TestJsonWebKeys;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.function.Executable;
import java.net.URI;
import java.net.http.HttpHeaders;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.Stream;
import static java.util.Objects.requireNonNull;
import static org.junit.jupiter.api.Assertions.*;

/** Actual internal consent/code/refresh integration with deterministic metadata transport; no durable backend claim. */
final class OAuthClientSelectionTests {
 private static final @NonNull String ID="https://client.example.com/metadata", ISSUER="https://issuer.example.com/tenant",
  RESOURCE="https://resource.example.com/mcp", REDIRECT="https://client.example.com/callback", BROWSER="A".repeat(43),
  VERIFIER="dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk", CHALLENGE="E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
 private static final @NonNull Instant NOW=Instant.parse("2026-10-06T12:00:00Z");
 private static final @NonNull OAuthServerIngressLimits LIMITS=OAuthServerIngressLimits.fromDefaults();
 private final @NonNull OAuthAtomicStoreFixture store=new OAuthAtomicStoreFixture();
 private final @NonNull StateSealer sealer=sealer();
 private final @NonNull OAuthStoreRecordCodec codec=new OAuthStoreRecordCodec(ISSUER,this.sealer,3800);
 private final @NonNull OAuthStoreCoordinator coordinator=new OAuthStoreCoordinator(this.store,this.codec,Clock.fixed(NOW,ZoneOffset.UTC),3,255);
 private final @NonNull OAuthAuthorizationLedger ledger=new OAuthAuthorizationLedger(this.coordinator,this.codec,LIMITS,Duration.ofMinutes(15),Duration.ofMinutes(2),3,255,true);
 private final @NonNull OAuthGrantRetention retention=new OAuthGrantRetention(Duration.ofMinutes(5),Duration.ofSeconds(30),Duration.ofSeconds(10),Duration.ofSeconds(60));
 private final OAuthTokenResponse.@NonNull Encoder encoder=encoder();
 private final @NonNull OAuthCodeRedemption codes=new OAuthCodeRedemption(this.coordinator,this.codec,LIMITS,this.retention,this.encoder,Duration.ofMinutes(5),true,Duration.ofDays(1),Duration.ofDays(7),3,255);
 private final @NonNull OAuthRefreshRotation refresh=new OAuthRefreshRotation(this.coordinator,this.codec,LIMITS,this.retention,this.encoder,Duration.ofMinutes(5),true,Duration.ofDays(1),3,255);
 private final @NonNull AtomicInteger fetches=new AtomicInteger(), cacheReads=new AtomicInteger(), cacheWrites=new AtomicInteger(), policies=new AtomicInteger();
 private @NonNull JsonObject document=document();
 private boolean transportFailure;
 private @Nullable Runnable fetchHook;
 private int status=200;
 private final @NonNull InMemoryOAuthClientMetadataCache memory=InMemoryOAuthClientMetadataCache.fromMaximumEntries(128);
 private final @NonNull OAuthClientMetadataCache cache=new OAuthClientMetadataCache() {
  @Override public @NonNull Optional<@NonNull OAuthClientMetadataCacheEntry> read(@NonNull OAuthClientMetadataCacheKey key,@NonNull Duration budget) throws OAuthClientMetadataCacheException {
   cacheReads.incrementAndGet();return memory.read(key,budget);
  }
  @Override public @NonNull Boolean compareAndSet(@NonNull OAuthClientMetadataCacheKey key,@Nullable String expected,@Nullable OAuthClientMetadataCacheEntry entry,@NonNull Duration budget) throws OAuthClientMetadataCacheException {
   cacheWrites.incrementAndGet();return memory.compareAndSet(key,expected,entry,budget);
  }
 };
 private final @NonNull OAuthClientMetadataPolicy metadataPolicy=OAuthClientMetadataPolicy.withAddressResolver((host,b)->{throw new AssertionError("deterministic seam");}).cache(this.cache).build();
 private final @NonNull AtomicReference<@Nullable Deadline> observed=new AtomicReference<>();
 private final @NonNull OAuthClientMetadataFetcher fetcher=new OAuthClientMetadataFetcher(ISSUER,this.sealer,this.metadataPolicy,LIMITS,true,true,
  OutboundUriPolicy.defaultInstance(),Clock.fixed(NOW,ZoneOffset.UTC),(uri,deadline)->{
   this.fetches.incrementAndGet();this.observed.set(deadline);Runnable hook=this.fetchHook;if(hook!=null)hook.run();
   if(this.transportFailure)throw new IllegalStateException("private transport failure");
   return new RawResponse(this.status,HttpHeaders.of(Map.of("Cache-Control",List.of("max-age=300")),(a,b)->true),this.document.toJson().getBytes(StandardCharsets.UTF_8),null,false,Duration.ZERO);
  });
 private final @NonNull OAuthServerClientSelection dynamic=selection((id,b)->Optional.empty());
 OAuthClientSelectionTests() { }
 private static @NonNull StateSealer sealer() {
  byte[] key=new byte[32];for(int i=0;i<32;i++)key[i]=(byte)(i+1);
  return StateSealer.withActiveKey(SealingKey.fromBase64("k",Base64.getEncoder().encodeToString(key))).clock(Clock.fixed(NOW,ZoneOffset.UTC)).build();
 }
 private static OAuthTokenResponse.@NonNull Encoder encoder() {
  var key=TestJsonWebKeys.Fixture.IDP_SIGNING_RSA_2048;
  return new OAuthTokenResponse.Encoder(ISSUER,"key",JwsSigner.fromRsaKeyPair(key.getPrivateKey(),key.getPublicKey(),JwsAlgorithm.RS256),32768,16384);
 }
 private @NonNull OAuthServerClientSelection selection(@NonNull OAuthServerClientRepository repository) {return new OAuthServerClientSelection(repository,LIMITS,this.fetcher);}
 private static @NonNull Map<@NonNull String,@NonNull Set<@NonNull String>> resources() {return Map.of(RESOURCE,Set.of("read","write"));}
 private static @NonNull Deadline deadline() {return Deadline.fromNow(Duration.ofSeconds(5));}
 private static @NonNull JsonObject document() {
  return JsonObject.builder().put("client_id",ID).put("client_name","Client").put("token_endpoint_auth_method","none")
   .put("redirect_uris",JsonArray.fromElements(List.of(JsonString.fromValue(REDIRECT))))
   .put("grant_types",JsonArray.fromElements(List.of(JsonString.fromValue("authorization_code"),JsonString.fromValue("refresh_token")))).build();
 }
 private void change(@NonNull String key,@NonNull JsonValue value) {var members=new LinkedHashMap<>(this.document.getMembers());members.put(key,value);this.document=JsonObject.fromMembers(members);}
 private static @NonNull OAuthServerClientRegistration registered(boolean confidential) {
  return OAuthServerClientRegistration.withClientId(ID).configurationVersion("v1").redirectUris(List.of(URI.create(REDIRECT))).allowedScopesByResource(resources()).refreshTokenPermitted(true)
   .authentication(confidential?OAuthServerClientAuthentication.fromClientSecretVerifier((i,s,b)->true):null).build();
 }
 private static @NonNull String encode(@NonNull String value) {try{return FormUrlEncoding.encode(value);}catch(com.revetsec.internal.encoding.EncodingException failure){throw new AssertionError(failure);}}
 private static @NonNull OAuthServerRequest authorize(@Nullable String scope,@NonNull String redirect) {
  String q="client_id="+encode(ID)+"&response_type=code&redirect_uri="+encode(redirect)+"&resource="+encode(RESOURCE)+"&code_challenge_method=S256&code_challenge="+CHALLENGE+(scope==null?"":"&scope="+encode(scope));
  return OAuthServerRequest.parse(OAuthServerRequest.Endpoint.AUTHORIZATION,"GET",q,new byte[0],Map.of(),LIMITS);
 }
 private static @NonNull OAuthServerRequest token(@NonNull String credential,boolean refresh,@NonNull Map<@NonNull String,@NonNull String> overrides,@Nullable String basic) {
  var fields=new LinkedHashMap<String,String>();fields.put("grant_type",refresh?"refresh_token":"authorization_code");fields.put(refresh?"refresh_token":"code",credential);
  if(!refresh)fields.put("code_verifier",VERIFIER);fields.put("client_id",ID);fields.put("resource",RESOURCE);fields.putAll(overrides);if(basic!=null)fields.remove("client_id");
  String text=String.join("&",fields.entrySet().stream().map(e->encode(e.getKey())+"="+encode(e.getValue())).toList());
  var headers=new LinkedHashMap<String,List<String>>();headers.put("Content-Type",List.of("application/x-www-form-urlencoded"));if(basic!=null)headers.put("Authorization",List.of(basic));
  return OAuthServerRequest.parse(OAuthServerRequest.Endpoint.TOKEN,"POST",null,text.getBytes(StandardCharsets.UTF_8),headers,LIMITS);
 }
 private static @NonNull String basic() {return "Basic "+Base64.getEncoder().encodeToString((encode(ID)+":secret").getBytes(StandardCharsets.US_ASCII));}
 private static @NonNull OAuthAuthorizationDecision decision(@NonNull String subject) {return OAuthAuthorizationDecision.withSubject(subject).authorizedScopesByResource(resources()).refreshTokenPermitted(true).build();}
 private @NonNull OAuthGrantPolicy allow() {return (context,budget)->{this.policies.incrementAndGet();return OAuthAuthorizationDecision.withSubject(context.getSubject()).authorizedScopesByResource(context.getAuthorizedScopesByResource()).refreshTokenPermitted(context.isRefreshTokenPermitted()).build();};}
 private @NonNull String code() {return code(this.dynamic);}
 private @NonNull String code(@NonNull OAuthServerClientSelection selection) {
  assertEquals(OAuthStoreCommitStatus.COMMITTED,this.coordinator.initializeFreshIssuer(deadline()));this.coordinator.establishNewSubject("subject",deadline());
  var admission=OAuthServerAuthorizationAdmission.admit(authorize(null,REDIRECT),selection,deadline(),resources(),LIMITS,true,true);
  String handle=this.ledger.begin(admission,BROWSER,deadline());
  return this.ledger.complete(handle,BROWSER,selection.authorization(ID,resources(),deadline()),resources(),decision("subject"),deadline()).orElseThrow();
 }
 private @NonNull OAuthTokenResponse redeem(@NonNull String credential) {return this.codes.redeem(token(credential,false,Map.of(),null),this.dynamic,resources(),allow(),deadline());}
 private @NonNull OAuthTokenResponse rotate(@NonNull String credential) {return this.refresh.rotate(token(credential,true,Map.of(),null),this.dynamic,resources(),allow(),deadline());}
 private static @NonNull JsonObject body(@NonNull OAuthTokenResponse response) {try{return (JsonObject)JsonCodec.parse(response.body(),JsonLimits.jose(131072));}catch(com.revetsec.internal.json.JsonParseException failure){throw new AssertionError(failure);}}
 private static @NonNull String refreshValue(@NonNull OAuthTokenResponse response) {return body(response).findString("refresh_token").orElseThrow();}
 private @NonNull JsonObject row(OAuthStoreKey.@NonNull Kind kind) {return this.codec.open(this.store.rows.values().stream().filter(e->e.getKey().getKind()==kind).findFirst().orElseThrow(),Clock.fixed(NOW,ZoneOffset.UTC));}
 private static void failure(OAuthServerAdmissionFailure.@NonNull Reason reason,@NonNull Executable call) {
  var e=assertThrows(OAuthServerAdmissionFailure.class,call);assertEquals(reason,e.reason());assertNull(e.getCause());assertEquals("OAuth server admission failed.",e.getMessage());
 }
 private static void invalid(@NonNull Executable call) {failure(OAuthServerAdmissionFailure.Reason.INVALID_GRANT,call);}
 @TestFactory @NonNull Stream<@NonNull DynamicTest> missingOrEmptyClientIdentityCannotFetch() {
  return Stream.of("", "&client_id=").map(suffix->DynamicTest.dynamicTest("missing-id"+suffix,()->{
   var request=OAuthServerRequest.parse(OAuthServerRequest.Endpoint.TOKEN,"POST",null,("grant_type=refresh_token&refresh_token="+BROWSER+"&resource="+encode(RESOURCE)+suffix).getBytes(StandardCharsets.UTF_8),Map.of("Content-Type",List.of("application/x-www-form-urlencoded")),LIMITS);
   failure(OAuthServerAdmissionFailure.Reason.INVALID_CLIENT,()->this.dynamic.authenticate(request,resources(),deadline()));assertEquals(0,this.fetches.get());
  }));
 }
 @Test void exactRegisteredUrlHasPrecedenceWithoutCacheOrTransport() {
  var client=registered(false);var selected=selection((id,b)->Optional.of(client)).authorization(ID,resources(),deadline());
  assertSame(client,selected.client());assertEquals(OAuthAuthorizationRecord.clientFingerprint(client),selected.fingerprint());assertEquals(0,this.fetches.get());assertEquals(0,this.cacheReads.get());
 }
 @Test void registeredCodeAndRefreshNeedNoMetadataFetch() {
  var client=registered(false);var selection=selection((id,b)->Optional.of(client));String code=code(selection);
  var first=this.codes.redeem(token(code,false,Map.of(),null),selection,resources(),allow(),deadline());
  this.refresh.rotate(token(refreshValue(first),true,Map.of(),null),selection,resources(),allow(),deadline());assertEquals(0,this.fetches.get());assertEquals(0,this.cacheReads.get());
 }
 @Test void disabledMetadataUnknownUrlNeverFetches() {failure(OAuthServerAdmissionFailure.Reason.INVALID_CLIENT,()->new OAuthServerClientSelection((id,b)->Optional.empty(),LIMITS,null).authorization(ID,resources(),deadline()));assertEquals(0,this.fetches.get());}
 @Test void unknownNonUrlCannotFetch() {failure(OAuthServerAdmissionFailure.Reason.INVALID_CLIENT,()->this.dynamic.authorization("unregistered",resources(),deadline()));assertEquals(0,this.fetches.get());}
 @Test void registryFaultDoesNotFallThrough() {failure(OAuthServerAdmissionFailure.Reason.INFRASTRUCTURE,()->selection((id,b)->{throw new IllegalStateException("private");}).authorization(ID,resources(),deadline()));assertEquals(0,this.fetches.get());}
 @Test @SuppressWarnings("NullAway") void nullRegistryResultDoesNotFallThrough() {failure(OAuthServerAdmissionFailure.Reason.INFRASTRUCTURE,()->selection((id,b)->null).authorization(ID,resources(),deadline()));assertEquals(0,this.fetches.get());}
 @Test void registryMismatchedIdentityDoesNotFallThrough() {
  var wrong=OAuthServerClientRegistration.withClientId("wrong").configurationVersion("v1").authorizationCodePermitted(false).build();
  failure(OAuthServerAdmissionFailure.Reason.INFRASTRUCTURE,()->selection((id,b)->Optional.of(wrong)).authorization(ID,resources(),deadline()));assertEquals(0,this.fetches.get());
 }
 @Test void registryInterruptionPreservesFlagAndDoesNotFetch() {
  try{failure(OAuthServerAdmissionFailure.Reason.INFRASTRUCTURE,()->selection((id,b)->{Thread.currentThread().interrupt();throw new IllegalStateException();}).authorization(ID,resources(),deadline()));assertTrue(Thread.currentThread().isInterrupted());assertEquals(0,this.fetches.get());}finally{Thread.interrupted();}
 }
 @Test void registryFatalPropagates() {assertThrows(Fatal.class,()->selection((id,b)->{throw new Fatal();}).authorization(ID,resources(),deadline()));assertEquals(0,this.fetches.get());}
 @Test void confidentialRegisteredClientCannotFallBackToPublicMetadata() {failure(OAuthServerAdmissionFailure.Reason.INVALID_CLIENT,()->selection((id,b)->Optional.of(registered(true))).authenticate(token(BROWSER,false,Map.of(),null),resources(),deadline()));assertEquals(0,this.fetches.get());}
 @Test void basicUnknownNeverFetches() {failure(OAuthServerAdmissionFailure.Reason.INVALID_CLIENT,()->this.dynamic.authenticate(token(BROWSER,false,Map.of(),basic()),resources(),deadline()));assertEquals(0,this.fetches.get());}
 @Test void basicPublicRegistrationNeverFetchesOrDowngrades() {failure(OAuthServerAdmissionFailure.Reason.INVALID_CLIENT,()->selection((id,b)->Optional.of(registered(false))).authenticate(token(BROWSER,false,Map.of(),basic()),resources(),deadline()));assertEquals(0,this.fetches.get());}
 @Test void dynamicIntrospectionNeverFetches() {
  var request=OAuthServerRequest.parse(OAuthServerRequest.Endpoint.INTROSPECTION,"POST",null,("token=x&client_id="+encode(ID)).getBytes(StandardCharsets.UTF_8),Map.of("Content-Type",List.of("application/x-www-form-urlencoded")),LIMITS);
  failure(OAuthServerAdmissionFailure.Reason.INVALID_CLIENT,()->this.dynamic.authenticate(request,resources(),deadline()));assertEquals(0,this.fetches.get());
 }
 @Test void authorizationCannotUseTokenAuthenticationHelper() {assertThrows(OAuthServerAdmissionFailure.class,()->this.dynamic.authenticate(authorize(null,REDIRECT),resources(),deadline()));assertEquals(0,this.fetches.get());}
 @Test void metadataScopesCannotGrantOrRestrictConfiguredRequestCeiling() {
  change("scope",JsonString.fromValue("admin"));var admission=OAuthServerAuthorizationAdmission.admit(authorize(null,REDIRECT),this.dynamic,deadline(),resources(),LIMITS,true,true);
  assertEquals(Set.of("read","write"),admission.scopes());failure(OAuthServerAdmissionFailure.Reason.INVALID_SCOPE,()->OAuthServerAuthorizationAdmission.admit(authorize("admin",REDIRECT),this.dynamic,deadline(),resources(),LIMITS,true,true));
 }
 @Test void explicitScopeCanNarrowConfiguredCeiling() {var a=OAuthServerAuthorizationAdmission.admit(authorize("read",REDIRECT),this.dynamic,deadline(),resources(),LIMITS,true,true);assertEquals(Set.of("read"),a.scopes());}
 @Test void emptyConfiguredScopeCannotAuthorize() {failure(OAuthServerAdmissionFailure.Reason.INVALID_SCOPE,()->OAuthServerAuthorizationAdmission.admit(authorize(null,REDIRECT),this.dynamic,deadline(),Map.of(RESOURCE,Set.of()),LIMITS,true,true));}
 @Test void emptyAppApprovalCannotCreateCode() {
  this.coordinator.initializeFreshIssuer(deadline());this.coordinator.establishNewSubject("subject",deadline());var a=OAuthServerAuthorizationAdmission.admit(authorize(null,REDIRECT),this.dynamic,deadline(),resources(),LIMITS,true,true);
  String interaction=this.ledger.begin(a,BROWSER,deadline());assertTrue(this.ledger.complete(interaction,BROWSER,this.dynamic.authorization(ID,resources(),deadline()),resources(),OAuthAuthorizationDecision.withSubject("subject").authorizedScopesByResource(Map.of(RESOURCE,Set.of())).build(),deadline()).isEmpty());assertFalse(this.store.rows.keySet().stream().anyMatch(k->k.getKind()==OAuthStoreKey.Kind.CODE));
 }
 @Test void dynamicCodeAndRefreshEachFetchOwn200IgnoringSharedCache() {
  String code=code();assertEquals(1,this.fetches.get());int reads=this.cacheReads.get(),writes=this.cacheWrites.get();
  var response=redeem(code);assertEquals(2,this.fetches.get());assertEquals(reads,this.cacheReads.get());assertEquals(writes,this.cacheWrites.get());
  String first=refreshValue(response),second=refreshValue(rotate(first));assertNotEquals(first,second);assertEquals(3,this.fetches.get());rotate(second);assertEquals(4,this.fetches.get());assertEquals(3,this.policies.get());assertEquals(reads,this.cacheReads.get());assertEquals(writes,this.cacheWrites.get());
 }
 @Test void separateSelectorsSharingCacheStillFetchForEachCredentialOperation() {
  String code=code();var another=selection((id,b)->Optional.empty());another.authorization(ID,resources(),deadline());assertEquals(1,this.fetches.get());
  var first=this.codes.redeem(token(code,false,Map.of(),null),another,resources(),allow(),deadline());this.refresh.rotate(token(refreshValue(first),true,Map.of(),null),this.dynamic,resources(),allow(),deadline());assertEquals(3,this.fetches.get());
 }
 @Test void freshFetchFailureLeavesUnusedCodeUnconsumed() {
  String code=code();int commits=this.store.commits,reads=this.store.reads;this.transportFailure=true;
  failure(OAuthServerAdmissionFailure.Reason.INFRASTRUCTURE,()->redeem(code));assertEquals(commits,this.store.commits);assertEquals(reads,this.store.reads);assertEquals("UNUSED",row(OAuthStoreKey.Kind.CODE).findString("status").orElseThrow());assertEquals(0,this.policies.get());
  this.transportFailure=false;redeem(code);assertEquals("USED",row(OAuthStoreKey.Kind.CODE).findString("status").orElseThrow());
 }
 @Test void refreshFetchFailureLeavesCurrentFamilyUsable() {
  String credential=refreshValue(redeem(code()));int commits=this.store.commits;this.transportFailure=true;
  failure(OAuthServerAdmissionFailure.Reason.INFRASTRUCTURE,()->rotate(credential));assertEquals(commits,this.store.commits);assertEquals("ACTIVE",row(OAuthStoreKey.Kind.GRANT).findString("status").orElseThrow());this.transportFailure=false;rotate(credential);
 }
 @TestFactory @NonNull Stream<@NonNull DynamicTest> non200NeverConsumesCodeOrRefresh() {
  return Stream.of(204,301,302,304,400,404,429,500).flatMap(status->Stream.of(false,true).map(refresh->DynamicTest.dynamicTest("non200-"+status+"-"+refresh,()->{
   var t=new OAuthClientSelectionTests();String code=t.code(),credential=refresh?refreshValue(t.redeem(code)):code;int commits=t.store.commits;t.status=status;
   failure(OAuthServerAdmissionFailure.Reason.INFRASTRUCTURE,()->{if(refresh)t.rotate(credential);else t.redeem(credential);});assertEquals(commits,t.store.commits);
  })));
 }
 @TestFactory @NonNull Stream<@NonNull DynamicTest> invalidOrChangedSecurityNeverConsumesOrPoisons() {
  return Stream.of("client_id","token_endpoint_auth_method","redirect_uris","application_type","grant_types").flatMap(field->Stream.of(false,true).map(refresh->DynamicTest.dynamicTest("security-"+field+"-"+refresh,()->{
   var t=new OAuthClientSelectionTests();String code=t.code(),credential=refresh?refreshValue(t.redeem(code)):code;int commits=t.store.commits;
   JsonValue changed=switch(field){case "client_id"->JsonString.fromValue("https://other.example.com/metadata");case "token_endpoint_auth_method"->JsonString.fromValue("client_secret_basic");case "redirect_uris"->JsonArray.fromElements(List.of(JsonString.fromValue("https://client.example.com/other")));case "application_type"->JsonString.fromValue("native");default->JsonArray.fromElements(List.of(JsonString.fromValue("authorization_code")));};
   t.change(field,changed);assertThrows(OAuthServerAdmissionFailure.class,()->{if(refresh)t.rotate(credential);else t.redeem(credential);});assertEquals(commits,t.store.commits);assertEquals(refresh?"ACTIVE":"PENDING",t.row(OAuthStoreKey.Kind.GRANT).findString("status").orElseThrow());
   t.document=document();if(refresh)t.rotate(credential);else t.redeem(credential);
  })));
 }
 @Test void displayAndDeclaredScopeChangesDoNotInvalidateCodeOrFamily() {
  String code=code();change("client_name",JsonString.fromValue("Renamed"));change("scope",JsonString.fromValue("admin"));change("software_version",JsonString.fromValue("99"));
  String credential=refreshValue(redeem(code));change("client_name",JsonString.fromValue("Again"));rotate(credential);
 }
 @Test void sourceChangeDynamicToRegisteredRequiresNewAuthorization() {String code=code();int commits=this.store.commits;invalid(()->this.codes.redeem(token(code,false,Map.of(),null),selection((id,b)->Optional.of(registered(false))),resources(),allow(),deadline()));assertEquals(commits,this.store.commits);}
 @Test void sourceChangeRegisteredToDynamicRequiresNewAuthorization() {String code=code(selection((id,b)->Optional.of(registered(false))));int commits=this.store.commits;invalid(()->redeem(code));assertEquals(commits,this.store.commits);}
 @Test void sourceChangeDuringRefreshDoesNotPoisonWinner() {String credential=refreshValue(redeem(code()));int commits=this.store.commits;invalid(()->this.refresh.rotate(token(credential,true,Map.of(),null),selection((id,b)->Optional.of(registered(false))),resources(),allow(),deadline()));assertEquals(commits,this.store.commits);rotate(credential);}
 @Test void boundUsedCodeRequiresFresh200BeforeReplayInvalidation() {String code=code();redeem(code);int commits=this.store.commits;this.status=304;failure(OAuthServerAdmissionFailure.Reason.INFRASTRUCTURE,()->redeem(code));assertEquals(commits,this.store.commits);this.status=200;invalid(()->redeem(code));assertEquals("REVOKED",row(OAuthStoreKey.Kind.GRANT).findString("status").orElseThrow());}
 @Test void boundUsedRefreshRequiresFresh200BeforeReplayInvalidation() {String credential=refreshValue(redeem(code()));rotate(credential);int commits=this.store.commits;this.status=500;failure(OAuthServerAdmissionFailure.Reason.INFRASTRUCTURE,()->rotate(credential));assertEquals(commits,this.store.commits);this.status=200;invalid(()->rotate(credential));assertEquals("REVOKED",row(OAuthStoreKey.Kind.GRANT).findString("status").orElseThrow());}
 @Test void changedFingerprintOnUsedCodeCannotRevokeActiveGrant() {String code=code();redeem(code);int commits=this.store.commits;change("application_type",JsonString.fromValue("native"));invalid(()->redeem(code));assertEquals(commits,this.store.commits);assertEquals("ACTIVE",row(OAuthStoreKey.Kind.GRANT).findString("status").orElseThrow());}
 @Test void changedFingerprintOnUsedRefreshCannotRevokeRacingWinner() {String credential=refreshValue(redeem(code()));String next=refreshValue(rotate(credential));int commits=this.store.commits;change("application_type",JsonString.fromValue("native"));invalid(()->rotate(credential));assertEquals(commits,this.store.commits);this.document=document();rotate(next);}
 @Test void invalidBindingsCannotPoisonCodeGrant() {String code=code();for(var override:List.of(Map.of("code_verifier","x".repeat(43)),Map.of("resource","https://other.example.com/mcp"),Map.of("redirect_uri","https://client.example.com/other"))){int commits=this.store.commits;invalid(()->this.codes.redeem(token(code,false,override,null),this.dynamic,resources(),allow(),deadline()));assertEquals(commits,this.store.commits);}redeem(code);}
 @Test void conflictFetchesAgainAndDoesNotReuseFirstOperationResponse() {String code=code();this.store.conflicts=1;redeem(code);assertEquals(3,this.fetches.get());assertEquals(2,this.policies.get());}
 @Test void refreshConflictFetchesAgain() {String credential=refreshValue(redeem(code()));int before=this.fetches.get();this.store.conflicts=1;rotate(credential);assertEquals(before+2,this.fetches.get());}
 @Test void metadataChangeAfterConflictPreventsCredentialRelease() {String code=code();int before=this.fetches.get();this.store.conflicts=1;this.fetchHook=()->{if(this.fetches.get()==before+2)change("application_type",JsonString.fromValue("native"));};invalid(()->redeem(code));assertEquals("UNUSED",row(OAuthStoreKey.Kind.CODE).findString("status").orElseThrow());assertEquals("PENDING",row(OAuthStoreKey.Kind.GRANT).findString("status").orElseThrow());}
 @Test void originalDeadlineIsRetainedFromRegistryThroughFetchAndPolicy() {
  String code=code();Deadline deadline=deadline();AtomicReference<Duration> registryBudget=new AtomicReference<>(),policyBudget=new AtomicReference<>();
  var selection=selection((id,b)->{registryBudget.set(b);return Optional.empty();});this.codes.redeem(token(code,false,Map.of(),null),selection,resources(),(context,b)->{policyBudget.set(b);return decision(context.getSubject());},deadline);
  assertSame(deadline,this.observed.get());assertTrue(requireNonNull(policyBudget.get()).compareTo(requireNonNull(registryBudget.get()))<=0);for(Duration budget:this.store.budgets)assertTrue(!budget.isNegative() && !budget.isZero());
 }
 @Test void exhaustedFetchDeadlineDoesNotReadOrConsumeStore() {String code=code();int reads=this.store.reads,commits=this.store.commits;this.fetchHook=()->{try{Thread.sleep(30);}catch(InterruptedException e){Thread.currentThread().interrupt();}};failure(OAuthServerAdmissionFailure.Reason.INFRASTRUCTURE,()->this.codes.redeem(token(code,false,Map.of(),null),this.dynamic,resources(),allow(),Deadline.fromNow(Duration.ofMillis(10))));assertEquals(reads,this.store.reads);assertEquals(commits,this.store.commits);}
 @Test void fetchInterruptionDoesNotReadOrConsumeStore() {String code=code();int reads=this.store.reads,commits=this.store.commits;this.fetchHook=()->Thread.currentThread().interrupt();try{failure(OAuthServerAdmissionFailure.Reason.INFRASTRUCTURE,()->redeem(code));assertTrue(Thread.currentThread().isInterrupted());assertEquals(reads,this.store.reads);assertEquals(commits,this.store.commits);}finally{Thread.interrupted();}}
 @Test void applicationDenialStillTerminatesAfterFreshFetch() {String code=code();invalid(()->this.codes.redeem(token(code,false,Map.of(),null),this.dynamic,resources(),(context,b)->OAuthAuthorizationDecision.deniedInstance(),deadline()));assertEquals(2,this.fetches.get());assertEquals("CANCELLED",row(OAuthStoreKey.Kind.CODE).findString("status").orElseThrow());}
 @Test void callbackFaultAfterFetchLeavesUnusedCode() {String code=code();int commits=this.store.commits;failure(OAuthServerAdmissionFailure.Reason.INFRASTRUCTURE,()->this.codes.redeem(token(code,false,Map.of(),null),this.dynamic,resources(),(context,b)->{throw new IllegalStateException("private");},deadline()));assertEquals(commits,this.store.commits);assertEquals(2,this.fetches.get());redeem(code);}
 @Test void resumeAndCompleteUsePersistedSourceSeparatedFingerprint() {
  this.coordinator.initializeFreshIssuer(deadline());this.coordinator.establishNewSubject("subject",deadline());var a=OAuthServerAuthorizationAdmission.admit(authorize(null,REDIRECT),this.dynamic,deadline(),resources(),LIMITS,true,true);String handle=this.ledger.begin(a,BROWSER,deadline());
  var selected=this.dynamic.authorization(ID,resources(),deadline());assertEquals(selected.fingerprint(),this.ledger.resume(handle,BROWSER,selected,deadline()).text("clientHash"));
  assertThrows(OAuthServerAdmissionFailure.class,()->this.ledger.resume(handle,BROWSER,registered(false),deadline()));assertThrows(OAuthServerAdmissionFailure.class,()->this.ledger.complete(handle,BROWSER,registered(false),resources(),decision("subject"),deadline()));
  assertTrue(this.ledger.complete(handle,BROWSER,selected,resources(),decision("subject"),deadline()).isPresent());
 }
 @Test void metadataSnapshotCannotBypassFreshCredentialSelection() {String code=code();var old=this.dynamic.authorization(ID,resources(),deadline());assertNotNull(old.client());this.status=304;failure(OAuthServerAdmissionFailure.Reason.INFRASTRUCTURE,()->redeem(code));assertEquals("UNUSED",row(OAuthStoreKey.Kind.CODE).findString("status").orElseThrow());}
 @Test void internalDiagnosticsRedactClientAndFingerprint() {var selected=this.dynamic.authorization(ID,resources(),deadline());for(String text:List.of(selected.toString(),this.dynamic.toString())){assertFalse(text.contains(ID));assertFalse(text.contains(selected.fingerprint()));assertTrue(text.contains("redacted"));}}
 private static final class Fatal extends VirtualMachineError {private static final long serialVersionUID=1L;Fatal(){super("fixture");}}
}
