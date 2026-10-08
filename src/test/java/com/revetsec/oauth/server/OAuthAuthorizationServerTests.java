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
import com.revetsec.SealingKey;
import com.revetsec.OutboundUriPolicy;
import com.revetsec.internal.encoding.FormUrlEncoding;
import com.revetsec.internal.http.Deadline;
import com.revetsec.internal.oauth.OidcTransactionAccess;
import com.revetsec.internal.json.JsonCodec;
import com.revetsec.internal.json.JsonLimits;
import com.revetsec.json.JsonObject;
import com.revetsec.jose.JwsAlgorithm;
import com.revetsec.jose.StaticJsonWebKeySource;
import com.revetsec.jose.JsonWebKeySet;
import com.revetsec.oauth.BearerToken;
import com.revetsec.oauth.JwtAccessTokenValidator;
import com.revetsec.oauth.OAuthTransportFailureFixture;
import com.revetsec.testing.TestJsonWebKeys;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.function.Executable;
import java.net.URI;
import java.net.InetAddress;
import java.lang.reflect.InvocationTargetException;
import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.AbstractMap;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Function;
import java.util.stream.Stream;
import static org.junit.jupiter.api.Assertions.*;
import static java.util.Objects.requireNonNull;
import static com.revetsec.oauth.server.OAuthServerException.Reason.*;

/** Public engine integration with an atomic single-process fixture; no durability/distributed claim. */
final class OAuthAuthorizationServerTests {
 private static final @NonNull String ISSUER="https://issuer.example/tenant",RESOURCE="https://resource.example/mcp",REDIRECT="https://client.example/cb?original=%2f";
 private static final @NonNull String BROWSER="A".repeat(43),VERIFIER="dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",CHALLENGE="E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
 private static final @NonNull Instant NOW=Instant.parse("2026-10-06T12:00:00Z");
 private static final TestJsonWebKeys.@NonNull Fixture KEY=TestJsonWebKeys.Fixture.IDP_SIGNING_RSA_2048;
 private final @NonNull OAuthAtomicStoreFixture store=new OAuthAtomicStoreFixture();
 private final @NonNull MutableClock clock=new MutableClock();
 private final @NonNull List<@NonNull OAuthGrantContext> contexts=new ArrayList<>();
 private @NonNull OAuthServerClientRegistration client=client("client");
 private @Nullable OAuthGrantPolicy override;
 private @Nullable Throwable policyFault;
 private @Nullable Runnable policyHook;
 private @NonNull OAuthAuthorizationServer server=builder().build();
 OAuthAuthorizationServerTests() { }
 private static @NonNull Map<@NonNull String,@NonNull Set<@NonNull String>> resources() {return Map.of(RESOURCE,Set.of("read","write"));}
 private static @NonNull OAuthServerClientRegistration client(@NonNull String id) {
  return OAuthServerClientRegistration.withClientId(id).configurationVersion("v1").redirectUris(List.of(URI.create(REDIRECT)))
   .allowedScopesByResource(resources()).refreshTokenPermitted(true).build();
 }
 private static @NonNull StateSealer sealer() {
  byte[] material=new byte[32];for(int i=0;i<material.length;i++)material[i]=(byte)(i+1);
  return StateSealer.withActiveKey(SealingKey.fromBase64("key",Base64.getEncoder().encodeToString(material))).build();
 }
 private static @NonNull OAuthIssuerKeySnapshot keys() {
  return OAuthIssuerKeySnapshot.withActiveKey(OAuthIssuerSigningKey.fromKeyPair("key",KEY.getPrivateKey(),KEY.getPublicKey()))
   .generation("g1").publishedAt(NOW.minusSeconds(120)).build();
 }
 private OAuthAuthorizationServer.@NonNull Builder builder() {
  return OAuthAuthorizationServer.withIssuer(ISSUER).authorizationEndpoint(URI.create(ISSUER+"/authorize")).tokenEndpoint(URI.create(ISSUER+"/token"))
   .jsonWebKeySetEndpoint(URI.create(ISSUER+"/jwks")).revocationEndpoint(URI.create(ISSUER+"/revoke")).introspectionEndpoint(URI.create(ISSUER+"/introspect"))
   .clientRepository((id,b)->Optional.of(id.equals("resource") ? resourceClient() : this.client)).store(this.store)
   .signingKeys(OAuthIssuerKeyProvider.fromSnapshot(keys())).stateSealer(sealer()).resources(resources()).clock(this.clock)
   .grantPolicy((context,budget)->{this.contexts.add(context);Runnable hook=this.policyHook;this.policyHook=null;if(hook!=null) hook.run();
    if(this.policyFault!=null) raise(this.policyFault);OAuthGrantPolicy policy=this.override;
    return policy==null ? decision(context.getSubject(),requireNonNull(context.getAuthorizedScopesByResource().get(RESOURCE)),context.isRefreshTokenPermitted()) : policy.authorizeGrant(context,budget);})
   .refreshTokensEnabled(true);
 }
 private static @NonNull OAuthAuthorizationServer constructForRuntime(OAuthAuthorizationServer.@NonNull Builder builder,
   Runtime.@NonNull Version version) {
  try {
   var constructor=OAuthAuthorizationServer.class.getDeclaredConstructor(OAuthAuthorizationServer.Builder.class,Runtime.Version.class);
   constructor.setAccessible(true);
   return constructor.newInstance(builder,version);
  } catch(InvocationTargetException failure) {
   Throwable cause=requireNonNull(failure.getCause());
   if(cause instanceof RuntimeException unchecked) throw unchecked;
   if(cause instanceof Error fatal) throw fatal;
   throw new AssertionError(cause);
  } catch(ReflectiveOperationException failure) { throw new AssertionError(failure); }
 }
 private static @NonNull OAuthServerClientRegistration resourceClient() {
  return OAuthServerClientRegistration.withClientId("resource").configurationVersion("r1").authorizationCodePermitted(false)
   .introspectionResources(Set.of(RESOURCE)).authentication(OAuthServerClientAuthentication.fromClientSecretVerifier((id,secret,budget)->java.util.Arrays.equals(secret,"secret".getBytes(StandardCharsets.UTF_8)))).build();
 }
 private static @NonNull OAuthAuthorizationDecision decision(@NonNull String subject,@NonNull Set<@NonNull String> scopes,boolean refresh) {
  return OAuthAuthorizationDecision.withSubject(subject).authorizedScopesByResource(Map.of(RESOURCE,scopes)).refreshTokenPermitted(refresh).build();
 }
 private static @NonNull String encode(@NonNull String value) {try{return FormUrlEncoding.encode(value);}catch(com.revetsec.internal.encoding.EncodingException e){throw new AssertionError(e);}}
 private static @NonNull String form(@NonNull Map<@NonNull String,@NonNull String> parameters) {return String.join("&",parameters.entrySet().stream().map(e->encode(e.getKey())+"="+encode(e.getValue())).toList());}
 private static byte @NonNull [] bytes(@NonNull String value) {return value.getBytes(StandardCharsets.UTF_8);}
 private static @NonNull Map<@NonNull String,@NonNull List<@NonNull String>> headers() {return Map.of("Content-Type",List.of("application/x-www-form-urlencoded"));}
 private static @NonNull JsonObject json(@NonNull OAuthServerResponse response) {try{return (JsonObject)JsonCodec.parse(response.toHttpBodyWithCredentials(),JsonLimits.protocolDocument(131072));}catch(com.revetsec.internal.json.JsonParseException e){throw new AssertionError(e);}}
 private static @NonNull BearerToken bearer(@NonNull String token) {return BearerToken.fromAuthorizationHeaderValues(List.of("Bearer "+token)).orElseThrow();}
 private void initialized() {assertEquals(OAuthStoreCommitStatus.COMMITTED,this.server.initializeFreshIssuer());this.server.establishNewSubject("subject");}
 private @NonNull String query() {return form(Map.of("client_id",this.client.getClientId(),"response_type","code","redirect_uri",REDIRECT,"resource",RESOURCE,"code_challenge",CHALLENGE,"code_challenge_method","S256","state","original-state"));}
 private @NonNull OAuthServerInteraction begin() {return assertInstanceOf(OAuthAuthorizationResult.InteractionRequired.class,this.server.beginAuthorizationResult("GET",query(),new byte[0],Map.of(),BROWSER)).getInteraction();}
 private @NonNull String code() {
  OAuthServerInteraction interaction=begin();OAuthServerResponse response=assertInstanceOf(OAuthAuthorizationResult.Completed.class,
   this.server.completeAuthorizationResult(interaction.getInteractionValue(),BROWSER,decision("subject",Set.of("read","write"),true))).getResponse();
  assertEquals(303,response.getStatusCode());String location=response.getLocationWithCredentials().orElseThrow().toString();assertTrue(location.startsWith(REDIRECT+"&code=rsc1_"));
  return location.substring(location.indexOf("code=")+5,location.indexOf("&state="));
 }
 private @NonNull OAuthTokenResult redeem(@NonNull String code) {return this.server.tokenResult("POST",null,bytes(form(Map.of("grant_type","authorization_code","client_id",this.client.getClientId(),"resource",RESOURCE,"code",code,"code_verifier",VERIFIER,"redirect_uri",REDIRECT))),headers());}
 private @NonNull JsonObject issued() {initialized();return json(assertInstanceOf(OAuthTokenResult.Succeeded.class,redeem(code())).getResponse());}
 private @NonNull OAuthTokenResult rotate(@NonNull String refresh) {return this.server.tokenResult("POST",null,bytes(form(Map.of("grant_type","refresh_token","client_id",this.client.getClientId(),"resource",RESOURCE,"refresh_token",refresh))),headers());}
 private @NonNull OAuthRevocationResult revoke(@NonNull String token) {return this.server.revokeResult("POST",null,bytes(form(Map.of("client_id",this.client.getClientId(),"token",token))),headers());}
 private @NonNull OAuthIntrospectionResult introspect(@NonNull String token) {Map<String,List<String>> h=new LinkedHashMap<>(headers());h.put("Authorization",List.of("Basic "+Base64.getEncoder().encodeToString(bytes("resource:secret"))));return this.server.introspectionResult("POST",null,bytes(form(Map.of("token",token))),h);}
 private static @NonNull DynamicTest test(@NonNull String name,@NonNull Executable call) {return DynamicTest.dynamicTest(name,call);}
 @Test void publicFlowRechecksPolicyAndReleasesProofOnlyAfterAtomicStatus() {
  JsonObject one=issued();String token=one.findString("access_token").orElseThrow();
  OAuthIssuerAccessTokenResult.Succeeded checked=assertInstanceOf(OAuthIssuerAccessTokenResult.Succeeded.class,this.server.validateAccessTokenResult(bearer(token),RESOURCE));
  assertEquals(Optional.of("subject"),checked.getAccessToken().getSubject());assertEquals(Set.of("read","write"),checked.getAccessToken().getScopes());
  assertEquals(4,requireNonNull(this.store.lastTransaction).getConditions().size());assertTrue(requireNonNull(this.store.lastTransaction).getMutations().isEmpty());
  assertEquals(2,this.contexts.size());assertEquals(this.contexts.get(0).getGrantValue(),this.contexts.get(1).getGrantValue());
  assertEquals("authorization_code",this.contexts.get(0).getGrantType());
  assertTrue(json(assertInstanceOf(OAuthIntrospectionResult.Succeeded.class,introspect(token)).getResponse()).findBoolean("active").orElseThrow());
  JsonObject two=json(assertInstanceOf(OAuthTokenResult.Succeeded.class,rotate(one.findString("refresh_token").orElseThrow())).getResponse());assertEquals(3,this.contexts.size());
  assertEquals("refresh_token",this.contexts.get(2).getGrantType());assertEquals(this.contexts.get(0).getGrantValue(),this.contexts.get(2).getGrantValue());
  assertInstanceOf(OAuthRevocationResult.Succeeded.class,revoke(two.findString("access_token").orElseThrow()));
  assertInstanceOf(OAuthIssuerAccessTokenResult.Rejected.class,this.server.validateAccessTokenResult(bearer(token),RESOURCE));
  assertFalse(json(assertInstanceOf(OAuthIntrospectionResult.Succeeded.class,introspect(token)).getResponse()).findBoolean("active").orElseThrow());
 }
 @TestFactory @NonNull Stream<@NonNull DynamicTest> initialPolicyCannotWidenOrChangeSubjectOrRefresh() {
  return Stream.of("subject","scope","resource","extra-resource","refresh","null","fault","denied","empty","narrowed").map(which->test(which,()->{
   var f=new OAuthAuthorizationServerTests();f.initialized();OAuthServerInteraction interaction=f.begin();var before=Map.copyOf(f.store.rows);
   f.override=(context,budget)->switch(which) {
    case "subject"->decision("different",Set.of("read"),false);
    case "scope"->decision("subject",Set.of("admin"),false);
    case "resource"->OAuthAuthorizationDecision.withSubject("subject").authorizedScopesByResource(Map.of("urn:wrong",Set.of("read"))).build();
    case "extra-resource"->OAuthAuthorizationDecision.withSubject("subject").authorizedScopesByResource(Map.of(RESOURCE,Set.of("read"),"urn:wrong",Set.of("read"))).build();
    case "denied"->OAuthAuthorizationDecision.deniedInstance();
    case "empty"->decision("subject",Set.of(),false);
    case "refresh"->decision("subject",Set.of("read"),true);
    default->decision("subject",Set.of("read"),false);
   };
   if(which.equals("null"))f.override=(context,budget)->invalidNullDecision();
   if(which.equals("fault"))f.policyFault=new IllegalStateException("sensitive app text");
   Executable complete=()->f.server.completeAuthorizationResult(interaction.getInteractionValue(),BROWSER,decision("subject",Set.of("read","write"),!which.equals("refresh")));
   if(Set.of("subject","scope","resource","extra-resource","refresh","null","fault").contains(which)) {
    OAuthServerConfigurationException failure=assertThrows(OAuthServerConfigurationException.class,complete);assertEquals(CONFIGURATION_INVALID,failure.getReason());assertNull(failure.getCause());assertEquals(before,f.store.rows);
   } else {
    OAuthAuthorizationResult result=f.server.completeAuthorizationResult(interaction.getInteractionValue(),BROWSER,decision("subject",Set.of("read","write"),true));
    if(which.equals("narrowed")) {assertInstanceOf(OAuthAuthorizationResult.Completed.class,result);assertEquals(Set.of("read","write"),f.contexts.get(0).getAuthorizedScopesByResource().get(RESOURCE));}
    else {OAuthServerResponse response=assertInstanceOf(OAuthAuthorizationResult.Denied.class,result).getResponse();assertTrue(response.getLocationWithCredentials().orElseThrow().toString().contains("error=access_denied"));}
   }
  }));
 }
 @SuppressWarnings("NullAway") private static @NonNull OAuthAuthorizationDecision invalidNullDecision() {return null;}
 @Test void completionConflictReloadsClientAndPolicyInsteadOfReusingApproval() {
  initialized();OAuthServerInteraction interaction=begin();AtomicInteger calls=new AtomicInteger();this.override=(context,b)->{calls.incrementAndGet();if(calls.get()==1)this.store.conflicts=1;return decision("subject",Set.of("read"),false);};
  assertInstanceOf(OAuthAuthorizationResult.Completed.class,this.server.completeAuthorizationResult(interaction.getInteractionValue(),BROWSER,decision("subject",Set.of("read"),false)));assertEquals(2,calls.get());
 }
 @TestFactory @NonNull Stream<@NonNull DynamicTest> consentBindingsAndReplayRejectWithoutRedirect() {
  return Stream.of("handle","browser","expired","completed","client-change","issuer-fence").map(which->test(which,()->{
   var f=new OAuthAuthorizationServerTests();f.initialized();var interaction=f.begin();String handle=interaction.getInteractionValue(),browser=BROWSER;
   if(which.equals("handle"))handle="B".repeat(42)+"A";
   if(which.equals("browser"))browser="B".repeat(42)+"A";
   if(which.equals("expired"))f.clock.time=NOW.plusSeconds(900);
   if(which.equals("completed"))assertInstanceOf(OAuthAuthorizationResult.Denied.class,f.server.completeAuthorizationResult(handle,browser,OAuthAuthorizationDecision.deniedInstance()));
   if(which.equals("client-change"))f.client=OAuthServerClientRegistration.withClientId("client").configurationVersion("v2").redirectUris(List.of(URI.create(REDIRECT))).allowedScopesByResource(resources()).build();
   if(which.equals("issuer-fence"))f.server.revokeAllGrants();
   var rejected=assertInstanceOf(OAuthAuthorizationResult.Rejected.class,f.server.resumeAuthorizationResult(handle,browser));assertTrue(rejected.getResponse().getLocationWithCredentials().isEmpty());
  }));
 }
 @Test void explicitConsentDenialDoesNotCallPolicyOrCreateGrant() {
  initialized();var interaction=begin();assertInstanceOf(OAuthAuthorizationResult.InteractionRequired.class,this.server.resumeAuthorizationResult(interaction.getInteractionValue(),BROWSER));
  assertInstanceOf(OAuthAuthorizationResult.Denied.class,this.server.completeAuthorizationResult(interaction.getInteractionValue(),BROWSER,OAuthAuthorizationDecision.deniedInstance()));assertTrue(this.contexts.isEmpty());
  assertTrue(this.store.rows.keySet().stream().noneMatch(k->k.getKind()==OAuthStoreKey.Kind.GRANT));
 }
 @TestFactory @NonNull Stream<@NonNull DynamicTest> unknownTransitionsNeverReleaseOrAutomaticallyRetry() {
  return Stream.of("initialize","begin","complete","redeem","validate","refresh","revoke","subject","issuer","grant","reseal").flatMap(which->Stream.of(false,true).map(after->test(which+after,()->{
   var f=new OAuthAuthorizationServerTests();String handle=null,code=null,token=null,refresh=null,grant=null;OAuthStoreKey key=null;
   if(!which.equals("initialize")) {f.initialized();key=f.store.rows.keySet().iterator().next();}
   if(which.equals("complete"))handle=f.begin().getInteractionValue();
   if(which.equals("redeem"))code=f.code();
   if(Set.of("validate","refresh","revoke","grant").contains(which)) {JsonObject one=json(assertInstanceOf(OAuthTokenResult.Succeeded.class,f.redeem(f.code())).getResponse());token=one.findString("access_token").orElseThrow();refresh=one.findString("refresh_token").orElseThrow();grant=f.contexts.get(0).getGrantValue();}
   String h=handle,co=code,to=token,re=refresh,gr=grant;OAuthStoreKey k=key;
   f.store.unknownBefore=!after;f.store.unknownAfter=after;int commits=f.store.commits;
   if(which.equals("initialize"))assertEquals(OAuthStoreCommitStatus.UNKNOWN,f.server.initializeFreshIssuer());
   else if(which.equals("reseal"))assertEquals(OAuthStoreCommitStatus.UNKNOWN,f.server.resealStoreEntry(requireNonNull(k)));
   else {
    Executable operation=switch(which) {case "begin"->f::begin;case "complete"->()->f.server.completeAuthorizationResult(requireNonNull(h),BROWSER,decision("subject",Set.of("read"),true));case "redeem"->()->f.redeem(requireNonNull(co));case "validate"->()->f.server.validateAccessTokenResult(bearer(requireNonNull(to)),RESOURCE);case "refresh"->()->f.rotate(requireNonNull(re));case "revoke"->()->f.revoke(requireNonNull(to));case "subject"->()->f.server.revokeSubject("subject");case "issuer"->f.server::revokeAllGrants;default->()->f.server.revokeGrant(requireNonNull(gr));};
    OAuthServerStoreException failure=assertThrows(OAuthServerStoreException.class,operation);assertEquals(COMMIT_OUTCOME_UNKNOWN,failure.getReason());assertFalse(failure.isTransient());assertEquals(503,f.server.responseForFailure(failure).getStatusCode());
   }
   assertEquals(commits+1,f.store.commits);
  })));
 }
 @TestFactory @NonNull Stream<@NonNull DynamicTest> trustedRevocationsInvalidateSubsequentProofs() {
  return Stream.of("grant","subject","issuer","refresh-replay","code-replay").map(which->test(which,()->{
   var f=new OAuthAuthorizationServerTests();f.initialized();String code=f.code();JsonObject one=json(assertInstanceOf(OAuthTokenResult.Succeeded.class,f.redeem(code)).getResponse());String token=one.findString("access_token").orElseThrow();
   switch(which){case "grant"->f.server.revokeGrant(f.contexts.get(0).getGrantValue());case "subject"->f.server.revokeSubject("subject");case "issuer"->f.server.revokeAllGrants();case "code-replay"->assertInstanceOf(OAuthTokenResult.Rejected.class,f.redeem(code));default->{String refresh=one.findString("refresh_token").orElseThrow();assertInstanceOf(OAuthTokenResult.Succeeded.class,f.rotate(refresh));assertInstanceOf(OAuthTokenResult.Rejected.class,f.rotate(refresh));}}
   assertInstanceOf(OAuthIssuerAccessTokenResult.Rejected.class,f.server.validateAccessTokenResult(bearer(token),RESOURCE));
  }));
 }
 @TestFactory @NonNull Stream<@NonNull DynamicTest> m5RejectionPrecedesBackendAndOnlineAbsenceIsNotCached() {
  return Stream.of("malformed","wrong-issuer","wrong-audience","expired","missing-jti","oversize").map(which->test(which,()->{
   var f=new OAuthAuthorizationServerTests();JsonObject one=f.issued();String token=one.findString("access_token").orElseThrow();
   if(which.equals("malformed"))token="malformed";
   else if(which.equals("oversize"))token="A".repeat(16385);
   else if(which.equals("expired"))f.clock.time=NOW.plusSeconds(331);
   else {String[] parts=token.split("\\.",-1);JsonObject original;
    try{original=(JsonObject)JsonCodec.parse(Base64.getUrlDecoder().decode(parts[1]),JsonLimits.jose(65536));}catch(com.revetsec.internal.json.JsonParseException e){throw new AssertionError(e);}
    JsonObject.Builder claims=JsonObject.builder();for(var member:original.getMembers().entrySet())if(!(member.getKey().equals("jti")&&which.equals("missing-jti")) && !(member.getKey().equals("iss")&&which.equals("wrong-issuer")) && !(member.getKey().equals("aud")&&which.equals("wrong-audience")))claims.put(member.getKey(),member.getValue());
    if(which.equals("wrong-issuer"))claims.put("iss","https://wrong.example");if(which.equals("wrong-audience"))claims.put("aud","urn:wrong");
    token=com.revetsec.jose.JwsSigner.fromRsaKeyPair(KEY.getPrivateKey(),KEY.getPublicKey(),JwsAlgorithm.RS256).toCompactSerialization("at+jwt","key",null,JsonCodec.toUtf8Bytes(claims.build()),Duration.ofSeconds(1));
   }
   int reads=f.store.reads;var result=assertInstanceOf(OAuthIssuerAccessTokenResult.Rejected.class,f.server.validateAccessTokenResult(bearer(token),RESOURCE));assertEquals(reads,f.store.reads);
   if(!which.equals("oversize"))assertTrue(result.getAccessTokenReason().isPresent());else assertEquals(MALFORMED_REQUEST,result.getReason());
  }));
 }
 @Test void proofAbsenceRequiresBarrierAndLaterRequestsObserveRevocation() {
  JsonObject one=issued();String token=one.findString("access_token").orElseThrow();OAuthStoreKey issuance=this.store.rows.keySet().stream().filter(k->k.getKind()==OAuthStoreKey.Kind.ACCESS_TOKEN).findFirst().orElseThrow();this.store.rows.remove(issuance);
  assertInstanceOf(OAuthIssuerAccessTokenResult.Rejected.class,this.server.validateAccessTokenResult(bearer(token),RESOURCE));assertEquals(2,requireNonNull(this.store.lastTransaction).getConditions().size());
 }
 @Test void originalBudgetIsSharedAcrossM5AndAuthoritativeCallbacks() {
  this.server=builder().totalDeadline(Duration.ofSeconds(1)).requestTimeout(Duration.ofSeconds(1)).build();JsonObject one=issued();String token=one.findString("access_token").orElseThrow();
  this.clock.hook=()->{long end=System.nanoTime()+1_050_000_000L;while(System.nanoTime()<end)Thread.onSpinWait();};int reads=this.store.reads;
  OAuthServerException failure=assertThrows(OAuthServerException.class,()->this.server.validateAccessTokenResult(bearer(token),RESOURCE));assertEquals(reads,this.store.reads);assertTrue(Set.of(STORE_UNAVAILABLE,CONFIGURATION_INVALID).contains(failure.getReason()));
 }
 @Test void resealPreservesAuthorityRetentionAndUsesCAS() {
  JsonObject one=issued();String token=one.findString("access_token").orElseThrow();for(OAuthStoreKey key:List.copyOf(this.store.rows.keySet())) {OAuthStoreEntry old=requireNonNull(this.store.rows.get(key));assertEquals(OAuthStoreCommitStatus.COMMITTED,this.server.resealStoreEntry(key));OAuthStoreEntry next=requireNonNull(this.store.rows.get(key));assertNotEquals(old.getVersion(),next.getVersion());assertEquals(old.getRetainUntil(),next.getRetainUntil());}
  assertInstanceOf(OAuthIssuerAccessTokenResult.Succeeded.class,this.server.validateAccessTokenResult(bearer(token),RESOURCE));this.store.conflicts=1;assertEquals(OAuthStoreCommitStatus.CONFLICT,this.server.resealStoreEntry(this.store.rows.keySet().iterator().next()));
  OAuthStoreKey absent=OAuthStoreFormat.key(OAuthStoreFormat.namespace(this.store.rows.keySet().iterator().next()),OAuthStoreKey.Kind.GRANT,"A".repeat(43));assertEquals(OAuthStoreCommitStatus.CONFLICT,this.server.resealStoreEntry(absent));
 }
 @Test void resealCannotCommitAcrossAnIssuerFenceAdvance() {
  issued();OAuthStoreKey access=this.store.rows.keySet().stream()
   .filter(key->key.getKind()==OAuthStoreKey.Kind.ACCESS_TOKEN).findFirst().orElseThrow();
  OAuthStoreEntry original=requireNonNull(this.store.rows.get(access));
  this.store.beforeCommit=this.server::revokeAllGrants;
  assertEquals(OAuthStoreCommitStatus.CONFLICT,this.server.resealStoreEntry(access));
  assertSame(original,this.store.rows.get(access));
 }
 @Test void resealRejectsAuthenticatedButMalformedPermanentFencePayload() {
  issued();OAuthStoreKey subject=this.store.rows.keySet().stream()
   .filter(key->key.getKind()==OAuthStoreKey.Kind.SUBJECT_STATE).findFirst().orElseThrow();
  OAuthStoreEntry old=requireNonNull(this.store.rows.get(subject));
  OAuthStoreRecordCodec codec=new OAuthStoreRecordCodec(ISSUER,sealer(),3800);
  this.store.rows.put(subject,codec.seal(subject,old.getRetainUntil(),"{}"));
  OAuthServerStoreException failure=assertThrows(OAuthServerStoreException.class,
   ()->this.server.resealStoreEntry(subject));
  assertEquals(STORE_CORRUPT,failure.getReason());
 }
 @Test void authorizationBeginCannotReleaseAnInteractionAfterItsCommitExpiry() {
  initialized();this.store.beforeCommit=()->this.clock.time=NOW.plusSeconds(900);
  OAuthServerStoreException failure=assertThrows(OAuthServerStoreException.class,this::begin);
  assertEquals(STORE_UNAVAILABLE,failure.getReason());
 }
 @Test void malformedBrowserBindingDoesNotCallTheApplicationClientRepository() {
  AtomicInteger lookups=new AtomicInteger();
  this.server=builder().clientRepository((id,budget)->{lookups.incrementAndGet();return Optional.of(this.client);}).build();
  OAuthAuthorizationResult.Rejected rejected=assertInstanceOf(OAuthAuthorizationResult.Rejected.class,
   this.server.beginAuthorizationResult("GET",query(),new byte[0],Map.of(),"invalid"));
  assertEquals(MALFORMED_REQUEST,rejected.getReason());
  assertEquals(0,lookups.get());
  assertTrue(this.store.rows.isEmpty());
 }
 @Test void authorizationClientLookupBarrierRetainsTheInteractionExpiry() {
  initialized();OAuthServerInteraction interaction=begin();
  this.store.beforeCommit=()->this.clock.time=NOW.plusSeconds(900);
  OAuthServerStoreException failure=assertThrows(OAuthServerStoreException.class,
   ()->this.server.resumeAuthorizationResult(interaction.getInteractionValue(),BROWSER));
  assertEquals(STORE_UNAVAILABLE,failure.getReason());
 }
 @Test void authorizationResumeBarrierRetainsTheInteractionExpiry() {
  initialized();OAuthServerInteraction interaction=begin();
  this.server=builder().clientRepository((id,budget)->{
   this.store.beforeCommit=()->this.clock.time=NOW.plusSeconds(900);
   return Optional.of(this.client);
  }).build();
  OAuthServerStoreException failure=assertThrows(OAuthServerStoreException.class,
   ()->this.server.resumeAuthorizationResult(interaction.getInteractionValue(),BROWSER));
  assertEquals(STORE_UNAVAILABLE,failure.getReason());
 }
 @Test void authorizationDenialCannotCommitAfterItsInteractionExpiry() {
  initialized();OAuthServerInteraction interaction=begin();
  this.server=builder().clientRepository((id,budget)->{
   this.store.beforeCommit=()->this.clock.time=NOW.plusSeconds(900);
   return Optional.of(this.client);
  }).build();
  OAuthServerStoreException failure=assertThrows(OAuthServerStoreException.class,
   ()->this.server.completeAuthorizationResult(interaction.getInteractionValue(),BROWSER,
    OAuthAuthorizationDecision.deniedInstance()));
  assertEquals(STORE_UNAVAILABLE,failure.getReason());
 }
 @TestFactory @NonNull Stream<@NonNull DynamicTest> missingOrCorruptPermanentStateNeverInitializesOnTraffic() {
  return Stream.of("issuer","subject","corrupt","warm-up").map(which->test(which,()->{
   var f=new OAuthAuthorizationServerTests();JsonObject one=f.issued();String token=one.findString("access_token").orElseThrow();int size=f.store.rows.size();
   OAuthStoreKey key=f.store.rows.keySet().stream().filter(k->k.getKind()==(which.equals("subject")?OAuthStoreKey.Kind.SUBJECT_STATE:OAuthStoreKey.Kind.ISSUER_STATE)).findFirst().orElseThrow();
   if(which.equals("corrupt")){OAuthStoreEntry old=requireNonNull(f.store.rows.get(key));f.store.rows.put(key,OAuthStoreEntry.fromStoredForm(key,old.getVersion(),old.getRetainUntil(),"corrupt"));}else f.store.rows.remove(key);
   Executable operation=which.equals("warm-up")?f.server::warmUp:()->f.server.validateAccessTokenResult(bearer(token),RESOURCE);
   OAuthServerStoreException failure=assertThrows(OAuthServerStoreException.class,operation);assertEquals(STORE_CORRUPT,failure.getReason());assertEquals(size-(which.equals("corrupt")?0:1),f.store.rows.size());
  }));
 }
 @Test void metadataJwksAndWarmUpUseConfiguredAuthorityAndDoNotFetchClients() {
  initialized();this.server.warmUp();JsonObject metadata=json(this.server.metadataResponse("GET"));assertEquals(ISSUER,metadata.findString("issuer").orElseThrow());assertTrue(metadata.getMembers().containsKey("revocation_endpoint"));
  assertEquals(0,this.server.metadataResponse("HEAD").toHttpBodyWithCredentials().length);assertEquals(405,this.server.metadataResponse("POST").getStatusCode());
  assertTrue(json(this.server.jsonWebKeySetResponse("GET")).getMembers().containsKey("keys"));assertEquals(0,this.server.jsonWebKeySetResponse("HEAD").toHttpBodyWithCredentials().length);assertEquals(405,this.server.jsonWebKeySetResponse("DELETE").getStatusCode());
  assertEquals(ISSUER,this.server.getIssuer());assertEquals(URI.create(ISSUER+"/authorize"),this.server.getAuthorizationEndpoint());assertEquals(URI.create(ISSUER+"/token"),this.server.getTokenEndpoint());assertEquals(URI.create(ISSUER+"/jwks"),this.server.getJsonWebKeySetEndpoint());assertEquals(URI.create(ISSUER+"/revoke"),this.server.getRevocationEndpoint().orElseThrow());assertEquals(URI.create(ISSUER+"/introspect"),this.server.getIntrospectionEndpoint().orElseThrow());
  assertEquals("OAuthAuthorizationServer{<redacted>}",this.server.toString());assertEquals("OAuthAuthorizationServer.Builder{<redacted>}",builder().toString());
 }
 @TestFactory @NonNull Stream<@NonNull DynamicTest> publicIngressRejectsBeforeAnyApplicationLookup() {
  return Stream.of("method","body","query","duplicate","encoding","mime","charset","query-credential","unknown-grant","basic","unknown-client").map(which->test(which,()->{
   var f=new OAuthAuthorizationServerTests();String method=which.equals("method")?"GET":"POST",query=which.equals("query")?"a".repeat(16385):which.equals("query-credential")?"client_id=client":null;
   String form=which.equals("unknown-grant")?"grant_type=password":which.equals("duplicate")?"client_id=x&client_id=x":"grant_type=authorization_code&client_id=unknown&resource="+encode(RESOURCE)+"&code=bad&code_verifier="+VERIFIER;
   Map<String,List<String>> h=new LinkedHashMap<>(headers());if(which.equals("encoding"))h.put("Content-Encoding",List.of("gzip"));if(which.equals("mime"))h.put("Content-Type",List.of("text/plain"));if(which.equals("charset"))h.put("Content-Type",List.of("application/x-www-form-urlencoded;charset=iso-8859-1"));if(which.equals("basic"))h.put("Authorization",List.of("Basic malformed"));
   byte[] body=which.equals("body")?new byte[16385]:bytes(form);var rejected=assertInstanceOf(OAuthTokenResult.Rejected.class,f.server.tokenResult(method,query,body,h));assertTrue(rejected.getResponse().getLocationWithCredentials().isEmpty());assertEquals(which.equals("method")?405:400,rejected.getResponse().getStatusCode());assertEquals(0,f.store.reads);
  }));
 }
 @Test @SuppressWarnings("NullAway") // Deliberate null trusted plumbing contract cases.
 void headerBoundsAndNullPlumbingHaveDifferentContracts() {
  var rejected=assertInstanceOf(OAuthAuthorizationResult.Rejected.class,this.server.beginAuthorizationResult("GET",query(),new byte[0],Map.of("X-Large",List.of("a".repeat(16385))),BROWSER));assertEquals(MALFORMED_REQUEST,rejected.getReason());
  assertThrows(NullPointerException.class,()->this.server.tokenResult(null,null,new byte[0],Map.of()));assertThrows(NullPointerException.class,()->this.server.resumeAuthorizationResult(null,BROWSER));assertThrows(NullPointerException.class,()->this.server.completeAuthorizationResult(BROWSER,BROWSER,null));assertThrows(NullPointerException.class,()->this.server.validateAccessTokenResult(null,RESOURCE));assertThrows(IllegalArgumentException.class,()->this.server.validateAccessTokenResult(bearer("malformed"),"urn:unknown"));
 }
 @Test void refreshDisabledAndOptionalRoutesAreConcreteConfigurationChoices() {
  this.server=builder().refreshTokensEnabled(null).revocationEndpoint(null).introspectionEndpoint(null).build();assertTrue(this.server.getRevocationEndpoint().isEmpty());assertTrue(this.server.getIntrospectionEndpoint().isEmpty());
  assertThrows(IllegalStateException.class,()->revoke("unknown"));assertThrows(IllegalStateException.class,()->introspect("unknown"));
  assertEquals(UNSUPPORTED_GRANT_TYPE,assertInstanceOf(OAuthTokenResult.Rejected.class,rotate("rsr1_"+BROWSER)).getReason());
  assertThrows(IllegalStateException.class,()->builder().revocationEndpoint(null).build());
 }
 @Test void optionalRoutesMustShareTheIssuerAuthority() {
  assertThrows(IllegalArgumentException.class,()->builder()
   .revocationEndpoint(URI.create("https://other.example/revoke")).build());
  assertThrows(IllegalArgumentException.class,()->builder()
   .introspectionEndpoint(URI.create("https://other.example/introspect")).build());
 }
 @TestFactory @NonNull Stream<@NonNull DynamicTest> builderRequiredNullsAreMissingRatherThanFallbacks() {
  Map<String,Function<OAuthAuthorizationServer.@NonNull Builder,OAuthAuthorizationServer.@NonNull Builder>> clear=Map.of("authorization",b->b.authorizationEndpoint(null),"token",b->b.tokenEndpoint(null),"jwks",b->b.jsonWebKeySetEndpoint(null),"clients",b->b.clientRepository(null),"store",b->b.store(null),"keys",b->b.signingKeys(null),"sealer",b->b.stateSealer(null),"resources",b->b.resources(null),"policy",b->b.grantPolicy(null));
  return clear.entrySet().stream().map(e->test(e.getKey(),()->{var f=new OAuthAuthorizationServerTests();var b=f.builder();b=e.getValue().apply(b);assertThrows(IllegalStateException.class,b::build);}));
 }
 @TestFactory @NonNull Stream<@NonNull DynamicTest> builderEndpointAuthorityIsNeverInferredOrRelaxed() {
  return Stream.of("https://wrong.example/token","http://issuer.example/token","https://issuer.example/token?x=1","https://issuer.example/token#x","https://u@issuer.example/token","https://issuer.example:0/token",ISSUER+"/authorize").map(uri->test(uri,()->assertThrows(IllegalArgumentException.class,()->builder().tokenEndpoint(URI.create(uri)).build())));
 }
 @Test @SuppressWarnings("NullAway") // Deliberate null primary factory argument.
 void primaryIssuerAndConfiguredResourceSnapshotsArePure() {
  assertThrows(NullPointerException.class,()->OAuthAuthorizationServer.withIssuer(null));for(String issuer:List.of("relative","https://user@issuer.example","https://issuer.example?q=1","https://issuer.example#x","http://localhost/issuer"))assertThrows(IllegalArgumentException.class,()->OAuthAuthorizationServer.withIssuer(issuer));
  assertThrows(IllegalArgumentException.class,()->builder().resources(Map.of()));
  Map<String,Set<String>> mutable=new LinkedHashMap<>(resources());var b=builder().resources(mutable);mutable.clear();assertNotNull(b.build());
  AtomicInteger callbacks=new AtomicInteger();b=builder().clientRepository((id,budget)->{callbacks.incrementAndGet();throw new AssertionError();}).signingKeys(budget->{callbacks.incrementAndGet();throw new AssertionError();}).grantPolicy((context,budget)->{callbacks.incrementAndGet();throw new AssertionError();}).clock(new Clock(){@Override public @NonNull ZoneId getZone(){throw new AssertionError();}@Override public @NonNull Clock withZone(@NonNull ZoneId z){throw new AssertionError();}@Override public @NonNull Instant instant(){callbacks.incrementAndGet();throw new AssertionError();}});
  assertNotNull(b.build());assertEquals(0,callbacks.get());
 }
 @Test void allDefaultResetSettersRemainUsableAndBuildSnapshotsDoNotAliasBuilder() {
  var b=builder().clock(null).observer(null).clientMetadataPolicy(null).outboundUriPolicy(null).refreshTokensEnabled(null).allowNativeLoopbackRedirects(null).allowLocalhostRedirects(null).allowInsecureLoopback(null).acknowledgeUnpatchedRuntime(null);
  assertSame(b,b.authorizationInteractionLifetime(null));
  assertSame(b,b.authorizationCodeLifetime(null));
  assertSame(b,b.accessTokenLifetime(null));
  assertSame(b,b.refreshTokenIdleLifetime(null));
  assertSame(b,b.refreshTokenAbsoluteLifetime(null));
  assertSame(b,b.clockSkew(null));
  assertSame(b,b.totalDeadline(null));
  assertSame(b,b.requestTimeout(null));
  assertSame(b,b.publicMetadataFreshness(null));
  assertSame(b,b.maximumRequestBodyBytes(null));
  assertSame(b,b.maximumRawQueryLength(null));
  assertSame(b,b.maximumHeaderBytes(null));
  assertSame(b,b.maximumResponseBodyBytes(null));
  assertSame(b,b.maximumStoreRecordBytes(null));
  assertSame(b,b.maximumStoreCommitAttempts(null));
  assertSame(b,b.maximumResources(null));
  assertSame(b,b.maximumRedirectUris(null));
  assertSame(b,b.maximumScopesPerResource(null));
  assertSame(b,b.maximumScopeLength(null));
  assertSame(b,b.maximumStateLength(null));
  assertSame(b,b.maximumClientIdLength(null));
  assertSame(b,b.maximumSubjectLength(null));
  OAuthAuthorizationServer first=b.build();assertSame(b,b.tokenEndpoint(URI.create(ISSUER+"/different")));assertEquals(URI.create(ISSUER+"/token"),first.getTokenEndpoint());assertEquals(URI.create(ISSUER+"/different"),b.build().getTokenEndpoint());
 }
 @Test void cimdOptInBuildDoesNotResolveAndPublicMetadataAdvertisesOnlyEnabledSupport() {
  AtomicInteger lookups=new AtomicInteger();OAuthClientMetadataPolicy policy=OAuthClientMetadataPolicy.fromAddressResolver((host,budget)->{lookups.incrementAndGet();return List.of(InetAddress.getLoopbackAddress());});
  this.server=builder().clientMetadataPolicy(policy).outboundUriPolicy(null).clientRepository((id,b)->Optional.empty()).build();assertEquals(0,lookups.get());assertTrue(json(this.server.metadataResponse("GET")).findBoolean("client_id_metadata_document_supported").orElseThrow());assertEquals(0,lookups.get());
  this.client=client("https://client.example.com/metadata");OAuthServerTransportException failure=assertThrows(OAuthServerTransportException.class,()->begin());assertEquals(CLIENT_METADATA_UNAVAILABLE,failure.getReason());assertFalse(failure.isTransient());assertEquals(1,lookups.get());
 }
 @Test void enabledClientMetadataConstructionRequiresAcknowledgmentOnUnpatchedRuntime() {
  OAuthClientMetadataPolicy enabled=OAuthClientMetadataPolicy.fromAddressResolver((host,budget)->List.of());
  Runtime.Version old=Runtime.Version.parse("17.0.2");
  assertNotNull(constructForRuntime(builder(),old));
  assertThrows(IllegalStateException.class,()->constructForRuntime(builder().clientMetadataPolicy(enabled),old));
  assertNotNull(constructForRuntime(builder().clientMetadataPolicy(enabled).acknowledgeUnpatchedRuntime(true),old));
  assertNotNull(constructForRuntime(builder().clientMetadataPolicy(enabled),Runtime.Version.parse("17.0.3")));
 }
 @TestFactory @NonNull Stream<@NonNull DynamicTest> callbacksPreserveInterruptionAndFatalVmErrors() {
  return Stream.of(false,true).map(fatal->test("policy"+fatal,()->{
   var f=new OAuthAuthorizationServerTests();f.initialized();var interaction=f.begin();Throwable error=fatal?new TestFatal():new InterruptedException("secret");f.policyFault=error;
   Executable operation=()->f.server.completeAuthorizationResult(interaction.getInteractionValue(),BROWSER,decision("subject",Set.of("read"),false));
   try{if(fatal)assertSame(error,assertThrows(TestFatal.class,operation));else{assertThrows(OAuthServerConfigurationException.class,operation);assertTrue(Thread.currentThread().isInterrupted());}}finally{Thread.interrupted();}
  }));
 }
 @Test void publicObserverPairsAreOutsideStoreCommitAndFixedKindsOnly() {
  List<String> events=new ArrayList<>();Thread caller=Thread.currentThread();OAuthServerObserver observer=new OAuthServerObserver(){
   @Override public void willHandleEndpoint(@NonNull Endpoint kind){assertSame(caller,Thread.currentThread());events.add("will:"+kind);}
   @Override public void didHandleEndpoint(@NonNull Endpoint kind,@Nullable Integer status,@NonNull Duration elapsed){assertSame(caller,Thread.currentThread());events.add("handled:"+kind);}
   @Override public void didRejectEndpoint(@NonNull Endpoint kind,OAuthServerException.@NonNull Reason reason,@Nullable Integer status,@NonNull Duration elapsed){events.add("rejected:"+kind);}
   @Override public void didFailToHandleEndpoint(@NonNull Endpoint kind,@NonNull OAuthServerException failure,@NonNull Duration elapsed){events.add("failed:"+kind);}
  };
  this.server=builder().observer(observer).build();JsonObject one=issued();assertInstanceOf(OAuthIssuerAccessTokenResult.Succeeded.class,this.server.validateAccessTokenResult(bearer(one.findString("access_token").orElseThrow()),RESOURCE));assertEquals(405,this.server.metadataResponse("POST").getStatusCode());assertInstanceOf(OAuthTokenResult.Rejected.class,this.server.tokenResult("GET",null,new byte[0],Map.of()));
  this.store.unknownAfter=true;assertThrows(OAuthServerStoreException.class,()->this.server.revokeSubject("subject"));
  assertEquals(0,events.size()%2);for(int i=0;i<events.size();i+=2){assertTrue(events.get(i).startsWith("will:"));assertFalse(events.get(i+1).startsWith("will:"));assertEquals(events.get(i).substring(5),events.get(i+1).substring(events.get(i+1).indexOf(':')+1));}
  assertTrue(events.contains("failed:SUBJECT_REVOCATION"));assertTrue(events.contains("rejected:METADATA"));
 }
 @Test void observerReportsEachPublicRejectionReason() {
  List<String> rejections=new ArrayList<>();
  OAuthServerObserver observer=new OAuthServerObserver(){
   @Override public void didRejectEndpoint(@NonNull Endpoint kind,OAuthServerException.@NonNull Reason reason,
      @Nullable Integer status,@NonNull Duration elapsed){rejections.add(kind+":"+reason);}
  };
  this.server=builder().observer(observer).build();
  initialized();
  assertInstanceOf(OAuthAuthorizationResult.Rejected.class,
   this.server.beginAuthorizationResult("GET","invalid=1",new byte[0],Map.of(),BROWSER));
  OAuthServerInteraction interaction=begin();
  assertInstanceOf(OAuthAuthorizationResult.Denied.class,this.server.completeAuthorizationResult(
   interaction.getInteractionValue(),BROWSER,OAuthAuthorizationDecision.deniedInstance()));
  assertInstanceOf(OAuthTokenResult.Rejected.class,this.server.tokenResult("GET",null,new byte[0],Map.of()));
  assertInstanceOf(OAuthRevocationResult.Rejected.class,this.server.revokeResult("GET",null,new byte[0],Map.of()));
  assertInstanceOf(OAuthIntrospectionResult.Rejected.class,this.server.introspectionResult("GET",null,new byte[0],Map.of()));
  assertInstanceOf(OAuthIssuerAccessTokenResult.Rejected.class,
   this.server.validateAccessTokenResult(bearer("malformed"),RESOURCE));
  assertEquals(405,this.server.metadataResponse("POST").getStatusCode());
  assertEquals(List.of("AUTHORIZATION:MALFORMED_REQUEST","AUTHORIZATION:ACCESS_DENIED",
   "TOKEN:METHOD_NOT_ALLOWED","REVOCATION:METHOD_NOT_ALLOWED","INTROSPECTION:METHOD_NOT_ALLOWED",
   "ACCESS_TOKEN_VALIDATION:TOKEN_REVOKED","METADATA:METHOD_NOT_ALLOWED"),rejections);
 }
 @Test void transportFaultFromCallerHeadersStillCompletesTheObserverEvent() {
  List<String> events=new ArrayList<>();
  OAuthServerObserver observer=new OAuthServerObserver(){
   @Override public void willHandleEndpoint(@NonNull Endpoint kind){events.add("will:"+kind);}
   @Override public void didFailToHandleEndpoint(@NonNull Endpoint kind,@NonNull OAuthServerException failure,
     @NonNull Duration elapsed){events.add("failed:"+kind+":"+failure.getReason());}
  };
  this.server=builder().observer(observer).build();
  Map<String,List<String>> headers=new AbstractMap<>(){
   @Override public @NonNull Set<Map.@NonNull Entry<@NonNull String,@NonNull List<@NonNull String>>> entrySet(){
    throw OAuthTransportFailureFixture.networkFailure();
   }
  };
  OAuthServerStoreException failure=assertThrows(OAuthServerStoreException.class,
   ()->this.server.tokenResult("POST",null,new byte[0],headers));
  assertEquals(STORE_UNAVAILABLE,failure.getReason());
  assertEquals(List.of("will:TOKEN","failed:TOKEN:STORE_UNAVAILABLE"),events);
 }
 @Test void invalidBasicTokenClientReceivesAnHttpAuthenticationChallenge() {
  this.server=builder().clientRepository((id,budget)->Optional.empty()).build();
  Map<String,List<String>> headers=new LinkedHashMap<>(headers());
  headers.put("Authorization",List.of("Basic "+Base64.getEncoder().encodeToString(bytes("unknown:secret"))));
  byte[] body=bytes(form(Map.of("grant_type","authorization_code","resource",RESOURCE,
   "code","rsc1_"+BROWSER,"code_verifier",VERIFIER)));
  OAuthTokenResult.Rejected rejected=assertInstanceOf(OAuthTokenResult.Rejected.class,
   this.server.tokenResult("POST",null,body,headers));
  assertEquals(INVALID_CLIENT,rejected.getReason());
  assertEquals(401,rejected.getResponse().getStatusCode());
  assertEquals(List.of("Basic realm=\"oauth\""),
   rejected.getResponse().getHeaders().get("WWW-Authenticate"));
 }
 @Test void accessTokenAtTheExactIngressLengthReachesValidation() {
  this.server=builder().maximumRequestBodyBytes(4096).build();
  initialized();
  OAuthIssuerAccessTokenResult.Rejected rejected=assertInstanceOf(OAuthIssuerAccessTokenResult.Rejected.class,
   this.server.validateAccessTokenResult(bearer("a".repeat(4096)),RESOURCE));
  assertEquals(TOKEN_REVOKED,rejected.getReason());
 }
 @Test @SuppressWarnings("NullAway") // Deliberately invalid caller input must fail before an observer event.
 void nullHttpMethodNeverStartsAnEndpointObservation() {
  AtomicInteger events=new AtomicInteger();
  OAuthServerObserver observer=new OAuthServerObserver(){
   @Override public void willHandleEndpoint(@NonNull Endpoint kind){events.incrementAndGet();}
  };
  this.server=builder().observer(observer).build();
  assertThrows(NullPointerException.class,()->this.server.beginAuthorizationResult(null,null,new byte[0],Map.of(),BROWSER));
  assertThrows(NullPointerException.class,()->this.server.tokenResult(null,null,new byte[0],Map.of()));
  assertThrows(NullPointerException.class,()->this.server.revokeResult(null,null,new byte[0],Map.of()));
  assertThrows(NullPointerException.class,()->this.server.introspectionResult(null,null,new byte[0],Map.of()));
  assertThrows(IllegalArgumentException.class,()->this.server.revokeGrant("bad"));
  assertEquals(0,events.get());
 }
 @Test void infrastructureAndSigningFailuresFinishTheirObserverEvents() {
  List<String> failures=new ArrayList<>();
  OAuthServerObserver observer=new OAuthServerObserver(){
   @Override public void didFailToHandleEndpoint(@NonNull Endpoint kind,@NonNull OAuthServerException failure,
      @NonNull Duration elapsed){failures.add(kind+":"+failure.getReason());}
  };
  this.server=builder().observer(observer).build();
  initialized();
  OAuthServerInteraction interaction=begin();
  this.policyFault=new IllegalStateException("fixture");
  assertThrows(OAuthServerConfigurationException.class,()->this.server.completeAuthorizationResult(
   interaction.getInteractionValue(),BROWSER,decision("subject",Set.of("read"),false)));
  this.policyFault=null;
  assertEquals(List.of("AUTHORIZATION:CONFIGURATION_INVALID"),failures);

  String code=code();
  OAuthIssuerSigningKey opaque=OAuthIssuerSigningKey.fromKeyPair("key",new OpaquePrivate(),KEY.getPublicKey());
  OAuthIssuerKeySnapshot snapshot=OAuthIssuerKeySnapshot.withActiveKey(opaque)
   .generation("g1").publishedAt(NOW.minusSeconds(120)).build();
  this.server=builder().signingKeys(OAuthIssuerKeyProvider.fromSnapshot(snapshot)).observer(observer).build();
  assertThrows(OAuthServerSigningException.class,()->redeem(code));
  assertEquals(List.of("AUTHORIZATION:CONFIGURATION_INVALID","TOKEN:SIGNING_FAILED"),failures);
 }
 @Test void localM5BridgeNeverResetsAnExpiredParentBudget() {
  var snapshot=keys();StaticJsonWebKeySource source=StaticJsonWebKeySource.fromJsonWebKeySet(JsonWebKeySet.fromJson(OAuthIssuerPublicKeys.jwks(snapshot.getVerificationKeys()).toJson()));
  String compact=issued().findString("access_token").orElseThrow();
  var validator=JwtAccessTokenValidator.withIssuer(ISSUER).jsonWebKeySource(source).expectedAudiences(Set.of(RESOURCE)).clock(this.clock).build();
  assertThrows(RuntimeException.class,()->OidcTransactionAccess.get().validateAccessToken(validator,bearer(compact),Deadline.fromNow(Duration.ZERO)));
 }
 @TestFactory @NonNull Stream<@NonNull DynamicTest> eachPublicNumericSetterChecksItsRegistryBounds() {
  return Stream.of("authorizationInteractionLifetime","authorizationCodeLifetime","accessTokenLifetime","refreshTokenIdleLifetime","refreshTokenAbsoluteLifetime","clockSkew","totalDeadline","requestTimeout","publicMetadataFreshness","maximumRequestBodyBytes","maximumRawQueryLength","maximumHeaderBytes","maximumResponseBodyBytes","maximumStoreRecordBytes","maximumStoreCommitAttempts","maximumResources","maximumRedirectUris","maximumScopesPerResource","maximumScopeLength","maximumStateLength","maximumClientIdLength","maximumSubjectLength").map(name->test(name,()->{
   var f=new OAuthAuthorizationServerTests();var b=f.builder();boolean duration=!name.startsWith("maximum");Object value=duration?Duration.ofDays(366):Integer.MAX_VALUE;
   var method=OAuthAuthorizationServer.Builder.class.getMethod(name,duration?Duration.class:Integer.class);assertSame(b,method.invoke(b,value));assertThrows(IllegalArgumentException.class,b::build);
   assertSame(b,method.invoke(b,new Object[]{null}));assertNotNull(b.build());
  }));
 }
 @Test void insecureNumericLoopbackRequiresExplicitBuilderFlagAndOtherFlagsAreResettable() {
  var b=OAuthAuthorizationServer.withIssuer("http://127.0.0.1:1234/tenant").authorizationEndpoint(URI.create("http://127.0.0.1:1234/authorize"))
   .tokenEndpoint(URI.create("http://127.0.0.1:1234/token")).jsonWebKeySetEndpoint(URI.create("http://127.0.0.1:1234/jwks"))
   .clientRepository((id,budget)->Optional.empty()).store(this.store).signingKeys(OAuthIssuerKeyProvider.fromSnapshot(keys())).stateSealer(sealer()).resources(resources()).grantPolicy((context,budget)->OAuthAuthorizationDecision.deniedInstance());
  assertThrows(IllegalArgumentException.class,b::build);assertNotNull(b.allowInsecureLoopback(true).allowLocalhostRedirects(true).allowNativeLoopbackRedirects(true).acknowledgeUnpatchedRuntime(true).build());
 }
 @Test void sealerCapAndScopeLimitsAreCheckedBeforeBuilderCallbacks() {
  assertThrows(IllegalArgumentException.class,()->builder().maximumStoreRecordBytes(3801).build());assertThrows(IllegalArgumentException.class,()->builder().maximumScopesPerResource(1).build());
 }
 @TestFactory @NonNull Stream<@NonNull DynamicTest> signingFailureKeepsCredentialUnusedAndNeverLeaksExternalCause() {
  return Stream.of(false,true).map(refresh->test("signing"+refresh,()->{
   var f=new OAuthAuthorizationServerTests();f.initialized();String code=f.code(),credential=code;
   if(refresh)credential=json(assertInstanceOf(OAuthTokenResult.Succeeded.class,f.redeem(code)).getResponse()).findString("refresh_token").orElseThrow();
   f.server=f.builder().signingKeys(OAuthIssuerKeyProvider.fromSnapshot(OAuthIssuerKeySnapshot.withActiveKey(OAuthIssuerSigningKey.fromKeyPair("key",new OpaquePrivate(),KEY.getPublicKey())).generation("g1").publishedAt(NOW.minusSeconds(120)).build())).build();
   String supplied=credential;var before=Map.copyOf(f.store.rows);var failure=assertThrows(OAuthServerSigningException.class,()->{if(refresh)f.rotate(supplied);else f.redeem(supplied);});
   assertEquals(SIGNING_FAILED,failure.getReason());assertNull(failure.getCause());assertEquals(before,f.store.rows);
  }));
 }
 @Test void interruptedM5SharedBudgetRemainsInfrastructureAndPreservesFlag() {
  String compact=issued().findString("access_token").orElseThrow();var snapshot=keys();StaticJsonWebKeySource source=StaticJsonWebKeySource.fromJsonWebKeySet(JsonWebKeySet.fromJson(OAuthIssuerPublicKeys.jwks(snapshot.getVerificationKeys()).toJson()));
  var validator=JwtAccessTokenValidator.withIssuer(ISSUER).jsonWebKeySource(source).expectedAudiences(Set.of(RESOURCE)).clock(this.clock).build();
  try {Thread.currentThread().interrupt();assertThrows(com.revetsec.oauth.OAuthTransportException.class,()->OidcTransactionAccess.get().validateAccessToken(validator,bearer(compact),Deadline.fromNow(Duration.ofSeconds(1))));assertTrue(Thread.currentThread().isInterrupted());}finally{Thread.interrupted();}
 }
 private static final class OpaquePrivate implements PrivateKey {
  private static final long serialVersionUID=1L;private OpaquePrivate(){}
  @Override public @NonNull String getAlgorithm(){return "RSA";}
  @Override public @Nullable String getFormat(){return null;}
  @Override public byte @Nullable [] getEncoded(){return null;}
 }
 @TestFactory @NonNull Stream<@NonNull DynamicTest> maintenanceFailuresDoNotRepairOrLaunderState() {
  return Stream.of("namespace","missing-issuer","clock-backward","expired","retention","fault","null-read","null-commit","initialization-fault").map(which->test(which,()->{
   var f=new OAuthAuthorizationServerTests();assertNotNull(f.issued());OAuthStoreKey key=f.store.rows.keySet().stream().filter(k->k.getKind()==OAuthStoreKey.Kind.ACCESS_TOKEN).findFirst().orElseThrow();
   OAuthStoreRecordCodec codec=new OAuthStoreRecordCodec(ISSUER,sealer(),3800);OAuthStoreCoordinator coordinator=new OAuthStoreCoordinator(f.store,codec,f.clock,3,255);
   if(which.equals("namespace")){OAuthStoreKey foreign=OAuthStoreFormat.key("A".repeat(43),OAuthStoreKey.Kind.GRANT,BROWSER);assertThrows(IllegalArgumentException.class,()->coordinator.reseal(foreign,Deadline.fromNow(Duration.ofSeconds(1))));return;}
   if(which.equals("missing-issuer"))f.store.rows.remove(codec.issuerKey());
   if(which.equals("clock-backward"))f.clock.time=NOW.minusSeconds(1);
   if(which.equals("expired")){f.clock.time=requireNonNull(f.store.rows.get(key)).getRetainUntil();assertEquals(OAuthStoreCommitStatus.CONFLICT,f.server.resealStoreEntry(key));return;}
   if(which.equals("retention")){OAuthStoreEntry old=requireNonNull(f.store.rows.get(key));JsonObject payload=codec.open(old,f.clock);f.store.rows.put(key,codec.seal(key,old.getRetainUntil().plusSeconds(1),payload.toJson()));}
   if(which.equals("fault")||which.equals("initialization-fault"))f.store.fault=new IllegalStateException("backend-sensitive");
   if(which.equals("null-read"))f.store.nullRead=true;if(which.equals("null-commit"))f.store.nullCommit=true;
   Executable operation=which.equals("initialization-fault")?f.server::initializeFreshIssuer:()->f.server.resealStoreEntry(key);
   var failure=assertThrows(OAuthServerStoreException.class,operation);assertEquals(Set.of("missing-issuer","retention").contains(which)?STORE_CORRUPT:STORE_UNAVAILABLE,failure.getReason());
  }));
 }
 @Test void clientLookupBarrierConflictExhaustionAndPolicyDenialConflictsAreBounded() {
  initialized();var interaction=begin();int commits=this.store.commits;this.store.conflicts=8;assertEquals(STORE_UNAVAILABLE,assertThrows(OAuthServerStoreException.class,()->this.server.resumeAuthorizationResult(interaction.getInteractionValue(),BROWSER)).getReason());assertEquals(commits+3,this.store.commits);
  this.store.conflicts=0;AtomicInteger calls=new AtomicInteger();this.override=(context,budget)->{if(calls.incrementAndGet()==1)this.store.conflicts=1;return OAuthAuthorizationDecision.deniedInstance();};
  assertInstanceOf(OAuthAuthorizationResult.Denied.class,this.server.completeAuthorizationResult(interaction.getInteractionValue(),BROWSER,decision("subject",Set.of("read"),false)));assertEquals(2,calls.get());
 }
 @TestFactory @NonNull Stream<@NonNull DynamicTest> optionalEndpointRejectionsRetainTheirFixedHttpBoundary() {
  return Stream.of("revocation-method","revocation-basic","introspection-method","introspection-public","introspection-basic","introspection-resource","introspection-ambiguous").map(which->test(which,()->{
   var f=new OAuthAuthorizationServerTests();Map<String,List<String>> h=new LinkedHashMap<>(headers());if(which.endsWith("basic"))h.put("Authorization",List.of("Basic invalid"));
   String method=which.endsWith("method")?"GET":"POST";Map<String,String> parameters=new LinkedHashMap<>(Map.of("token","unknown","client_id","client"));
   if(which.equals("introspection-resource"))parameters.put("resource","urn:unknown");
   if(which.equals("introspection-ambiguous"))f.server=f.builder().resources(Map.of(RESOURCE,Set.of("read"),"urn:second",Set.of("read"))).build();
   if(which.startsWith("revocation")){var rejected=assertInstanceOf(OAuthRevocationResult.Rejected.class,f.server.revokeResult(method,null,bytes(form(parameters)),h));assertEquals(which.endsWith("method")?405:401,rejected.getResponse().getStatusCode());}
   else{var rejected=assertInstanceOf(OAuthIntrospectionResult.Rejected.class,f.server.introspectionResult(method,null,bytes(form(parameters)),h));assertEquals(which.endsWith("method")?405:which.endsWith("resource")||which.endsWith("ambiguous")?400:401,rejected.getResponse().getStatusCode());}
  }));
 }
 @Test void warmUpExhaustionAndKeyFaultsAreInfrastructureAndMalformedContinuationsAreResults() {
  initialized();this.store.conflicts=3;assertEquals(STORE_UNAVAILABLE,assertThrows(OAuthServerStoreException.class,this.server::warmUp).getReason());this.store.conflicts=0;
  this.server=builder().signingKeys(budget->{throw new IllegalStateException("key provider sensitive");}).build();assertEquals(CONFIGURATION_INVALID,assertThrows(OAuthServerConfigurationException.class,this.server::warmUp).getReason());
  assertEquals(MALFORMED_REQUEST,assertInstanceOf(OAuthAuthorizationResult.Rejected.class,this.server.completeAuthorizationResult("bad",BROWSER,OAuthAuthorizationDecision.deniedInstance())).getReason());
 }
 @TestFactory @NonNull Stream<@NonNull DynamicTest> dynamicOwnerRevocationRequiresFreshCimdSourceBinding() {
  return Stream.of(false,true).map(refresh->test("dynamic-owner"+refresh,()->{
   var f=new OAuthAuthorizationServerTests();f.initialized();f.client=client("https://client.example.com/metadata");
   OAuthServerIngressLimits limits=OAuthServerIngressLimits.fromDefaults();OAuthStoreRecordCodec codec=new OAuthStoreRecordCodec(ISSUER,sealer(),3800);
   OAuthStoreCoordinator coordinator=new OAuthStoreCoordinator(f.store,codec,f.clock,3,255);AtomicInteger fetches=new AtomicInteger();
   JsonObject document=JsonObject.builder().put("client_id",f.client.getClientId()).put("client_name","reviewed client").put("redirect_uris",com.revetsec.json.JsonArray.fromElements(List.of(com.revetsec.json.JsonString.fromValue(REDIRECT))))
    .put("token_endpoint_auth_method","none").put("grant_types",com.revetsec.json.JsonArray.fromElements(List.of(com.revetsec.json.JsonString.fromValue("authorization_code"),com.revetsec.json.JsonString.fromValue("refresh_token"))))
    .put("response_types",com.revetsec.json.JsonArray.fromElements(List.of(com.revetsec.json.JsonString.fromValue("code")))).build();
   OAuthClientMetadataPolicy policy=OAuthClientMetadataPolicy.fromAddressResolver((host,budget)->List.of(InetAddress.getLoopbackAddress()));
   OAuthClientMetadataFetcher fetcher=new OAuthClientMetadataFetcher(ISSUER,sealer(),policy,limits,false,false,OutboundUriPolicy.defaultInstance(),f.clock,(uri,deadline)->{
    fetches.incrementAndGet();return new com.revetsec.internal.http.RawResponse(200,java.net.http.HttpHeaders.of(Map.of("Cache-Control",List.of("max-age=300")),(a,b)->true),JsonCodec.toUtf8Bytes(document),null,false,Duration.ZERO);
   });
   OAuthServerClientSelection selection=new OAuthServerClientSelection((id,budget)->Optional.empty(),limits,fetcher,true);
   Deadline deadline=Deadline.fromNow(Duration.ofSeconds(10));OAuthAuthorizationLedger ledger=new OAuthAuthorizationLedger(coordinator,codec,limits,Duration.ofMinutes(15),Duration.ofMinutes(2),3,255,true);
   var request=OAuthServerRequest.parse(OAuthServerRequest.Endpoint.AUTHORIZATION,"GET",f.query(),new byte[0],Map.of(),limits);
   var admission=OAuthServerAuthorizationAdmission.admit(request,selection,deadline,resources(),limits,false,false);String handle=ledger.begin(admission,BROWSER,deadline);
   String code=ledger.complete(handle,BROWSER,selection.authorization(f.client.getClientId(),resources(),deadline),resources(),decision("subject",Set.of("read","write"),true),deadline).orElseThrow();
   var retention=new OAuthGrantRetention(Duration.ofMinutes(5),Duration.ofSeconds(30),Duration.ofSeconds(10),Duration.ofSeconds(60));
   var signer=com.revetsec.jose.JwsSigner.fromRsaKeyPair(KEY.getPrivateKey(),KEY.getPublicKey(),JwsAlgorithm.RS256);
   var redemption=new OAuthCodeRedemption(coordinator,codec,limits,retention,new OAuthTokenResponse.Encoder(ISSUER,"key",signer,32768,16384),Duration.ofMinutes(5),true,Duration.ofDays(1),Duration.ofDays(7),3,255);
   var exchange=OAuthServerRequest.parse(OAuthServerRequest.Endpoint.TOKEN,"POST",null,bytes(form(Map.of("client_id",f.client.getClientId(),"grant_type","authorization_code","code",code,"code_verifier",VERIFIER,"resource",RESOURCE))),headers(),limits);
   JsonObject one=json(redemption.redeem(exchange,selection,resources(),(context,budget)->decision(context.getSubject(),Set.of("read","write"),true),deadline).response());
   String token=one.findString("access_token").orElseThrow(),credential=one.findString(refresh?"refresh_token":"access_token").orElseThrow();
   var revocationRequest=OAuthServerRequest.parse(OAuthServerRequest.Endpoint.REVOCATION,"POST",null,bytes(form(Map.of("client_id",f.client.getClientId(),"token",credential))),headers(),limits);
   var status=new OAuthIssuerTokenStatus(coordinator,codec,limits,f.clock,Duration.ofSeconds(30),3,255,65536);
   var revoker=new OAuthGrantRevocation(coordinator,codec,status,limits,3,255,32768,16384);
   var snapshot=StaticJsonWebKeySource.fromJsonWebKeySet(JsonWebKeySet.fromJson(OAuthIssuerPublicKeys.jwks(keys().getVerificationKeys()).toJson()));
   // A URL registration is another source and cannot borrow the earlier CIMD owner fingerprint.
   assertEquals(200,revoker.revoke(revocationRequest,new OAuthServerClientSelection((id,budget)->Optional.of(f.client),limits,null),resources(),snapshot,deadline).response().getStatusCode());
   assertInstanceOf(OAuthIssuerAccessTokenResult.Succeeded.class,f.server.validateAccessTokenResult(bearer(token),RESOURCE));int before=fetches.get();
   assertEquals(200,revoker.revoke(revocationRequest,selection,resources(),snapshot,deadline).response().getStatusCode());assertEquals(before+1,fetches.get());
   assertInstanceOf(OAuthIssuerAccessTokenResult.Rejected.class,f.server.validateAccessTokenResult(bearer(token),RESOURCE));
  }));
 }
 @SuppressWarnings("unchecked") private static <T extends Throwable> void raise(@NonNull Throwable error)throws T{throw(T)error;}
 private static final class TestFatal extends VirtualMachineError {private static final long serialVersionUID=1L;private TestFatal(){super("fixture");}}
 private static final class MutableClock extends Clock {
  private @NonNull Instant time=NOW;private @Nullable Runnable hook;
  private MutableClock(){}
  @Override public @NonNull ZoneId getZone(){return ZoneOffset.UTC;}
  @Override public @NonNull Clock withZone(@NonNull ZoneId zone){requireNonNull(zone);return this;}
  @Override public @NonNull Instant instant(){Runnable action=this.hook;this.hook=null;if(action!=null)action.run();return this.time;}
 }
}
