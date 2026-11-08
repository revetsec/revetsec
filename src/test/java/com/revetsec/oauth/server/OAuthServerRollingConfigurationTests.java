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
import com.revetsec.internal.encoding.FormUrlEncoding;
import com.revetsec.internal.json.JsonCodec;
import com.revetsec.internal.json.JsonLimits;
import com.revetsec.json.JsonObject;
import com.revetsec.json.JsonString;
import com.revetsec.oauth.BearerToken;
import com.revetsec.oauth.BearerTokenResult;
import com.revetsec.testing.TestJwk;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.ZoneId;
import java.util.Base64;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Stream;
import static java.util.Objects.requireNonNull;
import static org.junit.jupiter.api.Assertions.*;

/** Rebuilt engines share one atomic fixture: configuration contracts, not durable deployment qualification. */
final class OAuthServerRollingConfigurationTests {
 private static final @NonNull String ISSUER="https://issuer.example/tenant",RESOURCE="https://resource.example/mcp",REDIRECT="https://client.example/cb?raw=%2f";
 private static final @NonNull String BROWSER="A".repeat(43),VERIFIER="dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",CHALLENGE="E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
 private static final @NonNull Instant NOW=Instant.parse("2026-11-01T12:00:00Z");
 private static final @NonNull Duration SKEW=Duration.ofSeconds(30),DEADLINE=Duration.ofSeconds(10),CACHE=Duration.ofSeconds(60),ACCESS=Duration.ofMinutes(5);
 private static final @NonNull Set<@NonNull String> SCOPES=Set.of("read","write");
 private record Profile(@NonNull Duration skew,@NonNull Duration deadline,@NonNull Duration cache,@NonNull Duration access) {}
 private record Tokens(@NonNull String access,@NonNull String refresh,@NonNull String grant) {}
 private static @NonNull Profile baseline(){return new Profile(SKEW,DEADLINE,CACHE,ACCESS);}
 private static OAuthServerClientRegistration.@NonNull Builder registration(){return OAuthServerClientRegistration.withClientId("client").configurationVersion("v1")
  .redirectUris(List.of(URI.create(REDIRECT),URI.create("https://client.example/other"))).allowedScopesByResource(Map.of(RESOURCE,SCOPES)).refreshTokenPermitted(true);}
 private static @NonNull OAuthServerClientRegistration client(@NonNull String edit){
  var b=registration();return (switch(edit){
   case "version"->b.configurationVersion("v2");case "redirect"->b.redirectUris(List.of(URI.create(REDIRECT.replace("%2f","%2F")),URI.create("https://client.example/other")));
   case "scope-add"->b.allowedScopesByResource(Map.of(RESOURCE,Set.of("read","write","extra")));case "scope-remove"->b.allowedScopesByResource(Map.of(RESOURCE,Set.of("read")));
   case "refresh"->b.refreshTokenPermitted(false);case "code"->b.authorizationCodePermitted(false);
   case "authentication"->b.authentication(OAuthServerClientAuthentication.fromClientSecretVerifier((id,secret,budget)->true));
   case "display"->b.clientName("changed display");case "order"->b.redirectUris(List.of(URI.create("https://client.example/other"),URI.create(REDIRECT))).allowedScopesByResource(Map.of(RESOURCE,new LinkedHashSet<>(List.of("write","read"))));
   default->b;
  }).build();
 }
 private static final class Fixture {
  final @NonNull OAuthAtomicStoreFixture store=new OAuthAtomicStoreFixture(NOW);
  final @NonNull Clock clock=new Clock(){@Override public @NonNull ZoneId getZone(){return ZoneOffset.UTC;}@Override public @NonNull Clock withZone(@NonNull ZoneId zone){return this;}@Override public @NonNull Instant instant(){return Fixture.this.store.authorityNow;}};
  final @NonNull StateSealer sealer;final @NonNull OAuthStoreRecordCodec codec;
  @NonNull OAuthServerClientRegistration client=client("none");@Nullable String lastGrant;
  final @NonNull OAuthAuthorizationServer old;
  Fixture(){this(baseline());}
  Fixture(@NonNull Profile profile){
   byte[] material=new byte[32];for(int i=0;i<32;i++)material[i]=(byte)(i+1);
   this.sealer=StateSealer.withActiveKey(SealingKey.fromBase64("key",Base64.getEncoder().encodeToString(material))).build();this.codec=new OAuthStoreRecordCodec(ISSUER,this.sealer,3800);
   this.old=engine(profile);assertEquals(OAuthStoreCommitStatus.COMMITTED,this.old.initializeFreshIssuer().getStatus());this.old.establishNewSubject("subject");
  }
  @NonNull OAuthAuthorizationServer engine(@NonNull Profile p){
   var k=TestJwk.Fixture.IDP_SIGNING_RSA_2048;
   var keys=OAuthIssuerKeySnapshot.withActiveKey(OAuthIssuerSigningKey.fromRsaKeyPair("key",k.getPrivateKey(),k.getPublicKey())).generation("g1").publishedAt(NOW.minusSeconds(3600)).build();
   return OAuthAuthorizationServer.withIssuer(ISSUER).authorizationEndpoint(URI.create(ISSUER+"/authorize")).tokenEndpoint(URI.create(ISSUER+"/token")).jwksEndpoint(URI.create(ISSUER+"/jwks")).revocationEndpoint(URI.create(ISSUER+"/revoke"))
    .clientRepository((id,budget)->id.equals("client")?Optional.of(this.client):Optional.empty()).store(this.store).stateSealer(this.sealer).signingKeys(OAuthIssuerKeyProvider.fromSnapshot(keys))
    .resources(Map.of(RESOURCE,Set.of("read","write","extra"))).clock(this.clock).grantPolicy((context,budget)->{this.lastGrant=context.getGrantValue();return decision(context.getAuthorizedScopesByResource().get(RESOURCE));})
    .refreshTokensEnabled(true).refreshTokenIdleLifetime(Duration.ofDays(1)).refreshTokenAbsoluteLifetime(Duration.ofDays(7)).clockSkew(p.skew()).totalDeadline(p.deadline()).publicMetadataHttpCacheMaxAge(p.cache()).accessTokenLifetime(p.access()).acknowledgeUnpatchedRuntime(true).build();
  }
  @NonNull OAuthServerInteraction begin(@NonNull OAuthAuthorizationServer s){return assertInstanceOf(OAuthAuthorizationResult.InteractionRequired.class,s.beginAuthorizationResult("GET",form(Map.of("client_id","client","response_type","code","redirect_uri",REDIRECT,"resource",RESOURCE,"scope","read write","code_challenge",CHALLENGE,"code_challenge_method","S256")),new byte[0],Map.of(),BROWSER)).getInteraction();}
  @NonNull OAuthAuthorizationResult complete(@NonNull OAuthAuthorizationServer s,@NonNull OAuthServerInteraction i){return s.completeAuthorizationResult(i.getInteractionValue(),BROWSER,decision(SCOPES));}
  @NonNull String code(@NonNull OAuthAuthorizationServer s){var response=assertInstanceOf(OAuthAuthorizationResult.Completed.class,complete(s,begin(s))).getResponse();String location=response.getLocationWithCredentials().orElseThrow().toString();return location.substring(location.indexOf("code=")+5).split("&",2)[0];}
  @NonNull OAuthTokenResult redeem(@NonNull OAuthAuthorizationServer s,@NonNull String code){return s.tokenResult("POST",null,bytes(form(Map.of("grant_type","authorization_code","client_id","client","resource",RESOURCE,"code",code,"code_verifier",VERIFIER,"redirect_uri",REDIRECT))),headers());}
  @NonNull Tokens issue(@NonNull OAuthAuthorizationServer s){return tokens(assertInstanceOf(OAuthTokenResult.Succeeded.class,redeem(s,code(s))).getResponse());}
  @NonNull Tokens tokens(@NonNull OAuthServerResponse response){var json=json(response);return new Tokens(text(json,"access_token"),text(json,"refresh_token"),requireNonNull(this.lastGrant));}
  @NonNull OAuthTokenResult rotate(@NonNull OAuthAuthorizationServer s,@NonNull String refresh){return s.tokenResult("POST",null,bytes(form(Map.of("grant_type","refresh_token","client_id","client","resource",RESOURCE,"refresh_token",refresh))),headers());}
  @NonNull OAuthAuthorizationRecord grant(@NonNull String id){var key=this.codec.key(OAuthStoreKey.Kind.GRANT,id);var e=requireNonNull(this.store.rows.get(key));return OAuthAuthorizationRecord.decode(key.getKind(),id,IssuerTestRecords.open(this.codec,e,Clock.fixed(this.store.authorityNow,ZoneOffset.UTC)),OAuthServerIngressLimits.fromDefaults(),255);}
  void active(@NonNull OAuthAuthorizationServer s,@NonNull String access){assertInstanceOf(OAuthIssuerAccessTokenResult.Succeeded.class,s.validateAccessTokenResult(bearer(access),RESOURCE));}
  void inactive(@NonNull OAuthAuthorizationServer s,@NonNull String access){assertInstanceOf(OAuthIssuerAccessTokenResult.Rejected.class,s.validateAccessTokenResult(bearer(access),RESOURCE));}
 }
 private static @NonNull OAuthAuthorizationDecision decision(@Nullable Set<@NonNull String> scopes){return OAuthAuthorizationDecision.withSubject("subject").authorizedScopesByResource(Map.of(RESOURCE,requireNonNull(scopes))).refreshTokenPermitted(true).build();}
 private static @NonNull String form(@NonNull Map<@NonNull String,@NonNull String> fields){return String.join("&",fields.entrySet().stream().map(e->encode(e.getKey())+"="+encode(e.getValue())).toList());}
 private static @NonNull String encode(@NonNull String s){try{return FormUrlEncoding.encode(s);}catch(com.revetsec.internal.encoding.EncodingException e){throw new AssertionError(e);}}
 private static byte @NonNull [] bytes(@NonNull String s){return s.getBytes(StandardCharsets.UTF_8);}
 private static @NonNull Map<@NonNull String,@NonNull List<@NonNull String>> headers(){return Map.of("Content-Type",List.of("application/x-www-form-urlencoded"));}
 private static @NonNull JsonObject json(@NonNull OAuthServerResponse r){try{return (JsonObject)JsonCodec.parse(r.toHttpBodyWithCredentials(),JsonLimits.protocolDocument(32768));}catch(com.revetsec.internal.json.JsonParseException e){throw new AssertionError(e);}}
 private static @NonNull String text(@NonNull JsonObject j,@NonNull String name){return ((JsonString)j.find(name).orElseThrow()).getValue();}
 private static @NonNull BearerToken bearer(@NonNull String t){return assertInstanceOf(BearerTokenResult.Present.class,BearerToken.fromAuthorizationHeaderValuesResult(List.of("Bearer "+t))).getToken();}
 private static void invalidGrant(@NonNull OAuthTokenResult r){var rejected=assertInstanceOf(OAuthTokenResult.Rejected.class,r);assertEquals(OAuthServerException.Reason.INVALID_GRANT,rejected.getReason());assertEquals(400,rejected.getResponse().getStatusCode());assertEquals("{\"error\":\"invalid_grant\"}",new String(rejected.getResponse().toHttpBodyWithCredentials(),StandardCharsets.US_ASCII));assertTrue(rejected.getResponse().getLocationWithCredentials().isEmpty());}
 private static @NonNull Profile expanded(@NonNull String mode){return switch(mode){case "skew"->new Profile(SKEW.plusNanos(1),DEADLINE,CACHE,ACCESS);case "deadline"->new Profile(SKEW,DEADLINE.plusNanos(1),CACHE,ACCESS);case "cache"->new Profile(SKEW,DEADLINE,CACHE.plusNanos(1),ACCESS);default->new Profile(SKEW,DEADLINE,CACHE,ACCESS.plusSeconds(1));};}
 @TestFactory @NonNull Stream<@NonNull DynamicTest> incompatiblePolicyRevokesAcrossRebuiltAndOldEngines(){return Stream.of("skew","deadline","cache","access").map(mode->DynamicTest.dynamicTest(mode,()->{
  Fixture f=new Fixture();Tokens one=f.issue(f.old);var before=f.grant(one.grant());var next=f.engine(expanded(mode));f.active(next,one.access());
  invalidGrant(f.rotate(next,one.refresh()));var after=f.grant(one.grant());assertEquals("REVOKED",after.text("status"));assertEquals(before.horizon(),after.horizon());assertEquals(before.expires(),after.expires());assertEquals(before.maximumAccessLifetime(),after.maximumAccessLifetime());
  assertEquals(before.text("refreshId"),after.text("refreshId"));assertEquals(1,f.store.rows.keySet().stream().filter(k->k.getKind()==OAuthStoreKey.Kind.ACCESS_TOKEN).count());
  f.inactive(f.old,one.access());f.inactive(next,one.access());invalidGrant(f.rotate(f.old,one.refresh()));invalidGrant(f.rotate(next,one.refresh()));
  Tokens fresh=f.issue(next);f.active(next,fresh.access());assertNotEquals(one.grant(),fresh.grant());assertTrue(f.grant(fresh.grant()).horizon().isAfter(before.horizon()));
 }));}
 @TestFactory @NonNull Stream<@NonNull DynamicTest> compatibleChangesPreservePinnedGrantAndOldNodeCanUseReplacement(){return Stream.of("same","skew-down","deadline-down","cache-down","balanced","access-down").map(mode->DynamicTest.dynamicTest(mode,()->{
  Fixture f=new Fixture();Tokens one=f.issue(f.old);var before=f.grant(one.grant());Profile p=switch(mode){case "skew-down"->new Profile(SKEW.minusSeconds(1),DEADLINE,CACHE,ACCESS);case "deadline-down"->new Profile(SKEW,DEADLINE.minusSeconds(1),CACHE,ACCESS);case "cache-down"->new Profile(SKEW,DEADLINE,CACHE.minusSeconds(1),ACCESS);case "balanced"->new Profile(SKEW.plusSeconds(1),DEADLINE,CACHE.minusSeconds(1),ACCESS);case "access-down"->new Profile(SKEW,DEADLINE,CACHE,ACCESS.minusSeconds(1));default->baseline();};
  var next=f.engine(p);Tokens two=f.tokens(assertInstanceOf(OAuthTokenResult.Succeeded.class,f.rotate(next,one.refresh())).getResponse());var after=f.grant(one.grant());
  assertEquals(before.horizon(),after.horizon());assertEquals(before.expires(),after.expires());assertEquals(before.maximumAccessLifetime(),after.maximumAccessLifetime());assertEquals(before.scopes(OAuthServerIngressLimits.fromDefaults()),after.scopes(OAuthServerIngressLimits.fromDefaults()));f.active(f.old,one.access());f.active(next,two.access());assertInstanceOf(OAuthTokenResult.Succeeded.class,f.rotate(f.old,two.refresh()));
 }));}
 @TestFactory @NonNull Stream<@NonNull DynamicTest> fullPrecisionMarginUsesExistingRoundedHorizon(){return Stream.of(false,true).map(over->DynamicTest.dynamicTest("beyond-rounded-H="+over,()->{
  Fixture f=new Fixture(new Profile(SKEW.plusNanos(250_000_000),DEADLINE,CACHE,ACCESS));Tokens one=f.issue(f.old);var before=f.grant(one.grant());var next=f.engine(new Profile(over?SKEW.plusSeconds(1).plusNanos(1):SKEW.plusNanos(750_000_000),DEADLINE,CACHE,ACCESS));
  if(over){invalidGrant(f.rotate(next,one.refresh()));assertEquals("REVOKED",f.grant(one.grant()).text("status"));}else assertInstanceOf(OAuthTokenResult.Succeeded.class,f.rotate(next,one.refresh()));assertEquals(before.horizon(),f.grant(one.grant()).horizon());
 }));}
 @TestFactory @NonNull Stream<@NonNull DynamicTest> registrationSecurityEditsRejectStoredCredentialsWithoutRevokingAccess(){return Stream.of("version","redirect","scope-add","scope-remove","refresh").flatMap(edit->Stream.of(false,true).map(used->DynamicTest.dynamicTest(edit+" used="+used,()->{
  Fixture f=new Fixture();Tokens one=f.issue(f.old),current=used?f.tokens(assertInstanceOf(OAuthTokenResult.Succeeded.class,f.rotate(f.old,one.refresh())).getResponse()):one;var before=Map.copyOf(f.store.rows);
  f.client=client(edit);var next=f.engine(baseline());invalidGrant(f.rotate(next,one.refresh()));assertEquals(before,f.store.rows);assertEquals("ACTIVE",f.grant(one.grant()).text("status"));f.active(next,one.access());f.active(next,current.access());
  var response=assertInstanceOf(OAuthRevocationResult.Succeeded.class,next.revokeResult("POST",null,bytes(form(Map.of("client_id","client","token",current.refresh()))),headers())).getResponse();assertEquals(200,response.getStatusCode());assertEquals(before,f.store.rows);
  f.client=client("none");assertInstanceOf(OAuthTokenResult.Succeeded.class,f.rotate(f.old,current.refresh()));
 })));
 }
 @TestFactory @NonNull Stream<@NonNull DynamicTest> securityFingerprintRejectsPendingInteractionsAndCodes(){return Stream.of("version","redirect","scope-add","scope-remove","refresh").map(edit->DynamicTest.dynamicTest(edit,()->{
  Fixture f=new Fixture();var interaction=f.begin(f.old);String code=f.code(f.old);var before=Map.copyOf(f.store.rows);f.client=client(edit);var next=f.engine(baseline());
  assertInstanceOf(OAuthAuthorizationResult.Rejected.class,next.resumeAuthorizationResult(interaction.getInteractionValue(),BROWSER));assertInstanceOf(OAuthAuthorizationResult.Rejected.class,f.complete(next,interaction));invalidGrant(f.redeem(next,code));assertEquals(before,f.store.rows);
  f.client=client("none");assertInstanceOf(OAuthAuthorizationResult.Completed.class,f.complete(f.old,interaction));assertInstanceOf(OAuthTokenResult.Succeeded.class,f.redeem(f.old,code));
 }));}
 @TestFactory @NonNull Stream<@NonNull DynamicTest> displayAndCollectionOrderChangesRemainCompatibleAcrossEveryTransition(){return Stream.of("display","order").map(edit->DynamicTest.dynamicTest(edit,()->{
  Fixture f=new Fixture();Tokens one=f.issue(f.old);var interaction=f.begin(f.old);String code=f.code(f.old);f.client=client(edit);var next=f.engine(baseline());
  assertEquals(OAuthAuthorizationRecord.clientFingerprint(client("none")),OAuthAuthorizationRecord.clientFingerprint(f.client));
  assertInstanceOf(OAuthAuthorizationResult.Completed.class,f.complete(next,interaction));assertInstanceOf(OAuthTokenResult.Succeeded.class,f.redeem(next,code));assertInstanceOf(OAuthTokenResult.Succeeded.class,f.rotate(next,one.refresh()));f.active(next,one.access());
 }));}
 @TestFactory @NonNull Stream<@NonNull DynamicTest> fingerprintFieldsAndVerifierVersionObligationAreExplicit(){return Stream.of("version","redirect","scope-add","scope-remove","refresh","code","authentication","verifier-object","introspection").map(edit->DynamicTest.dynamicTest(edit,()->{
  var initial=client("none");var changed=client(edit);
  if(edit.equals("verifier-object")){
   initial=registration().authentication(OAuthServerClientAuthentication.fromClientSecretVerifier((id,secret,budget)->true)).build();changed=registration().authentication(OAuthServerClientAuthentication.fromClientSecretVerifier((id,secret,budget)->false)).build();
  }else if(edit.equals("introspection")){
   initial=registration().authentication(OAuthServerClientAuthentication.fromClientSecretVerifier((id,secret,budget)->true)).introspectionResources(Set.of(RESOURCE)).build();changed=registration().authentication(OAuthServerClientAuthentication.fromClientSecretVerifier((id,secret,budget)->true)).introspectionResources(Set.of()).build();
  }
  boolean same=edit.equals("verifier-object")||edit.equals("introspection");assertEquals(same,OAuthAuthorizationRecord.clientFingerprint(initial).equals(OAuthAuthorizationRecord.clientFingerprint(changed)));
 }));}
 @TestFactory @NonNull Stream<@NonNull DynamicTest> explicitManagementFencePreventsRegistrationRollbackResurrection(){return Stream.of("grant","subject","issuer").map(fence->DynamicTest.dynamicTest(fence,()->{
  Fixture f=new Fixture();Tokens one=f.issue(f.old);f.client=client("version");var next=f.engine(baseline());invalidGrant(f.rotate(next,one.refresh()));f.active(next,one.access());
  switch(fence){case "grant"->next.revokeGrant(one.grant());case "subject"->next.revokeSubject("subject");default->next.revokeAllGrants();}
  f.client=client("none");f.inactive(f.old,one.access());invalidGrant(f.rotate(f.old,one.refresh()));Tokens fresh=f.issue(next);assertNotEquals(one.grant(),fresh.grant());f.active(next,fresh.access());
 }));}
 @Test void lawfulExpiryCleanupCannotResurrectFamilyAfterPolicyChangeOrRollback(){
  Fixture f=new Fixture();Tokens one=f.issue(f.old);Instant horizon=f.grant(one.grant()).horizon();f.store.authorityNow=horizon;
  f.store.rows.entrySet().removeIf(e->e.getKey().getKind()!=OAuthStoreKey.Kind.ISSUER_STATE&&e.getKey().getKind()!=OAuthStoreKey.Kind.SUBJECT_STATE&&!e.getValue().getRetainUntil().isAfter(horizon));
  assertEquals(2,f.store.rows.size());var before=Map.copyOf(f.store.rows);var next=f.engine(expanded("skew"));invalidGrant(f.rotate(next,one.refresh()));invalidGrant(f.rotate(f.old,one.refresh()));f.inactive(next,one.access());assertEquals(before,f.store.rows);
 }
}
