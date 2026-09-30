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

package com.revetsec.oidc;

import com.revetsec.*;
import com.revetsec.internal.encoding.QueryParameters;
import com.revetsec.jose.*;
import com.revetsec.oauth.*;
import com.revetsec.json.*;
import com.revetsec.testing.*;
import com.revetsec.testing.TestJsonWebKeys.Fixture;
import com.revetsec.testing.TestJws.Algorithm;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.*;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.*;
import java.util.function.Consumer;
import java.util.stream.Stream;
import static org.junit.jupiter.api.Assertions.*;

final class OidcRefreshTests {
	private static final URI CALLBACK = URI.create("https://rp.example/callback");
	private static final Instant NOW = Instant.parse("2026-09-29T12:00:00Z");
	private static final Clock CLOCK = Clock.fixed(NOW, ZoneOffset.UTC);
	private static final String SUBJECT = "TEST-ONLY-refresh-subject";
	private static final String ACCESS = "TEST-ONLY-new-access";
	private static final String OLD_REFRESH = "TEST-ONLY-old-refresh+/=";
	private static final String NEW_REFRESH = "TEST-ONLY-new-refresh";
	private static final String SID = "TEST-ONLY-session-id";
	private static final String SECRET = "TEST-ONLY-identity-secret";

	@Test
	void omittedIdTokenReleasesNoNewIdentityAndRetainsOriginalReferenceAndRefreshCredential() throws Exception {
		try (TestHttpsServer server = TestHttpsServer.start()) {
			OidcClient client = builder(server).jsonWebKeySource(keys()).build(); Login login = login(server, client, CLOCK);
			OidcClient remote = builder(server).jsonWebKeySource(null).build(); respond(server, response(null, null, "bEaReR"));
			OidcRefreshResult result = remote.refresh(login.refresh(), login.reference());
			assertTrue(result.getIdToken().isEmpty()); assertSame(login.refresh(), result.getRefreshToken()); assertSame(login.reference(), result.getSessionReference());
			assertTrue(result.getTokens().getRefreshToken().isEmpty()); assertTrue(result.getTokens().getGrantedScopes().isEmpty()); assertEquals(ACCESS, result.getTokens().getAccessToken().getValue());
			assertTrue(result.getTokens().getParameter("id_token").isEmpty()); assertEquals(0, server.getHitCount("/jwks")); assertRedacted(result.toString());
			QueryParameters form = QueryParameters.parse(server.getRequests("/token").get(1).getBodyAsString());
			assertEquals(List.of("refresh_token"), form.getValues("grant_type")); assertEquals(List.of(OLD_REFRESH), form.getValues("refresh_token"));
			for (String name : List.of("scope", "resource", "nonce", "code", "code_verifier", "redirect_uri")) assertTrue(form.getValues(name).isEmpty(), name);
			respond(server, response(null, NEW_REFRESH, "Bearer")); OidcRefreshResult rotated = remote.refresh(result.getRefreshToken(), result.getSessionReference());
			assertEquals(NEW_REFRESH, rotated.getRefreshToken().getValue()); assertEquals(Optional.of(rotated.getRefreshToken()), rotated.getTokens().getRefreshToken()); assertEquals(3, server.getHitCount("/token"));
		}
	}

	@Test
	void signedRefreshAndOptionsReuseOAuthWriterAndPreserveSessionAndSafeTokenView() throws Exception {
		try (TestHttpsServer server = TestHttpsServer.start()) {
			List<String> events = new ArrayList<>(); OidcClient client = builder(server).observer(new OidcObserver() {
				@Override public void didRefreshTokens(Boolean id, Boolean refresh) { events.add("success:"+id+":"+refresh); throw new IllegalStateException(SECRET); }
			}).build(); Login login = login(server, client, CLOCK); Map<String,String> claims = claims(server); claims.put("nonce", JsonText.string(login.nonce()));
			claims.put("at_hash", JsonText.string(IdTokenHash.hash(JwsAlgorithm.RS256, ACCESS))); String compact = sign(claims, false); respond(server, response(compact, NEW_REFRESH, "Bearer"));
			OidcRefreshResult result = client.refresh(login.refresh(), login.reference(), TokenRequestOptions.builder().scopes(Set.of("email"))
					.resources(List.of(URI.create("https://api.example/resource"))).additionalParameters(Map.of("audience", "api")).build());
			assertEquals(compact, result.getIdToken().orElseThrow().toCompactSerialization()); assertSame(login.reference(), result.getSessionReference());
			assertEquals(NEW_REFRESH, result.getRefreshToken().getValue()); assertTrue(result.getTokens().getParameter("id_token").isEmpty()); assertEquals(Optional.of(Set.of("email")), result.getTokens().getGrantedScopes());
			assertEquals(List.of("success:true:true"), events); assertRedacted(result.toString()+events+result.getIdToken().orElseThrow());
			QueryParameters form = QueryParameters.parse(server.getRequests("/token").get(1).getBodyAsString()); assertEquals(List.of("email"), form.getValues("scope")); assertEquals(List.of("https://api.example/resource"), form.getValues("resource")); assertEquals(List.of("api"), form.getValues("audience"));
		}
	}

	@Test
	void lateRefreshDoesNotReapplyLoginAgeOrMaxAgeAndOriginalAuthTimeSurvivesOmission() throws Exception {
		try (TestHttpsServer server = TestHttpsServer.start()) {
			TestClock clock = TestClock.fromInstant(NOW); OidcClient client = builder(server).clock(clock).maximumIdTokenAge(Duration.ofMinutes(1)).build(); Login login = login(server, client, clock);
			clock.advance(Duration.ofHours(1)); Map<String,String> claims = claims(server); claims.put("iat", Long.toString(NOW.plusSeconds(3000).getEpochSecond())); claims.put("exp", Long.toString(NOW.plusSeconds(7200).getEpochSecond()));
			respond(server, response(sign(claims,false), null,"Bearer")); assertTrue(client.refresh(login.refresh(), login.reference()).getIdToken().isPresent());
			claims.remove("auth_time"); respond(server, response(sign(claims,false), null,"Bearer")); OidcRefreshResult result = client.refresh(login.refresh(),login.reference());
			assertSame(login.reference(),result.getSessionReference()); claims.put("auth_time", Long.toString(NOW.plusSeconds(1).getEpochSecond())); respond(server,response(sign(claims,false),null,"Bearer"));
			assertEquals(OidcValidationException.Reason.REFRESHED_ID_TOKEN_MISMATCH, assertThrows(OidcValidationException.class, () -> client.refresh(result.getRefreshToken(), result.getSessionReference())).getReason());
		}
	}

	@Test
	void audiencesCompareAsExactRecipientSetsAndOptionalNonceMatchesOriginalDigest() throws Exception {
		try (TestHttpsServer server = TestHttpsServer.start()) {
			OidcClient client = builder(server).trustedAudiences(Set.of("trusted")).build(); Login login = login(server, client, CLOCK, c -> c.put("aud", "[\"client\",\"trusted\"]"));
			Map<String,String> claims = claims(server); claims.put("aud", "[\"trusted\",\"client\"]"); claims.put("nonce",JsonText.string(login.nonce())); respond(server,response(sign(claims,false),null,"Bearer"));
			assertTrue(client.refresh(login.refresh(),login.reference()).getIdToken().isPresent());
		}
		try (TestHttpsServer server = TestHttpsServer.start()) {
			OidcClient client=builder(server).build(); Login login=login(server,client,CLOCK); Map<String,String> claims=claims(server); claims.put("aud","[\"client\"]"); respond(server,response(sign(claims,false),null,"Bearer"));
			assertTrue(client.refresh(login.refresh(),login.reference()).getIdToken().isPresent());
		}
	}

	@TestFactory
	Stream<DynamicTest> signedRefreshFailuresExposeNoTokensAndNeverCallSuccessHook() {
		record Case(String name, OidcValidationException.Reason reason, Consumer<Map<String,String>> change) { }
		return Stream.of(
			new Case("bad signature", OidcValidationException.Reason.ID_TOKEN_SIGNATURE_INVALID,c->{}),
			new Case("issuer", OidcValidationException.Reason.ISSUER_MISMATCH,c->c.put("iss","\"https://attacker.example\"")),
			new Case("subject", OidcValidationException.Reason.REFRESHED_ID_TOKEN_MISMATCH,c->c.put("sub","\"other\"")),
			new Case("audience", OidcValidationException.Reason.AUDIENCE_MISMATCH,c->c.put("aud","\"other\"")),
			new Case("extra trusted audience", OidcValidationException.Reason.REFRESHED_ID_TOKEN_MISMATCH,c->c.put("aud","[\"client\",\"trusted\"]")),
			new Case("azp added", OidcValidationException.Reason.REFRESHED_ID_TOKEN_MISMATCH,c->c.put("azp","\"client\"")),
			new Case("auth time changed", OidcValidationException.Reason.REFRESHED_ID_TOKEN_MISMATCH,c->c.put("auth_time",Long.toString(NOW.minusSeconds(1).getEpochSecond()))),
			new Case("nonce changed", OidcValidationException.Reason.REFRESHED_ID_TOKEN_MISMATCH,c->c.put("nonce","\"other\"")),
			new Case("nonce wrong type", OidcValidationException.Reason.ID_TOKEN_MALFORMED,c->c.put("nonce","null")),
			new Case("iat older original", OidcValidationException.Reason.REFRESHED_ID_TOKEN_MISMATCH,c->c.put("iat",Long.toString(NOW.minusSeconds(1).getEpochSecond()))),
			new Case("iat future", OidcValidationException.Reason.ISSUED_IN_FUTURE,c->c.put("iat",Long.toString(NOW.plusSeconds(1).getEpochSecond()))),
			new Case("iat absent", OidcValidationException.Reason.MISSING_CLAIM,c->c.remove("iat")),
			new Case("expired", OidcValidationException.Reason.EXPIRED,c->c.put("exp",Long.toString(NOW.getEpochSecond()))),
			new Case("exp absent", OidcValidationException.Reason.MISSING_CLAIM,c->c.remove("exp")),
			new Case("not yet", OidcValidationException.Reason.NOT_YET_VALID,c->c.put("nbf",Long.toString(NOW.plusSeconds(1).getEpochSecond()))),
			new Case("acr", OidcValidationException.Reason.INSUFFICIENT_ACR,c->c.put("acr","\"urn:weak\"")),
			new Case("access hash", OidcValidationException.Reason.ACCESS_TOKEN_HASH_MISMATCH,c->c.put("at_hash","\"wrong\"")),
			new Case("code hash", OidcValidationException.Reason.CODE_HASH_MISMATCH,c->c.put("c_hash","\"cannot-verify\"")),
			new Case("bad auth time", OidcValidationException.Reason.ID_TOKEN_MALFORMED,c->c.put("auth_time","\"date\"")),
			new Case("bad subject", OidcValidationException.Reason.INVALID_SUBJECT,c->c.put("sub","\"\"")))
		.map(test->DynamicTest.dynamicTest(test.name(),()->{
			try(TestHttpsServer server=TestHttpsServer.start()) {
				AtomicReference<OidcValidationException> observed=new AtomicReference<>(); AtomicInteger successes=new AtomicInteger();
				OidcClient client=builder(server).clockSkew(Duration.ZERO).trustedAudiences(Set.of("trusted")).observer(new OidcObserver(){
					@Override public void didRejectRefresh(OidcValidationException failure){ observed.set(failure); throw new IllegalStateException(ACCESS); }
					@Override public void didRefreshTokens(Boolean id,Boolean refresh){successes.incrementAndGet();}
				}).build(); Login login=login(server,client,CLOCK); Map<String,String> claims=claims(server);test.change().accept(claims); String compact=sign(claims,test.name().equals("bad signature")); respond(server,response(compact,NEW_REFRESH,"Bearer"));
				OidcValidationException failure=assertThrows(OidcValidationException.class,()->client.refresh(login.refresh(),login.reference())); assertEquals(test.reason(),failure.getReason()); assertSame(failure,observed.get()); assertEquals(0,successes.get()); assertSafe(failure,compact); assertEquals(2,server.getHitCount("/token"));
			}
		}));
	}

	@TestFactory
	Stream<DynamicTest> malformedPresentIdTokenNeverMasqueradesAsOmission() {
		return Stream.of("null","1","{}","[]","\"\"","\"malformed\"").map(value->DynamicTest.dynamicTest(value,()->{
			try(TestHttpsServer server=TestHttpsServer.start()){
				OidcClient client=builder(server).build();Login login=login(server,client,CLOCK);respond(server,"{\"access_token\":"+JsonText.string(ACCESS)+",\"token_type\":\"Bearer\",\"id_token\":"+value+"}");
				OidcValidationException failure=assertThrows(OidcValidationException.class,()->client.refresh(login.refresh(),login.reference()));assertEquals(OidcValidationException.Reason.ID_TOKEN_MALFORMED,failure.getReason());assertSafe(failure,value);
			}
		}));
	}

	@Test
	void azpAndOriginalAuthTimePresenceCannotBeInventedAndTrustedAzpDriftStillRejects() throws Exception {
		try(TestHttpsServer server=TestHttpsServer.start()){
			OidcClient client=builder(server).trustedAuthorizedParties(Set.of("trusted-party")).build();Login login=login(server,client,CLOCK,c->c.put("azp","\"client\""));
			for(String value:List.of("absent","trusted-party")){
				Map<String,String> claims=claims(server);if(!value.equals("absent"))claims.put("azp",JsonText.string(value));respond(server,response(sign(claims,false),null,"Bearer"));
				assertEquals(OidcValidationException.Reason.REFRESHED_ID_TOKEN_MISMATCH,assertThrows(OidcValidationException.class,()->client.refresh(login.refresh(),login.reference())).getReason());
			}
			com.revetsec.json.JsonObject envelope=(com.revetsec.json.JsonObject)com.revetsec.internal.json.JsonCodec.parse(login.reference().toSerializedForm().getBytes(StandardCharsets.UTF_8),com.revetsec.internal.json.JsonLimits.protocolDocument(64*1024));
			Map<String,JsonValue> originalClaims=new LinkedHashMap<>(((JsonObject)Objects.requireNonNull(envelope.getMembers().get("claims"))).getMembers()); originalClaims.remove("auth_time");
			Map<String,JsonValue> storage=new LinkedHashMap<>(envelope.getMembers()); storage.put("claims",JsonObject.fromMembers(originalClaims));
			OidcSessionReference withoutTime=OidcSessionReference.fromSerializedForm(JsonObject.fromMembers(storage).toJson());
			Map<String,String> claims=claims(server);claims.put("azp","\"client\"");respond(server,response(sign(claims,false),null,"Bearer"));
			assertEquals(OidcValidationException.Reason.REFRESHED_ID_TOKEN_MISMATCH,assertThrows(OidcValidationException.class,()->client.refresh(login.refresh(),withoutTime)).getReason());
		}
	}

	@Test
	void wrongIssuerOrClientReferenceRejectsBeforeDiscoveryOrTokenPost() throws Exception {
		try(TestHttpsServer server=TestHttpsServer.start()){
			Login login=login(server,builder(server).build(),CLOCK);
			for(OidcClient client:List.of(lazy(server).clientId("other").trustedAudiences(Set.of("client")).build(),OidcClient.withIssuer(server.uri("/other").toString()).clientId("client").redirectUri(CALLBACK).httpClient(TestTls.httpClient()).clock(CLOCK).build())) {
				assertEquals(OidcValidationException.Reason.REFRESHED_ID_TOKEN_MISMATCH,assertThrows(OidcValidationException.class,()->client.refresh(login.refresh(),login.reference())).getReason());
			}
			assertEquals(1,server.getRequests().size());
		}
	}

	@Test
	void refreshRetainsOidcDiscoveryOrderAndChecksDeadlineBeforeCredentialPost() throws Exception {
		try(TestHttpsServer server=TestHttpsServer.start()){
			Login login=login(server,builder(server).build(),CLOCK);discovery(server);respond(server,response(sign(claims(server),false),null,"Bearer"));
			OidcClient client=lazy(server).build();assertTrue(client.refresh(login.refresh(),login.reference()).getIdToken().isPresent());
			assertEquals(List.of("/token","/.well-known/openid-configuration","/token"),server.getRequests().stream().map(TestHttpsServer.RecordedRequest::getPath).toList());
			OidcClient exhausted=lazy(server).requestTimeout(Duration.ofSeconds(1)).totalDeadline(Duration.ofSeconds(1)).observer(new OidcObserver(){
				@Override public void didRequestEndpoint(OAuthEndpoint endpoint,URI uri,Integer status,Duration elapsed){if(endpoint==OAuthEndpoint.METADATA)pause();}
			}).build();assertEquals(OAuthException.Reason.NETWORK_FAILURE,assertThrows(OAuthException.class,()->exhausted.refresh(login.refresh(),login.reference())).getReason());assertEquals(2,server.getHitCount("/token"));
		}
	}

	@Test
	void tokenAndJwksShareDeadlineAndClockIsReadAfterKeyLookup() throws Exception {
		try(TestHttpsServer server=TestHttpsServer.start()){
			Login login=login(server,builder(server).build(),CLOCK);respond(server,response(sign(claims(server),false),null,"Bearer"));
			OidcClient client=builder(server).jsonWebKeySource(null).requestTimeout(Duration.ofSeconds(1)).totalDeadline(Duration.ofSeconds(1)).observer(new OidcObserver(){
				@Override public void didRequestEndpoint(OAuthEndpoint endpoint,URI uri,Integer status,Duration elapsed){if(endpoint==OAuthEndpoint.TOKEN)pause();}
			}).build();assertThrows(JsonWebKeySetUnavailableException.class,()->client.refresh(login.refresh(),login.reference()));assertEquals(0,server.getHitCount("/jwks"));
			TestClock clock=TestClock.fromInstant(NOW);server.script("/jwks",TestHttpsServer.Script.fromResponse(TestHttpsServer.Response.fromJsonWebKeySet(keyJson())));
			OidcClient slow=builder(server).clock(clock).jsonWebKeySource(null).clockSkew(Duration.ZERO).observer(new OidcObserver(){
				@Override public void didFetchJsonWebKeySet(URI uri,Integer usable,Integer skipped,Duration ttl,Duration elapsed){clock.advance(Duration.ofSeconds(2));}
			}).build();Map<String,String> claims=claims(server);claims.put("exp",Long.toString(NOW.plusSeconds(1).getEpochSecond()));respond(server,response(sign(claims,false),null,"Bearer"));
			assertEquals(OidcValidationException.Reason.EXPIRED,assertThrows(OidcValidationException.class,()->slow.refresh(login.refresh(),login.reference())).getReason());assertEquals(1,server.getHitCount("/jwks"));
		}
	}

	@TestFactory
	Stream<DynamicTest> refreshDoesNotFollowRedirectsOrRetryHttpErrorsAndRejectsOtherTokenTypes() {
		return Stream.of("redirect","503","DPoP").map(name->DynamicTest.dynamicTest(name,()->{
			try(TestHttpsServer server=TestHttpsServer.start()){
				OidcClient client=builder(server).build();Login login=login(server,client,CLOCK);
				if(name.equals("redirect")){server.script("/token",TestHttpsServer.Script.fromRedirect(302,server.uri("/attack").toString()));assertEquals(OAuthException.Reason.REDIRECT_NOT_FOLLOWED,assertThrows(OAuthException.class,()->client.refresh(login.refresh(),login.reference())).getReason());assertEquals(0,server.getHitCount("/attack"));}
				else if(name.equals("503")){server.script("/token",TestHttpsServer.Script.fromResponse(TestHttpsServer.Response.fromJson(503,"{\"error\":\"temporarily_unavailable\",\"error_description\":"+JsonText.string(ACCESS)+"}")));OAuthErrorResponseException failure=assertThrows(OAuthErrorResponseException.class,()->client.refresh(login.refresh(),login.reference()));assertEquals(503,failure.getStatus());assertRedacted(failure.toString());}
				else {respond(server,response(null,null,"DPoP"));assertEquals(OidcValidationException.Reason.TOKEN_TYPE_UNSUPPORTED,assertThrows(OidcValidationException.class,()->client.refresh(login.refresh(),login.reference())).getReason());}
				assertEquals(2,server.getHitCount("/token"));
			}
		}));
	}

	record Login(OidcSessionReference reference,RefreshToken refresh,String nonce){}
	static Login login(TestHttpsServer server,OidcClient client,Clock clock)throws Exception{return login(server,client,clock,c->{});}
	static Login login(TestHttpsServer server,OidcClient client,Clock clock,Consumer<Map<String,String>> change)throws Exception{
		AuthorizationRedirect redirect=client.beginAuthentication(OidcAuthenticationOptions.builder().maxAge(Duration.ZERO).build());QueryParameters query=QueryParameters.parse(redirect.getAuthorizationUri().getRawQuery());String nonce=query.getValues("nonce").get(0);Map<String,String> claims=claims(server);claims.put("nonce",JsonText.string(nonce));claims.put("email",JsonText.string(SECRET));change.accept(claims);respond(server,response(sign(claims,false),OLD_REFRESH,"Bearer"));StateSealer sealer=StateSealer.withActiveKey(TestSealers.fixedKey("refresh")).clock(clock).build();
		OidcAuthentication authentication=client.completeAuthentication(AuthorizationResponse.fromQueryString("state="+query.getValues("state").get(0)+"&code=TEST-ONLY-code"),PendingAuthorizationSource.fromSealedForm(redirect.getPendingAuthorization().toSealedForm(sealer,"refresh-pending"),sealer,"refresh-pending"),CALLBACK);
		return new Login(authentication.getSessionReference(),authentication.getTokens().getRefreshToken().orElseThrow(),nonce);
	}
	private static OidcProviderMetadata metadata(TestHttpsServer server){return OidcProviderMetadata.withIssuer(server.getBaseUri().toString()).authorizationEndpoint(server.uri("/authorize")).tokenEndpoint(server.uri("/token")).jwksUri(server.uri("/jwks")).build();}
	static OidcClient.Builder builder(TestHttpsServer server){return OidcClient.withProviderMetadata(metadata(server)).clientId("client").redirectUri(CALLBACK).clock(CLOCK).requiredAcrValues(Set.of("urn:mfa")).jsonWebKeySource(keys()).httpClient(TestTls.httpClient());}
	private static OidcClient.Builder lazy(TestHttpsServer server){return OidcClient.withIssuer(server.getBaseUri().toString()).clientId("client").redirectUri(CALLBACK).clock(CLOCK).requiredAcrValues(Set.of("urn:mfa")).jsonWebKeySource(keys()).httpClient(TestTls.httpClient());}
	private static String keyJson(){return TestJsonWebKeys.withFixture(Fixture.IDP_SIGNING_RSA_2048).kid("key").alg("RS256").toKeySetJson();}
	private static StaticJsonWebKeySource keys(){return StaticJsonWebKeySource.fromJsonWebKeySet(JsonWebKeySet.fromJson(keyJson()));}
	private static Map<String,String> claims(TestHttpsServer server){Map<String,String> claims=new LinkedHashMap<>();claims.put("iss",JsonText.string(server.getBaseUri().toString()));claims.put("sub",JsonText.string(SUBJECT));claims.put("aud","\"client\"");claims.put("iat",Long.toString(NOW.getEpochSecond()));claims.put("exp",Long.toString(NOW.plusSeconds(300).getEpochSecond()));claims.put("auth_time",Long.toString(NOW.getEpochSecond()));claims.put("acr","\"urn:mfa\"");claims.put("sid",JsonText.string(SID));return claims;}
	private static String sign(Map<String,String> claims,boolean forged){return TestJws.withAlgorithm(Algorithm.RS256).kid("key").payload(JsonText.object(new ArrayList<>(claims.entrySet()))).sign(forged?Fixture.NEGATIVE_ATTACKER_RSA_2048.getPrivateKey():Fixture.IDP_SIGNING_RSA_2048.getPrivateKey());}
	private static String response(@Nullable String id,@Nullable String refresh,String type){return "{\"access_token\":"+JsonText.string(ACCESS)+",\"token_type\":"+JsonText.string(type)+(id==null?"":",\"id_token\":"+JsonText.string(id))+(refresh==null?"":",\"refresh_token\":"+JsonText.string(refresh))+"}";}
	private static void respond(TestHttpsServer server,String body){server.script("/token",TestHttpsServer.Script.fromResponse(TestHttpsServer.Response.fromJson(200,body)));}
	private static void discovery(TestHttpsServer server){server.script("/.well-known/openid-configuration",TestHttpsServer.Script.fromResponse(TestHttpsServer.Response.fromJson(200,"{\"issuer\":"+JsonText.string(server.getBaseUri().toString())+",\"authorization_endpoint\":"+JsonText.string(server.uri("/authorize").toString())+",\"token_endpoint\":"+JsonText.string(server.uri("/token").toString())+",\"jwks_uri\":"+JsonText.string(server.uri("/jwks").toString())+",\"subject_types_supported\":[\"public\"],\"id_token_signing_alg_values_supported\":[\"RS256\"],\"response_types_supported\":[\"code\"]}")));}
	private static void pause(){try{new CountDownLatch(1).await(2,TimeUnit.SECONDS);}catch(InterruptedException interrupted){Thread.currentThread().interrupt();}}
	private static void assertRedacted(String text){for(String secret:List.of(ACCESS,OLD_REFRESH,NEW_REFRESH,SUBJECT,SID,SECRET))assertFalse(text.contains(secret),"Disclosed test-only sentinel");}
	private static void assertSafe(OidcValidationException failure,String compact)throws Exception{
		assertNull(failure.getCause());failure.addSuppressed(new IllegalStateException(ACCESS));assertEquals(0,failure.getSuppressed().length);assertRedacted(failure.toString());if(compact.length()>10)assertFalse(failure.toString().contains(compact));
		for(Class<?> type=failure.getClass();type!=RuntimeException.class;type=type.getSuperclass())for(var field:type.getDeclaredFields()){
			if(java.lang.reflect.Modifier.isStatic(field.getModifiers()))continue;field.setAccessible(true);Object value=field.get(failure);assertFalse(value instanceof OidcRefreshResult||value instanceof IdToken||value instanceof Jwt||value instanceof AccessToken||value instanceof RefreshToken);if(value instanceof String text)assertRedacted(text);
		}
	}
}
