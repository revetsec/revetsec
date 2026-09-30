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
import com.revetsec.testing.*;
import com.revetsec.testing.TestJws.Algorithm;
import org.junit.jupiter.api.*;
import org.jspecify.annotations.Nullable;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.*;
import java.util.*;
import java.util.concurrent.atomic.*;
import java.util.function.Consumer;
import java.util.stream.Stream;
import static org.junit.jupiter.api.Assertions.*;

final class OidcHmacTests {
	private static final URI CALLBACK = URI.create("https://rp.example/callback");
	private static final Instant NOW = Instant.parse("2026-09-29T12:00:00Z");
	private static final Clock CLOCK = Clock.fixed(NOW, ZoneOffset.UTC);
	private static final String ACCESS = "TEST-ONLY-hmac-access";
	private static final String REFRESH = "TEST-ONLY-hmac-refresh";
	private static final String CODE = "TEST-ONLY-hmac-code";
	private static final String SUBJECT = "TEST-ONLY-hmac-subject";
	private static final String SECRET = "TEST-ONLY-hmac-secret-" + "s".repeat(43);

	@TestFactory
	Stream<DynamicTest> optInRequiresConfidentialAuthenticationAndUtf8HashLength() {
		return Stream.of(JwsAlgorithm.HS256, JwsAlgorithm.HS384, JwsAlgorithm.HS512).flatMap(algorithm ->
				Stream.of("disabled", "public", "short", "mixed shortest", "invalid unicode", "supplier throws")
				.map(name -> DynamicTest.dynamicTest(algorithm+":"+name, () -> {
					try (TestHttpsServer server = TestHttpsServer.start()) {
						OidcClient.Builder builder = builder(server, algorithm).idTokenSigningAlgorithms(Set.of(algorithm));
						if (name.equals("disabled")) builder.compatibility(null);
						else if (name.equals("public")) builder.clientAuthentication(ClientAuthentication.noneInstance());
						else if (name.equals("short")) builder.clientAuthentication(ClientAuthentication.fromClientSecretPost("s".repeat(length(algorithm)-1)));
						else if (name.equals("mixed shortest")) builder.idTokenSigningAlgorithms(Set.of(JwsAlgorithm.HS256,JwsAlgorithm.HS512))
								.clientAuthentication(ClientAuthentication.fromClientSecretPost("s".repeat(32)));
						else if (name.equals("invalid unicode")) builder.clientAuthentication(ClientAuthentication.fromClientSecretPost("s".repeat(64)+"\ud800"));
						else if (name.equals("supplier throws")) builder.clientAuthentication(ClientAuthentication.fromClientSecretPost(() -> { throw new IllegalStateException(SECRET); }));
						IllegalArgumentException failure=assertThrows(IllegalArgumentException.class,builder::build);
						assertNull(failure.getCause());assertFalse(failure.toString().contains(SECRET));assertEquals(0,server.getRequests().size());
					}
				})));
	}

	@TestFactory
	Stream<DynamicTest> eachHmacAlgorithmUsesExactUtf8SecretWithBasicOrPostAndNoKeys() {
		return Stream.of(JwsAlgorithm.HS256,JwsAlgorithm.HS384,JwsAlgorithm.HS512).flatMap(algorithm -> Stream.of("basic","post")
				.map(method -> DynamicTest.dynamicTest(algorithm+":"+method,()->{
					try(TestHttpsServer server=TestHttpsServer.start()) {
						// Two UTF-8 bytes per character: the minimum is bytes, not characters, with no base64 decoding.
						String secret="é".repeat(length(algorithm)/2);
						OidcClient client=builder(server,algorithm).clientAuthentication(method.equals("basic")?ClientAuthentication.fromClientSecretBasic(secret):ClientAuthentication.fromClientSecretPost(secret)).build();
						client.warmUp();assertEquals(0,server.getRequests().size());
						AuthorizationRedirect redirect=client.beginAuthentication();Map<String,String> claims=claims(server);claims.put("nonce",JsonText.string(nonce(redirect)));
						claims.put("at_hash",JsonText.string(IdTokenHash.hash(algorithm,ACCESS)));claims.put("c_hash",JsonText.string(IdTokenHash.hash(algorithm,CODE)));
						String compact=sign(algorithm,claims,secret);respond(server,compact);OidcAuthentication auth=complete(client,redirect);
						assertEquals(SUBJECT,auth.getSubject());assertEquals(compact,auth.getIdToken().toCompactSerialization());assertTrue(auth.getTokens().getParameter("id_token").isEmpty());
						assertFalse(auth.toString().contains(secret));assertFalse(auth.getSessionReference().toSerializedForm().contains(secret));
						claims.remove("nonce");claims.remove("c_hash");respond(server,sign(algorithm,claims,secret));OidcRefreshResult result=client.refresh(auth.getTokens().getRefreshToken().orElseThrow(),auth.getSessionReference());
						assertTrue(result.getIdToken().isPresent());assertSame(auth.getSessionReference(),result.getSessionReference());assertEquals(2,server.getHitCount("/token"));assertEquals(0,server.getHitCount("/jwks"));
						QueryParameters form=QueryParameters.parse(server.getRequests("/token").get(0).getBodyAsString());
						if(method.equals("post")) assertEquals(List.of(secret),form.getValues("client_secret"));else assertTrue(form.getValues("client_secret").isEmpty());
					}
				})));
	}

	@Test
	void supplierSnapshotSurvivesRotationAndIsReadOnceAtBuildAndOncePerPost() throws Exception {
		try(TestHttpsServer server=TestHttpsServer.start()) {
			AtomicInteger calls=new AtomicInteger();AtomicReference<String> current=new AtomicReference<>(SECRET);List<String> events=new ArrayList<>();
			OidcClient client=builder(server,JwsAlgorithm.HS256).clientAuthentication(ClientAuthentication.fromClientSecretPost(()->{calls.incrementAndGet();return current.get();}))
					.observer(new OidcObserver(){
						@Override public void didEnableCompatibilityMode(OidcCompatibilityMode mode){events.add("build:"+mode);throw new IllegalStateException(SECRET);}
						@Override public void didUseCompatibilityMode(OidcCompatibilityMode mode){events.add("use:"+mode);throw new IllegalStateException(SECRET);}
						@Override public void didRequestEndpoint(OAuthEndpoint endpoint,URI uri,Integer status,Duration elapsed){if(endpoint==OAuthEndpoint.TOKEN)current.set(SECRET+"rotated");}
					}).build();
			assertEquals(1,calls.get());AuthorizationRedirect redirect=client.beginAuthentication();Map<String,String> claims=claims(server);claims.put("nonce",JsonText.string(nonce(redirect)));respond(server,sign(JwsAlgorithm.HS256,claims,SECRET));
			OidcAuthentication auth=complete(client,redirect);assertEquals(2,calls.get());
			claims.remove("nonce");respond(server,sign(JwsAlgorithm.HS256,claims,SECRET+"rotated"));OidcRefreshResult result=client.refresh(auth.getTokens().getRefreshToken().orElseThrow(),auth.getSessionReference());assertEquals(3,calls.get());assertTrue(result.getIdToken().isPresent());
			assertEquals(List.of("build:HMAC_ID_TOKENS","use:HMAC_ID_TOKENS","use:HMAC_ID_TOKENS"),events);assertEquals(0,server.getHitCount("/jwks"));
			current.set("short");int requests=server.getRequests().size();IllegalArgumentException failure=assertThrows(IllegalArgumentException.class,()->client.refresh(result.getRefreshToken(),result.getSessionReference()));assertNull(failure.getCause());assertFalse(failure.toString().contains(SECRET));assertEquals(requests,server.getRequests().size());assertEquals(4,calls.get());
		}
	}

	@TestFactory
	Stream<DynamicTest> hmacStillChecksClaimsHashesSignatureAndExactAudience() {
		record Case(String name,OidcValidationException.Reason reason,Consumer<Map<String,String>> change){}
		return Stream.of(
			new Case("bad signature",OidcValidationException.Reason.ID_TOKEN_SIGNATURE_INVALID,c->{}),
			new Case("issuer",OidcValidationException.Reason.ISSUER_MISMATCH,c->c.put("iss","\"https://attacker.example\"")),
			new Case("subject",OidcValidationException.Reason.INVALID_SUBJECT,c->c.put("sub","\"\"")),
			new Case("wrong aud",OidcValidationException.Reason.AUDIENCE_MISMATCH,c->c.put("aud","\"other\"")),
			new Case("multiple trusted aud",OidcValidationException.Reason.HMAC_MULTIPLE_AUDIENCES,c->c.put("aud","[\"client\",\"trusted\"]")),
			new Case("duplicate aud",OidcValidationException.Reason.HMAC_MULTIPLE_AUDIENCES,c->c.put("aud","[\"client\",\"client\"]")),
			new Case("expired",OidcValidationException.Reason.EXPIRED,c->c.put("exp",Long.toString(NOW.getEpochSecond()))),
			new Case("future iat",OidcValidationException.Reason.ISSUED_IN_FUTURE,c->c.put("iat",Long.toString(NOW.plusSeconds(1).getEpochSecond()))),
			new Case("nonce",OidcValidationException.Reason.NONCE_MISMATCH,c->c.put("nonce","\"other\"")),
			new Case("no nonce",OidcValidationException.Reason.NONCE_MISSING,c->c.remove("nonce")),
			new Case("at hash",OidcValidationException.Reason.ACCESS_TOKEN_HASH_MISMATCH,c->c.put("at_hash","\"wrong\"")),
			new Case("code hash",OidcValidationException.Reason.CODE_HASH_MISMATCH,c->c.put("c_hash","\"wrong\"")),
			new Case("missing auth time",OidcValidationException.Reason.AUTH_TIME_MISSING,c->c.remove("auth_time")))
		.map(test->DynamicTest.dynamicTest(test.name(),()->{
			try(TestHttpsServer server=TestHttpsServer.start()) {
				AtomicInteger used=new AtomicInteger(),completed=new AtomicInteger();AtomicReference<OidcValidationException> observed=new AtomicReference<>();
				OidcClient client=builder(server,JwsAlgorithm.HS256).trustedAudiences(Set.of("trusted")).observer(new OidcObserver(){
					@Override public void didUseCompatibilityMode(OidcCompatibilityMode mode){used.incrementAndGet();}
					@Override public void didCompleteAuthentication(){completed.incrementAndGet();}
					@Override public void didRejectIdToken(OidcValidationException failure){observed.set(failure);}
				}).build();AuthorizationRedirect redirect=client.beginAuthentication(OidcAuthenticationOptions.builder().maxAge(Duration.ZERO).build());Map<String,String> claims=claims(server);claims.put("nonce",JsonText.string(nonce(redirect)));test.change().accept(claims);String compact=sign(JwsAlgorithm.HS256,claims,test.name().equals("bad signature")?SECRET+"wrong":SECRET);respond(server,compact);
				OidcValidationException failure=assertThrows(OidcValidationException.class,()->complete(client,redirect));assertEquals(test.reason(),failure.getReason());assertSame(failure,observed.get());assertEquals(1,used.get());assertEquals(0,completed.get());assertSafe(failure,compact);assertEquals(0,server.getHitCount("/jwks"));
			}
		}));
	}

	@Test
	void hmacRefreshRetainsOriginalNonceAndRejectsSubjectDriftBeforeTokenRelease() throws Exception {
		try(TestHttpsServer server=TestHttpsServer.start()) {
			OidcClient client=builder(server,JwsAlgorithm.HS384).build();AuthorizationRedirect redirect=client.beginAuthentication();Map<String,String> claims=claims(server);claims.put("nonce",JsonText.string(nonce(redirect)));respond(server,sign(JwsAlgorithm.HS384,claims,SECRET));OidcAuthentication auth=complete(client,redirect);
			claims.put("aud","[\"client\"]");respond(server,sign(JwsAlgorithm.HS384,claims,SECRET));OidcRefreshResult result=client.refresh(auth.getTokens().getRefreshToken().orElseThrow(),auth.getSessionReference());assertTrue(result.getIdToken().isPresent());
			for(String name:List.of("sub","nonce","auth_time")) {
				Map<String,String> changed=new LinkedHashMap<>(claims);changed.put(name,name.equals("auth_time")?Long.toString(NOW.minusSeconds(1).getEpochSecond()):"\"other\"");String compact=sign(JwsAlgorithm.HS384,changed,SECRET);respond(server,compact);
				OidcValidationException failure=assertThrows(OidcValidationException.class,()->client.refresh(result.getRefreshToken(),result.getSessionReference()));assertEquals(OidcValidationException.Reason.REFRESHED_ID_TOKEN_MISMATCH,failure.getReason());assertSafe(failure,compact);
			}
			respond(server,null);assertTrue(client.refresh(result.getRefreshToken(),result.getSessionReference()).getIdToken().isEmpty());assertEquals(0,server.getHitCount("/jwks"));
		}
	}

	@TestFactory
	Stream<DynamicTest> rsaDerPemAndJwkBytesAreNeverHmacKeys() {
		return Stream.of("der","pem","jwk").map(encoding->DynamicTest.dynamicTest(encoding,()->{
			try(TestHttpsServer server=TestHttpsServer.start()) {
				OidcClient client=builder(server,JwsAlgorithm.HS256).idTokenSigningAlgorithms(Set.of(JwsAlgorithm.RS256,JwsAlgorithm.HS256)).build();AuthorizationRedirect redirect=client.beginAuthentication();Map<String,String> claims=claims(server);claims.put("nonce",JsonText.string(nonce(redirect)));
				var fixture=TestJsonWebKeys.Fixture.IDP_SIGNING_RSA_2048;
				byte[] key=switch(encoding){case "der"->fixture.getPublicKey().getEncoded();case "pem"->("-----BEGIN PUBLIC KEY-----\n"+Base64.getEncoder().encodeToString(fixture.getPublicKey().getEncoded())+"\n-----END PUBLIC KEY-----").getBytes(StandardCharsets.UTF_8);default->TestJsonWebKeys.withFixture(fixture).toKeySetJson().getBytes(StandardCharsets.UTF_8);};
				String compact=TestJws.withAlgorithm(Algorithm.HS256).payload(JsonText.object(new ArrayList<>(claims.entrySet()))).sign(key);respond(server,compact);
				OidcValidationException failure=assertThrows(OidcValidationException.class,()->complete(client,redirect));assertEquals(OidcValidationException.Reason.ID_TOKEN_SIGNATURE_INVALID,failure.getReason());assertSafe(failure,compact);assertEquals(0,server.getHitCount("/jwks"));
			}
		}));
	}

	@Test
	void mixedAllowlistUsesPublicKeysOnlyForRsaAndModeDoesNotChangeDefaults() throws Exception {
		try(TestHttpsServer server=TestHttpsServer.start()) {
			AtomicInteger used=new AtomicInteger();OidcClient client=builder(server,JwsAlgorithm.HS256).idTokenSigningAlgorithms(Set.of(JwsAlgorithm.RS256,JwsAlgorithm.HS256)).jsonWebKeySource(keys()).observer(new OidcObserver(){@Override public void didUseCompatibilityMode(OidcCompatibilityMode mode){used.incrementAndGet();}}).build();
			AuthorizationRedirect redirect=client.beginAuthentication();Map<String,String> claims=claims(server);claims.put("nonce",JsonText.string(nonce(redirect)));respond(server,TestJws.withAlgorithm(Algorithm.RS256).kid("key").payload(JsonText.object(new ArrayList<>(claims.entrySet()))).sign(TestJsonWebKeys.Fixture.IDP_SIGNING_RSA_2048.getPrivateKey()));assertEquals(SUBJECT,complete(client,redirect).getSubject());assertEquals(0,used.get());
			OidcClient defaults=builder(server,JwsAlgorithm.HS256).idTokenSigningAlgorithms(null).clientAuthentication(ClientAuthentication.noneInstance()).build();AuthorizationRedirect pending=defaults.beginAuthentication();claims.put("nonce",JsonText.string(nonce(pending)));respond(server,sign(JwsAlgorithm.HS256,claims,SECRET));assertEquals(OidcValidationException.Reason.ALGORITHM_NOT_ALLOWED,assertThrows(OidcValidationException.class,()->complete(defaults,pending)).getReason());
			for(JwsAlgorithm hmac:List.of(JwsAlgorithm.HS256,JwsAlgorithm.HS384,JwsAlgorithm.HS512))assertThrows(IllegalArgumentException.class,()->JwtValidator.withIssuer(server.getBaseUri().toString()).expectedAudiences(Set.of("client")).jsonWebKeySource(keys()).allowedAlgorithms(Set.of(hmac)).build());
		}
	}

	@Test
	void lazyDiscoveryIntersectsHmacAndWarmUpFetchesNoJwks() throws Exception {
		try(TestHttpsServer server=TestHttpsServer.start()) {
			String metadata="{\"issuer\":"+JsonText.string(server.getBaseUri().toString())+",\"authorization_endpoint\":"+JsonText.string(server.uri("/authorize").toString())+",\"token_endpoint\":"+JsonText.string(server.uri("/token").toString())+",\"jwks_uri\":"+JsonText.string(server.uri("/jwks").toString())+",\"subject_types_supported\":[\"public\"],\"response_types_supported\":[\"code\"],\"id_token_signing_alg_values_supported\":[\"RS256\",\"HS256\"]}";
			server.script("/.well-known/openid-configuration",TestHttpsServer.Script.fromResponse(TestHttpsServer.Response.fromJson(200,metadata)));
			OidcClient client=OidcClient.withIssuer(server.getBaseUri().toString()).clientId("client").redirectUri(CALLBACK).clock(CLOCK).httpClient(TestTls.httpClient()).clientAuthentication(ClientAuthentication.fromClientSecretBasic(SECRET)).idTokenSigningAlgorithms(Set.of(JwsAlgorithm.HS256)).compatibility(Set.of(OidcCompatibilityMode.HMAC_ID_TOKENS)).build();client.warmUp();assertEquals(1,server.getHitCount("/.well-known/openid-configuration"));assertEquals(0,server.getHitCount("/jwks"));
			AuthorizationRedirect redirect=client.beginAuthentication();Map<String,String> claims=claims(server);claims.put("nonce",JsonText.string(nonce(redirect)));respond(server,sign(JwsAlgorithm.HS256,claims,SECRET));assertEquals(SUBJECT,complete(client,redirect).getSubject());
			OidcClient unsupported=OidcClient.withIssuer(server.getBaseUri().toString()).clientId("client").redirectUri(CALLBACK).httpClient(TestTls.httpClient()).clientAuthentication(ClientAuthentication.fromClientSecretBasic(SECRET)).idTokenSigningAlgorithms(Set.of(JwsAlgorithm.HS512)).compatibility(Set.of(OidcCompatibilityMode.HMAC_ID_TOKENS)).build();
			assertEquals(OAuthException.Reason.METADATA_INVALID,assertThrows(OAuthException.class,unsupported::beginAuthentication).getReason());assertEquals(1,server.getHitCount("/token"));
			assertThrows(IllegalArgumentException.class,()->builder(server,JwsAlgorithm.HS256).idTokenSigningAlgorithms(Set.of(JwsAlgorithm.HS256)).userInfoSignedResponseAlgorithm(JwsAlgorithm.HS256).build());
		}
	}

	private static int length(JwsAlgorithm algorithm){return switch(algorithm){case HS256->32;case HS384->48;case HS512->64;default->throw new AssertionError();};}
	private static OidcClient.Builder builder(TestHttpsServer server,JwsAlgorithm algorithm){return OidcClient.withProviderMetadata(OidcProviderMetadata.withIssuer(server.getBaseUri().toString()).authorizationEndpoint(server.uri("/authorize")).tokenEndpoint(server.uri("/token")).jwksUri(server.uri("/jwks")).idTokenSigningAlgValuesSupported(Set.of("RS256","HS256","HS384","HS512")).build()).clientId("client").redirectUri(CALLBACK).clock(CLOCK).clockSkew(Duration.ZERO).httpClient(TestTls.httpClient()).clientAuthentication(ClientAuthentication.fromClientSecretPost(SECRET)).idTokenSigningAlgorithms(Set.of(algorithm)).compatibility(Set.of(OidcCompatibilityMode.HMAC_ID_TOKENS));}
	private static StaticJsonWebKeySource keys(){return StaticJsonWebKeySource.fromJsonWebKeySet(JsonWebKeySet.fromJson(TestJsonWebKeys.withFixture(TestJsonWebKeys.Fixture.IDP_SIGNING_RSA_2048).kid("key").alg("RS256").toKeySetJson()));}
	private static Map<String,String> claims(TestHttpsServer server){Map<String,String> c=new LinkedHashMap<>();c.put("iss",JsonText.string(server.getBaseUri().toString()));c.put("sub",JsonText.string(SUBJECT));c.put("aud","\"client\"");c.put("iat",Long.toString(NOW.getEpochSecond()));c.put("exp",Long.toString(NOW.plusSeconds(300).getEpochSecond()));c.put("auth_time",Long.toString(NOW.getEpochSecond()));return c;}
	private static String nonce(AuthorizationRedirect redirect)throws Exception{return QueryParameters.parse(redirect.getAuthorizationUri().getRawQuery()).getValues("nonce").get(0);}
	private static String sign(JwsAlgorithm algorithm,Map<String,String> claims,String secret){return TestJws.withAlgorithm(Algorithm.valueOf(algorithm.name())).payload(JsonText.object(new ArrayList<>(claims.entrySet()))).sign(secret.getBytes(StandardCharsets.UTF_8));}
	private static void respond(TestHttpsServer server,@Nullable String compact){server.script("/token",TestHttpsServer.Script.fromResponse(TestHttpsServer.Response.fromJson(200,"{\"access_token\":"+JsonText.string(ACCESS)+",\"token_type\":\"Bearer\",\"refresh_token\":"+JsonText.string(REFRESH)+(compact==null?"":",\"id_token\":"+JsonText.string(compact))+"}")));}
	private static OidcAuthentication complete(OidcClient client,AuthorizationRedirect redirect)throws Exception{return client.completeAuthentication(AuthorizationResponse.fromQueryString("state="+QueryParameters.parse(redirect.getAuthorizationUri().getRawQuery()).getValues("state").get(0)+"&code="+CODE),PendingAuthorizationSource.fromSealedForm(redirect.getPendingAuthorization().toSealedForm(StateSealer.withActiveKey(TestSealers.fixedKey("hmac")).clock(CLOCK).build(),"hmac-pending"),StateSealer.withActiveKey(TestSealers.fixedKey("hmac")).clock(CLOCK).build(),"hmac-pending"),CALLBACK);}
	private static void assertSafe(OidcValidationException failure,String compact){assertNull(failure.getCause());failure.addSuppressed(new IllegalStateException(SECRET));assertEquals(0,failure.getSuppressed().length);for(String input:List.of(SECRET,ACCESS,REFRESH,SUBJECT,compact))assertFalse(failure.toString().contains(input));}
}
