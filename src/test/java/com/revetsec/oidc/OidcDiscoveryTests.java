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

import com.revetsec.StateSealer;
import com.revetsec.OutboundUriPolicy;
import com.revetsec.internal.http.*;
import com.revetsec.internal.encoding.QueryParameters;
import com.revetsec.oauth.*;
import com.revetsec.jose.*;
import com.revetsec.testing.*;
import com.revetsec.json.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;
import org.junit.jupiter.api.DynamicTest;
import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.Consumer;
import java.util.stream.Stream;
import static org.junit.jupiter.api.Assertions.*;

final class OidcDiscoveryTests {
	private static final URI CALLBACK = URI.create("https://rp.example/callback");
	private static final Instant NOW = Instant.parse("2026-09-29T12:00:00Z");
	private static final String PATH = "/tenant/.well-known/openid-configuration";
	private static final String CLIENT = "client";
	@Test
	void pathIssuerPreservesExactSlashAndCachesOnlyOidcDocument() throws Exception {
		try (TestHttpsServer server = TestHttpsServer.start()) {
			String issuer = issuer(server); script(server, fields(server), "max-age=60");
			OidcClient client = builder(server, RewindableClock.fromInstant(NOW)).build();
			assertTrue(server.getRequests().isEmpty());
			AuthorizationRedirect first = client.beginAuthentication(); client.beginAuthentication();
			assertEquals(issuer, first.getPendingAuthorization().getIssuer());
			assertEquals(1, server.getRequests().size()); assertEquals(PATH, server.getRequests().get(0).getPath());
			assertEquals(URI.create("https://issuer.example/tenant/.well-known/openid-configuration"),
					OidcProviderCache.discoveryUri(URI.create("https://issuer.example/tenant/")));
			assertEquals(URI.create("https://issuer.example/%74enant/.well-known/openid-configuration"),
					OidcProviderCache.discoveryUri(URI.create("https://issuer.example/%74enant")));
		}
	}
	@TestFactory
	Stream<DynamicTest> rejectsMissingMistypedDuplicateAndMalformedRequiredMembers() {
		List<Consumer<Map<String,String>>> changes = new ArrayList<>();
		for (String name : List.of("issuer", "authorization_endpoint", "token_endpoint", "jwks_uri", "subject_types_supported", "id_token_signing_alg_values_supported", "response_types_supported")) {
			changes.add(map -> map.remove(name)); changes.add(map -> map.put(name, "null"));
		}
		changes.add(map -> map.put("subject_types_supported", "[]"));
		changes.add(map -> map.put("subject_types_supported", "[\"private\"]"));
		changes.add(map -> map.put("subject_types_supported", "[\"public\",\"public\"]"));
		changes.add(map -> map.put("id_token_signing_alg_values_supported", "[123]"));
		changes.add(map -> map.put("id_token_signing_alg_values_supported", "[\"ES256\"]"));
		changes.add(map -> map.put("id_token_signing_alg_values_supported", "[\"\"]"));
		changes.add(map -> map.put("response_types_supported", "[\"id_token\"]"));
		changes.add(map -> map.put("userinfo_endpoint", "123"));
		changes.add(map -> map.put("jwks_uri", "\"https://bad host\""));
		return java.util.stream.IntStream.range(0, changes.size()).mapToObj(index -> DynamicTest.dynamicTest("malformed " + index, () -> {
			try (TestHttpsServer server = TestHttpsServer.start()) {
				Map<String,String> map = fields(server); changes.get(index).accept(map); script(server, map, "max-age=60");
				OAuthResponseException failure = assertThrows(OAuthResponseException.class, () -> builder(server, Clock.systemUTC()).build().beginAuthentication());
				assertEquals(OAuthException.Reason.DOCUMENT_MALFORMED, failure.getReason()); assertNull(failure.getCause());
				assertEquals(1, server.getRequests().size());
			}
		}));
	}
	@Test
	void parserKeepsDiscoveryProvenanceAndUnknownFieldsWithoutBroadeningPolicy() {
		Map<String,String> fields = publicFields(); fields.put("future_extension", "{\"future\":true}");
		fields.put("id_token_signing_alg_values_supported", "[\"RS256\",\"FUTURE-ALG\",\"none\",\"HS256\"]");
		OidcProviderMetadata metadata = OidcProviderMetadata.fromJson("https://issuer.example", json(fields));
		assertEquals(Set.of("RS256", "FUTURE-ALG", "none", "HS256"), metadata.getIdTokenSigningAlgValuesSupported());
		assertTrue(metadata.oauthMetadata().isRemotelyDiscovered());
		assertEquals(Set.of("public"), metadata.getSubjectTypesSupported());
		for (Set<String> values : List.of(metadata.getSubjectTypesSupported(), metadata.getIdTokenSigningAlgValuesSupported(), metadata.getResponseTypesSupported()))
			assertThrows(UnsupportedOperationException.class, () -> values.add("unexpected"));
		assertThrows(OAuthResponseException.class, () -> OidcProviderMetadata.fromJson("https://issuer.example", "{\"issuer\":\"https://issuer.example\",\"issuer\":\"https://issuer.example\"}"));
		assertEquals(OAuthException.Reason.ISSUER_MISMATCH, assertThrows(OAuthValidationException.class,
				() -> OidcProviderMetadata.fromJson("https://issuer.example/", json(fields))).getReason());
	}
	@TestFactory
	Stream<DynamicTest> validatesEveryKnownEndpointEvenWithInjectedKeys() {
		return Stream.of("authorization_endpoint", "token_endpoint", "jwks_uri", "userinfo_endpoint", "revocation_endpoint")
				.map(name -> DynamicTest.dynamicTest(name, () -> {
					try (TestHttpsServer server = TestHttpsServer.start()) {
						Map<String,String> map = fields(server); map.put(name, JsonText.string("http://169.254.169.254/private?credential=SENTINEL")); script(server, map, "max-age=60");
						OAuthValidationException failure = assertThrows(OAuthValidationException.class, () -> builder(server, Clock.systemUTC()).jsonWebKeySource(keys()).build().beginAuthentication());
						assertEquals(OAuthException.Reason.METADATA_INVALID, failure.getReason()); assertFalse(failure.toString().contains("SENTINEL"));
						assertNull(failure.getCause()); assertEquals(1, server.getRequests().size());
					}
				}));
	}
	@Test
	void incompatibleRemoteAlgorithmsUseOAuthMetadataFailure() throws Exception {
		try (TestHttpsServer server = TestHttpsServer.start()) {
			script(server, fields(server), "max-age=60");
			assertEquals(OAuthException.Reason.METADATA_INVALID, assertThrows(OAuthValidationException.class,
					() -> builder(server, Clock.systemUTC()).idTokenSigningAlgorithms(Set.of(JwsAlgorithm.ES256)).build().beginAuthentication()).getReason());
			assertEquals(1, server.getRequests().size());
		}
	}
	@TestFactory
	Stream<DynamicTest> noFallbackAndNoRedirectFollowing() {
		return Stream.of(404,405,410,302).map(status -> DynamicTest.dynamicTest("status " + status, () -> {
			try (TestHttpsServer server = TestHttpsServer.start()) {
				server.script(PATH, TestHttpsServer.Script.fromResponse(TestHttpsServer.Response.withStatus(status).header("Location", server.uri("/target").toString()).build()));
				OidcClient client = builder(server, Clock.systemUTC()).build();
				OAuthException failure = assertThrows(OAuthException.class, client::beginAuthentication);
				assertEquals(status == 302 ? OAuthException.Reason.REDIRECT_NOT_FOLLOWED : OAuthException.Reason.ENDPOINT_ERROR, failure.getReason());
				assertEquals(1, server.getRequests().size()); assertEquals(0, server.getHitCount("/target"));
			}
		}));
	}
	@Test
	void badLocalCallbacksAndWrongFlowRejectBeforeAnyDiscovery() throws Exception {
		try (TestHttpsServer server = TestHttpsServer.start()) {
			RewindableClock clock = RewindableClock.fromInstant(NOW);
			OidcClient explicit = OidcClient.withProviderMetadata(OidcProviderMetadata.fromJson(issuer(server), json(fields(server))))
					.clientId(CLIENT).redirectUri(CALLBACK).clock(clock).httpClient(TestTls.httpClient()).build();
			AuthorizationRedirect redirect = explicit.beginAuthentication(); OidcClient lazy = builder(server, clock).build();
			PendingAuthorizationSource source = source(redirect, clock);
			assertEquals(OAuthException.Reason.CALLBACK_URI_MISMATCH, assertThrows(OAuthValidationException.class,
					() -> lazy.completeAuthentication(callback(redirect), source, URI.create("https://rp.example/other"))).getReason());
			assertEquals(OAuthException.Reason.STATE_MISMATCH, assertThrows(OAuthValidationException.class,
					() -> lazy.completeAuthentication(AuthorizationResponse.fromQueryString("code=test&state=wrong"), source, CALLBACK)).getReason());
			assertEquals(OAuthException.Reason.ISSUER_MISMATCH, assertThrows(OAuthValidationException.class,
					() -> lazy.completeAuthentication(AuthorizationResponse.fromQueryString(query(redirect) + "&iss=https%3A%2F%2Fother.example"), source, CALLBACK)).getReason());
			AuthorizationRedirect oauth = OAuthClient.withAuthorizationServerMetadata(OidcProviderMetadata.fromJson(issuer(server), json(fields(server))).oauthMetadata())
					.clientId(CLIENT).clientAuthentication(ClientAuthentication.noneInstance()).redirectUri(CALLBACK).clock(clock).httpClient(TestTls.httpClient()).build().beginAuthorization();
			assertEquals(OAuthException.Reason.PENDING_AUTHORIZATION_INVALID, assertThrows(OAuthValidationException.class,
					() -> lazy.completeAuthentication(callback(oauth), source(oauth,clock), CALLBACK)).getReason());
			assertTrue(server.getRequests().isEmpty());
		}
	}
	@Test
	void expiredMetadataDriftPreventsTokenPost() throws Exception {
		try (TestHttpsServer server = TestHttpsServer.start()) {
			RewindableClock clock = RewindableClock.fromInstant(NOW); script(server, fields(server), "max-age=30");
			OidcClient client = shortTtl(builder(server, clock)).build(); AuthorizationRedirect redirect = client.beginAuthentication();
			clock.advance(Duration.ofSeconds(31)); Map<String,String> changed = fields(server); changed.put("token_endpoint", JsonText.string(server.uri("/new-token").toString())); script(server, changed, "max-age=30");
			assertEquals(OAuthException.Reason.METADATA_ENDPOINT_DRIFT, assertThrows(OAuthValidationException.class,
					() -> client.completeAuthentication(callback(redirect), source(redirect,clock), CALLBACK)).getReason());
			assertEquals(2, server.getRequests().size()); assertEquals(0, server.getHitCount("/token")); assertEquals(0, server.getHitCount("/new-token"));
		}
	}
	@Test
	void lazyAuthenticationWarmupAndJwksUriRotationUseCurrentProvider() throws Exception {
		try (TestHttpsServer server = TestHttpsServer.start()) {
			RewindableClock clock = RewindableClock.fromInstant(NOW); script(server, fields(server), "max-age=30");
			server.script("/jwks", TestHttpsServer.Script.fromResponse(TestHttpsServer.Response.fromJsonWebKeySet(keyJson())));
			OidcClient client = shortTtl(builder(server,clock)).jsonWebKeySource(null).build(); client.warmUp(); client.warmUp();
			assertEquals(1,server.getHitCount(PATH)); assertEquals(1, server.getHitCount("/jwks"));
			AuthorizationRedirect redirect = client.beginAuthentication(); String token = token(issuer(server), nonce(redirect), clock.instant());
			server.script("/token", TestHttpsServer.Script.fromResponse(TestHttpsServer.Response.fromJson(200,
					"{\"access_token\":\"test-only-access\",\"token_type\":\"Bearer\",\"id_token\":" + JsonText.string(token) + "}")));
			assertEquals("subject", client.completeAuthentication(callback(redirect), source(redirect,clock), CALLBACK).getSubject());
			clock.advance(Duration.ofSeconds(31)); Map<String,String> changed = fields(server); changed.put("jwks_uri", JsonText.string(server.uri("/new-jwks").toString())); script(server,changed,"max-age=30");
			server.script("/new-jwks", TestHttpsServer.Script.fromResponse(TestHttpsServer.Response.fromJsonWebKeySet(keyJson())));
			client.warmUp(); assertEquals(2,server.getHitCount(PATH)); assertEquals(1, server.getHitCount("/new-jwks")); assertEquals(1,server.getHitCount("/jwks"));
		}
	}
	@Test
	void cacheHonorsFreshnessBoundsRollbackAndNeverServesStaleAfterFailure() throws Exception {
		try (TestHttpsServer server = TestHttpsServer.start()) {
			RewindableClock clock = RewindableClock.fromInstant(NOW); AtomicLong nanos = new AtomicLong();
			script(server,fields(server),"max-age=1"); OidcProviderCache<OidcProviderMetadata> cache = cache(server,clock,nanos);
			OidcProviderMetadata first = cache.get(deadline()); clock.advance(Duration.ofSeconds(20)); assertSame(first,cache.get(deadline()));
			clock.rewind(Duration.ofSeconds(1)); assertNotSame(first, cache.get(deadline())); assertEquals(2,server.getHitCount(PATH));
			nanos.addAndGet(Duration.ofSeconds(31).toNanos()); clock.advance(Duration.ofSeconds(61));
			server.script(PATH,TestHttpsServer.Script.fromResponse(TestHttpsServer.Response.fromRetryAfter(503,"1")));
			assertThrows(OAuthErrorResponseException.class, () -> cache.get(deadline()));
			clock.rewind(Duration.ofSeconds(40)); assertThrows(OAuthErrorResponseException.class, () -> cache.get(deadline()));
			assertEquals(3,server.getHitCount(PATH));
		}
	}
	@Test
	void twoFlightCeilingAndFailureBackoffUseMonotonicTime() throws Exception {
		try (TestHttpsServer server = TestHttpsServer.start()) {
			RewindableClock clock = RewindableClock.fromInstant(NOW); AtomicLong nanos = new AtomicLong(); script(server,fields(server),"max-age=60");
			OidcProviderCache<OidcProviderMetadata> cache = cache(server,clock,nanos); cache.get(deadline()); clock.advance(Duration.ofSeconds(61)); cache.get(deadline());
			clock.advance(Duration.ofSeconds(61)); assertEquals(OAuthException.Reason.ATTEMPT_LIMIT, assertThrows(OAuthTransportException.class, () -> cache.get(deadline())).getReason());
			nanos.addAndGet(Duration.ofSeconds(31).toNanos()); server.script(PATH,TestHttpsServer.Script.fromResponse(TestHttpsServer.Response.fromRetryAfter(503,"9999999999999999999999")));
			OAuthException failure = assertThrows(OAuthException.class, () -> cache.get(deadline()));
			assertSame(failure,assertThrows(OAuthException.class, () -> cache.get(deadline())));
			assertEquals(3, server.getHitCount(PATH));
		}
	}
	@Test
	void retryAfterIsBoundedAndExponentialBackoffPreventsImmediateRetries() throws Exception {
		try (TestHttpsServer server = TestHttpsServer.start()) {
			RewindableClock clock = RewindableClock.fromInstant(NOW); AtomicLong nanos = new AtomicLong();
			server.script(PATH,TestHttpsServer.Script.fromResponse(TestHttpsServer.Response.fromRetryAfter(503,"99999")));
			OidcProviderCache<OidcProviderMetadata> cache = cache(server,clock,nanos); OAuthException first = assertThrows(OAuthException.class, () -> cache.get(deadline()));
			nanos.addAndGet(Duration.ofMinutes(9).toNanos()); assertSame(first,assertThrows(OAuthException.class, () -> cache.get(deadline())));
			nanos.addAndGet(Duration.ofMinutes(1).toNanos()); server.script(PATH,TestHttpsServer.Script.fromResponse(TestHttpsServer.Response.fromStatus(503)));
			OAuthException second = assertThrows(OAuthException.class, () -> cache.get(deadline()));
			nanos.addAndGet(Duration.ofSeconds(59).toNanos()); assertSame(second,assertThrows(OAuthException.class, () -> cache.get(deadline())));
			nanos.addAndGet(Duration.ofSeconds(1).toNanos()); assertThrows(OAuthException.class, () -> cache.get(deadline())); assertEquals(3,server.getHitCount(PATH));
		}
	}
	@Test
	void concurrentDiscoveryIsSingleFlightAndWaiterInterruptionDoesNotCancelLeader() throws Exception {
		try (TestHttpsServer server = TestHttpsServer.start()) {
			TestHttpsServer.HeldScript held = TestHttpsServer.HeldScript.fromResponse(TestHttpsServer.Response.fromJson(200,json(fields(server)))); server.script(PATH,held);
			OidcProviderCache<OidcProviderMetadata> cache = cache(server,RewindableClock.fromInstant(NOW),new AtomicLong()); ExecutorService pool = Executors.newFixedThreadPool(4);
			try {
				Future<OidcProviderMetadata> leader = pool.submit(() -> cache.get(deadline())); assertTrue(held.awaitHeldCount(1,Duration.ofSeconds(5)));
				Future<OidcProviderMetadata> one = pool.submit(() -> cache.get(deadline())); Future<OidcProviderMetadata> two = pool.submit(() -> cache.get(deadline()));
				assertTrue(cache.awaitWaitersForTests(2,Duration.ofSeconds(5)));
				assertEquals(OAuthException.Reason.NETWORK_FAILURE, assertThrows(OAuthTransportException.class, () -> cache.get(Deadline.fromNow(Duration.ZERO))).getReason());
				Future<OAuthException.Reason> interrupted = pool.submit(() -> { Thread.currentThread().interrupt(); try { cache.get(deadline()); throw new AssertionError(); } catch (OAuthException failure) { assertTrue(Thread.currentThread().isInterrupted()); return failure.getReason(); } });
				assertEquals(OAuthException.Reason.INTERRUPTED,interrupted.get(5,TimeUnit.SECONDS));
				held.release(); OidcProviderMetadata result = leader.get(5,TimeUnit.SECONDS); assertSame(result,one.get(5,TimeUnit.SECONDS)); assertSame(result,two.get(5,TimeUnit.SECONDS)); assertEquals(1,server.getHitCount(PATH));
			} finally { held.release(); pool.shutdownNow(); assertTrue(pool.awaitTermination(5,TimeUnit.SECONDS)); }
		}
	}
	@Test
	void overdueFlightCannotPublishAfterReplacement() throws Exception {
		try (TestHttpsServer server = TestHttpsServer.start()) {
			TestHttpsServer.HeldScript held = TestHttpsServer.HeldScript.fromResponse(TestHttpsServer.Response.fromJson(200,json(fields(server)))); server.script(PATH,held);
			AtomicLong nanos = new AtomicLong(); OidcProviderCache<OidcProviderMetadata> cache = cache(server,RewindableClock.fromInstant(NOW),nanos); ExecutorService pool=Executors.newSingleThreadExecutor();
			try {
				Future<OidcProviderMetadata> old = pool.submit(() -> cache.get(deadline())); assertTrue(held.awaitHeldCount(1,Duration.ofSeconds(5)));
				nanos.set(Duration.ofSeconds(21).toNanos()); script(server,fields(server),"max-age=60"); OidcProviderMetadata replacement=cache.get(deadline()); held.release();
				assertInstanceOf(OAuthTransportException.class,assertThrows(ExecutionException.class, () -> old.get(5,TimeUnit.SECONDS)).getCause());
				assertSame(replacement,cache.get(deadline())); assertEquals(2,server.getHitCount(PATH));
			} finally { held.release();pool.shutdownNow();assertTrue(pool.awaitTermination(5,TimeUnit.SECONDS)); }
		}
	}
	@Test
	void cacheMaximumAgeAndNoStoreAreClamped() throws Exception {
		try (TestHttpsServer server = TestHttpsServer.start()) {
			RewindableClock clock=RewindableClock.fromInstant(NOW);AtomicLong nanos=new AtomicLong();script(server,fields(server),"max-age=99999");OidcProviderCache<OidcProviderMetadata> cache=cache(server,clock,nanos);
			OidcProviderMetadata first=cache.get(deadline());clock.advance(Duration.ofSeconds(59));assertSame(first,cache.get(deadline()));clock.advance(Duration.ofSeconds(1));assertNotSame(first,cache.get(deadline()));
			nanos.addAndGet(Duration.ofSeconds(31).toNanos());script(server,fields(server),"no-store");clock.advance(Duration.ofSeconds(61));OidcProviderMetadata noStore=cache.get(deadline());clock.advance(Duration.ofSeconds(29));assertSame(noStore,cache.get(deadline()));clock.advance(Duration.ofSeconds(1));assertNotSame(noStore,cache.get(deadline()));assertEquals(4,server.getHitCount(PATH));
		}
	}
	@Test
	void builderRejectsBadIssuerAndCacheOrderingWithoutIo() {
		for(String issuer:List.of("https://issuer.example?query=x","https://issuer.example/#frag","http://remote.example","https://user:pass@issuer.example"))
			assertThrows(IllegalArgumentException.class,()->OidcClient.withIssuer(issuer).clientId(CLIENT).redirectUri(CALLBACK).build());
		assertThrows(IllegalArgumentException.class,()->OidcClient.withIssuer("https://issuer.example").clientId(CLIENT).redirectUri(CALLBACK).trustedAudiences(Set.of("")).build());
		assertThrows(IllegalArgumentException.class,()->OidcClient.withIssuer("https://issuer.example").clientId(CLIENT).redirectUri(CALLBACK)
				.minimumTimeToLive(Duration.ofMinutes(10)).defaultTimeToLive(Duration.ofMinutes(1)).build());
	}
	@Test
	void concurrentMetadataRefreshCannotChangeAnInFlightCallbacksKeyPolicy() throws Exception {
		try (TestHttpsServer server=TestHttpsServer.start()) {
			RewindableClock clock=RewindableClock.fromInstant(NOW);script(server,fields(server),"max-age=30");
			OidcClient client=shortTtl(builder(server,clock)).jsonWebKeySource(null).build();AuthorizationRedirect redirect=client.beginAuthentication();
			String compact=token(issuer(server),nonce(redirect),clock.instant());
			TestHttpsServer.HeldScript held=TestHttpsServer.HeldScript.fromResponse(TestHttpsServer.Response.fromJson(200,"{\"access_token\":\"test-only-access\",\"token_type\":\"Bearer\",\"id_token\":"+JsonText.string(compact)+"}"));server.script("/token",held);
			server.script("/jwks",TestHttpsServer.Script.fromResponse(TestHttpsServer.Response.fromJsonWebKeySet(keyJson())));
			PendingAuthorizationSource pending=source(redirect,clock);ExecutorService pool=Executors.newSingleThreadExecutor();
			try {
				Future<OidcAuthentication> result=pool.submit(()->client.completeAuthentication(callback(redirect),pending,CALLBACK));assertTrue(held.awaitHeldCount(1,Duration.ofSeconds(5)));
				clock.advance(Duration.ofSeconds(31));Map<String,String> changed=fields(server);changed.put("jwks_uri",JsonText.string(server.uri("/new-jwks").toString()));script(server,changed,"max-age=30");
				server.script("/new-jwks",TestHttpsServer.Script.fromResponse(TestHttpsServer.Response.fromJsonWebKeySet("{\"keys\":[]}")));client.warmUp();held.release();
				assertEquals("subject",result.get(5,TimeUnit.SECONDS).getSubject());assertEquals(1,server.getHitCount("/jwks"));assertEquals(1,server.getHitCount("/new-jwks"));
			} finally { held.release();pool.shutdownNow();assertTrue(pool.awaitTermination(5,TimeUnit.SECONDS)); }
		}
	}
	@Test
	void discoveryCannotResetCompletionOrWarmupDeadline() throws Exception {
		try (TestHttpsServer server=TestHttpsServer.start()) {
			RewindableClock clock=RewindableClock.fromInstant(NOW);script(server,fields(server),"max-age=60");
			OidcObserver slow=new OidcObserver() {
				@Override public void didRequestEndpoint(OAuthEndpoint kind,URI uri,Integer status,Duration elapsed) {
					if(kind==OAuthEndpoint.METADATA)try {new CountDownLatch(1).await(2,TimeUnit.SECONDS);}catch(InterruptedException failure){Thread.currentThread().interrupt();}
				}
			};
			OidcClient explicit=OidcClient.withProviderMetadata(OidcProviderMetadata.fromJson(issuer(server),json(fields(server))))
					.clientId(CLIENT).redirectUri(CALLBACK).clock(clock).httpClient(TestTls.httpClient()).build();AuthorizationRedirect redirect=explicit.beginAuthentication();
			OidcClient lazy=builder(server,clock).requestTimeout(Duration.ofSeconds(1)).totalDeadline(Duration.ofSeconds(1)).observer(slow).build();
			assertEquals(OAuthException.Reason.NETWORK_FAILURE,assertThrows(OAuthTransportException.class,()->lazy.completeAuthentication(callback(redirect),source(redirect,clock),CALLBACK)).getReason());
			assertEquals(0,server.getHitCount("/token"));
			OidcClient warm=builder(server,clock).jsonWebKeySource(null).requestTimeout(Duration.ofSeconds(1)).totalDeadline(Duration.ofSeconds(1)).observer(slow).build();
			assertThrows(JsonWebKeySetUnavailableException.class,warm::warmUp);assertEquals(0,server.getHitCount("/jwks"));assertEquals(2,server.getHitCount(PATH));
		}
	}
	@TestFactory
	Stream<DynamicTest> capturedProvidersParseOfflineWithExactIssuer() {
		return Stream.of("google/2026-09-28/openid-configuration.json","apple/2026-09-28/openid-configuration.json","entra/2026-09-27/tenant-v2-openid.json")
				.map(path->DynamicTest.dynamicTest(path,()->{
					String document;try(var input=Objects.requireNonNull(OidcDiscoveryTests.class.getResourceAsStream("/fixtures/"+path))){document=new String(input.readAllBytes(),StandardCharsets.UTF_8);}
					JsonObject parsed=(JsonObject)com.revetsec.internal.json.JsonCodec.parse(document.getBytes(StandardCharsets.UTF_8),com.revetsec.internal.json.JsonLimits.protocolDocument(256*1024));
					String issuer=((JsonString)Objects.requireNonNull(parsed.getMembers().get("issuer"))).getValue();OidcProviderMetadata provider=OidcProviderMetadata.fromJson(issuer,document);
					assertEquals(issuer,provider.getIssuer());assertTrue(provider.getIdTokenSigningAlgValuesSupported().contains("RS256"));assertTrue(provider.getResponseTypesSupported().contains("code"));
				}));
	}
	private static OidcProviderCache<OidcProviderMetadata> cache(TestHttpsServer server,Clock clock,AtomicLong nanos) {
		return new OidcProviderCache<>(URI.create(issuer(server)),HttpExchange.fromHttpClient(TestTls.httpClient(),OutboundUriPolicy.defaultInstance(),false),
				OutboundUriPolicy.defaultInstance(),false,Duration.ofSeconds(10),clock,OidcObserver.disabledInstance(),Duration.ofSeconds(30),Duration.ofSeconds(30),Duration.ofSeconds(60),Duration.ofSeconds(30),metadata -> metadata,nanos::get);
	}
	private static Deadline deadline() { return Deadline.fromNow(Duration.ofSeconds(15)); }
	private static String issuer(TestHttpsServer server) { return server.uri("/tenant/").toString(); }
	private static OidcClient.Builder builder(TestHttpsServer server,Clock clock) { return OidcClient.withIssuer(issuer(server)).clientId(CLIENT).redirectUri(CALLBACK).clock(clock).httpClient(TestTls.httpClient()).jsonWebKeySource(keys()); }
	private static OidcClient.Builder shortTtl(OidcClient.Builder builder) { return builder.minimumTimeToLive(Duration.ofSeconds(30)).defaultTimeToLive(Duration.ofSeconds(30)).maximumTimeToLive(Duration.ofMinutes(1)).discoveryCooldown(Duration.ofSeconds(1)); }
	private static JsonWebKeySource keys() { return StaticJsonWebKeySource.fromJsonWebKeySet(JsonWebKeySet.fromJson(keyJson())); }
	private static String keyJson() { return TestJsonWebKeys.withFixture(TestJsonWebKeys.Fixture.IDP_SIGNING_RSA_2048).kid("key").alg("RS256").toKeySetJson(); }
	private static Map<String,String> publicFields() {
		Map<String,String> map=new LinkedHashMap<>(); map.put("issuer",JsonText.string("https://issuer.example"));
		map.put("authorization_endpoint",JsonText.string("https://issuer.example/auth"));map.put("token_endpoint",JsonText.string("https://issuer.example/token"));map.put("jwks_uri",JsonText.string("https://issuer.example/jwks"));
		map.put("subject_types_supported","[\"public\"]");map.put("id_token_signing_alg_values_supported","[\"RS256\"]");map.put("response_types_supported","[\"code\"]"); return map;
	}
	private static Map<String,String> fields(TestHttpsServer server) {
		Map<String,String> map=publicFields();map.put("issuer",JsonText.string(issuer(server)));
		map.put("authorization_endpoint",JsonText.string(server.uri("/authorize").toString()));map.put("token_endpoint",JsonText.string(server.uri("/token").toString()));map.put("jwks_uri",JsonText.string(server.uri("/jwks").toString()));return map;
	}
	private static String json(Map<String,String> fields) { return JsonText.object(new ArrayList<>(fields.entrySet())); }
	private static void script(TestHttpsServer server,Map<String,String> fields,String cache) { server.script(PATH,TestHttpsServer.Script.fromResponse(TestHttpsServer.Response.withStatus(200).header("Content-Type","application/json").header("Cache-Control",cache).body(json(fields)).build())); }
	private static String nonce(AuthorizationRedirect redirect) throws Exception { return QueryParameters.parse(redirect.getAuthorizationUri().getRawQuery()).getValues("nonce").get(0); }
	private static String query(AuthorizationRedirect redirect) throws Exception { return "code=TEST-ONLY-CODE&state="+URLEncoder.encode(QueryParameters.parse(redirect.getAuthorizationUri().getRawQuery()).getValues("state").get(0),StandardCharsets.UTF_8); }
	private static AuthorizationResponse callback(AuthorizationRedirect redirect) throws Exception { return AuthorizationResponse.fromQueryString(query(redirect)); }
	private static PendingAuthorizationSource source(AuthorizationRedirect redirect,Clock clock) { StateSealer sealer=StateSealer.withActiveKey(TestSealers.fixedKey("oidc-discovery")).clock(clock).build();String sealed=redirect.getPendingAuthorization().toSealedForm(sealer,"oidc-discovery");return PendingAuthorizationSource.fromSealedForm(sealed,sealer,"oidc-discovery"); }
	private static String token(String issuer,String nonce,Instant now) { return TestJws.withAlgorithm(TestJws.Algorithm.RS256).kid("key").payload(JsonText.object(List.of(Map.entry("iss",JsonText.string(issuer)),Map.entry("sub","\"subject\""),Map.entry("aud",JsonText.string(CLIENT)),Map.entry("iat",Long.toString(now.getEpochSecond())),Map.entry("exp",Long.toString(now.plusSeconds(300).getEpochSecond())),Map.entry("nonce",JsonText.string(nonce))))).sign(TestJsonWebKeys.Fixture.IDP_SIGNING_RSA_2048.getPrivateKey()); }
}
