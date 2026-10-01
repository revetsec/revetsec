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

package com.revetsec.oauth;

import org.junit.jupiter.api.*;
import static org.junit.jupiter.api.Assertions.*;
import com.revetsec.testing.*;
import com.revetsec.jose.*;
import com.revetsec.json.*;
import com.revetsec.internal.http.*;
import com.revetsec.internal.jose.*;
import com.revetsec.OutboundUriPolicy;
import org.jspecify.annotations.Nullable;
import java.net.*;
import java.net.http.*;
import java.time.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.*;
import java.util.function.*;
import java.util.stream.*;
import static com.revetsec.oauth.Phase2Fixtures.*;

/** Corrected M4 single-flight regression cases, now on RFC8414 resource-role discovery. */
final class ResourceServerMetadataCacheTests {
    private static final String PATH="/.well-known/oauth-authorization-server/tenant";
	@Test
	void cacheHonorsFreshnessBoundsRollbackAndNeverServesStaleAfterFailure() throws Exception {
		try (TestHttpsServer server = TestHttpsServer.start()) {
			RewindableClock clock = RewindableClock.fromInstant(NOW); AtomicLong nanos = new AtomicLong();
			script(server,fields(server),"max-age=1"); ResourceServerMetadataCache<ResourceServerMetadata> cache = cache(server,clock,nanos);
			ResourceServerMetadata first = cache.get(deadline()); clock.advance(Duration.ofSeconds(20)); assertSame(first,cache.get(deadline()));
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
			ResourceServerMetadataCache<ResourceServerMetadata> cache = cache(server,clock,nanos); cache.get(deadline()); clock.advance(Duration.ofSeconds(61)); cache.get(deadline());
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
			ResourceServerMetadataCache<ResourceServerMetadata> cache = cache(server,clock,nanos); OAuthException first = assertThrows(OAuthException.class, () -> cache.get(deadline()));
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
			ResourceServerMetadataCache<ResourceServerMetadata> cache = cache(server,RewindableClock.fromInstant(NOW),new AtomicLong()); ExecutorService pool = Executors.newFixedThreadPool(4);
			try {
				Future<ResourceServerMetadata> leader = pool.submit(() -> cache.get(deadline())); assertTrue(held.awaitHeldCount(1,Duration.ofSeconds(5)));
				Future<ResourceServerMetadata> one = pool.submit(() -> cache.get(deadline())); Future<ResourceServerMetadata> two = pool.submit(() -> cache.get(deadline()));
				assertTrue(cache.awaitWaitersForTests(2,Duration.ofSeconds(5)));
				assertEquals(OAuthException.Reason.NETWORK_FAILURE, assertThrows(OAuthTransportException.class, () -> cache.get(Deadline.fromNow(Duration.ZERO))).getReason());
				Future<OAuthException.Reason> interrupted = pool.submit(() -> { Thread.currentThread().interrupt(); try { cache.get(deadline()); throw new AssertionError(); } catch (OAuthException failure) { assertTrue(Thread.currentThread().isInterrupted()); return failure.getReason(); } });
				assertEquals(OAuthException.Reason.INTERRUPTED,interrupted.get(5,TimeUnit.SECONDS));
				held.release(); ResourceServerMetadata result = leader.get(5,TimeUnit.SECONDS); assertSame(result,one.get(5,TimeUnit.SECONDS)); assertSame(result,two.get(5,TimeUnit.SECONDS)); assertEquals(1,server.getHitCount(PATH));
			} finally { held.release(); pool.shutdownNow(); assertTrue(pool.awaitTermination(5,TimeUnit.SECONDS)); }
		}
	}
	@Test
	void overdueFlightCannotPublishAfterReplacement() throws Exception {
		try (TestHttpsServer server = TestHttpsServer.start()) {
			TestHttpsServer.HeldScript held = TestHttpsServer.HeldScript.fromResponse(TestHttpsServer.Response.fromJson(200,json(fields(server)))); server.script(PATH,held);
			AtomicLong nanos = new AtomicLong(); ResourceServerMetadataCache<ResourceServerMetadata> cache = cache(server,RewindableClock.fromInstant(NOW),nanos); ExecutorService pool=Executors.newSingleThreadExecutor();
			try {
				Future<ResourceServerMetadata> old = pool.submit(() -> cache.get(deadline())); assertTrue(held.awaitHeldCount(1,Duration.ofSeconds(5)));
				nanos.set(Duration.ofSeconds(21).toNanos()); script(server,fields(server),"max-age=60"); ResourceServerMetadata replacement=cache.get(deadline()); held.release();
				assertInstanceOf(OAuthTransportException.class,assertThrows(ExecutionException.class, () -> old.get(5,TimeUnit.SECONDS)).getCause());
				assertSame(replacement,cache.get(deadline())); assertEquals(2,server.getHitCount(PATH));
			} finally { held.release();pool.shutdownNow();assertTrue(pool.awaitTermination(5,TimeUnit.SECONDS)); }
		}
	}
	@Test
	void cacheMaximumAgeAndNoStoreAreClamped() throws Exception {
		try (TestHttpsServer server = TestHttpsServer.start()) {
			RewindableClock clock=RewindableClock.fromInstant(NOW);AtomicLong nanos=new AtomicLong();script(server,fields(server),"max-age=99999");ResourceServerMetadataCache<ResourceServerMetadata> cache=cache(server,clock,nanos);
			ResourceServerMetadata first=cache.get(deadline());clock.advance(Duration.ofSeconds(59));assertSame(first,cache.get(deadline()));clock.advance(Duration.ofSeconds(1));assertNotSame(first,cache.get(deadline()));
			nanos.addAndGet(Duration.ofSeconds(31).toNanos());script(server,fields(server),"no-store");clock.advance(Duration.ofSeconds(61));ResourceServerMetadata noStore=cache.get(deadline());clock.advance(Duration.ofSeconds(29));assertSame(noStore,cache.get(deadline()));clock.advance(Duration.ofSeconds(1));assertNotSame(noStore,cache.get(deadline()));assertEquals(4,server.getHitCount(PATH));
		}
	}

    private static ResourceServerMetadataCache<ResourceServerMetadata> cache(TestHttpsServer server,Clock clock,AtomicLong nanos) {
        return new ResourceServerMetadataCache<>(URI.create(issuer(server)),ResourceServerMetadata.Role.JWT,HttpExchange.fromHttpClient(TestTls.httpClient(),OutboundUriPolicy.defaultInstance(),false),
                OutboundUriPolicy.defaultInstance(),false,Duration.ofSeconds(10),clock,AccessTokenObserver.disabledInstance(),Duration.ofSeconds(30),Duration.ofSeconds(30),Duration.ofSeconds(60),Duration.ofSeconds(30),metadata->metadata,nanos::get);
    }
    private static Deadline deadline() { return Deadline.fromNow(Duration.ofSeconds(15)); }
    private static String issuer(TestHttpsServer server) { return server.uri("/tenant/").toString(); }
    private static Map<String,String> fields(TestHttpsServer server) { return Map.of("issuer",JsonText.string(issuer(server)),"jwks_uri",JsonText.string(server.uri("/jwks").toString())); }
    private static String json(Map<String,String> fields) { return JsonText.object(new ArrayList<>(fields.entrySet())); }
    private static void script(TestHttpsServer server,Map<String,String> fields,String cache) { server.script(PATH,TestHttpsServer.Script.fromResponse(TestHttpsServer.Response.withStatus(200).header("Content-Type","application/json").header("Cache-Control",cache).body(json(fields)).build())); }
    @Test void publicationHookCannotReplaceCurrentSourceAfterAnOverdueFlight() throws Exception {
        try(TestHttpsServer server=TestHttpsServer.start()) {
            TestHttpsServer.HeldScript held=TestHttpsServer.HeldScript.fromResponse(TestHttpsServer.Response.fromJson(200,json(fields(server))));server.script(PATH,held);
            AtomicLong nanos=new AtomicLong();AtomicReference<URI> current=new AtomicReference<>();AtomicInteger publications=new AtomicInteger();
            ResourceServerMetadataCache<ResourceServerMetadata> cache=new ResourceServerMetadataCache<>(URI.create(issuer(server)),ResourceServerMetadata.Role.JWT,HttpExchange.fromHttpClient(TestTls.httpClient(),OutboundUriPolicy.defaultInstance(),false),OutboundUriPolicy.defaultInstance(),false,Duration.ofSeconds(10),CLOCK,AccessTokenObserver.disabledInstance(),Duration.ofSeconds(30),Duration.ofSeconds(30),Duration.ofSeconds(60),Duration.ofSeconds(30),m->m,nanos::get,m->{current.set(m.endpoint());publications.incrementAndGet();});
            ExecutorService pool=Executors.newSingleThreadExecutor();
            try {
                Future<ResourceServerMetadata> old=pool.submit(()->cache.get(deadline()));assertTrue(held.awaitHeldCount(1,Duration.ofSeconds(5)));
                nanos.set(Duration.ofSeconds(21).toNanos());URI changed=server.uri("/replacement-keys");script(server,Map.of("issuer",JsonText.string(issuer(server)),"jwks_uri",JsonText.string(changed.toString())),"max-age=60");
                assertEquals(changed,cache.get(deadline()).endpoint());held.release();assertThrows(ExecutionException.class,()->old.get(5,TimeUnit.SECONDS));
                assertEquals(changed,current.get());assertEquals(1,publications.get());assertEquals(changed,cache.get(deadline()).endpoint());assertEquals(2,server.getHitCount(PATH));
            } finally {held.release();pool.shutdownNow();assertTrue(pool.awaitTermination(5,TimeUnit.SECONDS));}
        }
    }
    @Test void projectionRuntimeFailureIsSafeBackedOffAndDoesNotPublish() throws Exception {
        try(TestHttpsServer server=TestHttpsServer.start()) {
            script(server,fields(server),"max-age=60");AtomicLong nanos=new AtomicLong();AtomicInteger calls=new AtomicInteger();
            ResourceServerMetadataCache<ResourceServerMetadata> cache=new ResourceServerMetadataCache<>(URI.create(issuer(server)),ResourceServerMetadata.Role.JWT,HttpExchange.fromHttpClient(TestTls.httpClient(),OutboundUriPolicy.defaultInstance(),false),OutboundUriPolicy.defaultInstance(),false,Duration.ofSeconds(10),CLOCK,AccessTokenObserver.disabledInstance(),Duration.ofSeconds(30),Duration.ofSeconds(30),Duration.ofSeconds(60),Duration.ofSeconds(30),m->{if(calls.getAndIncrement()==0)throw new IllegalStateException("TEST-ONLY-secret");return m;},nanos::get);
            OAuthException failure=assertThrows(OAuthTransportException.class,()->cache.get(deadline()));redacted(failure,"TEST-ONLY-secret");assertNull(failure.getCause());assertSame(failure,assertThrows(OAuthTransportException.class,()->cache.get(deadline())));assertEquals(1,server.getHitCount(PATH));nanos.set(Duration.ofSeconds(31).toNanos());assertNotNull(cache.get(deadline()));assertEquals(2,server.getHitCount(PATH));
        }
    }

}
