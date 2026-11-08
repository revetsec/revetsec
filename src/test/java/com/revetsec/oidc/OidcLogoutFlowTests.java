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

import com.revetsec.BrowserBinding;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

import com.revetsec.OutboundUriPolicy;
import com.revetsec.StateSealer;
import com.revetsec.internal.crypto.SealedStateAccess;
import com.revetsec.internal.crypto.SealedStateType;
import com.revetsec.internal.encoding.Base64Url;
import com.revetsec.internal.encoding.QueryParameters;
import com.revetsec.internal.json.JsonCodec;
import com.revetsec.internal.json.JsonLimits;
import com.revetsec.json.JsonObject;
import com.revetsec.json.JsonString;
import com.revetsec.json.JsonValue;
import com.revetsec.oauth.InMemoryPendingAuthorizationStore;
import com.revetsec.oauth.PendingAuthorizationSaveResult;
import com.revetsec.oauth.PendingAuthorizationStore;
import com.revetsec.testing.TestHttpsServer;
import com.revetsec.testing.TestSealers;
import org.junit.jupiter.api.Test;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import static org.junit.jupiter.api.Assertions.*;

final class OidcLogoutFlowTests {
	private static final String BINDING = "TEST-ONLY-independent-browser-binding", SECRET = "TEST-ONLY-private-logout-provider-failure";
	private record Flow(@NonNull OidcClient client, @NonNull OidcLogoutHint hint, @NonNull OidcLogoutRequest request, OidcLogoutFixtures.@NonNull Login login) { }
	private static @NonNull Flow flow(@NonNull TestHttpsServer server, OidcLogoutFixtures.@NonNull MutableClock clock) throws Exception {
		OidcClient client = OidcLogoutFixtures.builder(server, clock).build(); OidcLogoutFixtures.Login login = OidcLogoutFixtures.login(server, client, clock);
		OidcLogoutHint hint = client.logoutHintFrom(login.authentication()); return new Flow(client, hint, client.beginLogout(login.authentication().getSessionReference(), hint), login);
	}
	@Test
	void preparedGetAndPostShareOneIndependentStateAndEmitCredentialsOnlyExplicitly() throws Exception {
		try (TestHttpsServer server = TestHttpsServer.start()) {
			OidcLogoutFixtures.MutableClock clock = new OidcLogoutFixtures.MutableClock(); Flow f = flow(server, clock); OidcLogoutRequest request = f.request;
			assertEquals(Set.of("id_token_hint", "client_id", "post_logout_redirect_uri", "state"), request.getFormParameters().keySet());
			QueryParameters get = QueryParameters.parse(request.getRedirectUri().getRawQuery()), post = QueryParameters.parse(request.toFormBody());
			assertTrue(get.getValuesByName().equals(post.getValuesByName()), "GET/form parameter identity"); assertTrue(get.getValues("id_token_hint").equals(List.of(f.login.compact())), "explicit credential emission");
			String state = java.util.Objects.requireNonNull(request.getFormParameters().get("state")); assertEquals(43, state.length()); assertEquals(32, Base64Url.decode(state).length); assertFalse(state.equals(f.login.nonce()));
			assertThrows(UnsupportedOperationException.class, () -> request.getFormParameters().put("state", "other")); assertEquals(server.uri("/logout"), request.getFormAction());
			assertEquals(OidcLogoutFixtures.LOGOUT, request.getPending().getCallbackUri()); assertEquals(clock.instant(), request.getPending().getCreatedAt()); assertEquals(Duration.ofMinutes(15), Duration.between(request.getPending().getCreatedAt(), request.getPending().getExpiresAt()));
			for (Object value : List.of(request, request.getPending(), f.hint)) { assertFalse(value.toString().contains(f.login.compact())); assertFalse(value.toString().contains(state)); assertFalse(value.toString().contains(BINDING)); }
			assertEquals(0, server.getHitCount("/logout")); assertEquals(0, server.getHitCount("/jwks"));
			OidcLogoutRequest second = f.client.beginLogout(f.login.authentication().getSessionReference(), f.hint); assertFalse(state.equals(second.getFormParameters().get("state")), "fresh state per operation");
		}
	}
	@Test
	void cookieReturnIsCorrelationOnlyAndCookieReplayLimitationIsExplicit() throws Exception {
		try (TestHttpsServer server = TestHttpsServer.start()) {
			OidcLogoutFixtures.MutableClock clock = new OidcLogoutFixtures.MutableClock(); Flow f = flow(server, clock); StateSealer sealer = sealer(clock); String cookie = f.request.getPending().toSealedForm(sealer, "pending");
			PendingOidcLogoutSource source = PendingOidcLogoutSource.fromSealedForm(cookie, sealer, "pending"); String query = query(f.request); int tokens = server.getHitCount("/token");
			assertInstanceOf(OidcLogoutResult.Returned.class, f.client.completeLogoutResult(query, source, OidcLogoutFixtures.LOGOUT));
			assertInstanceOf(OidcLogoutResult.Returned.class, f.client.completeLogoutResult(query, source, OidcLogoutFixtures.LOGOUT), "cookie alone does not supply concurrent atomic single use");
			assertEquals(tokens, server.getHitCount("/token")); assertEquals(0, server.getHitCount("/logout")); assertEquals(0, server.getHitCount("/jwks"));
		}
	}
	@Test
	void genuineStoreSaveBindsExactExpiryDigestAndOpaqueLogoutPurposeThenConsumesOnce() throws Exception {
		try (TestHttpsServer server = TestHttpsServer.start()) {
			OidcLogoutFixtures.MutableClock clock = new OidcLogoutFixtures.MutableClock(); Flow f = flow(server, clock); CaptureStore store = new CaptureStore();
			assertEquals(PendingAuthorizationSaveResult.SAVED, f.request.getPending().saveToResult(store, BINDING, Duration.ofSeconds(1))); String record = java.util.Objects.requireNonNull(store.row.get()); JsonObject object = object(record);
			assertEquals(Set.of("v", "purpose", "issuer", "client_id", "callback_uri", "state", "created_at", "expires_at", "binding_digest"), object.getMembers().keySet());
			assertTrue(record.contains("oidc-logout")); assertFalse(record.contains(f.login.compact())); assertFalse(record.contains(f.login.nonce())); assertFalse(record.contains(BINDING)); assertFalse(record.contains("TEST-ONLY-logout-access")); assertFalse(record.contains("TEST-ONLY-logout-refresh"));
			assertEquals(f.request.getPending().getExpiresAt(), store.expiry); assertTrue(positive(store.saveBudget)); assertTrue(java.util.Objects.requireNonNull(store.saveBudget).compareTo(Duration.ofSeconds(1)) <= 0);
			PendingOidcLogoutSource source = PendingOidcLogoutSource.fromStore(store, BINDING); assertInstanceOf(OidcLogoutResult.Returned.class, f.client.completeLogoutResult(query(f.request), source, OidcLogoutFixtures.LOGOUT));
			assertRejected(OidcLogoutResult.Reason.PENDING_NOT_FOUND, f.client.completeLogoutResult(query(f.request), source, OidcLogoutFixtures.LOGOUT)); assertEquals(2, store.consumes.get()); assertTrue(positive(store.consumeBudget));
		}
	}
	@Test
	void actualInMemoryAtomicStoreAllowsOneWinnerUnderConcurrentReturns() throws Exception {
		try (TestHttpsServer server = TestHttpsServer.start()) {
			OidcLogoutFixtures.MutableClock clock = new OidcLogoutFixtures.MutableClock(); Flow f = flow(server, clock); InMemoryPendingAuthorizationStore store = InMemoryPendingAuthorizationStore.builder().clock(clock).build();
			assertEquals(PendingAuthorizationSaveResult.SAVED, f.request.getPending().saveToResult(store, BINDING)); var pool = Executors.newFixedThreadPool(8); CountDownLatch start = new CountDownLatch(1); List<java.util.concurrent.Future<OidcLogoutResult>> futures = new ArrayList<>();
			try { for (int i = 0; i < 16; ++i) futures.add(pool.submit(() -> { start.await(); return f.client.completeLogoutResult(query(f.request), PendingOidcLogoutSource.fromStore(store, BINDING), OidcLogoutFixtures.LOGOUT); })); start.countDown();
				int winners = 0; for (var future : futures) { OidcLogoutResult result = future.get(10, TimeUnit.SECONDS); if (result instanceof OidcLogoutResult.Returned) ++winners; else assertRejected(OidcLogoutResult.Reason.PENDING_NOT_FOUND, result); } assertEquals(1, winners);
			} finally { start.countDown(); pool.shutdownNow(); assertTrue(pool.awaitTermination(5, TimeUnit.SECONDS)); }
		}
	}
	@Test
	void malformedStateOnlyGrammarAndWrongTrustedCallbackNeverConsume() throws Exception {
		try (TestHttpsServer server = TestHttpsServer.start()) {
			OidcLogoutFixtures.MutableClock clock = new OidcLogoutFixtures.MutableClock(); Flow f = flow(server, clock); CaptureStore store = saved(f.request); PendingOidcLogoutSource source = PendingOidcLogoutSource.fromStore(store, BINDING); String state = java.util.Objects.requireNonNull(f.request.getFormParameters().get("state"));
			for (String malformed : List.of("", "state=", "state=x", "?state=" + state, "%73tate=" + state, "state=" + state + "&state=" + state, "state=" + state + "&%73tate=" + state, "state=" + state + "&code=x", "state=" + state + "&error=denied", "state=" + state + "&iss=x", "state=" + state + "&id_token=x", "state=%ZZ", "state=%C0%AF", "state=%ED%A0%80", "state=" + state + "=", "state=" + state + ";", "x".repeat(4096), "x".repeat(4097), "state=" + state + "%0A"))
				assertRejected(OidcLogoutResult.Reason.MALFORMED_RETURN, f.client.completeLogoutResult(malformed, source, OidcLogoutFixtures.LOGOUT));
			assertRejected(OidcLogoutResult.Reason.CALLBACK_MISMATCH, f.client.completeLogoutResult(query(f.request), source, URI.create("https://other.example/logout"))); assertEquals(0, store.consumes.get()); assertNotNull(store.row.get());
			String encodedValue = "state=%" + Integer.toHexString(state.charAt(0)) + state.substring(1); assertInstanceOf(OidcLogoutResult.Returned.class, f.client.completeLogoutResult(encodedValue, source, OidcLogoutFixtures.LOGOUT));
		}
	}
	@Test
	void exactExpiryAndCreationRollbackAreCheckedAfterOpaqueConsume() throws Exception {
		try (TestHttpsServer server = TestHttpsServer.start()) {
			OidcLogoutFixtures.MutableClock clock = new OidcLogoutFixtures.MutableClock(); Flow f = flow(server, clock); String record = java.util.Objects.requireNonNull(saved(f.request).row.get());
			for (long delta : new long[] {-1, 0, 1}) { CaptureStore store = new CaptureStore(); store.row.set(record); clock.set(f.request.getPending().getExpiresAt().plusNanos(delta)); OidcLogoutResult result = f.client.completeLogoutResult(query(f.request), PendingOidcLogoutSource.fromStore(store, BINDING), OidcLogoutFixtures.LOGOUT);
				if (delta < 0) assertInstanceOf(OidcLogoutResult.Returned.class, result); else assertRejected(OidcLogoutResult.Reason.PENDING_EXPIRED, result); assertEquals(1, store.consumes.get()); }
			CaptureStore rollback = new CaptureStore(); rollback.row.set(record); clock.set(f.request.getPending().getCreatedAt().minusNanos(1)); assertRejected(OidcLogoutResult.Reason.PENDING_INVALID, f.client.completeLogoutResult(query(f.request), PendingOidcLogoutSource.fromStore(rollback, BINDING), OidcLogoutFixtures.LOGOUT));
		}
	}
	@Test
	void cookieExactExpiryTamperingContextAndPurposeMixupsNeverReturnCorrelation() throws Exception {
		try (TestHttpsServer server = TestHttpsServer.start()) {
			OidcLogoutFixtures.MutableClock clock = new OidcLogoutFixtures.MutableClock(); Flow f = flow(server, clock); StateSealer sealer = sealer(clock); String cookie = f.request.getPending().toSealedForm(sealer, "pending");
			String app = sealer.seal(OidcLogoutPendingCodec.encode(f.request.getPending(), null), "pending", Duration.ofMinutes(10)); String hint = f.hint.toSealedForm(sealer, "pending", Duration.ofMinutes(10)); String login = f.client.beginAuthentication().getPendingAuthorization().toSealedForm(sealer, "pending");
			for (String wrong : List.of(app, hint, login, cookie.substring(0, cookie.length() - 1), "x".repeat(16_385))) assertRejected(OidcLogoutResult.Reason.PENDING_INVALID, f.client.completeLogoutResult(query(f.request), PendingOidcLogoutSource.fromSealedForm(wrong, sealer, "pending"), OidcLogoutFixtures.LOGOUT));
			assertRejected(OidcLogoutResult.Reason.PENDING_INVALID, f.client.completeLogoutResult(query(f.request), PendingOidcLogoutSource.fromSealedForm(cookie, sealer, "other"), OidcLogoutFixtures.LOGOUT));
			assertInstanceOf(OidcLogoutHintParseResult.Rejected.class, OidcLogoutHint.fromSealedFormResult(cookie, sealer, "pending"));
			clock.set(f.request.getPending().getExpiresAt().minusNanos(1)); assertInstanceOf(OidcLogoutResult.Returned.class, f.client.completeLogoutResult(query(f.request), PendingOidcLogoutSource.fromSealedForm(cookie, sealer, "pending"), OidcLogoutFixtures.LOGOUT));
			clock.set(f.request.getPending().getExpiresAt()); assertRejected(OidcLogoutResult.Reason.PENDING_EXPIRED, f.client.completeLogoutResult(query(f.request), PendingOidcLogoutSource.fromSealedForm(cookie, sealer, "pending"), OidcLogoutFixtures.LOGOUT));
		}
	}
	@Test
	void storedFieldsBindingAndByteBudgetsAreRecheckedRatherThanTrustingLookupInputs() throws Exception {
		try (TestHttpsServer server = TestHttpsServer.start()) {
			OidcLogoutFixtures.MutableClock clock = new OidcLogoutFixtures.MutableClock(); Flow f = flow(server, clock); String record = java.util.Objects.requireNonNull(saved(f.request).row.get());
			CaptureStore wrongBinding = new CaptureStore(); wrongBinding.row.set(record); assertRejected(OidcLogoutResult.Reason.BROWSER_BINDING_MISMATCH, f.client.completeLogoutResult(query(f.request), PendingOidcLogoutSource.fromStore(wrongBinding, "other-browser"), OidcLogoutFixtures.LOGOUT));
			for (String key : List.of("issuer", "client_id", "callback_uri", "state", "purpose", "v", "unknown")) {
				Map<String, JsonValue> values = new LinkedHashMap<>(object(record).getMembers()); values.put(key, JsonString.fromValue(key.equals("state") ? "A".repeat(43) : "changed")); CaptureStore store = new CaptureStore(); store.row.set(JsonObject.fromMembers(values).toJson());
				OidcLogoutResult.Reason reason = Set.of("issuer", "client_id", "callback_uri").contains(key) ? OidcLogoutResult.Reason.CLIENT_MISMATCH : key.equals("state") ? OidcLogoutResult.Reason.STATE_MISMATCH : OidcLogoutResult.Reason.PENDING_INVALID;
				assertRejected(reason, f.client.completeLogoutResult(query(f.request), PendingOidcLogoutSource.fromStore(store, BINDING), OidcLogoutFixtures.LOGOUT)); assertEquals(1, store.consumes.get());
			}
			for (int bytes : new int[] {16_384, 16_385}) { CaptureStore store = new CaptureStore(); store.row.set(record + " ".repeat(bytes - record.length())); OidcLogoutResult result = f.client.completeLogoutResult(query(f.request), PendingOidcLogoutSource.fromStore(store, BINDING), OidcLogoutFixtures.LOGOUT); if (bytes == 16_384) assertInstanceOf(OidcLogoutResult.Returned.class, result); else assertRejected(OidcLogoutResult.Reason.PENDING_INVALID, result); }
			CaptureStore noDigest = new CaptureStore(); noDigest.row.set(OidcLogoutPendingCodec.encode(f.request.getPending(), null)); assertRejected(OidcLogoutResult.Reason.PENDING_INVALID, f.client.completeLogoutResult(query(f.request), PendingOidcLogoutSource.fromStore(noDigest, BINDING), OidcLogoutFixtures.LOGOUT));
		}
	}
	@Test
	void saveOutcomesAndPossiblyAppliedFailuresNeverPermitAutomaticRetry() throws Exception {
		try (TestHttpsServer server = TestHttpsServer.start()) {
			OidcLogoutFixtures.MutableClock clock = new OidcLogoutFixtures.MutableClock(); Flow f = flow(server, clock);
			for (PendingAuthorizationSaveResult status : PendingAuthorizationSaveResult.values()) { CaptureStore store = new CaptureStore(); store.saveResult = status; assertEquals(status, f.request.getPending().saveToResult(store, BINDING)); assertEquals(1, store.saves.get()); assertEquals(0, store.consumes.get()); }
			for (String mode : List.of("throw-before", "throw-after", "null", "late", "interrupt")) {
				CaptureStore store = new CaptureStore(); store.saveMode = mode;
				try { assertEquals(PendingAuthorizationSaveResult.INDETERMINATE, f.request.getPending().saveToResult(store, BINDING, mode.equals("late") ? Duration.ofMillis(100) : Duration.ofSeconds(2))); if (mode.equals("interrupt")) assertTrue(Thread.currentThread().isInterrupted()); }
				finally { Thread.interrupted(); }
				assertEquals(1, store.saves.get()); assertEquals(0, store.consumes.get()); assertEquals(!mode.equals("throw-before"), store.row.get() != null);
			}
			CaptureStore never = new CaptureStore(); assertEquals(PendingAuthorizationSaveResult.UNAVAILABLE, f.request.getPending().saveToResult(never, BINDING, Duration.ZERO)); assertEquals(0, never.saves.get());
		}
	}
	@Test
	void consumeUnknownAppliedAndNoEffectControlsAreIndeterminateWithoutReadRescue() throws Exception {
		try (TestHttpsServer server = TestHttpsServer.start()) {
			OidcLogoutFixtures.MutableClock clock = new OidcLogoutFixtures.MutableClock(); Flow f = flow(server, clock);
			for (String mode : List.of("throw-before", "throw-after", "null", "interrupt")) {
				CaptureStore store = saved(f.request); store.consumeMode = mode;
				try { OidcLogoutException failure = OidcLogoutHintTests.assertReason(OidcLogoutException.Reason.STORE_INDETERMINATE, () -> f.client.completeLogoutResult(query(f.request), PendingOidcLogoutSource.fromStore(store, BINDING), OidcLogoutFixtures.LOGOUT)); assertNull(failure.getCause()); assertEquals(0, failure.getSuppressed().length); assertFalse(failure.toString().contains(SECRET)); if (mode.equals("interrupt")) assertTrue(Thread.currentThread().isInterrupted()); }
				finally { Thread.interrupted(); }
				assertEquals(1, store.consumes.get()); assertEquals(mode.equals("throw-before"), store.row.get() != null);
			}
			CaptureStore never = saved(f.request); try { Thread.currentThread().interrupt(); OidcLogoutHintTests.assertReason(OidcLogoutException.Reason.INTERRUPTED, () -> f.client.completeLogoutResult(query(f.request), PendingOidcLogoutSource.fromStore(never, BINDING), OidcLogoutFixtures.LOGOUT)); assertTrue(Thread.currentThread().isInterrupted()); } finally { Thread.interrupted(); } assertEquals(0, never.consumes.get());
		}
	}
	@Test
	void browserBindingCapsAndCallbackBuilderBoundsApplyOnlyToLogoutOptin() throws Exception {
		try (TestHttpsServer server = TestHttpsServer.start()) {
			OidcLogoutFixtures.MutableClock clock = new OidcLogoutFixtures.MutableClock(); Flow f = flow(server, clock);
			for (String binding : List.of("x".repeat(512), "é".repeat(256))) {
				BrowserBinding typed = BrowserBinding.fromTrustedPersistence(binding);
				assertEquals(PendingAuthorizationSaveResult.SAVED,
						f.request.getPending().saveToResult(new CaptureStore(), typed));
			}
			assertThrows(IllegalArgumentException.class,
					() -> BrowserBinding.fromTrustedPersistence(""));
			for (String binding : List.of("x".repeat(513), "é".repeat(257), "\ud800")) {
				CaptureStore store = new CaptureStore();
				BrowserBinding typed = BrowserBinding.fromTrustedPersistence(binding);
				assertThrows(IllegalArgumentException.class,
						() -> PendingOidcLogoutSource.fromStore(store, typed));
				assertThrows(IllegalArgumentException.class,
						() -> f.request.getPending().saveToResult(store, typed));
				assertEquals(0, store.saves.get());
			}
			for (URI callback : List.of(URI.create("https://rp.example/logout?query=1"), URI.create("https://rp.example/logout#fragment"), URI.create("https://user@rp.example/logout"), URI.create("http://rp.example/logout"), URI.create("/relative"), URI.create("https://rp.example/" + "x".repeat(2048)))) assertThrows(IllegalArgumentException.class, () -> OidcLogoutFixtures.builder(server, clock).postLogoutRedirectUri(callback).build());
			String prefix = "https://rp.example/"; assertNotNull(OidcLogoutFixtures.builder(server, clock).postLogoutRedirectUri(URI.create(prefix + "x".repeat(2048 - prefix.length()))).build());
			OidcClient disabled = OidcLogoutFixtures.builder(server, clock).postLogoutRedirectUri(null).build(); OidcLogoutHintTests.assertReason(OidcLogoutException.Reason.LOGOUT_NOT_CONFIGURED, () -> disabled.beginLogout(f.login.authentication().getSessionReference(), f.hint));
		}
	}
	@Test
	void malformedStoredDatesAndUrisRejectAsInputAfterExactlyOneConsume() throws Exception {
		try (TestHttpsServer server = TestHttpsServer.start()) {
			OidcLogoutFixtures.MutableClock clock = new OidcLogoutFixtures.MutableClock(); Flow f = flow(server, clock); String record = java.util.Objects.requireNonNull(saved(f.request).row.get());
			for (String field : List.of("created_at", "expires_at", "callback_uri")) for (String value : List.of("not-a-date-or-uri", "2026-99-99T12:00:00Z", "https://bad host/path")) {
				Map<String, JsonValue> fields = new LinkedHashMap<>(object(record).getMembers()); fields.put(field, JsonString.fromValue(value)); CaptureStore store = new CaptureStore(); store.row.set(JsonObject.fromMembers(fields).toJson());
				OidcLogoutResult result = f.client.completeLogoutResult(query(f.request), PendingOidcLogoutSource.fromStore(store, BINDING), OidcLogoutFixtures.LOGOUT);
				assertRejected(field.equals("callback_uri") && value.equals("not-a-date-or-uri") ? OidcLogoutResult.Reason.CLIENT_MISMATCH : OidcLogoutResult.Reason.PENDING_INVALID, result); assertEquals(1, store.consumes.get()); assertNull(store.row.get());
			}
		}
	}

	private static @NonNull String query(@NonNull OidcLogoutRequest request) { return "state=" + request.getFormParameters().get("state"); }
	private static @NonNull StateSealer sealer(@NonNull Clock clock) { return StateSealer.withActiveKey(TestSealers.fixedKey("logout-pending")).clock(clock).build(); }
	private static @NonNull CaptureStore saved(@NonNull OidcLogoutRequest request) { CaptureStore store = new CaptureStore(); assertEquals(PendingAuthorizationSaveResult.SAVED, request.getPending().saveToResult(store, BINDING)); return store; }
	private static @NonNull JsonObject object(@NonNull String value) throws Exception { return assertInstanceOf(JsonObject.class, JsonCodec.parse(value.getBytes(StandardCharsets.UTF_8), JsonLimits.protocolDocument(16_384))); }
	private static boolean positive(@Nullable Duration remaining) { return remaining != null && !remaining.isZero() && !remaining.isNegative(); }
	private static void assertRejected(OidcLogoutResult.@NonNull Reason expected, @NonNull OidcLogoutResult result) { assertEquals(expected, assertInstanceOf(OidcLogoutResult.Rejected.class, result).getReason()); }
	private static void pause(long millis) { try { Thread.sleep(millis); } catch (InterruptedException failure) { Thread.currentThread().interrupt(); } }
	private static final class CaptureStore implements PendingAuthorizationStore {
		private final AtomicReference<String> row = new AtomicReference<>(); private final AtomicInteger saves = new AtomicInteger(), consumes = new AtomicInteger();
		private String saveMode = "normal", consumeMode = "normal"; private PendingAuthorizationSaveResult saveResult = PendingAuthorizationSaveResult.SAVED; private @Nullable Duration saveBudget, consumeBudget; private @Nullable Instant expiry;
		@Override @SuppressWarnings("NullAway") // Deliberate hostile null result tests the unchanged SPI boundary.
		public @NonNull PendingAuthorizationSaveResult save(@NonNull String binding, @NonNull String state, @NonNull String record, @NonNull Instant expires, @NonNull Duration remaining) {
			this.saves.incrementAndGet(); this.saveBudget = remaining; this.expiry = expires; assertTrue(positive(remaining));
			if (this.saveMode.equals("throw-before")) throw new IllegalStateException(SECRET);
			if (this.saveResult == PendingAuthorizationSaveResult.SAVED) this.row.set(record);
			if (this.saveMode.equals("throw-after")) throw new IllegalStateException(SECRET); if (this.saveMode.equals("null")) return null;
			if (this.saveMode.equals("late")) pause(250); if (this.saveMode.equals("interrupt")) Thread.currentThread().interrupt(); return this.saveResult;
		}
		@Override @SuppressWarnings("NullAway") // Deliberate hostile null result tests the unchanged SPI boundary.
		public @NonNull Optional<@NonNull String> consume(@NonNull String binding, @NonNull String state, @NonNull Duration remaining) {
			this.consumes.incrementAndGet(); this.consumeBudget = remaining; assertTrue(positive(remaining)); if (this.consumeMode.equals("throw-before")) throw new IllegalStateException(SECRET);
			String record = this.row.getAndSet(null); if (this.consumeMode.equals("throw-after")) throw new IllegalStateException(SECRET); if (this.consumeMode.equals("null")) return null; if (this.consumeMode.equals("interrupt")) Thread.currentThread().interrupt(); return Optional.ofNullable(record);
		}
	}
}
