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

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

import com.revetsec.StateSealer;
import com.revetsec.StateUnsealResult;
import com.revetsec.internal.crypto.SealedStateAccess;
import com.revetsec.internal.crypto.SealedStateType;
import com.revetsec.internal.crypto.UnsealException;
import com.revetsec.internal.json.JsonCodec;
import com.revetsec.internal.json.JsonLimits;
import com.revetsec.json.JsonObject;
import com.revetsec.json.JsonValue;
import com.revetsec.testing.TestHttpsServer;
import com.revetsec.testing.TestSealers;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;
import org.junit.jupiter.api.DynamicTest;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigestSpi;
import java.security.Provider;
import java.security.ProviderException;
import java.security.Security;
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
import java.util.Set;
import java.util.stream.Stream;
import static org.junit.jupiter.api.Assertions.*;

final class OidcLogoutHintTests {
	private static final String SECRET = "TEST-ONLY-private-logout-sentinel";
	@Test
	void genuineAuthenticationProducesAnExplicitCredentialCompanionWithUnchangedReferenceV1() throws Exception {
		try (TestHttpsServer server = TestHttpsServer.start()) {
			OidcLogoutFixtures.MutableClock clock = new OidcLogoutFixtures.MutableClock(); OidcClient client = OidcLogoutFixtures.builder(server, clock).build();
			OidcLogoutFixtures.Login login = OidcLogoutFixtures.login(server, client, clock); String before = login.authentication().getSessionReference().toSerializedForm();
			OidcLogoutHint hint = client.logoutHintFrom(login.authentication()); String serialized = hint.toSerializedForm();
			assertFalse(before.contains(login.compact())); assertTrue(serialized.contains(login.compact()), "explicit serialization emits credential");
			assertEquals(before, login.authentication().getSessionReference().toSerializedForm()); assertEquals("TEST-ONLY-original-sid", login.authentication().getSessionReference().getSessionId().orElseThrow());
			OidcLogoutHint restored = assertInstanceOf(OidcLogoutHintParseResult.Parsed.class, OidcLogoutHint.fromSerializedFormResult(serialized)).getHint();
			assertEquals(serialized, restored.toSerializedForm()); assertTrue(restored.reference().matchesOriginalReference(login.authentication().getSessionReference()));
			assertFalse(hint.toString().contains(login.compact())); assertFalse(hint.toString().contains("TEST-ONLY-logout-subject"));
			assertEquals(0, server.getHitCount("/logout"));
			JsonObject envelope = object(serialized); assertEquals(Set.of("v", "reference", "id_token"), envelope.getMembers().keySet()); assertInstanceOf(JsonObject.class, envelope.getMembers().get("reference"));
		}
	}
	@Test
	void exactClientOwnershipIsRequiredBeforeCredentialCreationWithoutDiscoveryOrOtherIo() throws Exception {
		try (TestHttpsServer server = TestHttpsServer.start()) {
			Clock clock = Clock.fixed(OidcLogoutFixtures.NOW, ZoneOffset.UTC); OidcClient client = OidcLogoutFixtures.builder(server, clock).build(), other = OidcLogoutFixtures.builder(server, clock).build();
			OidcLogoutFixtures.Login login = OidcLogoutFixtures.login(server, client, clock); int tokens = server.getHitCount("/token");
			assertReason(OidcLogoutException.Reason.HINT_MISMATCH, () -> other.logoutHintFrom(login.authentication())); assertEquals(tokens, server.getHitCount("/token")); assertEquals(0, server.getHitCount("/logout"));
		}
	}
	@Test
	void realRefreshOptionalHintRetainsExactOriginalReferenceAndRequiresProducingClient() throws Exception {
		try (TestHttpsServer server = TestHttpsServer.start()) {
			OidcLogoutFixtures.MutableClock clock = new OidcLogoutFixtures.MutableClock(); OidcClient client = OidcLogoutFixtures.builder(server, clock).build(), other = OidcLogoutFixtures.builder(server, clock).build();
			OidcLogoutFixtures.Login login = OidcLogoutFixtures.login(server, client, clock); OidcSessionReference original = login.authentication().getSessionReference(); String serialized = original.toSerializedForm();
			OidcLogoutFixtures.respond(server, null); OidcRefresh noId = assertInstanceOf(OidcRefreshResult.Succeeded.class, client.refreshResult(login.authentication().getTokens().getRefreshToken().orElseThrow(), original)).getRefresh();
			assertTrue(client.logoutHintFrom(noId).isEmpty()); assertSame(original, noId.getSessionReference()); assertReason(OidcLogoutException.Reason.HINT_MISMATCH, () -> other.logoutHintFrom(noId));
			clock.set(OidcLogoutFixtures.NOW.plusSeconds(30)); String replacement = OidcLogoutFixtures.token(server, clock.instant(), null, "TEST-ONLY-new-sid", ""); OidcLogoutFixtures.respond(server, replacement);
			OidcRefresh refreshed = assertInstanceOf(OidcRefreshResult.Succeeded.class, client.refreshResult(noId.getRefreshToken(), original)).getRefresh(); OidcLogoutHint hint = client.logoutHintFrom(refreshed).orElseThrow();
			assertSame(original, refreshed.getSessionReference()); assertEquals(serialized, original.toSerializedForm()); assertEquals("TEST-ONLY-original-sid", original.getSessionId().orElseThrow());
			assertTrue(hint.toSerializedForm().contains(replacement)); assertTrue(hint.reference().matchesOriginalReference(original)); assertReason(OidcLogoutException.Reason.HINT_MISMATCH, () -> other.logoutHintFrom(refreshed));
		}
	}
	@Test
	void expiredAuthenticationTokenRemainsAStorageHintWithoutReauthentication() throws Exception {
		try (TestHttpsServer server = TestHttpsServer.start()) {
			OidcLogoutFixtures.MutableClock clock = new OidcLogoutFixtures.MutableClock(); OidcClient client = OidcLogoutFixtures.builder(server, clock).build(); OidcLogoutFixtures.Login login = OidcLogoutFixtures.login(server, client, clock);
			clock.set(OidcLogoutFixtures.NOW.plusSeconds(3600)); OidcLogoutHint hint = client.logoutHintFrom(login.authentication()); StateSealer sealer = StateSealer.withActiveKey(TestSealers.fixedKey("logout-hint")).clock(clock).build();
			assertInstanceOf(OidcLogoutHintParseResult.Parsed.class, OidcLogoutHint.fromSealedFormResult(hint.toSealedForm(sealer, "hint", Duration.ofMinutes(1)), sealer, "hint")); assertEquals(1, server.getHitCount("/token"));
		}
	}
	@Test
	void typedHintLifetimeUsesConfiguredMutableClockAndNeverOpensAsAppOrSession() throws Exception {
		try (TestHttpsServer server = TestHttpsServer.start()) {
			OidcLogoutFixtures.MutableClock clock = new OidcLogoutFixtures.MutableClock(); OidcClient client = OidcLogoutFixtures.builder(server, clock).build(); OidcLogoutHint hint = client.logoutHintFrom(OidcLogoutFixtures.login(server, client, clock).authentication());
			clock.set(OidcLogoutFixtures.NOW.plusNanos(123)); StateSealer sealer = StateSealer.withActiveKey(TestSealers.fixedKey("hint-clock")).clock(clock).build(); String sealed = hint.toSealedForm(sealer, "hint", Duration.ofSeconds(2));
			assertInstanceOf(StateUnsealResult.Rejected.class, sealer.unsealResult(sealed, "hint"));
			String app = sealer.seal(hint.toSerializedForm(), "hint", Duration.ofSeconds(2)); assertInstanceOf(OidcLogoutHintParseResult.Rejected.class, OidcLogoutHint.fromSealedFormResult(app, sealer, "hint"));
			assertInstanceOf(OidcLogoutHintParseResult.Rejected.class, OidcLogoutHint.fromSealedFormResult(sealed, sealer, "other-context"));
			clock.set(OidcLogoutFixtures.NOW.plusSeconds(3).minusNanos(1)); assertInstanceOf(OidcLogoutHintParseResult.Parsed.class, OidcLogoutHint.fromSealedFormResult(sealed, sealer, "hint"));
			clock.set(OidcLogoutFixtures.NOW.plusSeconds(3)); assertInstanceOf(OidcLogoutHintParseResult.Rejected.class, OidcLogoutHint.fromSealedFormResult(sealed, sealer, "hint"));
			for (SealedStateType type : SealedStateType.values()) if (type != SealedStateType.OIDC_LOGOUT_HINT) {
				assertThrows(IllegalArgumentException.class, () -> SealedStateAccess.get().sealForLifetime(sealer, type, "test", "hint", Duration.ofSeconds(2)));
				assertThrows(IllegalArgumentException.class, () -> SealedStateAccess.get().unsealUsingConfiguredClock(sealer, type, sealed, "hint"));
			}
		}
	}
	@Test
	void explicitLifetimeContextAndExistingSizeProfileArePreservedWithoutChunking() throws Exception {
		try (TestHttpsServer server = TestHttpsServer.start()) {
			OidcLogoutFixtures.MutableClock clock = new OidcLogoutFixtures.MutableClock(); OidcClient client = OidcLogoutFixtures.builder(server, clock).build(); OidcLogoutHint hint = client.logoutHintFrom(OidcLogoutFixtures.login(server, client, clock).authentication()); StateSealer sealer = StateSealer.withActiveKey(TestSealers.fixedKey("hint-size")).clock(clock).build();
			for (Duration duration : List.of(Duration.ZERO, Duration.ofMillis(999), Duration.ofDays(400).plusNanos(1))) assertReason(OidcLogoutException.Reason.STORAGE_PROFILE_UNSUPPORTED, () -> hint.toSealedForm(sealer, "hint", duration));
			for (String context : List.of("", "x".repeat(257), "\ud800")) assertReason(OidcLogoutException.Reason.STORAGE_PROFILE_UNSUPPORTED, () -> hint.toSealedForm(sealer, context, Duration.ofSeconds(2)));
			OidcLogoutHint large = client.logoutHintFrom(OidcLogoutFixtures.login(server, client, clock, "x".repeat(45_000)).authentication());
			assertTrue(large.toSerializedForm().length() > 16_384); assertInstanceOf(OidcLogoutHintParseResult.Parsed.class, OidcLogoutHint.fromSerializedFormResult(large.toSerializedForm()));
			StateSealer maximum = StateSealer.withActiveKey(TestSealers.fixedKey("hint-size-max")).clock(clock).maximumSealedLength(16_384).build();
			assertReason(OidcLogoutException.Reason.STORAGE_PROFILE_UNSUPPORTED, () -> large.toSealedForm(maximum, "hint", Duration.ofSeconds(2)));
		}
	}
	@Test
	void hintEnvelopeBoundsUnknownDuplicateAndCrossPurposeStructuresFailClosed() throws Exception {
		try (TestHttpsServer server = TestHttpsServer.start()) {
			OidcLogoutFixtures.MutableClock clock = new OidcLogoutFixtures.MutableClock(); OidcClient client = OidcLogoutFixtures.builder(server, clock).build(); OidcLogoutHint hint = client.logoutHintFrom(OidcLogoutFixtures.login(server, client, clock).authentication()); String form = hint.toSerializedForm();
			assertInstanceOf(OidcLogoutHintParseResult.Parsed.class, OidcLogoutHint.fromSerializedFormResult(form + " ".repeat(131_200 - form.length())));
			for (String malformed : List.of(form + " ".repeat(131_201 - form.length()), form.substring(0, form.length() - 1) + ",\"unknown\":1}", form.replace("\"v\":1", "\"v\":1,\"v\":1"), form.replace("\"v\":1", "\"v\":2"), hint.reference().toSerializedForm(), "\ud800", " ".repeat(131_201), "é".repeat(65_601)))
				assertInstanceOf(OidcLogoutHintParseResult.Rejected.class, OidcLogoutHint.fromSerializedFormResult(malformed));
			Map<String, JsonValue> fields = new LinkedHashMap<>(object(form).getMembers()); fields.put("id_token", com.revetsec.json.JsonString.fromValue("a.b.c"));
			assertInstanceOf(OidcLogoutHintParseResult.Rejected.class, OidcLogoutHint.fromSerializedFormResult(JsonObject.fromMembers(fields).toJson()));
		}
	}
	@Test
	void continuityRestorationRejectsClaimMutationWithoutCreatingAuthenticationProof() throws Exception {
		try (TestHttpsServer server = TestHttpsServer.start()) {
			OidcLogoutFixtures.MutableClock clock = new OidcLogoutFixtures.MutableClock(); OidcClient client = OidcLogoutFixtures.builder(server, clock).build(); OidcLogoutFixtures.Login login = OidcLogoutFixtures.login(server, client, clock); OidcLogoutHint hint = client.logoutHintFrom(login.authentication());
			for (String key : List.of("iss", "sub", "aud", "nonce", "azp", "iat", "auth_time")) {
				String[] segments = login.compact().split("\\.", -1); byte[] payload = java.util.Base64.getUrlDecoder().decode(segments[1]); Map<String, JsonValue> claims = new LinkedHashMap<>(object(new String(payload, StandardCharsets.UTF_8)).getMembers()); Arrays.fill(payload, (byte) 0);
				claims.put(key, key.equals("iat") || key.equals("auth_time") ? com.revetsec.json.JsonNumber.fromValue(java.math.BigDecimal.ZERO) : com.revetsec.json.JsonString.fromValue(SECRET));
				String changed = segments[0] + "." + java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(JsonObject.fromMembers(claims).toJson().getBytes(StandardCharsets.UTF_8)) + "." + segments[2];
				Map<String, JsonValue> envelope = new LinkedHashMap<>(object(hint.toSerializedForm()).getMembers()); envelope.put("id_token", com.revetsec.json.JsonString.fromValue(changed));
				assertInstanceOf(OidcLogoutHintParseResult.Rejected.class, OidcLogoutHint.fromSerializedFormResult(JsonObject.fromMembers(envelope).toJson()));
			}
		}
	}
	@Test
	void cancellationAndDigestProviderFailureRemainDistinctAndValueFree() throws Exception {
		try (TestHttpsServer server = TestHttpsServer.start()) {
			OidcLogoutFixtures.MutableClock clock = new OidcLogoutFixtures.MutableClock(); OidcClient client = OidcLogoutFixtures.builder(server, clock).build(); OidcLogoutFixtures.Login login = OidcLogoutFixtures.login(server, client, clock); OidcLogoutHint hint = client.logoutHintFrom(login.authentication()); String form = hint.toSerializedForm();
			try { Thread.currentThread().interrupt(); assertReason(OidcLogoutException.Reason.INTERRUPTED, () -> OidcLogoutHint.fromSerializedFormResult(form)); assertTrue(Thread.currentThread().isInterrupted()); }
			finally { Thread.interrupted(); }
			Provider provider = new FailingDigestProvider(); Security.insertProviderAt(provider, 1);
			try {
				OidcLogoutException failure = assertReason(OidcLogoutException.Reason.PROVIDER_UNAVAILABLE, () -> OidcLogoutHint.fromSerializedFormResult(form));
				assertNull(failure.getCause()); assertEquals(0, failure.getSuppressed().length); assertFalse(failure.toString().contains(SECRET));
			} finally { Security.removeProvider(provider.getName()); }
		}
	}
	private static @NonNull JsonObject object(@NonNull String form) throws Exception { return assertInstanceOf(JsonObject.class, JsonCodec.parse(form.getBytes(StandardCharsets.UTF_8), JsonLimits.protocolDocument(131_200))); }
	static @NonNull OidcLogoutException assertReason(OidcLogoutException.@NonNull Reason expected, org.junit.jupiter.api.function.@NonNull Executable action) {
		OidcLogoutException failure = assertThrows(OidcLogoutException.class, action); assertEquals(expected, failure.getReason()); return failure;
	}
	public static final class FailingDigestProvider extends Provider {
		private static final long serialVersionUID = 1L;
		public FailingDigestProvider() { super("RevetsecLogoutHintDigest", "1.0", "test-only fixed failure"); put("MessageDigest.SHA-256", FailingDigest.class.getName()); }
	}
	public static final class FailingDigest extends MessageDigestSpi {
		static boolean nonfatalError;
		@Override protected void engineUpdate(byte value) { }
		@Override protected void engineUpdate(byte @NonNull [] bytes, int offset, int length) { }
		@Override protected byte @NonNull [] engineDigest() { if (nonfatalError) throw new AssertionError(SECRET); throw new ProviderException(SECRET); }
		@Override protected void engineReset() { }
	}
}
