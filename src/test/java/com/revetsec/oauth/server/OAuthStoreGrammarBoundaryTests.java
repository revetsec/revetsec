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
import com.revetsec.internal.crypto.SealedStateAccess;
import com.revetsec.internal.crypto.SealedStateType;
import com.revetsec.json.JsonArray;
import com.revetsec.json.JsonNull;
import com.revetsec.json.JsonObject;
import com.revetsec.json.JsonString;
import org.jspecify.annotations.NonNull;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

/** Exact boundary probes for the authenticated issuer-store grammar. */
final class OAuthStoreGrammarBoundaryTests {
	private static final @NonNull Instant NOW = Instant.parse("2026-10-04T00:00:00Z");
	private static final @NonNull String NONCE = "A".repeat(43);
	private static final @NonNull String OTHER = "B".repeat(42) + "A";
	private static final @NonNull String VERSION = "C".repeat(42) + "A";
	private static final @NonNull String ISSUER = "i";
	private static final @NonNull String RESOURCE = "https://resource.example/mcp";
	private static final @NonNull String REDIRECT = "https://client.example/cb";
	private static final @NonNull OAuthServerIngressLimits LIMITS = OAuthServerIngressLimits.fromDefaults();

	private static @NonNull StateSealer sealer(@NonNull String keyId, int maximum) {
		byte[] key = new byte[32];
		for (int index = 0; index < key.length; index++) key[index] = (byte) (index + 1);
		return StateSealer.withActiveKey(SealingKey.fromBase64(keyId, Base64.getEncoder().encodeToString(key)))
			.maximumSealedLength(maximum).clock(Clock.fixed(NOW, ZoneOffset.UTC)).build();
	}

	private static @NonNull OAuthStoreRecordCodec codec(@NonNull StateSealer sealer, int maximum) {
		return new OAuthStoreRecordCodec(ISSUER, sealer, maximum);
	}

	private static @NonNull JsonArray scopes(int count) {
		return JsonArray.fromElements(java.util.stream.IntStream.range(0, count)
			.mapToObj(index -> JsonString.fromValue("s" + index)).toList());
	}

	private static @NonNull JsonObject pendingInteraction(@NonNull String state, int scopeCount) {
		return JsonObject.builder().put("schema", 1L).put("id", NONCE).put("status", "PENDING")
			.put("expires", NOW.plusSeconds(300).getEpochSecond()).put("issuerIncarnation", NONCE).put("issuerEpoch", 0L)
			.put("browserHash", OTHER).put("clientHash", OTHER).put("clientId", "client").put("redirect", REDIRECT)
			.put("resource", RESOURCE).put("scopes", scopes(scopeCount)).put("challenge", NONCE).put("state", state).build();
	}

	private static @NonNull JsonObject grant(@NonNull String status, long maximumAccessNanos) {
		JsonObject.Builder result = JsonObject.builder().put("schema", 1L).put("id", NONCE).put("status", status)
			.put("expires", NOW.plusSeconds(300).getEpochSecond()).put("issuerIncarnation", NONCE).put("issuerEpoch", 0L)
			.put("subjectIncarnation", OTHER).put("subjectEpoch", 0L).put("codeId", OTHER).put("subject", "subject")
			.put("clientId", "client").put("clientHash", OTHER).put("resource", RESOURCE).put("scopes", scopes(1)).put("refresh", true);
		if (status.equals("ACTIVE")) result.put("horizon", NOW.plusSeconds(900).getEpochSecond())
			.put("maximumAccessSeconds", 30L).put("maximumAccessNanos", maximumAccessNanos).put("refreshId", OTHER);
		return result.build();
	}

	private static @NonNull OAuthAuthorizationRecord record(@NonNull JsonObject payload) {
		return OAuthAuthorizationRecord.decode(OAuthStoreKey.Kind.GRANT, NONCE, payload, LIMITS, 255);
	}

	private static @NonNull JsonObject accessPayload(@NonNull Instant retain) {
		return JsonObject.builder().put("schema", 1L).put("id", NONCE).put("status", "ISSUED")
			.put("expires", NOW.plusSeconds(60).getEpochSecond()).put("issuerIncarnation", NONCE).put("issuerEpoch", 0L)
			.put("subjectIncarnation", OTHER).put("subjectEpoch", 0L).put("grantId", OTHER).put("subject", "subject")
			.put("clientId", "client").put("resource", RESOURCE).put("scopes", scopes(1)).put("issued", NOW.getEpochSecond())
			.put("retain", retain.getEpochSecond()).build();
	}

	@Test void exactIssuerAndSubjectCharacterCapsAreAccepted() {
		StateSealer sealer = sealer("k", 3800);
		OAuthStoreRecordCodec exactIssuer = new OAuthStoreRecordCodec("i".repeat(2048), sealer, 3800);
		assertNotNull(exactIssuer.issuerKey());
		assertNotNull(codec(sealer, 3800).subjectKey("s".repeat(2048)));
	}

	@Test void storageAddressAuthenticatesTheNamespaceBeforeUse() throws Exception {
		String badNamespace = "A".repeat(42) + "B";
		assertThrows(IllegalArgumentException.class, () -> OAuthStoreKey.fromStoredForm("revetsec:as:1:"));
		assertThrows(IllegalArgumentException.class, () -> OAuthStoreKey.fromStoredForm(
			"revetsec:as:1:" + badNamespace + ":CODE:" + NONCE));

		StateSealer sealer = sealer("k", 3800);
		OAuthStoreRecordCodec codec = codec(sealer, 3800);
		OAuthStoreKey foreign = OAuthStoreFormat.key(OTHER, OAuthStoreKey.Kind.CODE, NONCE);
		assertThrows(IllegalArgumentException.class, () -> codec.seal(foreign, NOW.plusSeconds(60), "{}"));

		String envelope = "{\"schema\":1,\"issuer\":\"" + ISSUER + "\",\"key\":\"" + foreign.getStorageKey()
			+ "\",\"version\":\"" + VERSION + "\",\"retainUntil\":" + NOW.plusSeconds(60).getEpochSecond()
			+ ",\"payload\":{}}";
		String sealed = SealedStateAccess.get().seal(sealer, SealedStateType.AS_RECORD, envelope,
			"revetsec/as-record/v1:" + foreign.getStorageKey(), NOW.plusSeconds(60));
		OAuthStoreEntry entry = OAuthStoreEntry.fromStoredForm(foreign, VERSION, NOW.plusSeconds(60), sealed);
		assertThrows(IllegalArgumentException.class, () -> codec.open(entry, Clock.fixed(NOW, ZoneOffset.UTC)));
	}

	@Test void exactPlaintextAndConfiguredSealedCapsAreEnforced() {
		StateSealer shortIdSealer = sealer("k", 3800);
		OAuthStoreRecordCodec exact = codec(shortIdSealer, 1024);
		OAuthStoreKey key = exact.key(OAuthStoreKey.Kind.CODE, NONCE);
		String emptyEnvelope = envelope(key, VERSION, "{}");
		int payloadCharacters = 713 - (emptyEnvelope.length() - 2);
		String payload = "{\"x\":\"" + "a".repeat(payloadCharacters - 8) + "\"}";
		assertEquals(713, envelope(key, VERSION, payload).length());
		assertEquals(1024, exact.seal(key, NOW.plusSeconds(60), payload).toSealedForm().length());

		StateSealer longIdSealer = sealer("k".repeat(64), 3800);
		OAuthStoreRecordCodec compact = codec(longIdSealer, 1024);
		OAuthStoreRecordCodec wide = codec(longIdSealer, 3800);
		OAuthStoreKey compactKey = compact.key(OAuthStoreKey.Kind.CODE, NONCE);
		String compactEmptyEnvelope = envelope(compactKey, VERSION, "{}");
		int compactPayloadCharacters = 713 - (compactEmptyEnvelope.length() - 2);
		String compactPayload = "{\"x\":\"" + "a".repeat(compactPayloadCharacters - 8) + "\"}";
		assertThrows(IllegalArgumentException.class, () -> compact.seal(compactKey, NOW.plusSeconds(60), compactPayload));
		OAuthStoreEntry oversized = wide.seal(compactKey, NOW.plusSeconds(60), compactPayload);
		assertTrue(oversized.toSealedForm().length() > 1024);
		assertThrows(IllegalArgumentException.class, () -> compact.open(oversized, Clock.fixed(NOW, ZoneOffset.UTC)));
	}

	private static @NonNull String envelope(@NonNull OAuthStoreKey key, @NonNull String version, @NonNull String payload) {
		return "{\"schema\":1,\"issuer\":\"" + ISSUER + "\",\"key\":" + JsonString.fromValue(key.getStorageKey()).toJson()
			+ ",\"version\":\"" + version + "\",\"retainUntil\":" + NOW.plusSeconds(60).getEpochSecond()
			+ ",\"payload\":" + payload + "}";
	}

	@Test void fencePreservesTheFullInstantAndOnlyIssuerTimeAdvances() {
		JsonObject maximumNanos = JsonObject.builder().put("schema", 1L).put("incarnation", NONCE).put("epoch", 0L)
			.put("highWaterSeconds", NOW.getEpochSecond()).put("highWaterNanos", 999_999_999L).build();
		assertEquals(999_999_999, OAuthStoreFence.decode(maximumNanos, OAuthStoreKey.Kind.ISSUER_STATE).highWater().getNano());

		Instant later = NOW.plusSeconds(10);
		assertEquals(later, OAuthStoreFence.initialIssuer(NONCE, NOW).advance(later).highWater());
		assertEquals(Instant.EPOCH, OAuthStoreFence.initialSubject(NONCE).advance(later).highWater());
	}

	@Test void transitionFactoriesRejectFractionalSecondsBeforeSerialization() {
		OAuthAuthorizationRecord pending = record(grant("PENDING", 0));
		assertThrows(IllegalArgumentException.class, () -> pending.activated(NOW.plusSeconds(300).plusNanos(1),
			NOW.plusSeconds(900), Duration.ofSeconds(30), Set.of("s0"), OTHER, LIMITS, 255));
		assertThrows(IllegalArgumentException.class, () -> pending.activated(NOW.plusSeconds(300),
			NOW.plusSeconds(900).plusNanos(1), Duration.ofSeconds(30), Set.of("s0"), OTHER, LIMITS, 255));

		OAuthAuthorizationRecord active = record(grant("ACTIVE", 0));
		assertThrows(IllegalArgumentException.class, () -> OAuthAuthorizationRecord.access(NONCE, active, NOW,
			NOW.plusSeconds(60).plusNanos(1), NOW.plusSeconds(120), Set.of("s0"), LIMITS, 255));
		assertThrows(IllegalArgumentException.class, () -> OAuthAuthorizationRecord.access(NONCE, active, NOW,
			NOW.plusSeconds(60), NOW.plusSeconds(120).plusNanos(1), Set.of("s0"), LIMITS, 255));
		assertThrows(IllegalArgumentException.class, () -> OAuthAuthorizationRecord.refresh(OTHER, active,
			NOW.plusSeconds(120).plusNanos(1), LIMITS, 255));
	}

	@Test void decodedRecordCapsAcceptTheirExactUpperBound() {
		assertEquals(Duration.ofSeconds(30, 999_999_999), record(grant("ACTIVE", 999_999_999L)).maximumAccessLifetime());
		OAuthServerIngressLimits oneScope = new OAuthServerIngressLimits(1024, 1024, 1024, 128, 256, 1, 1, 1, 128);
		OAuthAuthorizationRecord interaction = OAuthAuthorizationRecord.decode(OAuthStoreKey.Kind.INTERACTION, NONCE,
			pendingInteraction("s".repeat(128), 1), oneScope, 255);
		assertEquals(Set.of("s0"), interaction.scopes(oneScope));
		assertEquals("s".repeat(128), interaction.state(128));
	}

	@Test void decodedCredentialLinksAndFiniteRetentionAreCanonical() {
		JsonObject refresh = JsonObject.builder().put("schema", 1L).put("id", NONCE).put("status", "ACTIVE")
			.put("expires", NOW.plusSeconds(60).getEpochSecond()).put("issuerIncarnation", NONCE).put("issuerEpoch", 0L)
			.put("subjectIncarnation", OTHER).put("subjectEpoch", 0L).put("grantId", "x")
			.put("horizon", NOW.plusSeconds(120).getEpochSecond()).build();
		assertThrows(IllegalArgumentException.class, () -> OAuthAuthorizationRecord.decode(
			OAuthStoreKey.Kind.REFRESH_TOKEN, NONCE, refresh, LIMITS, 255));
		assertThrows(IllegalArgumentException.class, () -> OAuthAuthorizationRecord.decode(
			OAuthStoreKey.Kind.ACCESS_TOKEN, NONCE, accessPayload(OAuthStoreFormat.PERMANENT), LIMITS, 255));
	}

	@Test void verifierAlphabetAndDigestInputsAreCheckedAtEveryBoundary() {
		for (char boundary : new char[] {'a', 'z', 'A', 'Z', '0', '9'})
			assertEquals(43, OAuthAuthorizationRecord.verifierDigest(Character.toString(boundary).repeat(43)).length());
		assertThrows(IllegalArgumentException.class, () -> OAuthAuthorizationRecord.equalDigest("x", NONCE));
		assertThrows(IllegalArgumentException.class, () -> OAuthAuthorizationRecord.equalDigest(NONCE, "x"));
	}

	@Test void confidentialAuthenticationIsPartOfTheClientFingerprint() {
		OAuthServerClientRegistration publicClient = OAuthServerClientRegistration.withClientId("client")
			.configurationVersion("v1").redirectUris(List.of(URI.create(REDIRECT)))
			.allowedScopesByResource(Map.of(RESOURCE, Set.of("s0"))).build();
		OAuthServerClientRegistration confidentialClient = OAuthServerClientRegistration.withClientId("client")
			.configurationVersion("v1").redirectUris(List.of(URI.create(REDIRECT)))
			.allowedScopesByResource(Map.of(RESOURCE, Set.of("s0")))
			.authentication(OAuthServerClientAuthentication.fromClientSecretVerifier((id, secret, budget) -> true)).build();
		assertEquals("kCnz7gECCKUYbZXqi4I4aIhbtKtvkSOtXfbUZjy88WU",
			OAuthAuthorizationRecord.clientFingerprint(publicClient));
		assertEquals("XnYYLianXCXYWM8FH5wkHBePfXUdINyDDuytA7s-1EQ",
			OAuthAuthorizationRecord.clientFingerprint(confidentialClient));
	}
}
