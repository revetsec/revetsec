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
import com.revetsec.StoreAdmission;
import com.revetsec.internal.crypto.AuthenticatedRecord;
import com.revetsec.internal.crypto.ClosedMigrationIntent;
import com.revetsec.internal.crypto.SealedStateAccess;
import com.revetsec.internal.crypto.SealedStateType;
import com.revetsec.internal.crypto.UnsealException;
import com.revetsec.internal.encoding.StrictUtf8;
import com.revetsec.json.JsonArray;
import com.revetsec.json.JsonNull;
import com.revetsec.json.JsonNumber;
import com.revetsec.json.JsonObject;
import com.revetsec.json.JsonString;
import com.revetsec.json.JsonValue;
import org.jspecify.annotations.NonNull;
import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

/** Inactive issuer MIG-03/04/05/06/11/12/13/14 codec components; no controller/store/credential admission. */
final class OAuthStoreMigrationCodecTests {
	private static final @NonNull String ISSUER = "https://issuer.example";
	private static final @NonNull Instant NOW = Instant.parse("2026-10-29T00:00:00Z");
	private static final @NonNull Instant MINIMUM = Instant.ofEpochSecond(1700000000L, 999999999);
	private static final @NonNull String ID = identifier(1);
	private static final @NonNull String AUTHORITY = identifier(2);
	private static final @NonNull String RECOVERY = identifier(3);
	private static final @NonNull OAuthServerIngressLimits LIMITS = OAuthServerIngressLimits.fromDefaults();

	@Test void exactRootOuterAndInnerGoldenShapesPreserveEveryPreciseComponent() throws Exception {
		StateSealer sealer = sealer("k", 16384);
		OAuthStoreRecordCodec old = old(sealer, 16384);
		OAuthStoreRecordCodecV2 next = next(sealer, 16384, LIMITS);
		OAuthStoreEntry legacyRoot = old.seal(old.issuerKey(), OAuthStoreFormat.PERMANENT, legacyRoot(MINIMUM).toPayload());
		OAuthStoreMigrationCodec migration = migration(next, 16384);
		var pinned = migration.openRoot(legacyRoot);
		OAuthStoreEntry converted = migration.convert(legacyRoot, pinned);
		assertNotEquals(legacyRoot.getVersion(), converted.getVersion());
		var opened = next.open(converted, clock(NOW));
		assertEquals(MINIMUM, opened.floor());
		assertEquals("{\"schema\":2,\"incarnation\":\"" + ID + "\",\"epoch\":0,\"authorityId\":\"" + AUTHORITY
				+ "\",\"minimumSeconds\":1700000000,\"minimumNanos\":999999999}", opened.payload().toJson());
		try (AuthenticatedRecord raw = SealedStateAccess.get().openRecord(sealer, SealedStateType.AS_RECORD,
				converted.toSealedForm(), OAuthStoreRecordCodecV2.context(converted.getKey()), clock(NOW))) {
			String prefix = "{\"schema\":2,\"issuer\":\"" + ISSUER + "\",\"key\":\"" + converted.getKey().getStorageKey()
					+ "\",\"version\":\"" + converted.getVersion() + "\",\"retainUntil\":" + OAuthStoreFormat.PERMANENT.getEpochSecond()
					+ ",\"floorSeconds\":1700000000,\"floorNanos\":999999999,\"payload\":";
			assertEquals(prefix + opened.payload().toJson() + "}", raw.getPlaintext());
			assertEquals(OAuthStoreFormat.PERMANENT, raw.getNotAfter());
		}
		assertEquals("OAuthStoreMigrationCodec.LegacyRoot{state=<redacted>}", pinned.toString());
		assertEquals("OAuthStoreRecordCodecV2.Opened{state=<redacted>}", opened.toString());
	}

	@Test void everyAuthorizationKindAndStatusSurvivesWithoutEpochMatchingOrReactivation() {
		StateSealer sealer = sealer("k", 16384);
		OAuthStoreRecordCodec old = old(sealer, 16384);
		OAuthStoreRecordCodecV2 next = next(sealer, 16384, LIMITS);
		OAuthStoreMigrationCodec migration = migration(next, 16384);
		var pinned = migration.openRoot(old.seal(old.issuerKey(), OAuthStoreFormat.PERMANENT, legacyRoot(MINIMUM).toPayload()));
		int count = 0;
		for (OAuthStoreKey.Kind kind : List.of(OAuthStoreKey.Kind.INTERACTION, OAuthStoreKey.Kind.CODE,
				OAuthStoreKey.Kind.GRANT, OAuthStoreKey.Kind.ACCESS_TOKEN, OAuthStoreKey.Kind.REFRESH_TOKEN)) {
			for (String status : statuses(kind)) {
				JsonObject payload = authorization(kind, status, NOW);
				OAuthStoreKey key = old.key(kind, ID);
				OAuthAuthorizationRecord semantic = OAuthAuthorizationRecord.decode(kind, ID, payload, LIMITS, 1024);
				OAuthStoreEntry source = old.seal(key, semantic.retention(), payload.toJson());
				OAuthStoreEntry converted = migration.convert(source, pinned);
				var decoded = next.open(converted, clock(NOW));
				assertEquals(payload, decoded.payload());
				assertEquals(source.getRetainUntil(), converted.getRetainUntil());
				assertNotEquals(source.getVersion(), converted.getVersion());
				assertEquals(kind == OAuthStoreKey.Kind.ACCESS_TOKEN ? NOW.plusSeconds(1) : MINIMUM, decoded.floor());
				assertEquals(999L, OAuthStoreFormat.longMember(decoded.payload(), "issuerEpoch").orElseThrow());
				count++;
			}
		}
		assertEquals(12, count);
	}

	@Test void subjectPayloadRemainsSchemaOneAndSeedsItsExactFloorFromAuthenticatedMinimum() {
		StateSealer sealer = sealer("k", 16384);
		OAuthStoreRecordCodec old = old(sealer, 16384);
		OAuthStoreRecordCodecV2 next = next(sealer, 16384, LIMITS);
		OAuthStoreMigrationCodec migration = migration(next, 16384);
		var root = migration.openRoot(old.seal(old.issuerKey(), OAuthStoreFormat.PERMANENT, legacyRoot(MINIMUM).toPayload()));
		JsonObject subject = OAuthStoreRecordCodecV2.parse(OAuthStoreFence.initialSubject(ID).toPayload(), 200);
		OAuthStoreEntry row = old.seal(old.subjectKey("álîçè"), OAuthStoreFormat.PERMANENT, subject.toJson());
		var decoded = next.open(migration.convert(row, root), clock(NOW));
		assertEquals(subject, decoded.payload());
		assertEquals(MINIMUM, decoded.floor());
	}

	@Test void signedAndFutureLegacyMinimaArePreservedRatherThanClampedOrRebased() {
		for (Instant minimum : List.of(Instant.ofEpochSecond(-1, 999999999),
				Instant.ofEpochSecond(253402300800L, 123), MINIMUM, Instant.MIN)) {
			StateSealer sealer = sealer("k", 16384);
			OAuthStoreRecordCodec old = old(sealer, 16384);
			OAuthStoreRecordCodecV2 next = next(sealer, 16384, LIMITS);
			OAuthStoreMigrationCodec migration = migration(next, 16384);
			OAuthStoreEntry source = old.seal(old.issuerKey(), OAuthStoreFormat.PERMANENT, legacyRoot(minimum).toPayload());
			var root = migration.openRoot(source);
			assertEquals(minimum, next.open(migration.convert(source, root), clock(NOW)).floor());
		}
	}

	@Test void oldAndNewNormalCandidatesRefuseTheOtherGeneration() {
		StateSealer sealer = sealer("k", 16384);
		OAuthStoreRecordCodec old = old(sealer, 16384);
		OAuthStoreRecordCodecV2 next = next(sealer, 16384, LIMITS);
		OAuthStoreEntry source = old.seal(old.issuerKey(), OAuthStoreFormat.PERMANENT, legacyRoot(MINIMUM).toPayload());
		OAuthStoreMigrationCodec migration = migration(next, 16384);
		OAuthStoreEntry converted = migration.convert(source, migration.openRoot(source));
		assertThrows(IllegalArgumentException.class, () -> next.open(source, clock(NOW)));
		assertThrows(IllegalArgumentException.class, () -> old.open(converted, clock(NOW)));
		assertThrows(IllegalArgumentException.class, () -> migration.openRoot(converted));
	}

	@Test void expiredEnvelopesOpenOnlyForClosedMigrationAndRemainExpiredAfterConversion() {
		StateSealer sealer = sealer("k", 16384);
		OAuthStoreRecordCodec old = old(sealer, 16384);
		OAuthStoreRecordCodecV2 next = next(sealer, 16384, LIMITS);
		OAuthStoreMigrationCodec migration = migration(next, 16384);
		var root = migration.openRoot(old.seal(old.issuerKey(), OAuthStoreFormat.PERMANENT, legacyRoot(MINIMUM).toPayload()));
		JsonObject payload = authorization(OAuthStoreKey.Kind.CODE, "USED", NOW.minusSeconds(2000));
		OAuthAuthorizationRecord record = OAuthAuthorizationRecord.decode(OAuthStoreKey.Kind.CODE, ID, payload, LIMITS, 1024);
		OAuthStoreEntry source = old.seal(old.key(OAuthStoreKey.Kind.CODE, ID), record.retention(), payload.toJson());
		assertThrows(IllegalArgumentException.class, () -> old.open(source, clock(NOW)));
		OAuthStoreEntry converted = migration.convert(source, root);
		assertEquals(source.getRetainUntil(), converted.getRetainUntil());
		assertThrows(IllegalArgumentException.class, () -> next.open(converted, clock(NOW)));
		assertEquals(payload, next.open(converted, clock(converted.getRetainUntil().minusNanos(1))).payload());
		assertThrows(IllegalArgumentException.class, () -> next.open(converted, clock(converted.getRetainUntil())));
	}

	@Test void ownerBoundMigrationRootCannotBeSubstitutedAcrossClosedTransformers() {
		StateSealer sealer = sealer("k", 16384);
		OAuthStoreRecordCodec old = old(sealer, 16384);
		OAuthStoreRecordCodecV2 next = next(sealer, 16384, LIMITS);
		OAuthStoreEntry source = old.seal(old.issuerKey(), OAuthStoreFormat.PERMANENT, legacyRoot(MINIMUM).toPayload());
		OAuthStoreMigrationCodec a = migration(next, 16384), b = migration(next, 16384);
		assertThrows(IllegalArgumentException.class, () -> b.convert(source, a.openRoot(source)));
		ClosedMigrationIntent wrong = ClosedMigrationIntent.fromExternalIntent(ID,
				StoreAdmission.fromIdentifiers(AUTHORITY, RECOVERY), Set.of(ClosedMigrationIntent.Format.TOTP_TTR3));
		assertThrows(IllegalArgumentException.class, () -> new OAuthStoreMigrationCodec(next, 16384, wrong));
		assertThrows(IllegalArgumentException.class, () -> a.openRoot(old.seal(old.subjectKey("alice"),
				OAuthStoreFormat.PERMANENT, OAuthStoreFence.initialSubject(ID).toPayload())));
		assertThrows(IllegalArgumentException.class,
				() -> OAuthIssuerRootV2.fromLegacy(OAuthStoreFence.initialSubject(ID), AUTHORITY));
	}

	@Test void permanentFenceAuthenticationNeedsActualNewRootAuthorityAndExactThreeLayerPermanence() {
		StateSealer sealer = sealer("k", 16384);
		OAuthStoreRecordCodecV2 next = next(sealer, 16384, LIMITS);
		OAuthIssuerRootV2 root = OAuthIssuerRootV2.fromLegacy(legacyRoot(MINIMUM), AUTHORITY);
		OAuthStoreEntry issuer = next.seal(next.issuerKey(), OAuthStoreFormat.PERMANENT, MINIMUM, root.toPayload());
		OAuthStoreEntry subject = next.seal(next.subjectKey("alice"), OAuthStoreFormat.PERMANENT, MINIMUM,
				OAuthStoreFence.initialSubject(ID).toPayload());
		StoreAdmission admission = StoreAdmission.fromIdentifiers(AUTHORITY, RECOVERY);
		assertEquals(MINIMUM, next.openPermanentFence(issuer, admission, issuer).floor());
		assertEquals(MINIMUM, next.openPermanentFence(subject, admission, issuer).floor());
		assertThrows(IllegalArgumentException.class, () -> next.openPermanentFence(subject,
				StoreAdmission.fromIdentifiers(ID, RECOVERY), issuer));
		assertThrows(IllegalArgumentException.class, () -> next.openPermanentFence(subject, admission, subject));
		JsonObject code = authorization(OAuthStoreKey.Kind.CODE, "UNUSED", NOW);
		OAuthStoreEntry finite = next.seal(next.key(OAuthStoreKey.Kind.CODE, ID), NOW.plusSeconds(100), MINIMUM, code.toJson());
		assertThrows(IllegalArgumentException.class, () -> next.openPermanentFence(finite, admission, issuer));
		// Correct outer permanent text, but finite authenticated encrypted notAfter.
		String plaintext = raw(issuer, sealer);
		OAuthStoreEntry badNotAfter = sealRaw(issuer.getKey(), issuer.getVersion(), OAuthStoreFormat.PERMANENT,
				plaintext, NOW.plusSeconds(100), SealedStateType.AS_RECORD, OAuthStoreRecordCodecV2.context(issuer.getKey()), sealer);
		assertThrows(IllegalArgumentException.class, () -> next.openPermanentFence(badNotAfter, admission, badNotAfter));
	}

	@Test void outerBindingsContextsTypeTamperAndExactFieldSetsFailClosed() {
		StateSealer sealer = sealer("k", 16384);
		OAuthStoreRecordCodecV2 next = next(sealer, 16384, LIMITS);
		String payload = OAuthIssuerRootV2.fromLegacy(legacyRoot(MINIMUM), AUTHORITY).toPayload();
		OAuthStoreEntry row = next.seal(next.issuerKey(), OAuthStoreFormat.PERMANENT, MINIMUM, payload);
		String text = raw(row, sealer);
		List<String> malformed = List.of(text.replace("\"schema\":2", "\"schema\":1"),
				text.replace("\"floorNanos\":999999999", "\"floorNanos\":1000000000"),
				text.replace("\"floorNanos\":999999999", "\"floorNanos\":-1"),
				text.replace("\"floorSeconds\":1700000000", "\"floorSeconds\":9223372036854775808"),
				text.replace("\"floorSeconds\":1700000000", "\"floorSeconds\":31556889864403199"),
				text.replace("\"schema\":2", "\"schema\":2,\"sch\\u0065ma\":2"), text + "x",
				text.substring(0, text.length() - 1), text.replace("\"payload\":{", "\"extra\":0,\"payload\":{"),
				text.replace(ISSUER, ISSUER + "/"), text.replace(row.getVersion(), identifier(7)),
				text.replace("\"payload\":{", "\"payload\":[{"));
		for (String bad : malformed) {
			OAuthStoreEntry forged = sealRaw(row.getKey(), row.getVersion(), row.getRetainUntil(), bad,
					row.getRetainUntil(), SealedStateType.AS_RECORD, OAuthStoreRecordCodecV2.context(row.getKey()), sealer);
			assertThrows(IllegalArgumentException.class, () -> next.open(forged, clock(NOW)));
		}
		for (String context : List.of("revetsec/as-record/v1:" + row.getKey().getStorageKey(),
				OAuthStoreRecordCodecV2.context(next.subjectKey("alice")))) {
			OAuthStoreEntry bad = sealRaw(row.getKey(), row.getVersion(), row.getRetainUntil(), text,
					row.getRetainUntil(), SealedStateType.AS_RECORD, context, sealer);
			assertThrows(IllegalArgumentException.class, () -> next.open(bad, clock(NOW)));
		}
		OAuthStoreEntry wrongType = sealRaw(row.getKey(), row.getVersion(), row.getRetainUntil(), text,
				row.getRetainUntil(), SealedStateType.APP, OAuthStoreRecordCodecV2.context(row.getKey()), sealer);
		assertThrows(IllegalArgumentException.class, () -> next.open(wrongType, clock(NOW)));
		String sealed = row.toSealedForm();
		OAuthStoreEntry tampered = OAuthStoreEntry.fromStoredForm(row.getKey(), row.getVersion(), row.getRetainUntil(),
				sealed.substring(0, sealed.length() - 1) + (sealed.endsWith("A") ? "E" : "A"));
		assertThrows(IllegalArgumentException.class, () -> next.open(tampered, clock(NOW)));
		assertThrows(IllegalArgumentException.class, () -> next.open(OAuthStoreEntry.fromStoredForm(row.getKey(), ID,
				row.getRetainUntil(), row.toSealedForm()), clock(NOW)));
	}

	@Test void rootShapeAuthorityMinimumAndAuthorizationPayloadSemanticsAreNotGenericJson() {
		StateSealer sealer = sealer("k", 16384);
		OAuthStoreRecordCodecV2 next = next(sealer, 16384, LIMITS);
		String root = OAuthIssuerRootV2.fromLegacy(legacyRoot(MINIMUM), AUTHORITY).toPayload();
		for (String payload : List.of(root.replace("\"schema\":2", "\"schema\":1"),
				root.replace("\"minimumNanos\":999999999", "\"minimumNanos\":1000000000"),
				root.replace(AUTHORITY, "A".repeat(42) + "B"), root.replace("\"epoch\":0", "\"epoch\":-1"),
				root.replace("\"epoch\":0", "\"epoch\":0,\"unknown\":1"))) {
			assertThrows(IllegalArgumentException.class, () -> next.seal(next.issuerKey(), OAuthStoreFormat.PERMANENT, MINIMUM, payload));
		}
		assertThrows(IllegalArgumentException.class, () -> next.seal(next.issuerKey(), OAuthStoreFormat.PERMANENT,
				MINIMUM.plusNanos(1), root));
		assertThrows(IllegalArgumentException.class, () -> next.seal(next.key(OAuthStoreKey.Kind.CODE, ID),
				NOW.plusSeconds(100), MINIMUM, "{}"));
		JsonObject valid = authorization(OAuthStoreKey.Kind.CODE, "USED", NOW);
		assertThrows(IllegalArgumentException.class, () -> next.seal(next.key(OAuthStoreKey.Kind.CODE, identifier(4)),
				NOW.plusSeconds(1000), MINIMUM, valid.toJson()));
		assertThrows(IllegalArgumentException.class, () -> next.seal(next.key(OAuthStoreKey.Kind.CODE, ID),
				NOW.plusSeconds(1001), MINIMUM, valid.toJson()));
	}

	@Test void canonicalWriterOrdersOuterMembersButDecoderAcceptsEquivalentWhitespaceAndMemberOrder() {
		StateSealer sealer = sealer("k", 16384);
		OAuthStoreRecordCodecV2 next = next(sealer, 16384, LIMITS);
		String root = OAuthIssuerRootV2.fromLegacy(legacyRoot(MINIMUM), AUTHORITY).toPayload();
		OAuthStoreEntry row = next.seal(next.issuerKey(), OAuthStoreFormat.PERMANENT, MINIMUM, root);
		JsonObject envelope = OAuthStoreRecordCodecV2.parse(raw(row, sealer), 12170);
		Map<String, JsonValue> reversed = new LinkedHashMap<>();
		List<String> names = new ArrayList<>(envelope.getMembers().keySet());
		java.util.Collections.reverse(names);
		for (String name : names) reversed.put(name, envelope.getMembers().get(name));
		String text = " \n" + JsonObject.fromMembers(reversed).toJson() + "\t ";
		OAuthStoreEntry reordered = sealRaw(row.getKey(), row.getVersion(), row.getRetainUntil(), text,
				row.getRetainUntil(), SealedStateType.AS_RECORD, OAuthStoreRecordCodecV2.context(row.getKey()), sealer);
		assertEquals(MINIMUM, next.open(reordered, clock(NOW)).floor());
	}

	@Test void completeBudgetReservesEveryAllowedKeyIdAndActualUtf8RatherThanCharacterCount() {
		for (int cap : List.of(1024, 3800, 16384)) {
			StateSealer one = sealer("k", cap), sixtyFour = sealer("k".repeat(64), cap);
			OAuthStoreRecordCodecV2 a = next(one, cap, LIMITS), b = next(sixtyFour, cap, LIMITS);
			assertEquals(cap * 3 / 4 - 118, a.maximumPlaintextBytes());
			assertEquals(a.maximumPlaintextBytes(), b.maximumPlaintextBytes());
			JsonObject payload = authorization(OAuthStoreKey.Kind.INTERACTION, "PENDING", NOW);
			// At C1024 even the mandatory authorization facts may not fit, and must refuse rather than trim.
			if (cap == 1024) {
				assertThrows(IllegalArgumentException.class, () -> a.seal(a.key(OAuthStoreKey.Kind.INTERACTION, ID),
						NOW.plusSeconds(100), MINIMUM, payload.toJson()));
			} else {
				OAuthStoreEntry x = a.seal(a.key(OAuthStoreKey.Kind.INTERACTION, ID), NOW.plusSeconds(100), MINIMUM, payload.toJson());
				OAuthStoreEntry y = b.seal(b.key(OAuthStoreKey.Kind.INTERACTION, ID), NOW.plusSeconds(100), MINIMUM, payload.toJson());
				assertEquals(84, y.toSealedForm().length() - x.toSealedForm().length());
				assertTrue(y.toSealedForm().length() <= cap);
			}
		}
		StateSealer sealer = sealer("k", 16384);
		OAuthStoreRecordCodecV2 next = next(sealer, 16384, LIMITS);
		assertThrows(IllegalArgumentException.class, () -> next(next.sealer(), 16385, LIMITS));
		assertThrows(IllegalArgumentException.class, () -> OAuthStoreRecordCodecV2.parse("é".repeat(326), 650));
		assertThrows(IllegalArgumentException.class, () -> OAuthStoreRecordCodecV2.parse("\ud800", 650));
	}

	@Test void authenticatedLegalLegacyMaximumHasNoImmediateNewFitEvenWithShortKey() throws Exception {
		StateSealer sealer = sealer("k", 16384);
		OAuthServerIngressLimits large = new OAuthServerIngressLimits(16384, 16384, 16384, 4096, 4096, 8, 16, 80, 128);
		OAuthStoreRecordCodec old = old(sealer, 16384);
		OAuthStoreRecordCodecV2 next = next(sealer, 16384, large);
		OAuthStoreMigrationCodec migration = migration(next, 16384);
		var root = migration.openRoot(old.seal(old.issuerKey(), OAuthStoreFormat.PERMANENT, legacyRoot(MINIMUM).toPayload()));
		JsonObject base = authorization(OAuthStoreKey.Kind.INTERACTION, "PENDING", NOW);
		Map<String, JsonValue> members = new LinkedHashMap<>(base.getMembers());
		List<JsonString> scopes = new ArrayList<>();
		for (int n = 0; n < 80; n++) scopes.add(JsonString.fromValue(String.format(java.util.Locale.ROOT, "%03d", n) + "s".repeat(125)));
		members.put("scopes", JsonArray.fromElements(scopes));
		members.put("clientId", JsonString.fromValue("c"));
		members.put("issuerEpoch", JsonNumber.fromValue(99L));
		members.put("state", JsonString.fromValue(""));
		JsonObject empty = JsonObject.fromMembers(members);
		OAuthStoreKey key = old.key(OAuthStoreKey.Kind.INTERACTION, ID);
		int stateSize = 12233 - StrictUtf8.encode(legacyEnvelope(key, ID, NOW.plusSeconds(100), empty)).length;
		assertEquals(1012, stateSize);
		members.put("state", JsonString.fromValue("x".repeat(stateSize)));
		JsonObject payload = JsonObject.fromMembers(members);
		OAuthAuthorizationRecord.decode(key.getKind(), ID, payload, large, 1024);
		OAuthStoreEntry row = old.seal(key, NOW.plusSeconds(100), payload.toJson());
		assertEquals(16384, row.toSealedForm().length());
		assertEquals(12233, rawLegacy(row, sealer).getBytes(java.nio.charset.StandardCharsets.UTF_8).length);
		assertThrows(IllegalArgumentException.class, () -> migration.convert(row, root));
	}

	@Test void explicitLargerAllowedCapCanResolveAFitFailureWithoutChangingSemanticPayload() {
		StateSealer sealer = sealer("k", 16384);
		OAuthStoreRecordCodec old = old(sealer, 16384);
		JsonObject payload = authorization(OAuthStoreKey.Kind.INTERACTION, "PENDING", NOW);
		OAuthStoreEntry source = old.seal(old.key(OAuthStoreKey.Kind.INTERACTION, ID), NOW.plusSeconds(100), payload.toJson());
		OAuthStoreEntry legacyRoot = old.seal(old.issuerKey(), OAuthStoreFormat.PERMANENT, legacyRoot(MINIMUM).toPayload());
		OAuthStoreMigrationCodec small = migration(next(sealer, 1024, LIMITS), 16384);
		assertThrows(IllegalArgumentException.class, () -> small.convert(source, small.openRoot(legacyRoot)));
		OAuthStoreRecordCodecV2 larger = next(sealer, 3800, LIMITS);
		OAuthStoreMigrationCodec large = migration(larger, 16384);
		assertEquals(payload, larger.open(large.convert(source, large.openRoot(legacyRoot)), clock(NOW)).payload());
	}

	private static @NonNull OAuthStoreRecordCodec old(@NonNull StateSealer sealer, int cap) { return new OAuthStoreRecordCodec(ISSUER, sealer, cap); }
	private static @NonNull OAuthStoreRecordCodecV2 next(@NonNull StateSealer sealer, int cap, @NonNull OAuthServerIngressLimits limits) {
		return new OAuthStoreRecordCodecV2(ISSUER, sealer, cap, limits, 1024);
	}
	private static @NonNull OAuthStoreMigrationCodec migration(@NonNull OAuthStoreRecordCodecV2 codec, int oldCap) {
		return new OAuthStoreMigrationCodec(codec, oldCap, ClosedMigrationIntent.fromExternalIntent(ID,
				StoreAdmission.fromIdentifiers(AUTHORITY, RECOVERY), Set.of(ClosedMigrationIntent.Format.ISSUER_SCHEMA2)));
	}
	private static @NonNull OAuthStoreFence legacyRoot(@NonNull Instant minimum) { return OAuthStoreFence.initialIssuer(ID, minimum); }
	private static @NonNull Clock clock(@NonNull Instant instant) { return Clock.fixed(instant, ZoneOffset.UTC); }
	private static @NonNull StateSealer sealer(@NonNull String id, int cap) {
		byte[] bytes = new byte[32]; for (int n = 0; n < bytes.length; n++) bytes[n] = (byte) (n + 1);
		try { return StateSealer.withActiveKey(SealingKey.fromBase64(id, Base64.getEncoder().encodeToString(bytes))).maximumSealedLength(cap).clock(clock(NOW)).build(); }
		finally { Arrays.fill(bytes, (byte) 0); }
	}
	private static @NonNull String identifier(int value) {
		byte[] bytes = new byte[32]; bytes[0] = (byte) value;
		return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
	}
	private static @NonNull List<@NonNull String> statuses(OAuthStoreKey.@NonNull Kind kind) {
		return switch (kind) {
			case INTERACTION -> List.of("PENDING", "COMPLETED");
			case CODE -> List.of("UNUSED", "USED", "CANCELLED");
			case GRANT -> List.of("PENDING", "DENIED", "ACTIVE", "REVOKED");
			case ACCESS_TOKEN -> List.of("ISSUED");
			case REFRESH_TOKEN -> List.of("ACTIVE", "USED");
			default -> throw new AssertionError("Not an authorization kind");
		};
	}
	private static @NonNull JsonObject authorization(OAuthStoreKey.@NonNull Kind kind, @NonNull String status, @NonNull Instant base) {
		JsonObject.Builder b = JsonObject.builder().put("schema", 1L).put("id", ID).put("status", status)
				.put("expires", base.plusSeconds(100).getEpochSecond()).put("issuerIncarnation", ID).put("issuerEpoch", 999L);
		if (kind == OAuthStoreKey.Kind.INTERACTION) return b.put("browserHash", ID).put("clientHash", ID)
				.put("clientId", "client").put("redirect", "https://client.example/cb").put("resource", "https://resource.example/mcp")
				.put("scopes", JsonArray.fromElements(List.of(JsonString.fromValue("read")))).put("challenge", ID).put("state", JsonNull.defaultInstance()).build();
		b.put("subjectIncarnation", ID).put("subjectEpoch", 999L);
		if (kind == OAuthStoreKey.Kind.CODE) {
			b.put("grantId", ID).put("challenge", ID).put("redirect", "https://client.example/cb");
			if (status.equals("USED")) b.put("horizon", base.plusSeconds(1000).getEpochSecond());
		} else if (kind == OAuthStoreKey.Kind.GRANT) {
			b.put("codeId", ID).put("subject", "álîçè").put("clientId", "client").put("clientHash", ID)
					.put("resource", "https://resource.example/mcp").put("scopes", JsonArray.fromElements(List.of(JsonString.fromValue("read"))))
					.put("refresh", true);
			if (status.equals("ACTIVE") || status.equals("REVOKED")) b.put("horizon", base.plusSeconds(1000).getEpochSecond())
					.put("maximumAccessSeconds", 30L).put("maximumAccessNanos", 123456789L).put("refreshId", ID);
		} else if (kind == OAuthStoreKey.Kind.ACCESS_TOKEN) {
			b.put("grantId", ID).put("subject", "álîçè").put("clientId", "client").put("resource", "https://resource.example/mcp")
					.put("scopes", JsonArray.fromElements(List.of(JsonString.fromValue("read"))))
					.put("issued", base.plusSeconds(1).getEpochSecond()).put("retain", base.plusSeconds(1000).getEpochSecond());
		} else b.put("grantId", ID).put("horizon", base.plusSeconds(1000).getEpochSecond());
		return b.build();
	}
	private static @NonNull String raw(@NonNull OAuthStoreEntry row, @NonNull StateSealer sealer) {
		try (AuthenticatedRecord opened = SealedStateAccess.get().openRecord(sealer, SealedStateType.AS_RECORD,
				row.toSealedForm(), OAuthStoreRecordCodecV2.context(row.getKey()), clock(NOW))) { return opened.getPlaintext(); }
		catch (UnsealException failure) { throw new AssertionError("Fixture authentication failed", failure); }
	}
	private static @NonNull String rawLegacy(@NonNull OAuthStoreEntry row, @NonNull StateSealer sealer) {
		try { return SealedStateAccess.get().unseal(sealer, SealedStateType.AS_RECORD, row.toSealedForm(),
				"revetsec/as-record/v1:" + row.getKey().getStorageKey(), clock(NOW)); }
		catch (UnsealException failure) { throw new AssertionError("Fixture authentication failed", failure); }
	}
	private static @NonNull OAuthStoreEntry sealRaw(@NonNull OAuthStoreKey key,
			@NonNull String version, @NonNull Instant retain, @NonNull String text, @NonNull Instant notAfter,
			@NonNull SealedStateType type, @NonNull String context, @NonNull StateSealer sealer) {
		String value = SealedStateAccess.get().seal(sealer, type, text, context, notAfter);
		return OAuthStoreEntry.fromStoredForm(key, version, retain, value);
	}
	private static @NonNull String legacyEnvelope(@NonNull OAuthStoreKey key, @NonNull String version,
			@NonNull Instant retention, @NonNull JsonObject payload) {
		return "{\"schema\":1,\"issuer\":" + JsonString.fromValue(ISSUER).toJson() + ",\"key\":" + JsonString.fromValue(key.getStorageKey()).toJson()
				+ ",\"version\":\"" + version + "\",\"retainUntil\":" + retention.getEpochSecond() + ",\"payload\":" + payload.toJson() + "}";
	}
}
