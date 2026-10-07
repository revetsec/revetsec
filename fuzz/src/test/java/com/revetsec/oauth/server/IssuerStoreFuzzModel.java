/* Copyright 2026 Revetware LLC. Licensed under the Apache License, Version 2.0. */
package com.revetsec.oauth.server;

import com.revetsec.M6FuzzOracle;
import com.revetsec.SealingKey;
import com.revetsec.StateSealer;
import com.revetsec.json.JsonObject;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Arrays;
import java.util.Base64;
import org.jspecify.annotations.NonNull;
import static org.junit.jupiter.api.Assertions.*;

/** Bounded authenticated-envelope model with independently enumerated substitutions. */
final class IssuerStoreFuzzModel {
	private static final @NonNull String ISSUER = "https://issuer.example/tenant";
	private static final @NonNull Instant NOW = Instant.parse("2026-10-07T12:00:00Z");
	private static final @NonNull StateSealer SEALER = sealer();
	private IssuerStoreFuzzModel() { }

	static void run(byte @NonNull [] input) throws Exception {
		OAuthStoreKey.Kind kind = OAuthStoreKey.Kind.values()[M6FuzzOracle.choice(input, 0, OAuthStoreKey.Kind.values().length)];
		int mutation = M6FuzzOracle.choice(input, 1, 9);
		byte[] tail = Arrays.copyOfRange(input, Math.min(4, input.length), Math.min(input.length, 260));
		String text = new String(tail, StandardCharsets.ISO_8859_1);
		OAuthStoreRecordCodec codec = new OAuthStoreRecordCodec(ISSUER, SEALER, 3800);
		String identifier = OAuthAuthorizationRecord.digest(Base64.getEncoder().encodeToString(tail));
		OAuthStoreKey key = kind == OAuthStoreKey.Kind.ISSUER_STATE ? codec.issuerKey()
			: kind == OAuthStoreKey.Kind.SUBJECT_STATE ? codec.subjectKey(text.isEmpty() ? "subject" : text)
			: codec.key(kind, identifier);
		assertEquals(key, OAuthStoreKey.fromStoredForm(key.getStorageKey()));
		Instant retention = kind == OAuthStoreKey.Kind.ISSUER_STATE || kind == OAuthStoreKey.Kind.SUBJECT_STATE
			? OAuthStoreFormat.PERMANENT : NOW.plusSeconds(60);
		String payload = JsonObject.builder().put("text", text).put("kind", kind.name()).build().toJson();
		if (mutation == 8) {
			assertThrows(IllegalArgumentException.class, () -> codec.seal(key, retention, "[]"));
			return;
		}
		OAuthStoreEntry original = codec.seal(key, retention, payload);
		assertEquals(43, original.getVersion().length());
		OAuthStoreEntry candidate = original;
		OAuthStoreRecordCodec openedCodec = codec;
		Clock openedClock = Clock.fixed(NOW, ZoneOffset.UTC);
		if (mutation == 1) candidate = OAuthStoreEntry.fromStoredForm(otherKey(codec, kind, identifier), original.getVersion(), retention, original.toSealedForm());
		if (mutation == 2) candidate = OAuthStoreEntry.fromStoredForm(key, alternate(original.getVersion()), retention, original.toSealedForm());
		if (mutation == 3) candidate = permanent(kind)
			? OAuthStoreEntry.fromStoredForm(key, alternate(original.getVersion()), retention, original.toSealedForm())
			: OAuthStoreEntry.fromStoredForm(key, original.getVersion(), retention.plusSeconds(1), original.toSealedForm());
		if (mutation == 4) candidate = OAuthStoreEntry.fromStoredForm(key, original.getVersion(), retention, original.toSealedForm() + "!");
		if (mutation == 5) openedCodec = new OAuthStoreRecordCodec(ISSUER + "/other", SEALER, 3800);
		if (mutation == 6 && retention != OAuthStoreFormat.PERMANENT) openedClock = Clock.fixed(retention, ZoneOffset.UTC);
		if (mutation == 7) openedCodec = new OAuthStoreRecordCodec(ISSUER, otherSealer(), 3800);
		boolean expected = mutation == 0 || mutation == 6 && retention == OAuthStoreFormat.PERMANENT;
		try {
			JsonObject opened = openedCodec.open(candidate, openedClock);
			assertTrue(expected, "substituted address/version/retention/ciphertext/namespace/key must reject");
			assertEquals(text, opened.findString("text").orElseThrow());
			assertEquals(kind.name(), opened.findString("kind").orElseThrow());
		} catch (IllegalArgumentException failure) { assertFalse(expected, "authentic unexpired envelope must open"); }
	}

	private static @NonNull OAuthStoreKey otherKey(@NonNull OAuthStoreRecordCodec codec, OAuthStoreKey.@NonNull Kind kind,
		@NonNull String identifier) {
		if (kind == OAuthStoreKey.Kind.ISSUER_STATE) return codec.subjectKey("alternate");
		if (kind == OAuthStoreKey.Kind.SUBJECT_STATE) return codec.issuerKey();
		OAuthStoreKey.Kind other = kind == OAuthStoreKey.Kind.GRANT ? OAuthStoreKey.Kind.CODE : OAuthStoreKey.Kind.GRANT;
		return codec.key(other, identifier);
	}
	private static boolean permanent(OAuthStoreKey.@NonNull Kind kind) {
		return kind == OAuthStoreKey.Kind.ISSUER_STATE || kind == OAuthStoreKey.Kind.SUBJECT_STATE;
	}
	private static @NonNull String alternate(@NonNull String nonce) {
		return nonce.substring(0, 42) + (nonce.charAt(42) == 'A' ? 'E' : 'A');
	}
	private static @NonNull StateSealer sealer() { return sealer((byte) 1, "g2"); }
	private static @NonNull StateSealer otherSealer() { return sealer((byte) 33, "other"); }
	private static @NonNull StateSealer sealer(byte start, @NonNull String id) {
		byte[] material = new byte[32];
		for (int i = 0; i < material.length; i++) material[i] = (byte) (start + i);
		return StateSealer.withActiveKey(SealingKey.fromBase64(id, Base64.getEncoder().encodeToString(material)))
			.maximumSealedLength(3800).clock(Clock.fixed(NOW, ZoneOffset.UTC)).build();
	}
}
