/* Copyright 2026 Revetware LLC. Licensed under the Apache License, Version 2.0. */
package com.revetsec.oauth.server;

import com.revetsec.M6FuzzOracle;
import com.revetsec.SealingKey;
import com.revetsec.StateSealer;
import com.revetsec.internal.http.CimdTransportFuzzOracle;
import com.revetsec.json.JsonArray;
import com.revetsec.json.JsonObject;
import com.revetsec.json.JsonString;
import com.revetsec.json.JsonValue;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import org.jspecify.annotations.NonNull;
import static org.junit.jupiter.api.Assertions.*;

/** Enumerated independent admission outcomes joined to authenticated cache invariants. */
final class CimdFuzzModel {
	private static final @NonNull String ISSUER = "https://issuer.example/tenant";
	private static final @NonNull String CLIENT = "https://client.example.com/metadata.json";
	private static final @NonNull Instant NOW = Instant.parse("2026-10-07T12:00:00Z");
	private static final @NonNull OAuthServerIngressLimits LIMITS = OAuthServerIngressLimits.fromDefaults();
	private static final @NonNull OAuthClientMetadataPolicy POLICY = OAuthClientMetadataPolicy
		.withAddressResolver((host, budget) -> List.of()).build();
	private static final @NonNull StateSealer SEALER = sealer();
	private CimdFuzzModel() { }

	static void run(byte @NonNull [] input) throws Exception {
		int documentMode = M6FuzzOracle.choice(input, 0, 11);
		int cacheMode = M6FuzzOracle.choice(input, 1, 7);
		byte[] tail = Arrays.copyOfRange(input, Math.min(4, input.length), Math.min(input.length, 1028));
		String display = tail.length == 0 ? "client" : Base64.getUrlEncoder().withoutPadding().encodeToString(tail);
		byte[] body = document(documentMode, display).getBytes(StandardCharsets.UTF_8);
		boolean expected = documentMode == 0 || documentMode == 9 || documentMode == 10;
		OAuthClientMetadataDocument parsed = null;
		try { parsed = OAuthClientMetadataDocument.parse(CLIENT, body, POLICY, LIMITS, false, false); }
		catch (OAuthServerAdmissionFailure failure) { assertFalse(expected, "enumerated invalid-client document"); }
		if (expected) {
			assertNotNull(parsed);
			assertEquals(CLIENT, parsed.clientId());
			assertEquals(display, parsed.clientName());
			assertEquals(List.of(java.net.URI.create("https://client.example.com/callback")), parsed.redirectUris());
			assertTrue(parsed.refreshTokenPermitted());
			cache(body, cacheMode, parsed.fingerprint());
		} else assertNull(parsed);
		CimdTransportFuzzOracle.run(input);
	}

	private static @NonNull String document(int mode, @NonNull String display) {
		JsonObject.Builder builder = JsonObject.builder().put("client_id", mode == 1 ? CLIENT + "/other" : CLIENT)
			.put("client_name", display).put("token_endpoint_auth_method", "none")
			.put("grant_types", JsonArray.fromElements(strings("authorization_code", "refresh_token")))
			.put("response_types", JsonArray.fromElements(strings(mode == 4 ? "token" : "code")))
			.put("redirect_uris", JsonArray.fromElements(mode == 6 ? List.of() : strings(
				mode == 5 ? "https://client.example.com/cb#fragment" : "https://client.example.com/callback")));
		if (mode == 2) builder.put("client_secret", "secret");
		if (mode == 3) builder.put("application_type", "service");
		if (mode == 7) builder.put("extension", JsonObject.builder().put("client_secret", "secret").build());
		if (mode == 8) builder.put("jwks", JsonObject.builder().put("keys", JsonArray.fromElements(List.of(
			(JsonValue) JsonObject.builder().put("kty", "oct").put("k", "AA").build()))).build());
		if (mode == 9) builder.put("extension", JsonObject.builder().put("untrusted", display).build());
		if (mode == 10) builder.put("contacts", JsonArray.fromElements(strings("owner@example.com")));
		return builder.build().toJson();
	}

	private static @NonNull List<@NonNull JsonValue> strings(@NonNull String @NonNull ... values) {
		return Arrays.stream(values).map(JsonString::fromValue).map(value -> (JsonValue) value).toList();
	}

	private static void cache(byte @NonNull [] body, int mode, @NonNull String fingerprint) {
		OAuthClientMetadataCacheCodec codec = new OAuthClientMetadataCacheCodec(ISSUER, SEALER, POLICY, LIMITS, false, false);
		OAuthClientMetadataCacheEntry original = codec.seal(CLIENT, body, NOW, NOW.plusSeconds(60));
		OAuthClientMetadataCacheEntry candidate = original;
		String openedClient = CLIENT;
		OAuthClientMetadataCacheCodec openedCodec = codec;
		Instant openedAt = NOW.plusSeconds(1);
		if (mode == 1) openedClient = CLIENT + "/other";
		if (mode == 2) candidate = OAuthClientMetadataCacheEntry.fromStoredForm(original.getKey(), alternate(original.getVersion()), original.getExpiresAt(), original.toSealedForm());
		if (mode == 3) candidate = OAuthClientMetadataCacheEntry.fromStoredForm(original.getKey(), original.getVersion(), original.getExpiresAt().plusSeconds(1), original.toSealedForm());
		if (mode == 4) candidate = OAuthClientMetadataCacheEntry.fromStoredForm(original.getKey(), original.getVersion(), original.getExpiresAt(), original.toSealedForm() + "!");
		if (mode == 5) openedAt = original.getExpiresAt();
		if (mode == 6) openedCodec = new OAuthClientMetadataCacheCodec(ISSUER + "/other", SEALER, POLICY, LIMITS, false, false);
		var opened = openedCodec.open(openedClient, candidate, openedAt);
		if (mode == 0) {
			assertTrue(opened.isPresent());
			assertEquals(fingerprint, opened.orElseThrow().document().fingerprint());
			assertEquals(NOW, codec.authenticatedFetchedAt(CLIENT, original).orElseThrow());
		} else assertTrue(opened.isEmpty(), "cache address/version/expiry/ciphertext/namespace must be authenticated");
	}

	private static @NonNull String alternate(@NonNull String nonce) {
		char last = nonce.charAt(42);
		return nonce.substring(0, 42) + (last == 'A' ? 'E' : 'A');
	}

	private static @NonNull StateSealer sealer() {
		byte[] material = new byte[32];
		for (int i = 0; i < material.length; i++) material[i] = (byte) (i + 1);
		return StateSealer.withActiveKey(SealingKey.fromBase64("g2", Base64.getEncoder().encodeToString(material)))
			.maximumSealedLength(16384).clock(Clock.fixed(NOW, ZoneOffset.UTC)).build();
	}
}
