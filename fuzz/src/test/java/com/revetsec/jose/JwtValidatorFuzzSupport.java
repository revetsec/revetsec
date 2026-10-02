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

package com.revetsec.jose;

import org.jspecify.annotations.Nullable;

import org.jspecify.annotations.NonNull;

import com.revetsec.internal.json.JsonCodec;
import com.revetsec.json.JsonArray;
import com.revetsec.json.JsonObject;
import com.revetsec.json.JsonString;
import com.revetsec.json.JsonValue;

import javax.annotation.concurrent.Immutable;
import javax.annotation.concurrent.ThreadSafe;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.EdECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECFieldFp;
import java.security.spec.EdECPoint;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.function.Function;

/**
 * What {@link JwtValidatorFuzzTests} and the seed generator ({@code com.revetsec.FuzzSeedGenerator}) share: the fixed
 * time, the issuers and audience, the key-set slots, and the writer that turns slots and keys into a JWK Set. Not a
 * fuzz target (no {@code FuzzTests} suffix), and it loads no key, so the generator can use it before the target's key
 * set exists.
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 */
@ThreadSafe
public final class JwtValidatorFuzzSupport {
	/**
	 * The instant every validator's clock is fixed at.
	 */
	public static final Instant NOW = Instant.parse("2026-09-27T12:00:00Z");

	/**
	 * The first validator's issuer.
	 */
	public static final String ISSUER = "https://issuer.example.com";

	/**
	 * The first validator's one expected audience.
	 */
	public static final String AUDIENCE = "https://api.example.com";

	/**
	 * The second validator's tenant: a made-up lowercase GUID, not a real tenant.
	 */
	public static final String ENTRA_TENANT = "7c3f0e2a-5b41-4d8e-9a6f-1e2d3c4b5a69";

	/**
	 * The second validator's issuer: Entra's v2 issuer for {@link #ENTRA_TENANT}.
	 */
	public static final String ENTRA_ISSUER = "https://login.microsoftonline.com/" + ENTRA_TENANT + "/v2.0";

	/**
	 * The third validator's issuer: an Entra v2 issuer spelled with {@link #ENTRA_TENANT} in upper case. M2-11 lets the
	 * template stand only for a lowercase {@code tid}, so no templated key verifies for it.
	 */
	public static final String UPPERCASE_ENTRA_ISSUER = "https://login.microsoftonline.com/"
			+ ENTRA_TENANT.toUpperCase(Locale.ROOT) + "/v2.0";

	/**
	 * Entra's templated JWK {@code issuer} member (M2-11).
	 */
	public static final String ENTRA_TEMPLATE = "https://login.microsoftonline.com/{tenantid}/v2.0";

	/**
	 * The claims the first validator requires besides {@code iss}, {@code exp} and {@code aud}.
	 */
	public static final Set<String> REQUIRED_CLAIMS = Set.of("sub", "client_id");

	/**
	 * The slots of both key sets: each key's {@code kid}, the fixture it holds (by the name of its file under
	 * {@code src/test/resources/fixtures/}), and its optional members. RSA keys without {@code alg} fit only the second
	 * and third validators, which allow one RSA algorithm each. Under the first validator two keys fit {@code RS256}, so
	 * an {@code RS256} token without {@code kid} is ambiguous. One slot has no {@code kid}: it fits only tokens without
	 * one, which the other {@code ES256} keys already make ambiguous, so a key without {@code kid} that matched any
	 * {@code kid} would turn every {@code ES256} token naming {@code ec-p256} ambiguous.
	 * <p>
	 * The Ed25519 key is there three times, without {@code alg}, with {@code EdDSA} and with {@code Ed25519}, so that a
	 * token naming either of the last two decides each direction of the {@code EdDSA}/{@code Ed25519} alias (Revetsec's
	 * own, on RFC 9864 sections 2.2 and 5), and an Ed25519 token without {@code kid} is ambiguous. Three slots share the
	 * {@code kid} {@code shared-kid}: the P-521 key with {@code ES512} and without {@code alg}, which make an
	 * {@code ES512} token naming it ambiguous, and an RSA key with {@code RS384}, which alone fits an {@code RS384} token
	 * naming it.
	 */
	public static final List<KeySlot> KEY_SLOTS = List.of(
			new KeySlot("rsa-2048-rs256", "idp-signing-rsa-2048", "RS256", null, "sig", null, false),
			new KeySlot("rsa-2048-rs384", "idp-signing-rsa-2048", "RS384", null, null, null, false),
			new KeySlot("rsa-2048-rs512", "idp-signing-rsa-2048", "RS512", null, null, null, false),
			new KeySlot("rsa-2048-ps256", "idp-signing-rsa-2048", "PS256", null, null, null, false),
			new KeySlot("rsa-2048-ps384", "idp-signing-rsa-2048", "PS384", null, null, List.of("verify"), false),
			new KeySlot("rsa-2048-ps512", "idp-signing-rsa-2048", "PS512", null, null, null, false),
			new KeySlot("rsa-3072", "idp-signing-rsa-3072", null, null, null, List.of("sign", "verify"), false),
			new KeySlot("ec-p256", "idp-signing-ec-p256", "ES256", null, "sig", null, true),
			new KeySlot("ec-p384", "idp-signing-ec-p384", null, null, null, null, true),
			new KeySlot("ec-p521", "idp-signing-ec-p521", "ES512", null, "sig", List.of("verify"), false),
			new KeySlot("ed25519", "ed25519", null, null, null, null, false),
			new KeySlot("rsa-2048-other-issuer", "sp-signing-rsa-2048", "RS256", "https://other.example.com", null, null,
					false),
			new KeySlot("entra-template", "idp-signing-rsa-3072", null, ENTRA_TEMPLATE, "sig", null, false),
			new KeySlot("entra-exact", "sp-signing-rsa-2048", null, ENTRA_ISSUER, "sig", null, false),
			new KeySlot("ec-p256-issuer-bound", "idp-signing-ec-p256", "ES256", ISSUER, null, null, false),
			new KeySlot(null, "idp-signing-ec-p256", "ES256", null, null, null, false),
			new KeySlot("ed25519-eddsa", "ed25519", "EdDSA", null, null, null, false),
			new KeySlot("ed25519-ed25519", "ed25519", "Ed25519", null, null, null, false),
			new KeySlot("shared-kid", "idp-signing-ec-p521", "ES512", null, null, null, false),
			new KeySlot("shared-kid", "idp-signing-ec-p521", null, null, null, null, false),
			new KeySlot("shared-kid", "idp-signing-rsa-2048", "RS384", null, null, null, false));

	/**
	 * The resource, in this package, that holds the fixture key set ({@code JwtValidatorFuzzTests.FIXTURE_KEY_SET}).
	 */
	public static final String FIXTURE_KEY_SET_RESOURCE = "fixture-key-set.json";

	private JwtValidatorFuzzSupport() {
	}

	/**
	 * Unpadded base64url (RFC 4648 section 5).
	 *
	 * @param bytes the octets
	 * @return the encoding
	 */
	public static @NonNull String encodeBase64Url(byte @NonNull [] bytes) {
		return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
	}

	/**
	 * Writes a JWK Set of {@code slots} over the given keys, members in a fixed order: {@code kty}, {@code kid},
	 * {@code use}, {@code key_ops}, {@code alg}, {@code issuer}, the key's members (RFC 7518 section 6, RFC 8037
	 * section 2), then {@code x5c} for a slot that has a certificate.
	 *
	 * @param slots        the slots
	 * @param keys         each fixture name's public key
	 * @param certificates each fixture name's certificate, or {@code null} if it has none
	 * @return the JSON text
	 */
	public static @NonNull String keySetJson(@NonNull List<@NonNull KeySlot> slots, @NonNull Function<@NonNull String, @NonNull PublicKey> keys,
																	@NonNull Function<@NonNull String, @Nullable X509Certificate> certificates) {
		List<JsonValue> elements = new ArrayList<>();

		for (KeySlot slot : slots) {
			Map<String, JsonValue> members = new LinkedHashMap<>();
			PublicKey key = keys.apply(slot.fixture);
			members.put("kty", JsonString.fromValue(key instanceof RSAPublicKey ? "RSA" : key instanceof ECPublicKey ? "EC"
					: "OKP"));
			if (slot.keyId != null)
				members.put("kid", JsonString.fromValue(slot.keyId));

			if (slot.use != null)
				members.put("use", JsonString.fromValue(slot.use));

			if (slot.keyOperations != null)
				members.put("key_ops", JsonArray.fromElements(slot.keyOperations.stream().map(JsonString::fromValue).toList()));

			if (slot.algorithm != null)
				members.put("alg", JsonString.fromValue(slot.algorithm));

			if (slot.issuer != null)
				members.put("issuer", JsonString.fromValue(slot.issuer));

			if (key instanceof RSAPublicKey rsa) {
				members.put("n", JsonString.fromValue(encodeBase64Url(unsigned(rsa.getModulus()))));
				members.put("e", JsonString.fromValue(encodeBase64Url(unsigned(rsa.getPublicExponent()))));
			} else if (key instanceof ECPublicKey ec) {
				int length = (((ECFieldFp) ec.getParams().getCurve().getField()).getP().bitLength() + 7) / 8;
				members.put("crv", JsonString.fromValue(length == 32 ? "P-256" : length == 48 ? "P-384" : "P-521"));
				members.put("x", JsonString.fromValue(encodeBase64Url(fixedLength(ec.getW().getAffineX(), length))));
				members.put("y", JsonString.fromValue(encodeBase64Url(fixedLength(ec.getW().getAffineY(), length))));
			} else {
				EdECPoint point = ((EdECPublicKey) key).getPoint();
				byte[] bigEndian = fixedLength(point.getY(), 32);
				byte[] encoded = new byte[32];

				for (int index = 0; index < 32; ++index)
					encoded[index] = bigEndian[31 - index];

				if (point.isXOdd())
					encoded[31] |= (byte) 0x80;

				members.put("crv", JsonString.fromValue("Ed25519"));
				members.put("x", JsonString.fromValue(encodeBase64Url(encoded)));
			}

			X509Certificate certificate = slot.withCertificate ? certificates.apply(slot.fixture) : null;

			if (certificate != null) {
				try {
					members.put("x5c", JsonArray.fromElements(List.of(JsonString.fromValue(Base64.getEncoder()
							.encodeToString(certificate.getEncoded())))));
				} catch (CertificateEncodingException e) {
					throw new IllegalStateException("A fixture certificate has no encoding", e);
				}
			}

			elements.add(JsonObject.fromMembers(members));
		}

		return new String(JsonCodec.toUtf8Bytes(JsonObject.fromMembers(Map.of("keys", JsonArray.fromElements(elements)))),
				StandardCharsets.UTF_8);
	}

	private static byte @NonNull [] unsigned(@NonNull BigInteger value) {
		byte[] bytes = value.toByteArray();
		return bytes.length > 1 && bytes[0] == 0 ? Arrays.copyOfRange(bytes, 1, bytes.length) : bytes;
	}

	/**
	 * {@code value} big-endian in exactly {@code length} octets, keeping the low octets of a larger value.
	 *
	 * @param value  the value
	 * @param length the length
	 * @return a new array
	 */
	public static byte @NonNull [] fixedLength(@NonNull BigInteger value, int length) {
		byte[] bytes = value.toByteArray();
		byte[] fixed = new byte[length];

		for (int index = 0; index < length && index < bytes.length; ++index)
			fixed[length - 1 - index] = bytes[bytes.length - 1 - index];

		return fixed;
	}

	/**
	 * One key-set slot.
	 *
	 * @author <a href="https://www.revetkn.com">Mark Allen</a>
	 */
	@Immutable
	public static final class KeySlot {
		private final String keyId;
		private final String fixture;
		private final String algorithm;
		private final String issuer;
		private final String use;
		private final List<String> keyOperations;
		private final boolean withCertificate;

		private KeySlot(@Nullable String keyId, @NonNull String fixture, @Nullable String algorithm, @Nullable String issuer, @Nullable String use,
										@Nullable List<@NonNull String> keyOperations, boolean withCertificate) {
			this.keyId = keyId;
			this.fixture = fixture;
			this.algorithm = algorithm;
			this.issuer = issuer;
			this.use = use;
			this.keyOperations = keyOperations;
			this.withCertificate = withCertificate;
		}

		/**
		 * The slot's {@code kid}.
		 *
		 * @return the key ID, or {@code null} for the slot without one
		 */
		public @Nullable String getKeyId() {
			return this.keyId;
		}

		/**
		 * The fixture the slot holds: a file stem under {@code src/test/resources/fixtures/keys/}, or {@code ed25519}
		 * for {@code src/test/resources/fixtures/pem/ed25519-*.pem}.
		 *
		 * @return the fixture name
		 */
		public @NonNull String getFixture() {
			return this.fixture;
		}

		/**
		 * The slot's {@code alg}.
		 *
		 * @return the wire value, or empty
		 */
		public @NonNull Optional<@NonNull String> getAlgorithm() {
			return Optional.ofNullable(this.algorithm);
		}

		/**
		 * The slot's JWK {@code issuer} member.
		 *
		 * @return the issuer, or empty
		 */
		public @NonNull Optional<@NonNull String> getIssuer() {
			return Optional.ofNullable(this.issuer);
		}
	}
}
