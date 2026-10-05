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

package com.revetsec;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.*;
import java.util.*;
import javax.annotation.concurrent.ThreadSafe;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import com.revetsec.jose.JwsAlgorithm;
import com.revetsec.json.JsonObject;
import com.revetsec.internal.json.JsonCodec;
import com.revetsec.internal.json.JsonLimits;
import static org.junit.jupiter.api.Assertions.*;

/** Independent JCA keys and signature oracle; no core test helpers or product signing/verification code. */
@ThreadSafe
public final class M6FuzzOracle {
	public static final @NonNull KeyPair KEY = keyPair();
	public static final @NonNull KeyPair OTHER = keyPair();
	private M6FuzzOracle() { }
	private static @NonNull KeyPair keyPair() {
		try { KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA"); generator.initialize(2048); return generator.generateKeyPair(); }
		catch (GeneralSecurityException failure) { throw new AssertionError(failure); }
	}
	public static int choice(byte @NonNull [] input, int offset, int bound) {
		return (offset < input.length ? Byte.toUnsignedInt(input[offset]) : 0) % bound;
	}
	public static @NonNull JsonObject object(@NonNull String text) throws com.revetsec.internal.json.JsonParseException { return (JsonObject) JsonCodec.parse(text.getBytes(StandardCharsets.UTF_8), JsonLimits.protocolDocument(65536)); }
	public static @NonNull String encode(byte @NonNull [] bytes) { return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes); }
	public static byte @NonNull [] decode(@NonNull String text) { return Base64.getUrlDecoder().decode(text); }
	public static @NonNull Signature engine(@NonNull JwsAlgorithm algorithm) throws GeneralSecurityException {
		Signature signature = Signature.getInstance(algorithm == JwsAlgorithm.PS256 ? "RSASSA-PSS" : algorithm == JwsAlgorithm.RS384 ? "SHA384withRSA" : "SHA256withRSA");
		if (algorithm == JwsAlgorithm.PS256) signature.setParameter(new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1));
		return signature;
	}
	public static void verify(@NonNull String compact, @NonNull PublicKey key, @NonNull JwsAlgorithm algorithm) throws GeneralSecurityException {
		String[] parts = compact.split("\\.", -1); assertEquals(3, parts.length);
		Signature signature = engine(algorithm); signature.initVerify(key);
		signature.update((parts[0] + "." + parts[1]).getBytes(StandardCharsets.US_ASCII));
		assertTrue(signature.verify(decode(parts[2])), "original JCA public key must verify the exact compact bytes");
	}
	public static @NonNull String sign(@NonNull JsonObject claims, @NonNull JwsAlgorithm algorithm, boolean forged) throws GeneralSecurityException {
		String prefix = encode(JsonObject.builder().put("alg", algorithm.getWireValue()).put("kid", "key").build().toJson().getBytes(StandardCharsets.UTF_8)) + "." + encode(claims.toJson().getBytes(StandardCharsets.UTF_8));
		Signature signature = engine(algorithm); signature.initSign((forged ? OTHER : KEY).getPrivate()); signature.update(prefix.getBytes(StandardCharsets.US_ASCII));
		return prefix + "." + encode(signature.sign());
	}
	public static @NonNull String jwks(@Nullable String issuer, @NonNull JwsAlgorithm algorithm) {
		RSAPublicKey key = (RSAPublicKey) KEY.getPublic();
		JsonObject.Builder builder = JsonObject.builder().put("kty", "RSA").put("kid", "key").put("alg", algorithm.getWireValue()).put("n", unsigned(key.getModulus())).put("e", unsigned(key.getPublicExponent()));
		if (issuer != null) builder.put("issuer", issuer);
		return "{\"keys\":[" + builder.build().toJson() + "]}";
	}
	private static @NonNull String unsigned(@NonNull BigInteger number) {
		byte[] bytes = number.toByteArray(); return encode(bytes[0] == 0 ? Arrays.copyOfRange(bytes, 1, bytes.length) : bytes);
	}
}
