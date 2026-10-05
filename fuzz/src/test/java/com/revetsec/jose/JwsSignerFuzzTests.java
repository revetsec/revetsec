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

import com.code_intelligence.jazzer.junit.FuzzTest;
import com.revetsec.M6FuzzOracle;
import com.revetsec.json.JsonObject;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.*;
import javax.annotation.concurrent.ThreadSafe;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import static org.junit.jupiter.api.Assertions.*;

/** Bounded signing grammar with independently verified signatures and unchanged payload bytes. */
@ThreadSafe
public class JwsSignerFuzzTests {
	/** Control bytes select algorithms, invalid grammar, pair mismatch and exhausted budgets; tail supplies data. */
	@FuzzTest(maxDuration = "5m")
	public void signingMatchesIndependentGrammarAndSignature(byte @NonNull [] input) throws Exception {
		JwsAlgorithm algorithm = List.of(JwsAlgorithm.PS256, JwsAlgorithm.RS256, JwsAlgorithm.RS384).get(M6FuzzOracle.choice(input, 0, 3));
		int typeCase = M6FuzzOracle.choice(input, 1, 5), kidCase = M6FuzzOracle.choice(input, 2, 5), digestCase = M6FuzzOracle.choice(input, 3, 4), payloadCase = M6FuzzOracle.choice(input, 4, 10);
		boolean mismatch = M6FuzzOracle.choice(input, 5, 2) == 1, exhausted = M6FuzzOracle.choice(input, 6, 2) == 1;
		String type = List.of("JWT", "client-authentication+jwt", "at+jwt", "jwt", "JWT\n").get(typeCase);
		@Nullable String kid = switch (kidCase) { case 0 -> null; case 1 -> "key"; case 2 -> ""; case 3 -> "k".repeat(257); default -> "\uD800"; };
		byte @Nullable [] digest = digestCase == 0 ? null : new byte[digestCase == 1 ? 32 : digestCase == 2 ? 31 : 33];
		String value = new String(Arrays.copyOfRange(input, Math.min(7, input.length), Math.min(2055, input.length)), StandardCharsets.ISO_8859_1);
		String payload = switch (payloadCase) {
			case 0 -> "{}";
			case 1 -> " \n{\"data\":" + JsonObject.builder().put("v", value).build().toJson().substring(5) + " \t";
			case 2 -> "{\"a\":1,\"a\":2}";
			case 3 -> "[]"; case 4 -> "{\"x\":NaN}"; case 5 -> "{\"x\":1}junk";
			case 6 -> "{\"x\":\"\\uD800\"}"; case 7 -> "{\"x\":\"" + "x".repeat(32760) + "\"}";
			case 8 -> "{\"x\":\"" + "x".repeat(32761) + "\"}";
			default -> "{\"x\":1,}";
		};
		byte[] bytes = payload.getBytes(StandardCharsets.UTF_8), original = bytes.clone();
		boolean grammar = typeCase < 3 && kidCase < 2 && digestCase < 2 && (payloadCase == 0 || payloadCase == 1 || payloadCase == 7);
		JwsSigner signer = JwsSigner.fromRsaKeyPair(M6FuzzOracle.KEY.getPrivate(), (mismatch ? M6FuzzOracle.OTHER : M6FuzzOracle.KEY).getPublic(), algorithm);
		try {
			String compact = signer.toCompactSerialization(type, kid, digest, bytes, exhausted ? Duration.ZERO : Duration.ofSeconds(10));
			assertTrue(grammar && !mismatch && !exhausted, "invalid grammar, key pairs or budgets cannot sign");
			M6FuzzOracle.verify(compact, M6FuzzOracle.KEY.getPublic(), algorithm);
			String[] parts = compact.split("\\.", -1); assertArrayEquals(original, M6FuzzOracle.decode(parts[1]));
			assertTrue(M6FuzzOracle.decode(parts[0]).length <= 4096); assertTrue(compact.length() <= 65536);
			JsonObject header = M6FuzzOracle.object(new String(M6FuzzOracle.decode(parts[0]), StandardCharsets.UTF_8));
			assertEquals(type, header.findString("typ").orElseThrow()); assertEquals(algorithm.getWireValue(), header.findString("alg").orElseThrow());
			assertEquals(Optional.ofNullable(kid), header.findString("kid"));
			assertEquals(digest == null ? Optional.empty() : Optional.of(M6FuzzOracle.encode(digest)), header.findString("x5t#S256"));
		} catch (IllegalArgumentException rejected) { assertFalse(grammar); }
		catch (JwsSigningException rejected) {
			assertTrue(!grammar || mismatch || exhausted); assertNull(rejected.getCause());
			if (grammar && !exhausted) assertEquals(JwsSigningException.Reason.KEY_PAIR_MISMATCH, rejected.getReason());
		}
		assertArrayEquals(original, bytes, "signing must not alter caller payload bytes");
	}
}
