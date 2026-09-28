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

import com.revetsec.testing.TestJsonWebKeys;
import com.revetsec.testing.TestJsonWebKeys.Fixture;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.util.List;

/**
 * {@link StaticJsonWebKeySource}: a fixed key set with at least one usable key (plan "Public types"), whose parsed
 * keys are the ones key selection sees.
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 */
final class StaticJsonWebKeySourceTests {
	// A source holds exactly its key set, and selection sees the same keys in the same order.
	@Test
	void aSourceHoldsItsKeySetAndItsParsedKeys() {
		JsonWebKeySet keySet = JsonWebKeySet.fromJson(TestJsonWebKeys.keySet(List.of(
				TestJsonWebKeys.withFixture(Fixture.IDP_SIGNING_RSA_2048).kid("a").toJson(),
				TestJsonWebKeys.withFixture(Fixture.IDP_SIGNING_EC_P256).kid("b").toJson())));
		StaticJsonWebKeySource source = StaticJsonWebKeySource.fromJsonWebKeySet(keySet);

		Assertions.assertSame(keySet, source.getJsonWebKeySet());
		Assertions.assertEquals(2, source.verificationKeys().size());
		Assertions.assertSame(keySet.getKeys().get(1).verificationKey(), source.verificationKeys().get(1));
		Assertions.assertNotEquals(source, StaticJsonWebKeySource.fromJsonWebKeySet(keySet),
				"sources compare by reference");
		Assertions.assertTrue(source.toString().startsWith("StaticJsonWebKeySource{jsonWebKeySet=JsonWebKeySet{"));
	}

	// A source that could verify nothing is a configuration error, whether the set is empty or every key was skipped.
	@Test
	@SuppressWarnings("NullAway")
	void aKeySetWithNoUsableKeyIsRefused() {
		for (String document : List.of("{\"keys\":[]}", TestJsonWebKeys.keySet(List.of(TestJsonWebKeys.octWithK("AQAB")
				.toJson(), TestJsonWebKeys.withFixture(Fixture.NEGATIVE_RSA_1024).toJson())))) {
			JsonWebKeySet keySet = JsonWebKeySet.fromJson(document);
			Assertions.assertThrows(IllegalArgumentException.class, () -> StaticJsonWebKeySource.fromJsonWebKeySet(keySet));
		}
		Assertions.assertThrows(NullPointerException.class, () -> StaticJsonWebKeySource.fromJsonWebKeySet(null));
	}
}
