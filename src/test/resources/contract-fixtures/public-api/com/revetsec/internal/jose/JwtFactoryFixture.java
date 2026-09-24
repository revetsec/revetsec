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

package com.revetsec.internal.jose;

import com.revetsec.jose.Jwt;
import com.revetsec.oidc.ForgedIdToken;

import java.util.Optional;

/**
 * Seeded violations: public static factories for verified types, in an internal package, returning one directly,
 * as a type argument, through a type-variable bound, and as a subtype.
 */
public final class JwtFactoryFixture {
	private JwtFactoryFixture() {
	}

	public static Jwt fromCompactSerialization(String compactSerialization) {
		return new Jwt();
	}

	public static Optional<Jwt> tryParse(String compactSerialization) {
		return Optional.of(new Jwt());
	}

	public static <T extends Jwt> T forge() {
		throw new UnsupportedOperationException();
	}

	public static ForgedIdToken forgedIdToken() {
		return new ForgedIdToken();
	}
}
