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

import javax.annotation.concurrent.ThreadSafe;

/**
 * An exported sealed interface, shaped like JsonWebKeySource. Controls: a final exported implementation
 * ({@link StaticKeySourceFixture}), and a package-private record and enum, which are implicitly final. Seeded
 * violations: a package-private non-sealed implementation, and a non-sealed interface behind a sealed one, either of
 * which lets classes outside the permits list implement it (M2-10 item 6).
 *
 * @since 1.0.0
 */
@ThreadSafe
public sealed interface KeySourceFixture permits StaticKeySourceFixture, RecordKeySourceFixture,
		EnumKeySourceFixture, OpenKeySourceFixture, NarrowKeySourceFixture {
}

/**
 * Control: a record is implicitly final.
 */
record RecordKeySourceFixture(String name) implements KeySourceFixture {
}

/**
 * Control: an enum without constant bodies is implicitly final.
 */
enum EnumKeySourceFixture implements KeySourceFixture {
	ONLY
}

/**
 * Non-sealed: any class in the package may extend it.
 */
non-sealed class OpenKeySourceFixture implements KeySourceFixture {
	OpenKeySourceFixture() {
	}
}

/**
 * Sealed, so the walk continues to its permitted subtype.
 */
sealed interface NarrowKeySourceFixture extends KeySourceFixture permits WideKeySourceFixture {
}

/**
 * Non-sealed: any class in the package may implement it.
 */
non-sealed interface WideKeySourceFixture extends NarrowKeySourceFixture {
}
