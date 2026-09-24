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

import com.revetsec.internal.jose.InternalBaseFixture;
import com.revetsec.internal.jose.InternalJoseFixture;

/**
 * A package-private class between an exported type and an internal one. Its public method returns an internal type
 * and is callable through the exported {@link JoseApiFixture}.
 */
abstract class JoseBaseFixture extends InternalBaseFixture {
	JoseBaseFixture() {
	}

	public InternalJoseFixture helper() {
		return new InternalJoseFixture();
	}
}
