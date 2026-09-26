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

package com.revetsec.json;

/**
 * Seeded violation: json may not use internal.http, reached here through a fully qualified name.
 */
public final class JsonUsesHttpFixture {
	private JsonUsesHttpFixture() {
	}

	static Object http() {
		return com.revetsec.internal.http.HttpFixture.CONSTANT;
	}
}
