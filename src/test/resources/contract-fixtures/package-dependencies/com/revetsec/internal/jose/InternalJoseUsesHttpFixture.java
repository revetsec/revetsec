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

import com.revetsec.internal.http.HttpFixture;

/**
 * Seeded violation: internal.jose holds only pure, I/O-free JOSE code, and the JWKS fetch lives in jose (G8-11), so
 * internal.jose may not use internal.http, although its layer, jose, may.
 */
public final class InternalJoseUsesHttpFixture {
	private InternalJoseUsesHttpFixture() {
	}

	static Class<?> http() {
		return HttpFixture.class;
	}
}
