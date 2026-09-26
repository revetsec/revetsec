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
 * Control: internal.jose may use internal.http. The restriction matches the importing package by name, so
 * internal.jose must be listed in its own right.
 */
public final class InternalJoseUsesHttpFixture {
	private InternalJoseUsesHttpFixture() {
	}

	static Class<?> http() {
		return HttpFixture.class;
	}
}
