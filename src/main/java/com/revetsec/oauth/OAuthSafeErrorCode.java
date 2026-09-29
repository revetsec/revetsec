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

package com.revetsec.oauth;

import org.jspecify.annotations.Nullable;

import javax.annotation.concurrent.ThreadSafe;

/** A bounded OAuth error code. Never retains response prose or untrusted control characters. */
@ThreadSafe
final class OAuthSafeErrorCode {
	private OAuthSafeErrorCode() {
	}

	@Nullable
	static String fromValue(String value) {
		if (value == null || value.isEmpty() || value.length() > 64)
			return null;
		for (int i = 0; i < value.length(); i++) {
			char c = value.charAt(i);
			if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_'))
				return null;
		}
		return value;
	}
}
