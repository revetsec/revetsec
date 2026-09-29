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

import javax.annotation.concurrent.ThreadSafe;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;

/** Fixed, nonauthenticating cookie-name suffixes for optional concurrent flows. */
@ThreadSafe
final class OAuthCookieNames {
	private OAuthCookieNames() {
	}

	static String fromState(String state) {
		if (state == null || state.isEmpty())
			throw new IllegalArgumentException("A callback state is required for a per-flow cookie name.");
		try {
			byte[] digest = MessageDigest.getInstance("SHA-256").digest(state.getBytes(StandardCharsets.UTF_8));
			return "__Host-revetsec-oauth-" + HexFormat.of().formatHex(digest, 0, 8);
		} catch (NoSuchAlgorithmException impossible) {
			throw new IllegalStateException("SHA-256 is unavailable.");
		}
	}
}
