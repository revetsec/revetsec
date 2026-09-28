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

import static java.util.Base64.getUrlDecoder;

/**
 * Seeded violations: the JDK's base64url decoder outside internal.encoding (raw-base64url-decoder, INV-J7), called
 * through the class, through a static import (the import line itself names it without calling it) and through a
 * method reference. The encoder and the standard decoder in controls() are not reported.
 */
final class SegmentDecoderFixture {
	byte[] seeded(String segment) {
		byte[] decoded = java.util.Base64.getUrlDecoder().decode(segment);
		decoded = getUrlDecoder().decode(segment);
		java.util.function.Supplier<java.util.Base64.Decoder> decoders = java.util.Base64::getUrlDecoder;
		return decoders.get().decode(decoded);
	}

	String controls(byte[] value) {
		return java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(value)
				+ java.util.Base64.getDecoder().decode("QQ==").length;
	}
}
