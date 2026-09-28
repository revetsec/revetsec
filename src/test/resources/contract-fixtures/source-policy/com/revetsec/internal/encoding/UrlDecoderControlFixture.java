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

package com.revetsec.internal.encoding;

/**
 * Control: internal.encoding is where Base64Url wraps the JDK's base64url decoder in its canonical checks, so
 * raw-base64url-decoder does not apply here.
 */
final class UrlDecoderControlFixture {
	private static final java.util.Base64.Decoder DECODER = java.util.Base64.getUrlDecoder();

	byte[] controls(String encoded) {
		return DECODER.decode(encoded);
	}
}
