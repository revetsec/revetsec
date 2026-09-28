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

package com.revetsec;

/**
 * Seeded violations in the root package, which is exported too: jsr305's CheckReturnValue, whose one element has a
 * default, on a method, and jsr305's GuardedBy on a private field of a private nested class
 * (provided-annotation-with-element, M2-10). A base64url decoder here is raw-base64url-decoder: that rule applies
 * everywhere but internal.encoding.
 */
final class ProvidedAnnotationFixture {
	@javax.annotation.CheckReturnValue
	String value() {
		return "";
	}

	private static final class Holder {
		@javax.annotation.concurrent.GuardedBy("this")
		private int count;
	}

	byte[] decode(String encoded) {
		return java.util.Base64.getUrlDecoder().decode(encoded);
	}
}
