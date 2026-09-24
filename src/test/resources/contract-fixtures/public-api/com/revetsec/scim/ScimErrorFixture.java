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

package com.revetsec.scim;

import org.jspecify.annotations.NonNull;

import javax.annotation.concurrent.ThreadSafe;

/**
 * Control: a concrete exported class that must have a subclass (plan 7.8's ScimException), so it is sealed instead of
 * final, and callers create it through a static factory.
 *
 * @since 1.0.0
 */
@ThreadSafe
public sealed class ScimErrorFixture permits ScimFilterErrorFixture {
	ScimErrorFixture() {
	}

	/**
	 * Creates an error.
	 *
	 * @param status an HTTP status
	 * @return the error
	 * @since 1.0.0
	 */
	public static @NonNull ScimErrorFixture fromStatus(@NonNull Integer status) {
		return new ScimErrorFixture();
	}
}
