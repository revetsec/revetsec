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

import javax.annotation.concurrent.NotThreadSafe;
import javax.annotation.concurrent.ThreadSafe;

/**
 * Seeded violation: a verified (R17) type with a public constructor and a builder.
 *
 * @since 1.0.0
 */
@ThreadSafe
public final class Jwt {
	/**
	 * A public constructor, which R17 forbids.
	 *
	 * @since 1.0.0
	 */
	public Jwt() {
	}

	/**
	 * A builder, which R17 forbids.
	 *
	 * @since 1.0.0
	 */
	@NotThreadSafe
	public static final class Builder {
		private Builder() {
		}
	}
}
