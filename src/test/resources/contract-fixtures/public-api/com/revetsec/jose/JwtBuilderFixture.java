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

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

import javax.annotation.concurrent.NotThreadSafe;

/**
 * Seeded violations: a top-level builder whose instance method returns a verified type, and a public field that
 * holds one.
 *
 * @since 1.0.0
 */
@NotThreadSafe
public final class JwtBuilderFixture {
	/**
	 * A ready-made "verified" token.
	 *
	 * @since 1.0.0
	 */
	public static final @Nullable Jwt TEMPLATE = null;

	private JwtBuilderFixture() {
	}

	/**
	 * Starts a builder.
	 *
	 * @return a builder
	 * @since 1.0.0
	 */
	public static @NonNull JwtBuilderFixture builder() {
		return new JwtBuilderFixture();
	}

	/**
	 * Builds a "verified" token without verifying anything.
	 *
	 * @return never
	 * @since 1.0.0
	 */
	public @NonNull Jwt build() {
		throw new UnsupportedOperationException();
	}
}
