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

import org.jspecify.annotations.NonNull;

import javax.annotation.concurrent.NotThreadSafe;

/**
 * Seeded violations: a non-sealed abstract subclass reopens its sealed parent's hierarchy to every package, and a
 * protected static method is callable from any subclass there.
 *
 * @since 1.0.0
 */
@NotThreadSafe
public abstract non-sealed class ReopenedFixtureException extends OAuthFixtureException {
	private static final long serialVersionUID = 1L;

	/**
	 * For subclasses in any package, which is the problem.
	 *
	 * @param fixedMessage a fixed message
	 * @since 1.0.0
	 */
	protected ReopenedFixtureException(@NonNull String fixedMessage) {
		super(fixedMessage);
	}

	/**
	 * Seeded violation: a protected static method on an exported exception, which is not listed.
	 *
	 * @param status an HTTP status
	 * @return a fixed message
	 * @since 1.0.0
	 */
	protected static @NonNull String fromLegacyStatus(@NonNull Integer status) {
		return "The token request failed.";
	}
}
