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

import com.revetsec.jose.JsonWebKeySkipReason;
import org.jspecify.annotations.NonNull;

import javax.annotation.concurrent.NotThreadSafe;

import static java.util.Objects.requireNonNull;

/**
 * Checked refusal of one JWK by {@link JwkParser}: the key is skipped with a {@link JsonWebKeySkipReason}, and the
 * rest of its key set is still used (RFC 7517 section 5).
 * <p>
 * The message names only the reason, never the key. It has no cause, suppression is disabled, and it records no
 * stack trace. It never leaves Revetsec.
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 */
@NotThreadSafe
public final class SkippedKeyException extends Exception {
	private static final long serialVersionUID = 1L;

	/**
	 * Why the key is skipped.
	 */
	@NonNull
	private final JsonWebKeySkipReason reason;

	/**
	 * Creates a refusal for {@code reason}.
	 *
	 * @param reason why the key is skipped
	 */
	SkippedKeyException(@NonNull JsonWebKeySkipReason reason) {
		super("A JSON Web Key was skipped: " + requireNonNull(reason).name() + ".", null, false, false);
		this.reason = reason;
	}

	/**
	 * Returns why the key is skipped.
	 *
	 * @return the skip reason
	 */
	@NonNull
	public JsonWebKeySkipReason getReason() {
		return this.reason;
	}
}
