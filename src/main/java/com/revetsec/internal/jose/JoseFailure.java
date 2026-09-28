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

import com.revetsec.jose.JoseException;
import org.jspecify.annotations.NonNull;

import javax.annotation.concurrent.NotThreadSafe;

import static java.util.Objects.requireNonNull;

/**
 * Checked failure of the internal JOSE layer: a token or key set document that a check rejected (M1 plan, G6-2).
 * <p>
 * It carries the public {@link JoseException.Reason} that the entry point reports: {@code jose.JwtValidator}
 * translates it into the matching public exception, a key set source reports a document failure as
 * {@code MALFORMED_INPUT}, and later milestones map it into their own exceptions' JOSE reason. The message names only
 * the reason, never the input. It has no cause, suppression is disabled, and it records no stack trace, so nothing
 * about it depends on the input. It never leaves Revetsec.
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 */
@NotThreadSafe
public final class JoseFailure extends Exception {
	private static final long serialVersionUID = 1L;

	/**
	 * Why the input was rejected.
	 */
	private final JoseException.@NonNull Reason reason;

	/**
	 * Creates a failure for {@code reason}.
	 *
	 * @param reason why the input was rejected
	 */
	JoseFailure(JoseException.@NonNull Reason reason) {
		super("A JOSE check failed: " + requireNonNull(reason).name() + ".", null, false, false);
		this.reason = reason;
	}

	/**
	 * Returns why the input was rejected.
	 *
	 * @return the public reason
	 */
	public JoseException.@NonNull Reason getReason() {
		return this.reason;
	}
}
