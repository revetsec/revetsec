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

import javax.annotation.concurrent.Immutable;

/**
 * The broad kind of failure a {@link RevetsecException} reports.
 * <p>
 * Every {@code RevetsecException} has exactly one category. The documented category, reason, cause and response status
 * determine its fixed temporary condition classification (see {@link RevetsecException#isTemporaryCondition()}).
 * Only {@link #TRANSPORT} and {@link #REMOTE_ERROR} failures may be marked temporary; no category establishes
 * whether earlier work had effects or is safe to replay.
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 * @since 1.0.0
 */
@Immutable
public enum ErrorCategory {
	/**
	 * The input could not be parsed, or it exceeded a configured limit: bad syntax, bad encoding, an oversized
	 * document or an unexpected structure. Never transient.
	 */
	MALFORMED_INPUT,
	/**
	 * The input was well formed but failed a security or protocol check, such as a signature, issuer, audience,
	 * lifetime or state check. Never transient.
	 */
	VALIDATION_FAILURE,
	/**
	 * The remote party answered with an error, such as an HTTP error status or a protocol error response. Transient
	 * only for HTTP 429 or 5xx, or OAuth {@code error=temporarily_unavailable}.
	 */
	REMOTE_ERROR,
	/**
	 * An external exchange or admitted operation did not yield ordinary successful output. Selected timeout, I/O
	 * and held-back-request conditions may be marked temporary. Interrupted threads and documented fixed commit
	 * outcome reasons retain their false classification; the category alone is no effect or replay verdict.
	 */
	TRANSPORT,
	/**
	 * Revetsec's configuration or runtime environment prevents the operation, in a way that could be discovered only
	 * at runtime, such as remote metadata that is incompatible with the configuration, or a default HTTP client that
	 * could not be started in this JVM. Never transient.
	 */
	CONFIGURATION,
	/**
	 * The input uses a feature that Revetsec does not support. Never transient.
	 */
	UNSUPPORTED
}
