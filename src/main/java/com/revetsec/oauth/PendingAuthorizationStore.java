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

import javax.annotation.concurrent.ThreadSafe;
import java.time.Instant;
import java.util.Optional;

/**
 * Storage for opaque, browser-bound pending authorization records. A shared implementation must make
 * {@link #consume(String, String)} atomic across all participating nodes: a record is returned at most once, even
 * when callbacks race. The browser binding and state are lookup inputs, not an excuse to omit Revetsec's authenticated
 * checks after a record is consumed. A durable shared store is required for client-side single use across nodes or
 * restarts; {@link InMemoryPendingAuthorizationStore} covers one process only.
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 * @since 1.0.0
 */
@ThreadSafe
public interface PendingAuthorizationStore {
	/**
	 * Saves one opaque record until its authenticated expiry. A duplicate live binding and state must be rejected.
	 *
	 * @param browserBinding an application-generated, browser-specific secret
	 * @param state          the authorization state
	 * @param opaqueRecord   a record produced by Revetsec, never interpreted by the store
	 * @param expiresAt      the exact expiry supplied by Revetsec
	 * @since 1.0.0
	 */
	void save(@NonNull String browserBinding, @NonNull String state, @NonNull String opaqueRecord,
			@NonNull Instant expiresAt);

	/**
	 * Atomically removes and returns one matching record. A consumed record is never returned again.
	 *
	 * @param browserBinding the browser-specific binding
	 * @param state          the authorization state
	 * @return the removed record, or empty when absent or expired
	 * @since 1.0.0
	 */
	@NonNull Optional<@NonNull String> consume(@NonNull String browserBinding, @NonNull String state);
}
