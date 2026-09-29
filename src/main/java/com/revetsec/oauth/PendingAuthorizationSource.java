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

import com.revetsec.StateSealer;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

import javax.annotation.concurrent.Immutable;

import static java.util.Objects.requireNonNull;

/**
 * A browser-bound source for completing one authorization. A sealed form must come from the browser cookie set at
 * begin; a store source uses that browser's binding. Neither variant exposes a state-only completion path.
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 * @since 1.0.0
 */
@Immutable
public final class PendingAuthorizationSource {
	private final @Nullable String sealedForm;
	private final @Nullable StateSealer sealer;
	private final @Nullable String context;
	private final @Nullable PendingAuthorizationStore store;
	private final @Nullable String browserBinding;

	private PendingAuthorizationSource(@Nullable String sealedForm, @Nullable StateSealer sealer,
			@Nullable String context, @Nullable PendingAuthorizationStore store, @Nullable String browserBinding) {
		this.sealedForm = sealedForm;
		this.sealer = sealer;
		this.context = context;
		this.store = store;
		this.browserBinding = browserBinding;
	}

	/**
	 * Uses a sealed pending-authorization cookie under an exact application context.
	 *
	 * @param sealedForm browser cookie value
	 * @param sealer sealing and verification keys
	 * @param context fixed application context
	 * @return the source
	 * @since 1.0.0
	 */
	public static @NonNull PendingAuthorizationSource fromSealedForm(@NonNull String sealedForm,
			@NonNull StateSealer sealer, @NonNull String context) {
		return new PendingAuthorizationSource(requireNonNull(sealedForm), requireNonNull(sealer),
				requireNonNull(context), null, null);
	}

	/**
	 * Uses a store with a browser-specific binding. The store must consume atomically.
	 *
	 * @param store the store
	 * @param browserBinding browser-specific secret
	 * @return the source
	 * @since 1.0.0
	 */
	public static @NonNull PendingAuthorizationSource fromStore(@NonNull PendingAuthorizationStore store,
			@NonNull String browserBinding) {
		if (requireNonNull(browserBinding).isEmpty())
			throw new IllegalArgumentException("A browser binding must not be empty.");
		return new PendingAuthorizationSource(null, null, null, requireNonNull(store), browserBinding);
	}

	@Nullable String sealedForm() { return this.sealedForm; }
	@Nullable StateSealer sealer() { return this.sealer; }
	@Nullable String context() { return this.context; }
	@Nullable PendingAuthorizationStore store() { return this.store; }
	@Nullable String browserBinding() { return this.browserBinding; }

	/**
	 * Redacts the source and its browser binding.
	 *
	 * @return a redacted description
	 * @since 1.0.0
	 */
	@Override
	public @NonNull String toString() { return "PendingAuthorizationSource{secrets=<redacted>}"; }
}
