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

package com.revetsec.oidc;

import org.jspecify.annotations.NonNull;
import javax.annotation.concurrent.Immutable;
import static java.util.Objects.requireNonNull;

/**
 * Structure-only restoration of a logout credential from trusted or typed sealed storage. A parsed hint creates
 * no authenticated identity. Invalid stored forms release no credential or value-dependent details.
 * Future releases may add variants; consuming switches should include a rejecting default branch.
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 * @since 1.0.0
 */
@Immutable
public abstract sealed class OidcLogoutHintParseResult permits OidcLogoutHintParseResult.Parsed, OidcLogoutHintParseResult.Rejected {
	private OidcLogoutHintParseResult() { }
	static @NonNull OidcLogoutHintParseResult fromHint(@NonNull OidcLogoutHint hint) { return new Parsed(requireNonNull(hint)); }
	static @NonNull OidcLogoutHintParseResult fromRejection() { return new Rejected(); }
	/** Redacts the credential.
	 * @return redacted description
	 * @since 1.0.0
	 */
	@Override public final @NonNull String toString() { return "OidcLogoutHintParseResult{credential=<redacted>}"; }
	/**
	 * A structurally consistent hint, not an authentication proof.
	 * @author <a href="https://www.revetkn.com">Mark Allen</a>
	 * @since 1.0.0
	 */
	@Immutable
	public static final class Parsed extends OidcLogoutHintParseResult {
		private final @NonNull OidcLogoutHint hint;
		private Parsed(@NonNull OidcLogoutHint hint) { this.hint = hint; }
		/** Returns the restored credential for explicit logout preparation.
		 * @return hint, not authenticated identity
		 * @since 1.0.0
		 */
		public @NonNull OidcLogoutHint getHint() { return this.hint; }
	}
	/**
	 * A stored form could not be opened or structurally restored. No credential is released.
	 * @author <a href="https://www.revetkn.com">Mark Allen</a>
	 * @since 1.0.0
	 */
	@Immutable
	public static final class Rejected extends OidcLogoutHintParseResult { private Rejected() { } }
}
