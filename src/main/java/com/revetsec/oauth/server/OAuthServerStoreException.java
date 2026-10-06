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

package com.revetsec.oauth.server;

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import com.google.errorprone.annotations.CheckReturnValue;
import javax.annotation.concurrent.Immutable;
import java.util.Optional;
import static java.util.Objects.requireNonNull;
import javax.annotation.concurrent.NotThreadSafe;

/** A fixed store failure in issuer processing; construction is restricted to Revetsec.
 * @since 1.0.0
 */
@NotThreadSafe
public final class OAuthServerStoreException extends OAuthServerException {
	private static final long serialVersionUID=1L;
	private OAuthServerStoreException(@NonNull Reason reason, boolean knownTransientFailure) { super(reason,knownTransientFailure && reason==Reason.STORE_UNAVAILABLE && !Thread.currentThread().isInterrupted()); }
	static @NonNull OAuthServerStoreException fromReason(@NonNull Reason reason, boolean knownTransientFailure) {
		requireNonNull(reason).requireKind(Kind.STORE); return new OAuthServerStoreException(reason,knownTransientFailure);
	}
}
