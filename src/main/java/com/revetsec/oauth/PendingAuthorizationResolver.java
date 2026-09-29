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

import com.revetsec.internal.crypto.SealedStateAccess;
import com.revetsec.internal.crypto.SealedStateType;
import com.revetsec.internal.crypto.UnsealException;
import com.revetsec.internal.crypto.ConstantTime;
import org.jspecify.annotations.NonNull;

import javax.annotation.concurrent.ThreadSafe;
import java.time.Clock;
import java.util.Optional;

import static java.util.Objects.requireNonNull;

/** Opens a pending source and checks browser binding and state before any AS I/O. */
@ThreadSafe
final class PendingAuthorizationResolver {
	private PendingAuthorizationResolver() {
	}

	static PendingAuthorization resolve(@NonNull PendingAuthorizationSource source, @NonNull String callbackState,
			@NonNull Clock clock) {
		requireNonNull(source);
		requireNonNull(callbackState);
		requireNonNull(clock);
		if (callbackState.isEmpty())
			throw OAuthValidationException.fromReason(OAuthException.Reason.STATE_MISMATCH);
		String encoded;
		if (source.store() != null) {
			Optional<String> consumed = source.store().consume(requireNonNull(source.browserBinding()), callbackState);
			if (consumed.isEmpty())
				throw OAuthValidationException.fromReason(OAuthException.Reason.PENDING_AUTHORIZATION_NOT_FOUND);
			encoded = consumed.get();
		} else {
			try {
				encoded = SealedStateAccess.get().unseal(requireNonNull(source.sealer()),
						SealedStateType.PENDING_AUTHORIZATION, requireNonNull(source.sealedForm()),
						requireNonNull(source.context()), clock);
			} catch (UnsealException exception) {
				throw OAuthValidationException.fromReason(exception.getKind() == UnsealException.Kind.EXPIRED
						? OAuthException.Reason.PENDING_AUTHORIZATION_EXPIRED
						: OAuthException.Reason.PENDING_AUTHORIZATION_INVALID);
			}
		}
		PendingAuthorizationCodec.Decoded decoded = PendingAuthorizationCodec.decode(encoded);
		if (source.store() != null) {
			String digest = decoded.bindingDigest();
			if (digest == null || !ConstantTime.isEqual(digest,
					PendingAuthorizationCodec.bindingDigest(requireNonNull(source.browserBinding()))))
				throw OAuthValidationException.fromReason(OAuthException.Reason.BROWSER_BINDING_MISMATCH);
		} else if (decoded.bindingDigest() != null) {
			throw OAuthValidationException.fromReason(OAuthException.Reason.PENDING_AUTHORIZATION_INVALID);
		}
		PendingAuthorization pending = decoded.pending();
		if (!ConstantTime.isEqual(pending.state(), callbackState))
			throw OAuthValidationException.fromReason(OAuthException.Reason.STATE_MISMATCH);
		if (!clock.instant().isBefore(pending.getExpiresAt()))
			throw OAuthValidationException.fromReason(OAuthException.Reason.PENDING_AUTHORIZATION_EXPIRED);
		return pending;
	}
}
