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
import com.revetsec.internal.http.HttpExchangeException;

import javax.annotation.concurrent.ThreadSafe;
import java.io.IOException;

/** Maps checked HTTP failures to safe OAuth exceptions. */
@ThreadSafe
final class OAuthHttpErrors {
	private OAuthHttpErrors() { }

	static @NonNull OAuthException fromExchange(@NonNull HttpExchangeException exception) {
		return switch (exception.getKind()) {
			case TIMEOUT -> OAuthTransportException.fromReason(OAuthException.Reason.NETWORK_FAILURE, null);
			case IO -> OAuthTransportException.fromReason(OAuthException.Reason.NETWORK_FAILURE,
					exception.getCause() instanceof IOException io ? io : null);
			case INTERRUPTED -> OAuthTransportException.fromReason(OAuthException.Reason.INTERRUPTED, null);
			case DEFAULT_CLIENT_UNAVAILABLE -> OAuthTransportException.fromReason(
					OAuthException.Reason.HTTP_CLIENT_UNAVAILABLE, null);
			case URI_REJECTED -> OAuthValidationException.fromReason(OAuthException.Reason.METADATA_INVALID);
			case REDIRECT -> OAuthResponseException.fromReason(OAuthException.Reason.REDIRECT_NOT_FOLLOWED);
			case TOO_LARGE -> OAuthResponseException.fromReason(OAuthException.Reason.TOO_LARGE);
			case MEDIA_TYPE -> OAuthResponseException.fromReason(OAuthException.Reason.UNEXPECTED_CONTENT_TYPE);
			case CONTENT_ENCODING, FRAMING ->
					OAuthResponseException.fromReason(OAuthException.Reason.ENDPOINT_RESPONSE_MALFORMED);
		};
	}
}
