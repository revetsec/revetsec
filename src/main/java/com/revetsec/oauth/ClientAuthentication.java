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

import com.revetsec.internal.encoding.EncodingException;
import com.revetsec.internal.encoding.FormUrlEncoding;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

import javax.annotation.concurrent.ThreadSafe;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;
import java.util.Map;
import java.util.function.Supplier;

import static java.util.Objects.requireNonNull;

/**
 * One OAuth client authentication strategy. A supplier is consulted once per outgoing request, supporting a
 * rotating client secret; its result is never placed in a URL, exception or string rendering. Supplier
 * implementations must be thread-safe when the client is shared between threads.
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 * @since 1.0.0
 */
@ThreadSafe
public final class ClientAuthentication {
	private enum Method { NONE, BASIC, POST }
	private static final ClientAuthentication NONE = new ClientAuthentication(Method.NONE, null,
			ClientSecretBasicEncoding.FORM_URLENCODED);
	private final @NonNull Method method;
	private final @Nullable Supplier<@NonNull String> secretSupplier;
	private final @NonNull ClientSecretBasicEncoding encoding;

	private ClientAuthentication(@NonNull Method method, @Nullable Supplier<@NonNull String> secretSupplier,
			@NonNull ClientSecretBasicEncoding encoding) {
		this.method = method;
		this.secretSupplier = secretSupplier;
		this.encoding = encoding;
	}

	/**
	 * Selects no client authentication for a public client.
	 *
	 * @return the shared public-client strategy
	 * @since 1.0.0
	 */
	public static @NonNull ClientAuthentication noneInstance() { return NONE; }

	/**
	 * Selects RFC 6749 client-secret Basic with form encoding.
	 *
	 * @param secret the nonempty secret
	 * @return the strategy
	 * @since 1.0.0
	 */
	public static @NonNull ClientAuthentication fromClientSecretBasic(@NonNull String secret) {
		return fromClientSecretBasic(secret, ClientSecretBasicEncoding.FORM_URLENCODED);
	}

	/**
	 * Selects client-secret Basic with an explicit encoding choice.
	 *
	 * @param secret the nonempty secret
	 * @param encoding the encoding
	 * @return the strategy
	 * @since 1.0.0
	 */
	public static @NonNull ClientAuthentication fromClientSecretBasic(@NonNull String secret,
			@NonNull ClientSecretBasicEncoding encoding) {
		String checked = requireSecret(secret);
		return new ClientAuthentication(Method.BASIC, () -> checked, requireNonNull(encoding));
	}

	/**
	 * Selects client-secret POST with a fixed secret.
	 *
	 * @param secret the nonempty secret
	 * @return the strategy
	 * @since 1.0.0
	 */
	public static @NonNull ClientAuthentication fromClientSecretPost(@NonNull String secret) {
		String checked = requireSecret(secret);
		return new ClientAuthentication(Method.POST, () -> checked, ClientSecretBasicEncoding.FORM_URLENCODED);
	}

	/**
	 * Selects client-secret POST with a supplier called once per request.
	 *
	 * @param secretSupplier the supplier
	 * @return the strategy
	 * @since 1.0.0
	 */
	public static @NonNull ClientAuthentication fromClientSecretPost(
			@NonNull Supplier<@NonNull String> secretSupplier) {
		return new ClientAuthentication(Method.POST, requireNonNull(secretSupplier),
				ClientSecretBasicEncoding.FORM_URLENCODED);
	}

	boolean isPublicClient() { return this.method == Method.NONE; }
	boolean isUnencodedBasic() {
		return this.method == Method.BASIC && this.encoding == ClientSecretBasicEncoding.UNENCODED;
	}

	void apply(String clientId, Map<String, String> headers, Map<String, String> form) {
		if (this.method == Method.NONE) {
			form.put("client_id", clientId);
			return;
		}
		String secret;
		try {
			secret = requireSecret(requireNonNull(this.secretSupplier).get());
		} catch (RuntimeException supplierFailure) {
			throw new IllegalArgumentException("The client secret is unavailable.");
		}
		if (this.method == Method.POST) {
			form.put("client_id", clientId);
			form.put("client_secret", secret);
			return;
		}
		try {
			String idPart = this.encoding == ClientSecretBasicEncoding.FORM_URLENCODED
					? FormUrlEncoding.encode(clientId) : clientId;
			String secretPart = this.encoding == ClientSecretBasicEncoding.FORM_URLENCODED
					? FormUrlEncoding.encode(secret) : secret;
			String credentials = idPart + ":" + secretPart;
			byte[] bytes = credentials.getBytes(StandardCharsets.UTF_8);
			try {
				headers.put("Authorization", "Basic " + Base64.getEncoder().encodeToString(bytes));
			} finally {
				Arrays.fill(bytes, (byte) 0);
			}
		} catch (EncodingException exception) {
			throw new IllegalArgumentException("A client identifier or secret contains invalid text.");
		}
	}

	private static String requireSecret(String value) {
		if (requireNonNull(value).isEmpty())
			throw new IllegalArgumentException("A client secret must not be empty.");
		return value;
	}

	/**
	 * Redacts the strategy and any secret.
	 *
	 * @return a redacted description
	 * @since 1.0.0
	 */
	@Override
	public @NonNull String toString() { return "ClientAuthentication{secret=<redacted>}"; }
}
