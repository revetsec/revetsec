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

import com.revetsec.internal.encoding.StrictUtf8;
import com.revetsec.jose.JwsAlgorithm;
import com.revetsec.internal.Limits;
import com.google.errorprone.annotations.CheckReturnValue;
import java.time.Duration;
import javax.annotation.concurrent.NotThreadSafe;
import java.util.Set;

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
	private enum Method { NONE, BASIC, POST, PRIVATE_KEY_JWT }
	private static final ClientAuthentication NONE = new ClientAuthentication(Method.NONE, null,
			ClientSecretBasicEncoding.FORM_URLENCODED);
	private final @NonNull Method method;
	private final @Nullable Supplier<@NonNull String> secretSupplier;
	private final @NonNull ClientSecretBasicEncoding encoding;
	private final @Nullable ClientAssertionKeyProvider keyProvider;
	private final @NonNull ClientAssertionAudience assertionAudience;
	private final @NonNull Duration assertionLifetime;

	private ClientAuthentication(@NonNull Method method, @Nullable Supplier<@NonNull String> secretSupplier,
			@NonNull ClientSecretBasicEncoding encoding) {
		this.method = method;
		this.secretSupplier = secretSupplier;
		this.encoding = encoding;
		this.keyProvider = null;
		this.assertionAudience = ClientAssertionAudience.ISSUER;
		this.assertionLifetime = Limits.CLIENT_ASSERTION_LIFETIME.getDefaultDuration();
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

	private ClientAuthentication(@NonNull PrivateKeyJwtBuilder builder) {
		this.method = Method.PRIVATE_KEY_JWT;
		this.secretSupplier = null;
		this.encoding = ClientSecretBasicEncoding.FORM_URLENCODED;
		this.keyProvider = builder.keyProvider;
		this.assertionAudience = builder.audience;
		this.assertionLifetime = builder.lifetime;
	}
	/**
	 * Selects generated private-key assertions with the issuer audience and 60-second lifetime.
	 * @param keyProvider thread-safe cooperative key provider
	 * @return the strategy
	 * @since 1.0.0
	 */
	@CheckReturnValue
	public static @NonNull ClientAuthentication fromPrivateKeyJwt(@NonNull ClientAssertionKeyProvider keyProvider) {
		return withPrivateKeyJwt(keyProvider).build();
	}
	/**
	 * Starts private-key assertion configuration without selecting a key or signing.
	 * @param keyProvider thread-safe cooperative key provider
	 * @return the builder
	 * @since 1.0.0
	 */
	@CheckReturnValue
	public static @NonNull PrivateKeyJwtBuilder withPrivateKeyJwt(@NonNull ClientAssertionKeyProvider keyProvider) {
		return new PrivateKeyJwtBuilder(keyProvider);
	}
	boolean isPrivateKeyJwt() { return this.method == Method.PRIVATE_KEY_JWT; }
	@NonNull ClientAssertionKeyProvider keyProvider() { return requireNonNull(this.keyProvider); }
	@NonNull ClientAssertionAudience assertionAudience() { return this.assertionAudience; }
	@NonNull Duration assertionLifetime() { return this.assertionLifetime; }

	/**
	 * Configures assertion audience and lifetime. Building makes no application callback or signing call.
	 * @author <a href="https://www.revetkn.com">Mark Allen</a>
	 * @since 1.0.0
	 */
	@NotThreadSafe @CheckReturnValue
	public static final class PrivateKeyJwtBuilder {
		private final @NonNull ClientAssertionKeyProvider keyProvider;
		private @NonNull ClientAssertionAudience audience = ClientAssertionAudience.ISSUER;
		private @NonNull Duration lifetime = Limits.CLIENT_ASSERTION_LIFETIME.getDefaultDuration();
		private PrivateKeyJwtBuilder(@NonNull ClientAssertionKeyProvider keyProvider) { this.keyProvider = requireNonNull(keyProvider); }
		/**
		 * Selects the sole assertion audience. Endpoint compatibility uses the actual outgoing POST URI.
		 * @param value audience, or null to restore ISSUER
		 * @return this builder
		 * @since 1.0.0
		 */
		public @NonNull PrivateKeyJwtBuilder audience(@Nullable ClientAssertionAudience value) {
			this.audience = value == null ? ClientAssertionAudience.ISSUER : value; return this;
		}
		/**
		 * Replaces assertion lifetime with exact whole seconds in [1, 300].
		 * @param value lifetime, or null to restore 60 seconds
		 * @return this builder
		 * @since 1.0.0
		 */
		public @NonNull PrivateKeyJwtBuilder assertionLifetime(@Nullable Duration value) {
			if (value != null && value.getNano() != 0) throw new IllegalArgumentException("The assertion lifetime must contain exact whole seconds.");
			this.lifetime = value == null ? Limits.CLIENT_ASSERTION_LIFETIME.getDefaultDuration() : Limits.CLIENT_ASSERTION_LIFETIME.require(value);
			return this;
		}
		/**
		 * Builds without key selection or signing.
		 * @return strategy
		 * @since 1.0.0
		 */
		public @NonNull ClientAuthentication build() { return new ClientAuthentication(this); }
		/**
		 * Redacts configured keys and identifiers.
		 * @return redacted description
		 * @since 1.0.0
		 */
		@Override public @NonNull String toString() { return "ClientAuthentication.PrivateKeyJwtBuilder{key=<redacted>}"; }
	}

	@NonNull String methodName() { return switch (this.method) { case NONE -> "none"; case BASIC -> "client_secret_basic"; case POST -> "client_secret_post"; case PRIVATE_KEY_JWT -> "private_key_jwt"; }; }
	boolean isPublicClient() { return this.method == Method.NONE; }
	boolean isUnencodedBasic() {
		return this.method == Method.BASIC && this.encoding == ClientSecretBasicEncoding.UNENCODED;
	}

	void checkHmac(@NonNull Set<@NonNull JwsAlgorithm> algorithms) {
		if (algorithms.isEmpty()) return;
		if (isPublicClient() || isPrivateKeyJwt()) throw new IllegalArgumentException("HMAC ID tokens require confidential client authentication.");
		checkHmacSecret(readSecret(), algorithms);
	}
	private @NonNull String readSecret() {
		try { return requireSecret(requireNonNull(this.secretSupplier).get()); }
		catch (RuntimeException unavailable) { throw new IllegalArgumentException("The client secret is unavailable."); }
	}
	private static void checkHmacSecret(@NonNull String secret, @NonNull Set<@NonNull JwsAlgorithm> algorithms) {
		if (algorithms.isEmpty()) return;
		byte[] bytes;
		try { bytes = StrictUtf8.encode(secret); }
		catch (EncodingException malformed) { throw new IllegalArgumentException("The OIDC client secret contains invalid text."); }
		try {
			for (JwsAlgorithm algorithm : algorithms) {
				int minimum = switch (algorithm) { case HS256 -> 32; case HS384 -> 48; case HS512 -> 64;
					default -> throw new IllegalArgumentException("Only HMAC algorithms use a client secret."); };
				if (bytes.length < minimum) throw new IllegalArgumentException("The OIDC client secret is shorter than an allowed HMAC hash.");
			}
		} finally { Arrays.fill(bytes, (byte) 0); }
	}
	void apply(@NonNull String clientId, @NonNull Map<@NonNull String, @NonNull String> headers, @NonNull Map<@NonNull String, @NonNull String> form) {
		applyForOidc(clientId, headers, form, Set.of());
	}
	@Nullable String applyForOidc(@NonNull String clientId, @NonNull Map<@NonNull String, @NonNull String> headers, @NonNull Map<@NonNull String, @NonNull String> form,
			@NonNull Set<@NonNull JwsAlgorithm> hmacAlgorithms) {
		if (this.method == Method.NONE) {
			form.put("client_id", clientId);
			if (!hmacAlgorithms.isEmpty()) throw new IllegalArgumentException("HMAC ID tokens require confidential client authentication.");
			return null;
		}
		if (isPrivateKeyJwt()) throw new IllegalStateException("Client assertions require endpoint preparation.");
		String secret = readSecret();
		checkHmacSecret(secret, hmacAlgorithms);
		if (this.method == Method.POST) {
			form.put("client_id", clientId);
			form.put("client_secret", secret);
			return secret;
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
		return secret;
	}

	private static @NonNull String requireSecret(@NonNull String value) {
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
