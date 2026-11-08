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
package example.rsa;

import com.revetsec.jose.JwsAlgorithm;
import com.revetsec.jose.JwsSigner;
import com.revetsec.jose.PublishedJwk;
import com.revetsec.jose.JwksPublisher;
import com.revetsec.oauth.AuthorizationServerMetadata;
import com.revetsec.oauth.ClientAssertionKeyProvider;
import com.revetsec.oauth.ClientAssertionSigningKey;
import com.revetsec.oauth.ClientAuthentication;
import com.revetsec.oauth.OAuthClient;
import org.jspecify.annotations.NonNull;
import javax.annotation.concurrent.ThreadSafe;
import java.security.KeyPair;
import java.util.List;
import java.util.Objects;

/** Application configuration using keys already provisioned and registered by the application. */
@ThreadSafe
public final class PrivateKeyClients {
	private PrivateKeyClients() { }

	/** Fixed-key example. Register the public projection and this identifier at the provider first. */
	public static @NonNull ClientAssertionKeyProvider registeredKey(@NonNull KeyPair keys,
			@NonNull JwsAlgorithm algorithm, @NonNull String registeredKeyId) {
		return provider(signer(keys, algorithm), registeredKeyId);
	}

	/** A matching immutable signing/publication snapshot; registration and HTTP hosting remain application-owned.
	 * Public JWKS serialization and ETag hashing occur here; private key material stays opaque.
	 * Generic RSA publication excludes typed/restricted PSS containers even when sign-only use is supported. */
	public static @NonNull Registration registration(@NonNull KeyPair keys,
			@NonNull JwsAlgorithm algorithm, @NonNull String registeredKeyId) {
		JwsSigner signer = signer(keys, algorithm);
		ClientAssertionKeyProvider provider = provider(signer, registeredKeyId);
		PublishedJwk publicKey = PublishedJwk.withPublicKey(signer.getPublicKey())
				.algorithm(signer.getAlgorithm()).keyId(registeredKeyId).build();
		return new Registration(provider, JwksPublisher.fromKeys(List.of(publicKey)));
	}

	private static @NonNull JwsSigner signer(@NonNull KeyPair keys, @NonNull JwsAlgorithm algorithm) {
		Objects.requireNonNull(keys); Objects.requireNonNull(algorithm);
		return switch (algorithm) {
			case RS256, RS384, RS512, PS256, PS384, PS512 ->
					JwsSigner.fromRsaKeyPair(keys.getPrivate(), keys.getPublic(), algorithm);
			case ES256, ES384 -> JwsSigner.fromEcKeyPair(keys.getPrivate(), keys.getPublic(), algorithm);
			case ED25519 -> JwsSigner.fromEd25519KeyPair(keys.getPrivate(), keys.getPublic());
			default -> throw new IllegalArgumentException("Unsupported registered client signing algorithm");
		};
	}

	private static @NonNull ClientAssertionKeyProvider provider(@NonNull JwsSigner signer,
			@NonNull String registeredKeyId) {
		return ClientAssertionKeyProvider.fromKey(ClientAssertionSigningKey.withSigner(signer)
				.keyId(Objects.requireNonNull(registeredKeyId)).build());
	}

	/** Matching registered identifier, signing-key snapshot and public JWKS response producer. */
	@ThreadSafe
	public static final class Registration {
		private final @NonNull ClientAssertionKeyProvider keys;
		private final @NonNull JwksPublisher publicKeys;
		private Registration(@NonNull ClientAssertionKeyProvider keys, @NonNull JwksPublisher publicKeys) {
			this.keys = keys; this.publicKeys = publicKeys;
		}
		/** Returns the exact immutable signing-key provider for this registration. */
		public @NonNull ClientAssertionKeyProvider getKeyProvider() { return this.keys; }
		/** Returns the matching public-only response publisher; host it at an application-approved endpoint. */
		public @NonNull JwksPublisher getJwksPublisher() { return this.publicKeys; }
		@Override public @NonNull String toString() { return "PrivateKeyClients.Registration{<redacted>}"; }
	}

	/** Issuer audience is the default; metadata must describe each actual role's registration. */
	public static OAuthClient.@NonNull Builder withMetadata(@NonNull AuthorizationServerMetadata metadata,
			@NonNull String clientId, @NonNull ClientAssertionKeyProvider keys) {
		return OAuthClient.withAuthorizationServerMetadata(metadata).clientId(clientId)
				.clientAuthentication(ClientAuthentication.fromPrivateKeyJwt(keys));
	}
}
