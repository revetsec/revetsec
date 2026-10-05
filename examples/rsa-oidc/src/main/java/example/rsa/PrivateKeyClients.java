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
import com.revetsec.oauth.AuthorizationServerMetadata;
import com.revetsec.oauth.ClientAssertionKeyProvider;
import com.revetsec.oauth.ClientAssertionSigningKey;
import com.revetsec.oauth.ClientAuthentication;
import com.revetsec.oauth.OAuthClient;
import org.jspecify.annotations.NonNull;
import javax.annotation.concurrent.ThreadSafe;
import java.security.KeyPair;

/** Application configuration using keys already provisioned and registered by the application. */
@ThreadSafe
public final class PrivateKeyClients {
	private PrivateKeyClients() { }

	/** Fixed-key example. Register the public projection and this identifier at the provider first. */
	public static @NonNull ClientAssertionKeyProvider registeredKey(@NonNull KeyPair keys,
			@NonNull JwsAlgorithm algorithm, @NonNull String registeredKeyId) {
		JwsSigner signer = JwsSigner.fromRsaKeyPair(keys.getPrivate(), keys.getPublic(), algorithm);
		return ClientAssertionKeyProvider.fromKey(ClientAssertionSigningKey.withSigner(signer)
				.keyId(registeredKeyId).build());
	}

	/** Issuer audience is the default; metadata must describe each actual role's registration. */
	public static OAuthClient.@NonNull Builder withMetadata(@NonNull AuthorizationServerMetadata metadata,
			@NonNull String clientId, @NonNull ClientAssertionKeyProvider keys) {
		return OAuthClient.withAuthorizationServerMetadata(metadata).clientId(clientId)
				.clientAuthentication(ClientAuthentication.fromPrivateKeyJwt(keys));
	}
}
