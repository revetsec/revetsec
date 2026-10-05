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

import com.revetsec.oauth.ClientAuthentication;
import com.revetsec.oidc.OidcClient;
import com.revetsec.oidc.OidcIssuerPolicy;
import org.jspecify.annotations.NonNull;
import javax.annotation.concurrent.ThreadSafe;
import java.net.URI;
import java.util.function.Predicate;

/** Trusted startup configuration; tenant policy and application sessions belong to the application. */
@ThreadSafe
public final class EntraLogin {
	private EntraLogin() { }

	/** Use exactly the public-cloud common or organizations v2.0 issuer, never a callback-derived issuer. */
	public static OidcClient.@NonNull Builder withIssuer(@NonNull String configuredIssuer,
			@NonNull String registeredClientId, @NonNull URI registeredCallback,
			@NonNull Predicate<@NonNull String> allowedTenant, @NonNull ClientAuthentication authentication) {
		OidcIssuerPolicy policy = OidcIssuerPolicy.fromMicrosoftEntraMultiTenant(allowedTenant);
		return OidcClient.withIssuer(configuredIssuer).issuerPolicy(policy).clientId(registeredClientId)
				.redirectUri(registeredCallback).clientAuthentication(authentication).requirePkceAdvertised(true);
	}
}
