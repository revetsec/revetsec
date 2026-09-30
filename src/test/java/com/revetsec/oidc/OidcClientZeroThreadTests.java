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

import com.revetsec.oauth.ClientAuthentication;
import com.revetsec.jose.JwsAlgorithm;

import com.revetsec.testing.ChildJvm;
import org.junit.jupiter.api.Test;

import java.lang.management.ManagementFactory;
import java.lang.management.ThreadMXBean;
import java.net.URI;
import java.time.Duration;

import static org.junit.jupiter.api.Assertions.assertEquals;

final class OidcClientZeroThreadTests {
	@Test
	void thousandOidcClientBuildsWithLazyRemoteKeysStartNoThread() throws Exception {
		ChildJvm.Result result = ChildJvm.withMainClass(BuildChild.class)
				.timeout(Duration.ofSeconds(60)).build().run();
		assertEquals(0, result.getExitCode(), result::toString);
		assertEquals("built 2000 OIDC clients; threads started: 0",
				result.getStandardOutput().strip(), result::toString);
	}

	public static final class BuildChild {
		private BuildChild() { }

		public static void main(String[] arguments) {
			OidcProviderMetadata metadata = OidcProviderMetadata.withIssuer("https://issuer.example")
					.authorizationEndpoint(URI.create("https://issuer.example/authorize"))
					.tokenEndpoint(URI.create("https://issuer.example/token"))
					.jwksUri(URI.create("https://issuer.example/jwks"))
					.userInfoEndpoint(URI.create("https://issuer.example/userinfo"))
					.build();
			ThreadMXBean threads = ManagementFactory.getThreadMXBean();
			long before = threads.getTotalStartedThreadCount();
			for (int index = 0; index < 1_000; index++) {
				OidcClient.withProviderMetadata(metadata)
						.clientId("service-" + index)
						.redirectUri(URI.create("https://rp.example/callback"))
						.clientAuthentication(ClientAuthentication.fromClientSecretBasic("test-secret"))
						.userInfoSignedResponseAlgorithm(index % 2 == 0 ? JwsAlgorithm.RS256 : null)
						.build();
				OidcClient.withIssuer("https://issuer.example/tenant/")
						.clientId("lazy-" + index).redirectUri(URI.create("https://rp.example/callback"))
						.userInfoSignedResponseAlgorithm(index % 2 == 0 ? JwsAlgorithm.RS256 : null).build();
			}
			System.out.println("built 2000 OIDC clients; threads started: "
					+ (threads.getTotalStartedThreadCount() - before));
		}
	}
}
