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

import org.junit.jupiter.api.Test;

import java.net.URI;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

final class OAuthClientRuntimeFloorTests {
	@Test
	void vulnerableRuntimesRefuseBuildWithoutAcknowledgment() {
		// Runtime.Version.parse canonicalizes the 18.0.0 release as "18".
		for (String version : List.of("17.0.2", "18"))
			assertThrows(IllegalStateException.class, () -> builder().build(Runtime.Version.parse(version)));
	}

	@Test
	void acknowledgmentIsObservedWithOnlyRuntimeVersion() {
		List<String> observed = new ArrayList<>();
		OAuthObserver observer = new OAuthObserver() {
			@Override public void didUseUnpatchedRuntime(String runtimeVersion) {
				observed.add(runtimeVersion);
			}
		};
		assertNotNull(builder().observer(observer).acknowledgeUnpatchedRuntime(true).build(Runtime.Version.parse("17.0.2")));
		assertNotNull(builder().observer(observer).acknowledgeUnpatchedRuntime(true).build(Runtime.Version.parse("18")));
		assertEquals(List.of("17.0.2", "18"), observed);
	}

	@Test
	void acknowledgmentNullResetRestoresRuntimeRefusal() {
		assertThrows(IllegalStateException.class, () -> builder().acknowledgeUnpatchedRuntime(true)
				.acknowledgeUnpatchedRuntime(null).build(Runtime.Version.parse("17.0.2")));
	}

	private static OAuthClient.Builder builder() {
		AuthorizationServerMetadata metadata = AuthorizationServerMetadata.withIssuer("https://issuer.example")
				.authorizationEndpoint(URI.create("https://issuer.example/authorize"))
				.tokenEndpoint(URI.create("https://issuer.example/token"))
				.build();
		return OAuthClient.withAuthorizationServerMetadata(metadata).clientId("client")
				.clientAuthentication(ClientAuthentication.noneInstance());
	}
}
