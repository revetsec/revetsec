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

import com.revetsec.OutboundUriPolicy;
import com.revetsec.testing.TestHttpsServer;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

final class AuthorizationServerMetadataTests {
	private static final String ISSUER = "https://issuer.example/tenant";
	private static final String JSON = "{" +
			"\"issuer\":\"https://issuer.example/tenant\"," +
			"\"authorization_endpoint\":\"https://issuer.example/auth\"," +
			"\"token_endpoint\":\"https://issuer.example/token\"," +
			"\"revocation_endpoint\":\"https://issuer.example/revoke\"," +
			"\"code_challenge_methods_supported\":[\"S256\"]," +
			"\"authorization_response_iss_parameter_supported\":true}";

	@Test
	void remoteMetadataHasTypedFieldsAndExactIssuer() {
		AuthorizationServerMetadata metadata = AuthorizationServerMetadata.fromJson(ISSUER, JSON);
		assertEquals(ISSUER, metadata.getIssuer());
		assertEquals(URI.create("https://issuer.example/token"), metadata.getTokenEndpoint());
		assertEquals(URI.create("https://issuer.example/revoke"), metadata.getRevocationEndpoint().orElseThrow());
		assertEquals(Set.of("S256"), metadata.getCodeChallengeMethodsSupported().orElseThrow());
		assertTrue(metadata.isAuthorizationResponseIssuerSupported());
		assertTrue(metadata.isRemotelyDiscovered());
		assertEquals(OAuthException.Reason.ISSUER_MISMATCH,
				assertThrows(OAuthValidationException.class,
						() -> AuthorizationServerMetadata.fromJson(ISSUER + "/", JSON)).getReason());
	}

	@Test
	void malformedKnownFieldsDoNotBecomeAbsent() {
		for (String malformed : new String[] {
				JSON.replace("\"S256\"", "13"),
				JSON.replace("true", "\"true\""),
				JSON.replace("\"issuer\":\"" + ISSUER + "\"", "\"issuer\":7"),
				JSON.replace("\"token_endpoint\":\"https://issuer.example/token\"", "\"token_endpoint\":null"),
				JSON.replace("\"token_endpoint\":\"https://issuer.example/token\"",
						"\"token_endpoint\":\"https://issuer.example/token\","
								+ "\"token_endpoint\":\"https://issuer.example/other\""),
				JSON.replace("\"issuer\"", "\"issuer\":\"other\",\"issuer\"")
		})
			assertThrows(OAuthResponseException.class, () -> AuthorizationServerMetadata.fromJson(ISSUER, malformed));
	}

	@Test
	void unsafeEndpointInRemoteMetadataCannotBuildAClient() {
		AuthorizationServerMetadata unsafe = AuthorizationServerMetadata.fromJson(ISSUER,
				JSON.replace("https://issuer.example/token", "http://issuer.example/token"));
		assertThrows(IllegalArgumentException.class, () -> OAuthClient.withAuthorizationServerMetadata(unsafe)
				.clientId("client").clientAuthentication(ClientAuthentication.noneInstance()).build());
	}

	@Test
	void publicAddressPolicyRejectsMetadataDerivedLoopbackTokenEndpointBeforeRequest() throws Exception {
		try (TestHttpsServer server = TestHttpsServer.start()) {
			String document = JSON.replace("https://issuer.example/token", server.uri("/token").toString());
			AuthorizationServerMetadata remote = AuthorizationServerMetadata.fromJson(ISSUER, document);
			assertThrows(IllegalArgumentException.class, () -> OAuthClient.withAuthorizationServerMetadata(remote)
					.clientId("client").clientAuthentication(ClientAuthentication.noneInstance())
					.outboundUriPolicy(OutboundUriPolicy.publicAddressesOnlyInstance()).build());
			assertEquals(0, server.getRequests().size());
		}
	}

	@Test
	void manualMetadataKeepsAdvertisementUnknown() {
		AuthorizationServerMetadata metadata = AuthorizationServerMetadata.withIssuer(ISSUER)
				.authorizationEndpoint(URI.create("https://issuer.example/auth"))
				.tokenEndpoint(URI.create("https://issuer.example/token"))
				.build();
		assertFalse(metadata.isRemotelyDiscovered());
		assertFalse(metadata.isAuthorizationResponseIssuerSupported());
		assertTrue(metadata.getCodeChallengeMethodsSupported().isEmpty());
	}
}
