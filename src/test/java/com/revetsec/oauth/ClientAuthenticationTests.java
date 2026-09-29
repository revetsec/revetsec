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
import com.revetsec.testing.TestHttpsServer;
import com.revetsec.testing.TestTls;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

final class ClientAuthenticationTests {
	@Test
	void basicFormEncodesBothFieldsBeforeJoining() {
		ClientAuthentication authentication = ClientAuthentication.fromClientSecretBasic(" %&+£€");
		Map<String, String> headers = new HashMap<>();
		Map<String, String> form = new HashMap<>();
		authentication.apply("a:b", headers, form);
		assertEquals("a%3Ab:+%25%26%2B%C2%A3%E2%82%AC", new String(Base64.getDecoder().decode(
				java.util.Objects.requireNonNull(headers.get("Authorization")).substring("Basic ".length())),
				StandardCharsets.UTF_8));
		assertFalse(form.containsKey("client_secret"));
		assertFalse(headers.toString().contains("£"));
		assertFalse(authentication.toString().contains("£"));
	}

	@Test
	void explicitUnencodedCompatibilityChangesBytes() {
		ClientAuthentication authentication = ClientAuthentication.fromClientSecretBasic(" a",
				ClientSecretBasicEncoding.UNENCODED);
		Map<String, String> headers = new HashMap<>();
		authentication.apply("id", headers, new HashMap<>());
		assertEquals("id: a", new String(Base64.getDecoder().decode(
				java.util.Objects.requireNonNull(headers.get("Authorization")).substring(6)),
				StandardCharsets.UTF_8));
	}

	@Test
	void postSupplierIsUsedOncePerRequestAndPublicClientHasNoSecret() {
		AtomicInteger calls = new AtomicInteger();
		ClientAuthentication authentication = ClientAuthentication.fromClientSecretPost(() -> "secret-" + calls.incrementAndGet());
		Map<String, String> form = new HashMap<>();
		authentication.apply("id", new HashMap<>(), form);
		assertEquals("secret-1", form.get("client_secret"));
		assertEquals(1, calls.get());
		authentication.apply("id", new HashMap<>(), form);
		assertEquals("secret-2", form.get("client_secret"));
		assertEquals(2, calls.get());
		assertThrows(IllegalArgumentException.class,
				() -> ClientAuthentication.fromClientSecretPost(() -> "").apply("id", new HashMap<>(), form));

		ClientAuthentication none = ClientAuthentication.noneInstance();
		assertTrue(none.isPublicClient());
		Map<String, String> publicForm = new HashMap<>();
		none.apply("public-id", new HashMap<>(), publicForm);
		assertEquals(Map.of("client_id", "public-id"), publicForm);
	}

	@Test
	void supplierFailureDoesNotExposeItsMessageOrCause() {
		ClientAuthentication authentication = ClientAuthentication.fromClientSecretPost(
				() -> { throw new IllegalStateException("sensitive-supplier-value"); });
		IllegalArgumentException failure = assertThrows(IllegalArgumentException.class,
				() -> authentication.apply("id", new HashMap<>(), new HashMap<>()));
		assertFalse(failure.toString().contains("sensitive-supplier-value"));
		assertEquals(null, failure.getCause());
	}

	@Test
	void unencodedBasicIsObservedAtBuildAndUse() throws Exception {
		try (TestHttpsServer server = TestHttpsServer.start()) {
			server.script("/token", TestHttpsServer.Script.fromResponse(
					TestHttpsServer.Response.withStatus(200).header("Content-Type", "application/json")
							.body("{\"access_token\":\"token\",\"token_type\":\"Bearer\"}").build()));
			AtomicInteger notices = new AtomicInteger();
			OAuthObserver observer = new OAuthObserver() {
				@Override public void didUseUnencodedBasic() { notices.incrementAndGet(); }
			};
			AuthorizationServerMetadata metadata = AuthorizationServerMetadata.withIssuer(
					server.getBaseUri().toString()).authorizationEndpoint(server.uri("/auth"))
					.tokenEndpoint(server.uri("/token")).build();
			OAuthClient client = OAuthClient.withAuthorizationServerMetadata(metadata).clientId("id")
					.clientAuthentication(ClientAuthentication.fromClientSecretBasic("secret",
							ClientSecretBasicEncoding.UNENCODED))
					.observer(observer).httpClient(TestTls.httpClient()).build();
			assertEquals(1, notices.get());
			client.requestClientCredentialsToken(TokenRequestOptions.builder().build());
			assertEquals(2, notices.get());
		}
	}
}
