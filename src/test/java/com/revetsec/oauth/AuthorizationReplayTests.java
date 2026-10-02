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

import com.revetsec.StateSealer;
import com.revetsec.internal.encoding.QueryParameters;
import com.revetsec.testing.TestHttpsServer;
import com.revetsec.testing.TestSealers;
import com.revetsec.testing.TestTls;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import static org.junit.jupiter.api.Assertions.assertEquals;

final class AuthorizationReplayTests {
	private static final URI CALLBACK = URI.create("https://app.example/callback");

	@Test
	void atomicStoreAllowsOneConcurrentCodePost() throws Exception {
		try (TestHttpsServer server = TestHttpsServer.start()) {
			server.script("/token", TestHttpsServer.Script.fromResponse(success()));
			OAuthClient client = client(server);
			AuthorizationRedirect begin = client.beginAuthorization();
			InMemoryPendingAuthorizationStore store = InMemoryPendingAuthorizationStore.fromDefaults();
			begin.getPendingAuthorization().saveTo(store, "browser");
			String state = state(begin);
			int accepted = concurrentCompletions(client, state,
					() -> PendingAuthorizationSource.fromStore(store, "browser"));
			assertEquals(1, accepted);
			assertEquals(1, server.getHitCount("/token"));
		}
	}

	@Test
	void sameSealedCookieCanSendTwoConcurrentCodePosts() throws Exception {
		try (TestHttpsServer server = TestHttpsServer.start()) {
			server.script("/token", TestHttpsServer.Script.fromSequence(List.of(success(), success())));
			OAuthClient client = client(server);
			AuthorizationRedirect begin = client.beginAuthorization();
			StateSealer sealer = TestSealers.fromFixedKey();
			String sealed = begin.getPendingAuthorization().toSealedForm(sealer, "provider");
			int accepted = concurrentCompletions(client, state(begin),
					() -> PendingAuthorizationSource.fromSealedForm(sealed, sealer, "provider"));
			assertEquals(2, accepted);
			assertEquals(2, server.getHitCount("/token"));
		}
	}

	private static int concurrentCompletions(@NonNull OAuthClient client, @NonNull String state,
			java.util.function.@NonNull Supplier<@NonNull PendingAuthorizationSource> source) throws Exception {
		CountDownLatch start = new CountDownLatch(1);
		ExecutorService executor = Executors.newFixedThreadPool(2);
		try {
			java.util.concurrent.Callable<Boolean> call = () -> {
				start.await();
				try {
					client.completeAuthorization(AuthorizationResponse.fromQueryString(
							"state=" + state + "&code=single-code"), source.get(), CALLBACK);
					return true;
				} catch (OAuthValidationException rejected) {
					assertEquals(OAuthException.Reason.PENDING_AUTHORIZATION_NOT_FOUND, rejected.getReason());
					return false;
				}
			};
			Future<Boolean> first = executor.submit(call);
			Future<Boolean> second = executor.submit(call);
			start.countDown();
			return (first.get() ? 1 : 0) + (second.get() ? 1 : 0);
		} finally {
			executor.shutdownNow();
		}
	}

	private static @NonNull String state(@NonNull AuthorizationRedirect begin) throws Exception {
		return QueryParameters.parse(begin.getAuthorizationUri().getRawQuery()).getValues("state").get(0);
	}

	private static @NonNull OAuthClient client(@NonNull TestHttpsServer server) {
		AuthorizationServerMetadata metadata = AuthorizationServerMetadata.withIssuer(server.getBaseUri().toString())
				.authorizationEndpoint(server.uri("/authorize"))
				.tokenEndpoint(server.uri("/token"))
				.build();
		return OAuthClient.withAuthorizationServerMetadata(metadata).clientId("client")
				.clientAuthentication(ClientAuthentication.noneInstance()).redirectUri(CALLBACK)
				.httpClient(TestTls.httpClient()).build();
	}

	private static TestHttpsServer.@NonNull Response success() {
		return TestHttpsServer.Response.withStatus(200).header("Content-Type", "application/json")
				.body("{\"access_token\":\"token\",\"token_type\":\"Bearer\"}").build();
	}
}
