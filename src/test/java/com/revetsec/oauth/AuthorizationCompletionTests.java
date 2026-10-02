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
import com.revetsec.testing.TestSealers;
import com.revetsec.testing.TestHttpsServer;
import com.revetsec.testing.TestTls;
import com.revetsec.testing.RewindableClock;
import org.junit.jupiter.api.Test;
import org.jspecify.annotations.Nullable;

import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

final class AuthorizationCompletionTests {
	private static final URI CALLBACK = URI.create("https://app.example/callback");

	@Test
	void validOtherFlowCookieAndWrongTrustedRouteFailBeforeNetwork() throws Exception {
		OAuthClient client = client(false);
		StateSealer sealer = TestSealers.fromFixedKey();
		AuthorizationRedirect a = client.beginAuthorization();
		AuthorizationRedirect b = client.beginAuthorization();
		String stateA = QueryParameters.parse(a.getAuthorizationUri().getRawQuery()).getValues("state").get(0);
		String sealedB = b.getPendingAuthorization().toSealedForm(sealer, "provider");
		assertEquals(OAuthException.Reason.STATE_MISMATCH,
				assertThrows(OAuthValidationException.class, () -> client.completeAuthorization(
						AuthorizationResponse.fromQueryString("state=" + stateA + "&code=correct"),
						PendingAuthorizationSource.fromSealedForm(sealedB, sealer, "provider"), CALLBACK)).getReason());
		String sealedA = a.getPendingAuthorization().toSealedForm(sealer, "provider");
		assertEquals(OAuthException.Reason.CALLBACK_URI_MISMATCH,
				assertThrows(OAuthValidationException.class, () -> client.completeAuthorization(
						AuthorizationResponse.fromQueryString("state=" + stateA + "&code=correct"),
						PendingAuthorizationSource.fromSealedForm(sealedA, sealer, "provider"),
						URI.create("https://app.example/other"))).getReason());
	}

	@Test
	void advertisedMissingIssuerWinsBeforeAuthorizationError() throws Exception {
		OAuthClient client = client(true);
		StateSealer sealer = TestSealers.fromFixedKey();
		AuthorizationRedirect redirect = client.beginAuthorization();
		String state = QueryParameters.parse(redirect.getAuthorizationUri().getRawQuery()).getValues("state").get(0);
		String sealed = redirect.getPendingAuthorization().toSealedForm(sealer, "provider");
		assertEquals(OAuthException.Reason.ISSUER_MISSING,
				assertThrows(OAuthValidationException.class, () -> client.completeAuthorization(
						AuthorizationResponse.fromQueryString("state=" + state + "&error=access_denied"),
						PendingAuthorizationSource.fromSealedForm(sealed, sealer, "provider"), CALLBACK)).getReason());
	}

	@Test
	void validOtherFlowCookieWithErrorMakesNoAuthorizationServerRequest() throws Exception {
		try (TestHttpsServer server = TestHttpsServer.start()) {
			OAuthClient client = loopbackClient(server);
			StateSealer sealer = TestSealers.fromFixedKey();
			AuthorizationRedirect a = client.beginAuthorization();
			AuthorizationRedirect b = client.beginAuthorization();
			String stateA = QueryParameters.parse(a.getAuthorizationUri().getRawQuery()).getValues("state").get(0);
			String sealedB = b.getPendingAuthorization().toSealedForm(sealer, "provider");
			assertEquals(OAuthException.Reason.STATE_MISMATCH,
					assertThrows(OAuthValidationException.class, () -> client.completeAuthorization(
							AuthorizationResponse.fromQueryString("state=" + stateA + "&error=access_denied"),
							PendingAuthorizationSource.fromSealedForm(sealedB, sealer, "provider"), CALLBACK))
							.getReason());
			assertEquals(0, server.getRequests().size());
		}
	}

	@Test
	void stateOnlyStoreCannotTransferAuthorizationToAnotherBrowser() throws Exception {
		try (TestHttpsServer server = TestHttpsServer.start()) {
			OAuthClient client = loopbackClient(server);
			AuthorizationRedirect redirect = client.beginAuthorization();
			String state = QueryParameters.parse(redirect.getAuthorizationUri().getRawQuery()).getValues("state").get(0);
			PendingAuthorizationStore defective = new PendingAuthorizationStore() {
				private @Nullable String record;
				@Override public void save(@NonNull String binding, @NonNull String key, @NonNull String opaque, @NonNull Instant expiry) {
					this.record = opaque;
				}
				@Override public @NonNull Optional<@NonNull String> consume(@NonNull String binding, @NonNull String key) {
					String found = this.record;
					this.record = null;
					return Optional.ofNullable(found);
				}
			};
			redirect.getPendingAuthorization().saveTo(defective, "browser-A");
			assertEquals(OAuthException.Reason.BROWSER_BINDING_MISMATCH,
					assertThrows(OAuthValidationException.class, () -> client.completeAuthorization(
							AuthorizationResponse.fromQueryString("state=" + state + "&code=valid-code"),
							PendingAuthorizationSource.fromStore(defective, "browser-B"), CALLBACK))
							.getReason());
			assertEquals(0, server.getRequests().size());
		}
	}

	@Test
	void authorizationErrorIsTrustedOnlyAfterStateAndIssuerValidation() throws Exception {
		try (TestHttpsServer server = TestHttpsServer.start()) {
			OAuthClient client = loopbackClient(server);
			StateSealer sealer = TestSealers.fromFixedKey();
			AuthorizationRedirect redirect = client.beginAuthorization();
			String state = redirect.getPendingAuthorization().state();
			String sealed = redirect.getPendingAuthorization().toSealedForm(sealer, "provider");
			PendingAuthorizationSource source = PendingAuthorizationSource.fromSealedForm(sealed, sealer, "provider");
			AuthorizationResponse wrongState = AuthorizationResponse.fromQueryString(
					"state=attacker&error=access_denied&error_description=secret");
			assertEquals(OAuthException.Reason.STATE_MISMATCH,
					assertThrows(OAuthValidationException.class, () -> client.completeAuthorization(
							wrongState, source, CALLBACK)).getReason());
			AuthorizationResponse wrongIssuer = AuthorizationResponse.fromQueryString("state=" + state
					+ "&iss=https%3A%2F%2Fattacker.example&error=access_denied&error_description=secret");
			OAuthValidationException issuerFailure = assertThrows(OAuthValidationException.class,
					() -> client.completeAuthorization(wrongIssuer, source, CALLBACK));
			assertEquals(OAuthException.Reason.ISSUER_MISMATCH, issuerFailure.getReason());
			org.junit.jupiter.api.Assertions.assertFalse(java.util.Objects.requireNonNull(issuerFailure.getMessage())
					.contains("secret"));
			AuthorizationResponse valid = AuthorizationResponse.fromQueryString("state=" + state
					+ "&error=access_denied&error_description=secret");
			AuthorizationErrorException denied = assertThrows(AuthorizationErrorException.class,
					() -> client.completeAuthorization(valid, source, CALLBACK));
			assertEquals("access_denied", denied.getErrorCode().orElseThrow());
			org.junit.jupiter.api.Assertions.assertFalse(java.util.Objects.requireNonNull(denied.getMessage())
					.contains("secret"));
			assertEquals(0, server.getRequests().size());
		}
	}

	@Test
	void callbackIssuerComparisonIsExactEvenWithoutAdvertisement() throws Exception {
		OAuthClient client = client(false);
		StateSealer sealer = TestSealers.fromFixedKey();
		AuthorizationRedirect redirect = client.beginAuthorization();
		String state = redirect.getPendingAuthorization().state();
		PendingAuthorizationSource source = PendingAuthorizationSource.fromSealedForm(
				redirect.getPendingAuthorization().toSealedForm(sealer, "provider"), sealer, "provider");
		for (String wrong : List.of("https://ISSUER.example", "https://issuer.example/",
				"https://issuer.example:443", "https%3A%2F%2Fissuer.example")) {
			String callback = "state=" + state + "&iss="
					+ URLEncoder.encode(wrong, StandardCharsets.UTF_8) + "&error=access_denied";
			assertEquals(OAuthException.Reason.ISSUER_MISMATCH,
					assertThrows(OAuthValidationException.class, () -> client.completeAuthorization(
							AuthorizationResponse.fromQueryString(callback), source, CALLBACK)).getReason());
		}
		String matching = "state=" + state + "&iss=https%3A%2F%2Fissuer.example&error=access_denied";
		assertEquals("access_denied", assertThrows(AuthorizationErrorException.class,
				() -> client.completeAuthorization(AuthorizationResponse.fromQueryString(matching), source, CALLBACK))
				.getErrorCode().orElseThrow());
	}

	@Test
	void absentAndEmptyStateAreRejectedBeforeAuthorizationServerWork() throws Exception {
		try (TestHttpsServer server = TestHttpsServer.start()) {
			OAuthClient client = loopbackClient(server);
			StateSealer sealer = TestSealers.fromFixedKey();
			PendingAuthorization pending = client.beginAuthorization().getPendingAuthorization();
			PendingAuthorizationSource source = PendingAuthorizationSource.fromSealedForm(
					pending.toSealedForm(sealer, "provider"), sealer, "provider");
			for (String query : List.of("code=one-time-code", "state=&code=one-time-code"))
				assertEquals(OAuthException.Reason.STATE_MISMATCH,
						assertThrows(OAuthValidationException.class, () -> client.completeAuthorization(
								AuthorizationResponse.fromQueryString(query), source, CALLBACK)).getReason());
			assertEquals(0, server.getRequests().size());
		}
	}

	@Test
	void pendingAuthorizationExpiresAtTheExactConfiguredInstant() throws Exception {
		RewindableClock clock = RewindableClock.fromInstant(Instant.parse("2026-09-28T12:00:00Z"));
		OAuthClient client = OAuthClient.withAuthorizationServerMetadata(metadata("https://issuer.example"))
				.clientId("client").clientAuthentication(ClientAuthentication.noneInstance())
				.redirectUri(CALLBACK).clock(clock).pendingAuthorizationLifetime(Duration.ofMinutes(1)).build();
		PendingAuthorization pending = client.beginAuthorization().getPendingAuthorization();
		StateSealer sealer = TestSealers.fromFixedKey();
		PendingAuthorizationSource source = PendingAuthorizationSource.fromSealedForm(
				pending.toSealedForm(sealer, "provider"), sealer, "provider");
		clock.advance(Duration.ofMinutes(1));
		assertEquals(OAuthException.Reason.PENDING_AUTHORIZATION_EXPIRED,
				assertThrows(OAuthValidationException.class, () -> client.completeAuthorization(
						AuthorizationResponse.fromQueryString("state=" + pending.state() + "&code=code"),
						source, CALLBACK)).getReason());
	}

	@Test
	void pendingClientIssuerAndFlowKindAreAuthenticated() throws Exception {
		OAuthClient first = client(false);
		StateSealer sealer = TestSealers.fromFixedKey();
		PendingAuthorization pending = first.beginAuthorization().getPendingAuthorization();
		AuthorizationResponse response = AuthorizationResponse.fromQueryString(
				"state=" + pending.state() + "&code=one-time-code");
		PendingAuthorizationSource source = PendingAuthorizationSource.fromSealedForm(
				pending.toSealedForm(sealer, "provider"), sealer, "provider");
		OAuthClient otherClientId = OAuthClient.withAuthorizationServerMetadata(metadata("https://issuer.example"))
				.clientId("another-client").clientAuthentication(ClientAuthentication.noneInstance())
				.redirectUri(CALLBACK).build();
		assertEquals(OAuthException.Reason.CLIENT_MISMATCH,
				assertThrows(OAuthValidationException.class, () -> otherClientId.completeAuthorization(
						response, source, CALLBACK)).getReason());
		OAuthClient otherIssuer = clientWithIssuer("https://another.example");
		assertEquals(OAuthException.Reason.ISSUER_MISMATCH,
				assertThrows(OAuthValidationException.class, () -> otherIssuer.completeAuthorization(
						response, source, CALLBACK)).getReason());
		PendingAuthorization oidc = new PendingAuthorization("oidc", pending.getIssuer(), pending.getClientId(),
				pending.getRedirectUri(), pending.state(), pending.verifier(), pending.nonce(),
				Set.of(), List.of(), pending.responseMode(), pending.getCreatedAt(), pending.getExpiresAt(), Map.of(),
				pending.issuerRequired(), pending.authorizationEndpoint(), pending.tokenEndpoint());
		PendingAuthorizationSource oidcSource = PendingAuthorizationSource.fromSealedForm(
				oidc.toSealedForm(sealer, "provider"), sealer, "provider");
		assertEquals(OAuthException.Reason.PENDING_AUTHORIZATION_INVALID,
				assertThrows(OAuthValidationException.class, () -> first.completeAuthorization(
						response, oidcSource, CALLBACK)).getReason());
	}

	@Test
	void twoAuthorizationServersWithDistinctRoutesRejectWrongRouteBeforeNetwork() throws Exception {
		try (TestHttpsServer firstServer = TestHttpsServer.start();
				TestHttpsServer secondServer = TestHttpsServer.start()) {
			URI firstCallback = URI.create("https://app.example/first/callback");
			URI secondCallback = URI.create("https://app.example/second/callback");
			OAuthClient firstClient = OAuthClient.withAuthorizationServerMetadata(
					AuthorizationServerMetadata.withIssuer(firstServer.getBaseUri().toString())
							.authorizationEndpoint(firstServer.uri("/authorize"))
							.tokenEndpoint(firstServer.uri("/token")).build())
					.clientId("shared-client").clientAuthentication(ClientAuthentication.noneInstance())
					.redirectUri(firstCallback).httpClient(TestTls.httpClient()).build();
			OAuthClient secondClient = OAuthClient.withAuthorizationServerMetadata(
					AuthorizationServerMetadata.withIssuer(secondServer.getBaseUri().toString())
							.authorizationEndpoint(secondServer.uri("/authorize"))
							.tokenEndpoint(secondServer.uri("/token")).build())
					.clientId("shared-client").clientAuthentication(ClientAuthentication.noneInstance())
					.redirectUri(secondCallback).httpClient(TestTls.httpClient()).build();
			PendingAuthorization pending = firstClient.beginAuthorization().getPendingAuthorization();
			StateSealer sealer = TestSealers.fromFixedKey();
			PendingAuthorizationSource source = PendingAuthorizationSource.fromSealedForm(
					pending.toSealedForm(sealer, "provider"), sealer, "provider");
			AuthorizationResponse response = AuthorizationResponse.fromQueryString(
					"state=" + pending.state() + "&code=attacker-code");
			assertEquals(OAuthException.Reason.ISSUER_MISMATCH,
					assertThrows(OAuthValidationException.class, () -> secondClient.completeAuthorization(
							response, source, secondCallback)).getReason());
			assertEquals(OAuthException.Reason.CALLBACK_URI_MISMATCH,
					assertThrows(OAuthValidationException.class, () -> firstClient.completeAuthorization(
							response, source, secondCallback)).getReason());
			assertEquals(0, firstServer.getRequests().size());
			assertEquals(0, secondServer.getRequests().size());
		}
	}

	private static @NonNull OAuthClient loopbackClient(@NonNull TestHttpsServer server) {
		AuthorizationServerMetadata metadata = AuthorizationServerMetadata.withIssuer(server.getBaseUri().toString())
				.authorizationEndpoint(server.uri("/authorize"))
				.tokenEndpoint(server.uri("/token"))
				.build();
		return OAuthClient.withAuthorizationServerMetadata(metadata).clientId("client")
				.clientAuthentication(ClientAuthentication.noneInstance()).redirectUri(CALLBACK)
				.httpClient(TestTls.httpClient()).build();
	}

	private static @NonNull OAuthClient client(boolean issuerAdvertised) {
		AuthorizationServerMetadata metadata = AuthorizationServerMetadata.withIssuer("https://issuer.example")
				.authorizationEndpoint(URI.create("https://issuer.example/auth"))
				.tokenEndpoint(URI.create("https://issuer.example/token"))
				.authorizationResponseIssuerSupported(issuerAdvertised).build();
		return OAuthClient.withAuthorizationServerMetadata(metadata).clientId("client")
				.clientAuthentication(ClientAuthentication.noneInstance()).redirectUri(CALLBACK).build();
	}

	private static @NonNull OAuthClient clientWithIssuer(@NonNull String issuer) {
		return OAuthClient.withAuthorizationServerMetadata(metadata(issuer)).clientId("client")
				.clientAuthentication(ClientAuthentication.noneInstance()).redirectUri(CALLBACK).build();
	}

	private static @NonNull AuthorizationServerMetadata metadata(@NonNull String issuer) {
		return AuthorizationServerMetadata.withIssuer(issuer)
				.authorizationEndpoint(URI.create(issuer + "/auth"))
				.tokenEndpoint(URI.create(issuer + "/token")).build();
	}
}
