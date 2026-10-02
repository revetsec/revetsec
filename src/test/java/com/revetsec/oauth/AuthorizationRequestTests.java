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

import com.revetsec.internal.encoding.QueryParameters;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.util.List;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

final class AuthorizationRequestTests {
	private static final URI CALLBACK = URI.create("https://app.example/callback?fixed=1");

	@Test
	void freshS256ChallengeStateResourcesAndEndpointQuery() throws Exception {
		OAuthClient client = client(metadata());
		AuthorizationRequestOptions options = AuthorizationRequestOptions.builder()
				.scopes(Set.of("openid", "profile"))
				.resources(List.of(URI.create("https://api.example/a"), URI.create("https://api.example/b")))
				.responseMode(AuthorizationRequestOptions.ResponseMode.FORM_POST)
				.applicationData(Map.of("returnTo", "/account"))
				.build();
		AuthorizationRedirect first = client.beginAuthorization(options);
		AuthorizationRedirect second = client.beginAuthorization(options);
		assertEquals("https://issuer.example/authorize", first.getAuthorizationUri().getScheme()
				+ "://" + first.getAuthorizationUri().getHost() + first.getAuthorizationUri().getPath());
		QueryParameters parameters = QueryParameters.parse(first.getAuthorizationUri().getRawQuery());
		assertEquals(List.of("1"), parameters.getValues("existing"));
		assertEquals(List.of("code"), parameters.getValues("response_type"));
		assertEquals(List.of("client"), parameters.getValues("client_id"));
		assertEquals(List.of(CALLBACK.toString()), parameters.getValues("redirect_uri"));
		assertEquals(List.of("openid profile"), parameters.getValues("scope"));
		assertEquals(List.of("S256"), parameters.getValues("code_challenge_method"));
		assertEquals(List.of("form_post"), parameters.getValues("response_mode"));
		assertEquals(List.of("https://api.example/a", "https://api.example/b"), parameters.getValues("resource"));
		assertTrue(parameters.getValues("state").get(0).matches("[A-Za-z0-9_-]{43}"));
		assertTrue(parameters.getValues("code_challenge").get(0).matches("[A-Za-z0-9_-]{43}"));
		assertNotEquals(parameters.getValues("state"), QueryParameters.parse(second.getAuthorizationUri().getRawQuery())
				.getValues("state"));
		assertEquals(first.getPerFlowCookieName(), AuthorizationResponse.fromQueryString(
				"state=" + parameters.getValues("state").get(0)).getPerFlowCookieName());
		assertFalse(first.toString().contains(parameters.getValues("state").get(0)));
		assertEquals(Map.of("returnTo", "/account"), first.getPendingAuthorization().getApplicationData());
	}

	@Test
	void strictAdvertisementAndReservedAdditionalParameters() {
		AuthorizationServerMetadata absent = metadata();
		assertThrows(OAuthValidationException.class, () -> OAuthClient.withAuthorizationServerMetadata(absent)
				.clientId("client").clientAuthentication(ClientAuthentication.noneInstance()).redirectUri(CALLBACK)
				.requirePkceAdvertised(true).build().beginAuthorization());
		AuthorizationServerMetadata plainOnly = AuthorizationServerMetadata.withIssuer("https://issuer.example")
				.authorizationEndpoint(URI.create("https://issuer.example/authorize"))
				.tokenEndpoint(URI.create("https://issuer.example/token"))
				.codeChallengeMethodsSupported(Set.of("plain")).build();
		assertEquals(OAuthException.Reason.PKCE_UNSUPPORTED,
				assertThrows(OAuthValidationException.class, () -> client(plainOnly).beginAuthorization()).getReason());
		for (String reserved : List.of("response_type", "client_id", "redirect_uri", "state", "nonce",
				"code_challenge", "code_challenge_method", "resource", "request_uri", "dpop_jkt"))
			assertThrows(IllegalArgumentException.class,
					() -> AuthorizationRequestOptions.builder().additionalParameters(Map.of(reserved, "x")));
		assertThrows(IllegalArgumentException.class, () -> AuthorizationRequestOptions.builder()
				.resources(List.of(URI.create("https://api.example/resource#fragment"))));
		for (String badScope : List.of("", "two words", "quote\"", "backslash\\"))
			assertThrows(IllegalArgumentException.class, () -> AuthorizationRequestOptions.builder()
					.scopes(Set.of(badScope)));
	}

	@Test
	void unsafeAuthorizationAndTokenEndpointsAreRejectedAtBuild() {
		for (String bad : List.of("http://issuer.example/token", "https://issuer.example/token#fragment")) {
			AuthorizationServerMetadata metadata = AuthorizationServerMetadata.withIssuer("https://issuer.example")
					.authorizationEndpoint(URI.create("https://issuer.example/authorize"))
					.tokenEndpoint(URI.create(bad)).build();
			assertThrows(IllegalArgumentException.class, () -> client(metadata));
		}
		AuthorizationServerMetadata badAuthorization = AuthorizationServerMetadata
				.withIssuer("https://issuer.example")
				.authorizationEndpoint(URI.create("http://issuer.example/authorize"))
				.tokenEndpoint(URI.create("https://issuer.example/token")).build();
		assertThrows(IllegalArgumentException.class, () -> client(badAuthorization));
		AuthorizationServerMetadata fragmentedAuthorization = AuthorizationServerMetadata
				.withIssuer("https://issuer.example")
				.authorizationEndpoint(URI.create("https://issuer.example/authorize#fragment"))
				.tokenEndpoint(URI.create("https://issuer.example/token")).build();
		assertThrows(IllegalArgumentException.class, () -> client(fragmentedAuthorization));
		AuthorizationServerMetadata badRevocation = AuthorizationServerMetadata.withIssuer("https://issuer.example")
				.authorizationEndpoint(URI.create("https://issuer.example/authorize"))
				.tokenEndpoint(URI.create("https://issuer.example/token"))
				.revocationEndpoint(URI.create("http://issuer.example/revoke")).build();
		assertThrows(IllegalArgumentException.class, () -> client(badRevocation));
		AuthorizationServerMetadata loopback = AuthorizationServerMetadata.withIssuer("http://127.0.0.1:18080")
				.authorizationEndpoint(URI.create("http://127.0.0.1:18080/authorize"))
				.tokenEndpoint(URI.create("http://127.0.0.1:18080/token"))
				.revocationEndpoint(URI.create("http://127.0.0.1:18080/revoke")).build();
		assertThrows(IllegalArgumentException.class, () -> client(loopback));
		OAuthClient allowedTestClient = OAuthClient.withAuthorizationServerMetadata(loopback).clientId("client")
				.clientAuthentication(ClientAuthentication.noneInstance())
				.redirectUri(URI.create("http://127.0.0.1:18081/callback"))
				.allowInsecureLoopback(true).build();
		assertTrue(allowedTestClient.beginAuthorization().getAuthorizationUri().toString()
				.startsWith("http://127.0.0.1:18080/authorize?"));
	}

	@Test
	void callbackUriMustBeRegisteredShapeAtBuild() {
		for (String uri : List.of("/relative", "http://app.example/cb", "https://user@app.example/cb",
				"https://app.example/cb#fragment", "https://app.example:0/cb"))
			assertThrows(IllegalArgumentException.class, () -> OAuthClient.withAuthorizationServerMetadata(metadata())
					.clientId("client").clientAuthentication(ClientAuthentication.noneInstance())
					.redirectUri(URI.create(uri)).build());
		assertTrue(client(metadata()).beginAuthorization().getAuthorizationUri().toString().contains("code_challenge"));
	}

	@Test
	void tenThousandStatesAndVerifiersAreDistinctAndFullLength() throws Exception {
		OAuthClient client = client(metadata());
		Set<String> states = new HashSet<>();
		Set<String> verifiers = new HashSet<>();
		for (int index = 0; index < 10_000; index++) {
			AuthorizationRedirect begin = client.beginAuthorization();
			String state = QueryParameters.parse(begin.getAuthorizationUri().getRawQuery())
					.getValues("state").get(0);
			String verifier = begin.getPendingAuthorization().verifier();
			assertTrue(state.matches("[A-Za-z0-9_-]{43}"));
			assertTrue(verifier.matches("[A-Za-z0-9_-]{43}"));
			assertTrue(states.add(state));
			assertTrue(verifiers.add(verifier));
		}
	}

	@Test
	void rfc7636AppendixBVerifierHasExpectedS256Challenge() {
		assertEquals("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
				OAuthClient.challenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"));
	}

	private static @NonNull OAuthClient client(@NonNull AuthorizationServerMetadata metadata) {
		return OAuthClient.withAuthorizationServerMetadata(metadata).clientId("client")
				.clientAuthentication(ClientAuthentication.noneInstance()).redirectUri(CALLBACK).build();
	}

	private static @NonNull AuthorizationServerMetadata metadata() {
		return AuthorizationServerMetadata.withIssuer("https://issuer.example")
				.authorizationEndpoint(URI.create("https://issuer.example/authorize?existing=1"))
				.tokenEndpoint(URI.create("https://issuer.example/token"))
				.build();
	}
}
