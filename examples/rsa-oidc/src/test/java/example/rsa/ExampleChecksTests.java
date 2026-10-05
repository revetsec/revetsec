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
import com.revetsec.jose.JoseException;
import com.revetsec.oauth.*;
import com.revetsec.oidc.*;
import org.jspecify.annotations.NonNull;
import org.junit.jupiter.api.Test;
import java.net.URI;
import java.nio.file.*;
import java.security.KeyPair;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.atomic.AtomicInteger;
import static org.junit.jupiter.api.Assertions.*;

/** Runs the same actual public-API scenarios as JUnit and as a separate capture process. */
public final class ExampleChecksTests {
	private static final URI CALLBACK = URI.create("https://app.example/callback");
	private static final String BINDING = "TEST-ONLY-private-browser-binding";

	@Test void issuerAudienceAcrossAllRolesAndAlgorithms() throws Exception {
		for (JwsAlgorithm algorithm : List.of(JwsAlgorithm.PS256, JwsAlgorithm.RS256, JwsAlgorithm.RS384)) runPrivateKey(algorithm, false);
	}
	@Test void explicitEndpointAudienceNamesEachActualRole() throws Exception { runPrivateKey(JwsAlgorithm.PS256, true); }
	@Test void signatureVerifiedTenantIdentityAndUserInfo() throws Exception { runEntra("valid"); }
	@Test void applicationTenantDenialReturnsNoIdentity() throws Exception { runEntra("denied"); }
	@Test void invalidSignatureNeverReachesTenantDecision() throws Exception { runEntra("forged"); }
	@Test void verifyingKeyMustCarryIssuer() throws Exception { runEntra("key-issuer"); }
	@Test void refreshCannotSwitchToAnotherAllowedTenant() throws Exception { runEntra("refresh-switch"); }

	/** Only fixed case labels, validated booleans and aggregate counts enter this redacted capture. */
	public static void main(@NonNull String @NonNull [] arguments) throws Exception {
		if (arguments.length != 1) throw new IllegalArgumentException("Provide a new absolute capture file");
		Path path = Path.of(arguments[0]); if (!path.isAbsolute()) throw new IllegalArgumentException("Absolute capture path required");
		List<String> cases = new ArrayList<>();
		for (JwsAlgorithm algorithm : List.of(JwsAlgorithm.PS256, JwsAlgorithm.RS256, JwsAlgorithm.RS384)) cases.add(runPrivateKey(algorithm, false));
		cases.add(runPrivateKey(JwsAlgorithm.PS256, true));
		for (String mode : List.of("valid", "denied", "forged", "key-issuer", "refresh-switch")) cases.add(runEntra(mode));
		Files.writeString(path, "{\"schema\":1,\"synthetic\":true,\"hostedEntraVerified\":false,\"cases\":[" + String.join(",", cases) + "]}\n", StandardOpenOption.CREATE_NEW);
		System.out.println("Nine local example scenarios passed; capture contains no credentials or identity fields.");
	}

	private static @NonNull String runPrivateKey(@NonNull JwsAlgorithm algorithm, boolean endpoint) throws Exception {
		KeyPair keys = LocalProvider.freshKey(); AtomicInteger snapshots = new AtomicInteger();
		ClientAssertionKeyProvider fixed = PrivateKeyClients.registeredKey(keys, algorithm, "application-key");
		ClientAssertionKeyProvider rotating = budget -> { assertTrue(budget.compareTo(Duration.ZERO) > 0); snapshots.incrementAndGet(); return fixed.getSigningKey(budget); };
		try (LocalProvider fixture = new LocalProvider(keys, algorithm, endpoint, false)) {
			OAuthClient.Builder builder = PrivateKeyClients.withMetadata(fixture.metadata(), "example-client", rotating)
					.httpClient(fixture.httpClient()).clock(LocalProvider.CLOCK);
			if (endpoint) builder.clientAuthentication(ClientAuthentication.withPrivateKeyJwt(rotating).audience(ClientAssertionAudience.TOKEN_ENDPOINT).build());
			OAuthClient client = builder.build(); assertEquals(0, snapshots.get());
			ClientCredentialsTokenSource cache = ClientCredentialsTokenSource.withClient(client).build();
			AccessToken first = cache.getAccessToken(); assertSame(first, cache.getAccessToken()); assertEquals(1, snapshots.get());
			client.refresh(RefreshToken.fromValue(LocalProvider.REFRESH), TokenRequestOptions.builder().build());
			TokenIntrospectionClient introspection = TokenIntrospectionClient.withOAuthClient(client)
					.expectedAudiences(Set.of("https://resource.example")).build();
			assertNotNull(introspection.validate(BearerToken.fromAuthorizationHeaderValues(List.of("Bearer " + LocalProvider.ACCESS)).orElseThrow()));
			client.revoke(LocalProvider.ACCESS, TokenTypeHint.ACCESS_TOKEN);
			assertNull(fixture.failure, "Independent provider rejected a request (details redacted)");
			assertEquals(4, fixture.posts.get()); assertEquals(4, fixture.assertions.get()); assertEquals(4, snapshots.get());
			assertEquals(4, fixture.identifiers.size());
			if (endpoint) assertEquals(Set.of(fixture.endpoint("/token").toString(), fixture.endpoint("/revoke").toString(), fixture.endpoint("/inspect").toString()), new HashSet<>(fixture.audiences));
			else assertEquals(Set.of(fixture.issuer()), new HashSet<>(fixture.audiences));
			return "{\"case\":\"private-key-" + algorithm.getWireValue() + "-" + (endpoint ? "endpoint" : "issuer") + "\",\"posts\":4,\"independentSignaturesVerified\":4,\"freshIdentifiers\":4,\"cacheHitKeyCalls\":0,\"passed\":true}";
		}
	}

	private static @NonNull String runEntra(@NonNull String mode) throws Exception {
		KeyPair keys = LocalProvider.freshKey(); AtomicInteger tenantCalls = new AtomicInteger();
		ClientAuthentication authentication = ClientAuthentication.withPrivateKeyJwt(PrivateKeyClients.registeredKey(keys, JwsAlgorithm.PS256, "application-key"))
				.audience(ClientAssertionAudience.TOKEN_ENDPOINT).build();
		try (LocalProvider fixture = new LocalProvider(keys, JwsAlgorithm.PS256, true, true)) {
			fixture.forge = mode.equals("forged"); fixture.missingKeyIssuer = mode.equals("key-issuer");
			Set<String> permitted = Set.of(LocalProvider.TENANT, LocalProvider.OTHER);
			OidcClient client = EntraLogin.withIssuer(LocalProvider.TRUST, "example-client", CALLBACK,
					tenant -> { tenantCalls.incrementAndGet(); return !mode.equals("denied") && permitted.contains(tenant); }, authentication)
					.httpClient(fixture.httpClient()).clock(LocalProvider.CLOCK).clockSkew(Duration.ZERO).build();
			assertEquals(0, tenantCalls.get()); assertEquals(0, fixture.posts.get());
			AuthorizationRedirect redirect = client.beginAuthentication();
			Map<String,String> query = LocalProvider.form(redirect.getAuthorizationUri().getRawQuery());
			InMemoryPendingAuthorizationStore pending = InMemoryPendingAuthorizationStore.builder().clock(LocalProvider.CLOCK).build();
			redirect.getPendingAuthorization().saveTo(pending, BINDING);
			// The synthetic code is the nonce so the test-only fixture can bind its independently signed token.
			AuthorizationResponse callback = AuthorizationResponse.fromQueryString("code=" + query.get("nonce") + "&state=" + query.get("state"));
			OidcAuthenticationResult result = client.completeAuthenticationResult(callback, PendingAuthorizationSource.fromStore(pending, BINDING), CALLBACK);
			if (mode.equals("valid") || mode.equals("refresh-switch")) {
				OidcAuthentication auth = assertInstanceOf(OidcAuthenticationResult.Succeeded.class, result).getAuthentication();
				assertEquals(LocalProvider.actualIssuer(LocalProvider.TENANT), auth.getIssuer());
				assertEquals("TEST-ONLY-example-user", auth.getSubject()); assertEquals(1, tenantCalls.get());
				if (mode.equals("valid")) {
					assertEquals(auth.getSubject(), client.fetchUserInfo(auth).getSubject()); assertEquals(2, tenantCalls.get());
				} else {
					fixture.tenant = LocalProvider.OTHER;
					OidcSessionReference stored = OidcSessionReference.fromSerializedForm(auth.getSessionReference().toSerializedForm());
					OidcValidationException failure = assertThrows(OidcValidationException.class, () -> client.refresh(auth.getTokens().getRefreshToken().orElseThrow(), stored));
					assertEquals(OidcValidationException.Reason.REFRESHED_ID_TOKEN_MISMATCH, failure.getReason());
					assertEquals(1, tenantCalls.get());
				}
			} else {
				OidcAuthenticationResult.RejectedIdToken rejected = assertInstanceOf(OidcAuthenticationResult.RejectedIdToken.class, result);
				if (mode.equals("denied")) { assertEquals(OidcValidationException.Reason.TENANT_NOT_ALLOWED, rejected.getReason()); assertEquals(1, tenantCalls.get()); }
				else if (mode.equals("forged")) { assertEquals(OidcValidationException.Reason.ID_TOKEN_SIGNATURE_INVALID, rejected.getReason()); assertEquals(0, tenantCalls.get()); }
				else { assertEquals(Optional.of(JoseException.Reason.KEY_ISSUER_MISMATCH), rejected.getJoseReason()); assertEquals(0, tenantCalls.get()); }
			}
			assertNull(fixture.failure, "Independent provider rejected a request (details redacted)");
			assertEquals(mode.equals("refresh-switch") ? 2 : 1, fixture.posts.get());
			assertEquals(fixture.posts.get(), fixture.assertions.get());
			assertEquals(mode.equals("valid") ? 1 : 0, fixture.userInfoCalls.get());
			return "{\"case\":\"entra-" + mode + "\",\"posts\":" + fixture.posts.get() + ",\"independentSignaturesVerified\":" + fixture.assertions.get()
					+ ",\"tenantDecisionCalls\":" + tenantCalls.get() + ",\"userInfoCalls\":" + fixture.userInfoCalls.get() + ",\"passed\":true}";
		}
	}
}
