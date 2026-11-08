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

import com.revetsec.BrowserBinding;
import com.revetsec.jose.JwsAlgorithm;
import com.revetsec.jose.JoseException;
import com.revetsec.oauth.*;
import com.revetsec.oidc.*;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.io.TempDir;
import java.util.concurrent.TimeUnit;
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
	private static final BrowserBinding BINDING = BrowserBinding.fromTrustedPersistence("TEST-ONLY-private-browser-binding");

  @TempDir static @NonNull Path tlsDirectory;
  private static @Nullable String originalTlsStore;

  @BeforeAll static void prepareTestTls() throws Exception {
    originalTlsStore = System.getProperty("example.tlsStore");
    if (originalTlsStore != null && !originalTlsStore.isBlank()) return;
    // This private, two-day localhost certificate is trusted only by the test client.
    Path store = tlsDirectory.resolve("localhost.p12");
    String executable = System.getProperty("os.name").startsWith("Windows") ? "keytool.exe" : "keytool";
    Process keytool = new ProcessBuilder(
      Path.of(System.getProperty("java.home"), "bin", executable).toString(),
      "-genkeypair", "-alias", "local", "-keyalg", "RSA", "-keysize", "2048",
      "-sigalg", "SHA256withRSA", "-storetype", "PKCS12", "-keystore", store.toString(),
      "-storepass", "changeit", "-keypass", "changeit", "-dname", "CN=localhost",
      "-ext", "SAN=dns:localhost,ip:127.0.0.1", "-validity", "2", "-noprompt")
      .redirectOutput(ProcessBuilder.Redirect.DISCARD)
      .redirectError(ProcessBuilder.Redirect.DISCARD).start();
    if (!keytool.waitFor(30, TimeUnit.SECONDS)) {
      keytool.destroyForcibly().waitFor();
      throw new IllegalStateException("Test keytool timed out");
    }
    if (keytool.exitValue() != 0) throw new IllegalStateException("Test keytool failed");
    System.setProperty("example.tlsStore", store.toString());
  }

  @AfterAll static void restoreTestTls() {
    if (originalTlsStore == null) System.clearProperty("example.tlsStore");
    else System.setProperty("example.tlsStore", originalTlsStore);
  }

	@Test void issuerAudienceAcrossAllRolesAndAlgorithms() throws Exception {
		for (JwsAlgorithm algorithm : SelectedKeyProfileTests.SELECTED) runPrivateKey(algorithm, false);
	}
	@Test void explicitEndpointAudienceNamesEachActualRole() throws Exception { for (JwsAlgorithm algorithm : SelectedKeyProfileTests.SELECTED) runPrivateKey(algorithm, true); }
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
		for (JwsAlgorithm algorithm : SelectedKeyProfileTests.SELECTED) cases.add(runPrivateKey(algorithm, false));
		for (JwsAlgorithm algorithm : SelectedKeyProfileTests.SELECTED) cases.add(runPrivateKey(algorithm, true));
		for (String mode : List.of("valid", "denied", "forged", "key-issuer", "refresh-switch")) cases.add(runEntra(mode));
		for (String role : List.of("token", "refresh", "introspection", "revocation")) cases.add(runLegacyMetadataRefusal(role));
		for (JwsAlgorithm algorithm : List.of(JwsAlgorithm.RS256,JwsAlgorithm.ES256,JwsAlgorithm.ES384,JwsAlgorithm.ED25519)) cases.add(runMismatchedPrivate(algorithm));
		Files.writeString(path, "{\"schema\":1,\"synthetic\":true,\"hostedEntraVerified\":false,\"cases\":[" + String.join(",", cases) + "]}\n", StandardOpenOption.CREATE_NEW);
		System.out.println("Thirty-one local example scenarios passed; capture contains no credentials or identity fields.");
	}

	private static @NonNull String runPrivateKey(@NonNull JwsAlgorithm algorithm, boolean endpoint) throws Exception {
		KeyPair keys = SelectedKeyProfileTests.fresh(algorithm); AtomicInteger snapshots = new AtomicInteger();
		var registration = PrivateKeyClients.registration(keys, algorithm, "application-key");
		ClientAssertionKeyProvider fixed = registration.getKeyProvider();
		ClientAssertionKeyProvider rotating = budget -> { assertTrue(budget.compareTo(Duration.ZERO) > 0); snapshots.incrementAndGet(); return fixed.getSigningKey(budget); };
		try (LocalProvider fixture = new LocalProvider(registration.getJwksPublisher(), algorithm, endpoint, false)) {
			OAuthClient.Builder builder = PrivateKeyClients.withMetadata(fixture.metadata(), "example-client", rotating)
					.httpClient(fixture.httpClient()).clock(LocalProvider.CLOCK);
			if (endpoint) builder.clientAuthentication(ClientAuthentication.withPrivateKeyJwt(rotating).audience(ClientAssertionAudience.TOKEN_ENDPOINT).build());
			OAuthClient client = builder.build(); assertEquals(0, snapshots.get());
			ClientCredentialsTokenSource cache = ClientCredentialsTokenSource.withClient(client).build();
			AccessToken first = assertInstanceOf(AccessTokenAcquisitionResult.Succeeded.class, cache.getAccessTokenResult()).getAccessToken(); assertSame(first, assertInstanceOf(AccessTokenAcquisitionResult.Succeeded.class, cache.getAccessTokenResult()).getAccessToken()); assertEquals(1, snapshots.get());
			assertInstanceOf(OAuthTokenRequestResult.Succeeded.class, client.refreshResult(RefreshToken.fromValue(LocalProvider.REFRESH), TokenRequestOptions.builder().build()));
			TokenIntrospectionClient introspection = TokenIntrospectionClient.withOAuthClient(client)
					.expectedAudiences(Set.of("https://resource.example")).build();
			assertInstanceOf(AccessTokenValidationResult.Succeeded.class, introspection.validateResult(((com.revetsec.oauth.BearerTokenResult.Present) BearerToken.fromAuthorizationHeaderValuesResult(List.of("Bearer " + LocalProvider.ACCESS))).getToken()));
			assertInstanceOf(OAuthRevocationResult.Succeeded.class, client.revokeResult(LocalProvider.ACCESS, TokenTypeHint.ACCESS_TOKEN));
			assertNull(fixture.failure, "Independent provider rejected a request (details redacted)");
			assertEquals(4, fixture.posts.get()); assertEquals(4, fixture.assertions.get()); assertEquals(4, snapshots.get());
			assertEquals(4, fixture.identifiers.size()); assertEquals(1, fixture.applicationJwksFetches.get()); assertEquals(1, fixture.signatureProviders.size());
			if (endpoint) assertEquals(Set.of(fixture.endpoint("/token").toString(), fixture.endpoint("/revoke").toString(), fixture.endpoint("/inspect").toString()), new HashSet<>(fixture.audiences));
			else assertEquals(Set.of(fixture.issuer()), new HashSet<>(fixture.audiences));
			return "{\"case\":\"private-key-" + algorithm.getWireValue() + "-" + (endpoint ? "endpoint" : "issuer") + "\",\"posts\":4,\"independentSignaturesVerified\":4,\"freshIdentifiers\":4,\"cacheHitKeyCalls\":0,\"publicJwksFetches\":1,\"signatureProvider\":\"" + fixture.signatureProviders.iterator().next() + "\",\"passed\":true}";
		}
	}

	private static @NonNull String runEntra(@NonNull String mode) throws Exception {
		KeyPair keys = LocalProvider.freshKey(); AtomicInteger tenantCalls = new AtomicInteger();
		var registration = PrivateKeyClients.registration(keys, JwsAlgorithm.PS256, "application-key");
		ClientAuthentication authentication = ClientAuthentication.withPrivateKeyJwt(registration.getKeyProvider())
				.audience(ClientAssertionAudience.TOKEN_ENDPOINT).build();
		try (LocalProvider fixture = new LocalProvider(registration.getJwksPublisher(), JwsAlgorithm.PS256, true, true)) {
			fixture.forge = mode.equals("forged"); fixture.missingKeyIssuer = mode.equals("key-issuer");
			Set<String> permitted = Set.of(LocalProvider.TENANT, LocalProvider.OTHER);
			OidcClient client = EntraLogin.withIssuer(LocalProvider.TRUST, "example-client", CALLBACK,
					tenant -> { tenantCalls.incrementAndGet(); return !mode.equals("denied") && permitted.contains(tenant); }, authentication)
					.httpClient(fixture.httpClient()).clock(LocalProvider.CLOCK).clockSkew(Duration.ZERO).build();
			assertEquals(0, tenantCalls.get()); assertEquals(0, fixture.posts.get());
			AuthorizationRedirect redirect = client.beginAuthentication();
			Map<String,String> query = LocalProvider.form(redirect.getAuthorizationUri().getRawQuery());
			InMemoryPendingAuthorizationStore pending = InMemoryPendingAuthorizationStore.builder().clock(LocalProvider.CLOCK).build();
			assertEquals(com.revetsec.oauth.PendingAuthorizationSaveResult.SAVED,
                    redirect.getPendingAuthorization().saveToResult(pending, BINDING));
			// The synthetic code is the nonce so the test-only fixture can bind its independently signed token.
			AuthorizationResponse callback = ((com.revetsec.oauth.AuthorizationResponseParseResult.Succeeded) AuthorizationResponse.fromQueryStringResult("code=" + query.get("nonce") + "&state=" + query.get("state"))).getResponse();
			OidcAuthenticationResult result = client.completeAuthenticationResult(callback, PendingAuthorizationSource.fromStore(pending, BINDING), CALLBACK);
			if (mode.equals("valid") || mode.equals("refresh-switch")) {
				OidcAuthentication auth = assertInstanceOf(OidcAuthenticationResult.Succeeded.class, result).getAuthentication();
				assertEquals(LocalProvider.actualIssuer(LocalProvider.TENANT), auth.getIssuer());
				assertEquals("TEST-ONLY-example-user", auth.getSubject()); assertEquals(1, tenantCalls.get());
				if (mode.equals("valid")) {
					assertEquals(auth.getSubject(), assertInstanceOf(OidcUserInfoResult.Succeeded.class, client.fetchUserInfoResult(auth)).getUserInfo().getSubject()); assertEquals(2, tenantCalls.get());
				} else {
					fixture.tenant = LocalProvider.OTHER;
					OidcSessionReference stored = ((com.revetsec.oidc.OidcSessionReferenceParseResult.Succeeded) OidcSessionReference.fromSerializedFormResult(auth.getSessionReference().toSerializedForm())).getReference();
					OidcRefreshOutcome.Rejected failure = assertInstanceOf(OidcRefreshOutcome.Rejected.class, client.refreshResult(auth.getTokens().getRefreshToken().orElseThrow(), stored));
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

    @org.junit.jupiter.api.TestFactory @NonNull List<org.junit.jupiter.api.@NonNull DynamicTest> legacyEdDsaMetadataDoesNotAuthorizeFullySpecifiedEd25519Posts(){
        List<org.junit.jupiter.api.DynamicTest> cells=new ArrayList<>();for(String role:List.of("token","refresh","introspection","revocation"))cells.add(org.junit.jupiter.api.DynamicTest.dynamicTest("legacy-metadata-"+role,()->runLegacyMetadataRefusal(role)));return cells;
    }
    @org.junit.jupiter.api.TestFactory @NonNull List<org.junit.jupiter.api.@NonNull DynamicTest> mismatchedPrivateKeyCannotReleaseAnyCredentialRequest(){
        List<org.junit.jupiter.api.DynamicTest> cells=new ArrayList<>();for(JwsAlgorithm algorithm:List.of(JwsAlgorithm.RS256,JwsAlgorithm.ES256,JwsAlgorithm.ES384,JwsAlgorithm.ED25519))cells.add(org.junit.jupiter.api.DynamicTest.dynamicTest("mismatched-private-"+algorithm.getWireValue(),()->runMismatchedPrivate(algorithm)));return cells;
    }

    private static @NonNull String runLegacyMetadataRefusal(@NonNull String role)throws Exception{
        var registration=PrivateKeyClients.registration(SelectedKeyProfileTests.fresh(JwsAlgorithm.ED25519),JwsAlgorithm.ED25519,"application-key");AtomicInteger snapshots=new AtomicInteger();ClientAssertionKeyProvider provider=budget->{snapshots.incrementAndGet();return registration.getKeyProvider().getSigningKey(budget);};
        try(LocalProvider fixture=new LocalProvider(registration.getJwksPublisher(),JwsAlgorithm.ED25519,false,false)){
            String selected=JwsAlgorithm.ED25519.getWireValue();var metadata=fixture.metadataWithAlgorithms(role.equals("token")||role.equals("refresh")?"EdDSA":selected,role.equals("revocation")?"EdDSA":selected,role.equals("introspection")?"EdDSA":selected);
            OAuthClient client=PrivateKeyClients.withMetadata(metadata,"example-client",provider).httpClient(fixture.httpClient()).clock(LocalProvider.CLOCK).build();
            OAuthConfigurationException refused=assertThrows(OAuthConfigurationException.class,()->{switch(role){
                case "token"->ClientCredentialsTokenSource.withClient(client).build().getAccessTokenResult();
                case "refresh"->client.refreshResult(RefreshToken.fromValue(LocalProvider.REFRESH),TokenRequestOptions.builder().build());
                case "introspection"->TokenIntrospectionClient.withOAuthClient(client).expectedAudiences(Set.of("https://resource.example")).build().validateResult(((BearerTokenResult.Present)BearerToken.fromAuthorizationHeaderValuesResult(List.of("Bearer "+LocalProvider.ACCESS))).getToken());
                case "revocation"->client.revokeResult(LocalProvider.ACCESS,TokenTypeHint.ACCESS_TOKEN);
                default->throw new IllegalArgumentException("Unknown fixed role");
            }});
            assertEquals(OAuthException.Reason.CLIENT_ASSERTION_ENDPOINT_MISMATCH,refused.getReason());
            assertEquals(0,fixture.posts.get());assertEquals(0,fixture.assertions.get());assertEquals(1,snapshots.get());assertEquals(1,fixture.applicationJwksFetches.get());assertNull(fixture.failure);
            return "{\"case\":\"legacy-metadata-"+role+"\",\"credentialPosts\":0,\"keySnapshots\":1,\"outcome\":\""+refused.getReason().name()+"\",\"passed\":true}";
        }
    }

    private static @NonNull String runMismatchedPrivate(@NonNull JwsAlgorithm algorithm)throws Exception{
        KeyPair first=SelectedKeyProfileTests.fresh(algorithm),second=SelectedKeyProfileTests.fresh(algorithm);var registration=PrivateKeyClients.registration(new KeyPair(second.getPublic(),first.getPrivate()),algorithm,"application-key");AtomicInteger snapshots=new AtomicInteger();ClientAssertionKeyProvider provider=budget->{snapshots.incrementAndGet();return registration.getKeyProvider().getSigningKey(budget);};
        try(LocalProvider fixture=new LocalProvider(registration.getJwksPublisher(),algorithm,false,false)){
            var client=PrivateKeyClients.withMetadata(fixture.metadata(),"example-client",provider).httpClient(fixture.httpClient()).clock(LocalProvider.CLOCK).build();var source=ClientCredentialsTokenSource.withClient(client).build();OAuthConfigurationException refused=assertThrows(OAuthConfigurationException.class,source::getAccessTokenResult);
            assertEquals(OAuthException.Reason.CLIENT_ASSERTION_KEY_PAIR_MISMATCH,refused.getReason());assertEquals(0,fixture.posts.get());assertEquals(0,fixture.assertions.get());assertEquals(1,snapshots.get());assertEquals(1,fixture.applicationJwksFetches.get());assertNull(fixture.failure);
            return "{\"case\":\"mismatched-private-"+algorithm.getWireValue()+"\",\"credentialPosts\":0,\"keySnapshots\":1,\"outcome\":\""+refused.getReason().name()+"\",\"passed\":true}";
        }
    }
}
