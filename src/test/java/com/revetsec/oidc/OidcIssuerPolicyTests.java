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

import com.revetsec.ErrorCategory;
import com.revetsec.StateSealer;
import com.revetsec.internal.encoding.QueryParameters;
import com.revetsec.internal.http.Deadline;
import com.revetsec.jose.*;
import com.revetsec.oauth.*;
import com.revetsec.testing.*;
import com.revetsec.testing.TestJsonWebKeys.Fixture;
import com.revetsec.testing.TestJws.Algorithm;
import org.junit.jupiter.api.*;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import javax.annotation.concurrent.ThreadSafe;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import java.io.IOException;
import java.net.*;
import java.net.http.*;
import java.time.*;
import java.util.*;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Executor;
import java.util.concurrent.atomic.*;
import java.util.function.Consumer;
import java.util.function.Predicate;
import java.util.stream.Stream;
import static org.junit.jupiter.api.Assertions.*;

final class OidcIssuerPolicyTests {
	private static final String COMMON = "https://login.microsoftonline.com/common/v2.0";
	private static final String ORGANIZATIONS = "https://login.microsoftonline.com/organizations/v2.0";
	private static final String TEMPLATE = "https://login.microsoftonline.com/{tenantid}/v2.0";
	private static final String TENANT = "11111111-2222-3333-4444-555555555555";
	private static final String OTHER = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
	private static final String CONSUMER = "9188040d-6c67-4c5b-b112-36a304b66dad";
	private static final String ACTUAL = issuer(TENANT);
	private static final String ACCESS = "TEST-ONLY-entra-access";
	private static final String NONCE = "TEST-ONLY-entra-nonce";
	private static final String CODE = "TEST-ONLY-entra-code";
	private static final URI CALLBACK = URI.create("https://rp.example/callback");
	private static final Instant NOW = Instant.parse("2026-10-02T12:00:00Z");
	private static final Clock CLOCK = Clock.fixed(NOW, ZoneOffset.UTC);

	@Test
	@SuppressWarnings("NullAway") // Required-null factory/parser inputs are deliberate negative contract cases.
	void exactDefaultAndSelectedParsersKeepConfiguredAndAdvertisedIssuersSeparate() throws Exception {
		AtomicInteger calls = new AtomicInteger();
		OidcIssuerPolicy policy = OidcIssuerPolicy.fromMicrosoftEntraMultiTenant(tenant -> { calls.incrementAndGet(); return true; });
		for (String configured : List.of(COMMON, ORGANIZATIONS)) {
			String json = metadataJson(TEMPLATE, "https://issuer.example");
			OidcProviderMetadata metadata = OidcProviderMetadata.fromJson(configured, json, policy);
			assertEquals(configured, metadata.getIssuer()); assertEquals(TEMPLATE, metadata.getAdvertisedIssuer());
			assertEquals(configured, metadata.oauthMetadata().getIssuer());
			assertThrows(OAuthException.class, () -> OidcProviderMetadata.fromJson(configured, json));
			assertThrows(OAuthException.class, () -> AuthorizationServerMetadata.fromJson(configured, json));
			assertThrows(IllegalArgumentException.class, () -> configured(metadata, policy).issuerPolicy(null).build());
			OidcClient built = configured(metadata, policy).build(); assertNotNull(built);
		}
		OidcProviderMetadata exact = OidcProviderMetadata.fromJson("https://issuer.example", metadataJson("https://issuer.example", "https://issuer.example"));
		assertEquals(exact.getIssuer(), exact.getAdvertisedIssuer()); assertEquals(0, calls.get());
		assertSame(OidcIssuerPolicy.exactInstance(), OidcIssuerPolicy.exactInstance());
		assertFalse(policy.toString().contains(TENANT));
		assertThrows(NullPointerException.class, () -> OidcIssuerPolicy.fromMicrosoftEntraMultiTenant(null));
		assertThrows(NullPointerException.class, () -> OidcProviderMetadata.fromJson(COMMON, "{}", null));
	}

	@TestFactory
	@NonNull Stream<@NonNull DynamicTest> onlyFixedIssuerAndAdvertisedTemplateShapesAreAccepted() {
		List<String> unsupported = List.of(ACTUAL, COMMON + "/", COMMON.toUpperCase(Locale.ROOT), COMMON + "?tenant=" + TENANT,
				"http://login.microsoftonline.com/common/v2.0", "https://login.microsoftonline.com:443/common/v2.0",
				"https://login.microsoftonline.com/common", "https://login.microsoftonline.us/common/v2.0",
				"https://login.microsoftonline.com.attacker.test/common/v2.0", "https://example.b2clogin.com/common/v2.0",
				"https://example.ciamlogin.com/common/v2.0", "https://login.microsoftonline.com/v2.0");
		OidcIssuerPolicy policy = OidcIssuerPolicy.fromMicrosoftEntraMultiTenant(tenant -> { fail("unverified tenant"); return false; });
		Stream<DynamicTest> configured = unsupported.stream().map(value -> DynamicTest.dynamicTest("configured:" + value, () -> {
			assertThrows(IllegalArgumentException.class, () -> OidcProviderMetadata.fromJson(value, metadataJson(TEMPLATE, "https://issuer.example"), policy));
			assertThrows(IllegalArgumentException.class, () -> OidcClient.withIssuer(value).clientId("client").redirectUri(CALLBACK).issuerPolicy(policy).build());
		}));
		Stream<DynamicTest> advertised = Stream.of(COMMON, ACTUAL, TEMPLATE + "/", TEMPLATE.replace("{tenantid}", "{tenantId}"), TEMPLATE.replace("login.microsoftonline.com", "evil.test"), TEMPLATE.replace("{tenantid}", "%7Btenantid%7D"))
				.map(value -> DynamicTest.dynamicTest("advertised:" + value, () -> assertThrows(OAuthException.class,
						() -> OidcProviderMetadata.fromJson(COMMON, metadataJson(value, "https://issuer.example"), policy))));
		return Stream.concat(configured, advertised);
	}

	@TestFactory
	@NonNull Stream<@NonNull DynamicTest> selectedAlgorithmsAndBothKeyIssuerFormsValidateUnderBothTrustIssuers() {
		return Stream.of(Algorithm.RS256, Algorithm.RS384, Algorithm.PS256).flatMap(algorithm -> Stream.of(COMMON, ORGANIZATIONS)
				.flatMap(trust -> Stream.of(TEMPLATE, ACTUAL).map(keyIssuer -> DynamicTest.dynamicTest(algorithm + ":" + trust + ":" + keyIssuer, () -> {
			AtomicInteger calls = new AtomicInteger(); List<String> seen = new ArrayList<>();
			OidcIssuerPolicy policy = OidcIssuerPolicy.fromMicrosoftEntraMultiTenant(tenant -> { calls.incrementAndGet(); seen.add(tenant); return true; });
			Map<String,String> claims = claims(TENANT, NONCE); String compact = sign(claims, algorithm, false);
			IdToken token = validator(trust, keyIssuer, algorithm, policy, CLOCK, OidcObserver.disabledInstance()).validate(compact, NONCE, ACCESS, CODE, null, Set.of());
			assertEquals(ACTUAL, token.getClaims().getIssuer().orElseThrow()); assertEquals(List.of(TENANT), seen); assertEquals(1, calls.get());
		}))));
	}

	@TestFactory
	@NonNull Stream<@NonNull DynamicTest> fixedClaimsAndFullOidcProfileRejectBeforeApplicationPredicate() {
		record Case(@NonNull String name, OidcValidationException.@NonNull Reason reason, @NonNull Consumer<@NonNull Map<@NonNull String,@NonNull String>> change) { }
		return Stream.of(
			new Case("missing tid", OidcValidationException.Reason.ISSUER_MISMATCH, c -> c.remove("tid")),
			new Case("uppercase tid", OidcValidationException.Reason.ISSUER_MISMATCH, c -> c.put("tid", JsonText.string(OTHER.toUpperCase(Locale.ROOT)))),
			new Case("non string tid", OidcValidationException.Reason.ISSUER_MISMATCH, c -> c.put("tid", "1")),
			new Case("malformed tid", OidcValidationException.Reason.ISSUER_MISMATCH, c -> c.put("tid", "\"short\"")),
			new Case("template iss", OidcValidationException.Reason.ISSUER_MISMATCH, c -> c.put("iss", JsonText.string(TEMPLATE))),
			new Case("other tenant iss", OidcValidationException.Reason.ISSUER_MISMATCH, c -> c.put("iss", JsonText.string(issuer(OTHER)))),
			new Case("foreign host", OidcValidationException.Reason.ISSUER_MISMATCH, c -> c.put("iss", JsonText.string(ACTUAL.replace("login.microsoftonline.com", "evil.test")))),
			new Case("nonce", OidcValidationException.Reason.NONCE_MISMATCH, c -> c.put("nonce", "\"other\"")),
			new Case("missing nonce", OidcValidationException.Reason.NONCE_MISSING, c -> c.remove("nonce")),
			new Case("aud", OidcValidationException.Reason.AUDIENCE_MISMATCH, c -> c.put("aud", "\"other\"")),
			new Case("extra aud", OidcValidationException.Reason.UNTRUSTED_AUDIENCE, c -> c.put("aud", "[\"client\",\"other\"]")),
			new Case("azp", OidcValidationException.Reason.AUTHORIZED_PARTY_MISMATCH, c -> c.put("azp", "\"other\"")),
			new Case("exp", OidcValidationException.Reason.EXPIRED, c -> c.put("exp", Long.toString(NOW.getEpochSecond()))),
			new Case("future iat", OidcValidationException.Reason.ISSUED_IN_FUTURE, c -> c.put("iat", Long.toString(NOW.plusSeconds(1).getEpochSecond()))),
			new Case("future nbf", OidcValidationException.Reason.NOT_YET_VALID, c -> c.put("nbf", Long.toString(NOW.plusSeconds(1).getEpochSecond()))),
			new Case("confirmation", OidcValidationException.Reason.ID_TOKEN_UNSUPPORTED, c -> c.put("cnf", "{}")),
			new Case("at hash", OidcValidationException.Reason.ACCESS_TOKEN_HASH_MISMATCH, c -> c.put("at_hash", "\"bad\"")),
			new Case("c hash", OidcValidationException.Reason.CODE_HASH_MISMATCH, c -> c.put("c_hash", "\"bad\"")),
			new Case("age", OidcValidationException.Reason.TOO_OLD, c -> c.put("iat", Long.toString(NOW.minusSeconds(1000).getEpochSecond()))),
			new Case("subject", OidcValidationException.Reason.INVALID_SUBJECT, c -> c.put("sub", "\"é\"")))
			.map(row -> DynamicTest.dynamicTest(row.name(), () -> {
			AtomicInteger calls = new AtomicInteger(); Map<String,String> claims = claims(TENANT, NONCE); row.change().accept(claims);
			OidcIssuerPolicy policy = OidcIssuerPolicy.fromMicrosoftEntraMultiTenant(tenant -> { calls.incrementAndGet(); return true; });
			OidcValidationException failure = assertThrows(OidcValidationException.class, () -> validator(COMMON, TEMPLATE, Algorithm.RS256, policy, CLOCK, OidcObserver.disabledInstance())
					.validate(sign(claims, Algorithm.RS256, false), NONCE, ACCESS, CODE, null, Set.of()));
			assertEquals(row.reason(), failure.getReason()); assertEquals(0, calls.get()); assertNull(failure.getCause());
		}));
	}

	@TestFactory
	@NonNull Stream<@NonNull DynamicTest> verifyingKeyIssuerIsRequiredAndMalformedClaimsCannotBeatTheSignature() {
		return Stream.of("missing", "https://foreign.test", issuer(OTHER), TEMPLATE + "/", TEMPLATE.replace("tenantid", "tenantId"), ACTUAL + "/")
				.map(value -> DynamicTest.dynamicTest(value, () -> {
			AtomicInteger calls = new AtomicInteger(); OidcIssuerPolicy policy = OidcIssuerPolicy.fromMicrosoftEntraMultiTenant(tenant -> { calls.incrementAndGet(); return true; });
			IdTokenValidator validator = validator(COMMON, value.equals("missing") ? null : value, Algorithm.RS256, policy, CLOCK, OidcObserver.disabledInstance());
			OidcValidationException failure = assertThrows(OidcValidationException.class, () -> validator.validate(sign(claims(TENANT, NONCE), Algorithm.RS256, false), NONCE, ACCESS, CODE, null, Set.of()));
			assertEquals(Optional.of(JoseException.Reason.KEY_ISSUER_MISMATCH), failure.getJoseReason());
			Map<String,String> malformed = claims(TENANT, NONCE); malformed.put("tid", "null");
			OidcValidationException forged = assertThrows(OidcValidationException.class, () -> validator.validate(sign(malformed, Algorithm.RS256, true), NONCE, ACCESS, CODE, null, Set.of()));
			assertEquals(OidcValidationException.Reason.ID_TOKEN_SIGNATURE_INVALID, forged.getReason()); assertEquals(0, calls.get());
		}));
	}

	@Test
	void genericExactTenantValidationStaysExactEvenWithSharedCommonKeys() {
		StaticJsonWebKeySource shared = keys(TEMPLATE, "RS256");
		JwtValidator exact = JwtValidator.withIssuer(ACTUAL).jsonWebKeySource(shared).expectedAudiences(Set.of("client")).clock(CLOCK).clockSkew(Duration.ZERO).build();
		assertEquals(ACTUAL, exact.validate(sign(claims(TENANT, NONCE), Algorithm.RS256, false)).getClaims().getIssuer().orElseThrow());
		for (String tenant : List.of(OTHER, CONSUMER)) assertEquals(JoseException.Reason.ISSUER_MISMATCH, assertThrows(JoseException.class,
				() -> exact.validate(sign(claims(tenant, NONCE), Algorithm.RS256, false))).getReason());
		OidcIssuerPolicy first = OidcIssuerPolicy.fromMicrosoftEntraMultiTenant(tenant -> tenant.equals(TENANT));
		OidcIssuerPolicy second = OidcIssuerPolicy.fromMicrosoftEntraMultiTenant(tenant -> false);
		assertNotSame(first, second);
		assertEquals(OidcValidationException.Reason.TENANT_NOT_ALLOWED, assertThrows(OidcValidationException.class,
				() -> validator(COMMON, TEMPLATE, Algorithm.RS256, second, CLOCK, OidcObserver.disabledInstance()).validate(sign(claims(TENANT, NONCE), Algorithm.RS256, false), NONCE, ACCESS, CODE, null, Set.of())).getReason());
	}

	@TestFactory
	@NonNull Stream<@NonNull DynamicTest> predicateFailurePartitionAndConsumerTenantHaveNoCauseOrPolicyDisclosure() {
		return Stream.of("false", "runtime", "error", "consumer-deny", "consumer-allow", "vm", "interrupt").map(mode -> DynamicTest.dynamicTest(mode, () -> {
			String tenant = mode.startsWith("consumer") ? CONSUMER : TENANT;
			InternalError fatal = new InternalError("TEST-ONLY-predicate-secret");
			OidcIssuerPolicy policy = OidcIssuerPolicy.fromMicrosoftEntraMultiTenant(value -> switch(mode) {
				case "runtime" -> throw new IllegalStateException("TEST-ONLY-predicate-secret");
				case "error" -> throw new AssertionError("TEST-ONLY-predicate-secret");
				case "vm" -> throw fatal;
				case "interrupt" -> { Thread.currentThread().interrupt(); yield true; }
				case "consumer-allow" -> value.equals(CONSUMER);
				default -> false;
			});
			IdTokenValidator validator = validator(COMMON, TEMPLATE, Algorithm.RS256, policy, CLOCK, OidcObserver.disabledInstance());
			String compact = sign(claims(tenant, NONCE), Algorithm.RS256, false);
			try {
				if (mode.equals("vm")) assertSame(fatal, assertThrows(InternalError.class, () -> validator.validate(compact, NONCE, ACCESS, CODE, null, Set.of())));
				else if (mode.equals("consumer-allow")) assertEquals(issuer(CONSUMER), validator.validate(compact, NONCE, ACCESS, CODE, null, Set.of()).getClaims().getIssuer().orElseThrow());
				else if (mode.equals("runtime") || mode.equals("error") || mode.equals("interrupt")) {
					OAuthException failure = assertThrows(OAuthException.class, () -> validator.validate(compact, NONCE, ACCESS, CODE, null, Set.of()));
					assertEquals(mode.equals("interrupt") ? OAuthException.Reason.INTERRUPTED : OAuthException.Reason.ISSUER_POLICY_UNAVAILABLE, failure.getReason());
					assertNull(failure.getCause()); assertEquals(0, failure.getSuppressed().length); assertFalse(failure.toString().contains("TEST-ONLY-predicate-secret"));
					assertFalse(failure.isTransient());
					if (!mode.equals("interrupt")) { assertInstanceOf(OAuthConfigurationException.class, failure); assertEquals(ErrorCategory.CONFIGURATION, failure.getCategory()); }
				} else assertEquals(OidcValidationException.Reason.TENANT_NOT_ALLOWED, assertThrows(OidcValidationException.class,
						() -> validator.validate(compact, NONCE, ACCESS, CODE, null, Set.of())).getReason());
			} finally { if (mode.equals("interrupt")) assertTrue(Thread.interrupted()); }
		}));
	}

	@TestFactory
	@NonNull Stream<@NonNull DynamicTest> callbackCannotExtendBudgetOrExpiryOrRollBackClock() {
		return Stream.of("expiry", "rollback", "deadline", "already-expired").map(mode -> DynamicTest.dynamicTest(mode, () -> {
			TestClock clock = TestClock.fromInstant(NOW); AtomicInteger calls = new AtomicInteger();
			Deadline deadline = Deadline.fromNow(mode.equals("already-expired") ? Duration.ZERO : Duration.ofMillis(mode.equals("deadline") ? 1000 : 10000));
			OidcIssuerPolicy policy = OidcIssuerPolicy.fromMicrosoftEntraMultiTenant(tenant -> {
				calls.incrementAndGet();
				if (mode.equals("expiry")) clock.advance(Duration.ofSeconds(300));
				if (mode.equals("rollback")) clock.set(NOW.minusSeconds(1));
				if (mode.equals("deadline")) { while (deadline.remainingNanos() > 0) Thread.onSpinWait(); }
				return true;
			});
			IdTokenValidator validator = validator(COMMON, TEMPLATE, Algorithm.RS256, policy, clock, OidcObserver.disabledInstance());
			String compact = sign(claims(TENANT, NONCE), Algorithm.RS256, false);
			if (mode.equals("expiry")) assertEquals(OidcValidationException.Reason.EXPIRED, assertThrows(OidcValidationException.class,
					() -> validator.validate(compact, NONCE, ACCESS, CODE, null, Set.of(), deadline)).getReason());
			else assertEquals(mode.equals("rollback") ? OAuthException.Reason.ISSUER_POLICY_UNAVAILABLE : OAuthException.Reason.NETWORK_FAILURE,
					assertThrows(OAuthException.class, () -> validator.validate(compact, NONCE, ACCESS, CODE, null, Set.of(), deadline)).getReason());
			assertEquals(mode.equals("already-expired") ? 0 : 1, calls.get());
		}));
	}

	@Test
	void lazyDiscoveryUsesPolicyAndPreservesActualTenantIdentityAndCallbackIssuer() throws Exception {
		try (TestHttpsServer server = TestHttpsServer.start()) {
			AtomicInteger calls = new AtomicInteger(); List<String> events = new ArrayList<>();
			OidcIssuerPolicy policy = OidcIssuerPolicy.fromMicrosoftEntraMultiTenant(tenant -> { calls.incrementAndGet(); return tenant.equals(TENANT); });
			respond(server,"/discovery", "application/json", metadataJson(TEMPLATE,server.getBaseUri().toString()));
			respond(server,"/jwks","application/json",keyJson(TEMPLATE,"RS256"));
			OidcClient client = OidcClient.withIssuer(COMMON).issuerPolicy(policy).clientId("client").redirectUri(CALLBACK).clock(CLOCK)
					.httpClient(new LocalDiscoveryClient(server)).observer(observer(events)).build();
			assertEquals(List.of("enable"), events); assertEquals(0, server.getRequests().size()); assertEquals(0,calls.get());
			AuthorizationRedirect redirect = client.beginAuthentication(); assertEquals(1,server.getHitCount("/discovery")); assertEquals(0,calls.get());
			respond(server,"/token","application/json",response(sign(claims(TENANT,nonce(redirect)),Algorithm.RS256,false)));
			OidcAuthentication auth = client.completeAuthentication(callback(redirect,null),sealed(redirect),CALLBACK);
			assertEquals(ACTUAL,auth.getIssuer()); assertEquals(1,calls.get()); assertEquals(List.of("enable","use"),events);
			assertEquals(1,server.getHitCount("/jwks")); assertEquals(1,server.getHitCount("/token"));
			AuthorizationRedirect another = client.beginAuthentication();
			assertThrows(OAuthValidationException.class, () -> client.completeAuthentication(callback(another,ACTUAL),sealed(another),CALLBACK));
			assertEquals(1,server.getHitCount("/token")); assertEquals(1,calls.get());
		}
	}

	@Test
	void currentTenantAndClientProofAreCheckedBeforeUserInfoBearerDisclosure() throws Exception {
		try (TestHttpsServer server = TestHttpsServer.start()) {
			AtomicBoolean allow = new AtomicBoolean(true); AtomicInteger calls = new AtomicInteger();
			OidcIssuerPolicy policy = OidcIssuerPolicy.fromMicrosoftEntraMultiTenant(tenant -> { calls.incrementAndGet(); return allow.get(); });
			OidcClient first=client(server,policy).build(); OidcClient second=client(server,policy).build(); OidcAuthentication auth=login(server,first,TENANT);
			respond(server,"/userinfo","application/json","{\"sub\":\"subject\"}");
			assertEquals(OidcValidationException.Reason.USERINFO_AUTHENTICATION_MISMATCH,assertThrows(OidcValidationException.class,()->second.fetchUserInfo(auth)).getReason());
			assertEquals(1,calls.get()); assertEquals(0,server.getHitCount("/userinfo"));
			allow.set(false); assertEquals(OidcValidationException.Reason.TENANT_NOT_ALLOWED,assertThrows(OidcValidationException.class,()->first.fetchUserInfo(auth)).getReason());
			assertEquals(2,calls.get()); assertEquals(0,server.getHitCount("/userinfo"));
			allow.set(true); OidcUserInfo info=first.fetchUserInfo(auth); assertEquals(ACTUAL,info.getIssuer()); assertEquals(3,calls.get());
			assertEquals(Optional.of("Bearer "+ACCESS),server.getRequests("/userinfo").get(0).getHeader("Authorization"));
		}
	}

	@TestFactory
	@NonNull Stream<@NonNull DynamicTest> signedUserInfoUsesTrustedTenantBindingAndOptionalTidButRequiresKeyIssuer() {
		record Case(@NonNull String name, @Nullable String keyIssuer, @NonNull Consumer<@NonNull Map<@NonNull String,@NonNull String>> change, boolean accepted) { }
		return Stream.of(new Case("missing tid",TEMPLATE,c->c.remove("tid"),true),new Case("present tid",ACTUAL,c->{},true),
			new Case("other tid",TEMPLATE,c->c.put("tid",JsonText.string(OTHER)),false),new Case("null tid",TEMPLATE,c->c.put("tid","null"),false),
			new Case("missing key issuer",null,c->{},false),new Case("other key issuer",issuer(OTHER),c->{},false),
			new Case("foreign key issuer","https://evil.test",c->{},false),new Case("foreign iss",TEMPLATE,c->c.put("iss","\"https://evil.test\""),false),
			new Case("aud",TEMPLATE,c->c.put("aud","\"other\""),false),new Case("sub",TEMPLATE,c->c.put("sub","\"other\""),false),
			new Case("expiry",TEMPLATE,c->c.put("exp",Long.toString(NOW.getEpochSecond())),false),
			new Case("no expiry",TEMPLATE,c->c.remove("exp"),true),new Case("cnf",TEMPLATE,c->c.put("cnf","{}"),false))
			.map(row->DynamicTest.dynamicTest(row.name(),()->{
			Map<String,String> claims=claims(TENANT,NONCE);row.change().accept(claims);String compact=sign(claims,Algorithm.RS256,false);
			if(row.accepted()) assertEquals("subject",UserInfoValidator.signed(compact,ACTUAL,"client","subject",JwsAlgorithm.RS256,keys(row.keyIssuer(),"RS256"),Duration.ZERO,CLOCK,OidcObserver.disabledInstance(),Set.of(),Deadline.fromNow(Duration.ofSeconds(10)),true).findString("sub").orElseThrow());
			else assertThrows(OidcValidationException.class,()->UserInfoValidator.signed(compact,ACTUAL,"client","subject",JwsAlgorithm.RS256,keys(row.keyIssuer(),"RS256"),Duration.ZERO,CLOCK,OidcObserver.disabledInstance(),Set.of(),Deadline.fromNow(Duration.ofSeconds(10)),true));
		}));
	}

	@Test
	void signedUserInfoPublicPathAllowsMissingTidOnlyWithOriginalAuthentication() throws Exception {
		try(TestHttpsServer server=TestHttpsServer.start()){
			OidcIssuerPolicy policy=OidcIssuerPolicy.fromMicrosoftEntraMultiTenant(tenant->true);
			OidcClient client=client(server,policy).userInfoSignedResponseAlgorithm(JwsAlgorithm.RS256).build();OidcAuthentication auth=login(server,client,TENANT);
			Map<String,String> claims=claims(TENANT,NONCE);claims.remove("tid");respond(server,"/userinfo","application/jwt",sign(claims,Algorithm.RS256,false));
			assertEquals(ACTUAL,client.fetchUserInfo(auth).getIssuer());
		}
	}

	@Test
	void restoredReferenceRefreshWithoutIdTokenCreatesNoNewPredicateOrIdentityAndKeepsUserInfoAssociation() throws Exception {
		try(TestHttpsServer server=TestHttpsServer.start()){
			AtomicInteger calls=new AtomicInteger();OidcIssuerPolicy policy=OidcIssuerPolicy.fromMicrosoftEntraMultiTenant(tenant->{calls.incrementAndGet();return true;});
			OidcClient client=client(server,policy).build();OidcAuthentication auth=login(server,client,TENANT);
			OidcSessionReference restored=OidcSessionReference.fromSerializedForm(auth.getSessionReference().toSerializedForm());
			respond(server,"/token","application/json",response(null));OidcRefreshResult refreshed=client.refresh(RefreshToken.fromValue("TEST-ONLY-refresh"),restored);
			assertTrue(refreshed.getIdToken().isEmpty());assertSame(restored,refreshed.getSessionReference());assertEquals(1,calls.get());
			respond(server,"/userinfo","application/json","{\"sub\":\"subject\"}");assertEquals(ACTUAL,client.fetchUserInfo(auth,refreshed).getIssuer());assertEquals(2,calls.get());
			OidcSessionReference invalid=OidcSessionReference.fromSerializedForm(auth.getSessionReference().toSerializedForm().replace(ACTUAL,"https://login.microsoftonline.com/v2.0"));
			int posts=server.getHitCount("/token");assertThrows(OidcValidationException.class,()->client.refresh(RefreshToken.fromValue("TEST-ONLY-refresh"),invalid));assertEquals(posts,server.getHitCount("/token"));assertEquals(2,calls.get());
		}
	}

	@TestFactory
	@NonNull Stream<@NonNull DynamicTest> refreshedIdTokensPreserveActualIssuerAndOriginalContinuityWithoutUnsignedRouting() {
		return Stream.of("valid","aud-array","other-tenant","sub","azp","older-iat","nonce","auth-time","c-hash").map(mode->DynamicTest.dynamicTest(mode,()->{
			try(TestHttpsServer server=TestHttpsServer.start()){
				AtomicInteger calls=new AtomicInteger();OidcIssuerPolicy policy=OidcIssuerPolicy.fromMicrosoftEntraMultiTenant(tenant->{calls.incrementAndGet();return true;});
				OidcClient client=client(server,policy).build();OidcAuthentication auth=login(server,client,TENANT);Map<String,String> claims=claims(TENANT,NONCE);claims.remove("nonce");
				switch(mode){case "aud-array"->claims.put("aud","[\"client\"]");case "other-tenant"->{claims.put("iss",JsonText.string(issuer(OTHER)));claims.put("tid",JsonText.string(OTHER));}case "sub"->claims.put("sub","\"other\"");case "azp"->claims.put("azp","\"client\"");case "older-iat"->claims.put("iat",Long.toString(NOW.minusSeconds(1).getEpochSecond()));case "nonce"->claims.put("nonce","\"other\"");case "auth-time"->claims.put("auth_time",Long.toString(NOW.getEpochSecond()));case "c-hash"->claims.put("c_hash","\"bad\"");default->{} }
				respond(server,"/token","application/json",response(sign(claims,Algorithm.RS256,false)));OidcSessionReference restored=OidcSessionReference.fromSerializedForm(auth.getSessionReference().toSerializedForm());
				if(mode.equals("valid")||mode.equals("aud-array")){OidcRefreshResult refreshed=client.refresh(RefreshToken.fromValue("TEST-ONLY-refresh"),restored);assertEquals(ACTUAL,refreshed.getIdToken().orElseThrow().getClaims().getIssuer().orElseThrow());assertSame(restored,refreshed.getSessionReference());assertEquals(2,calls.get());}
				else {assertThrows(OidcValidationException.class,()->client.refresh(RefreshToken.fromValue("TEST-ONLY-refresh"),restored));assertEquals(1,calls.get());}
				assertEquals(2,server.getHitCount("/token"));for(TestHttpsServer.RecordedRequest request:server.getRequests("/token"))assertEquals(server.uri("/token").getRawPath(),request.getUri().getRawPath());
			}
		}));
	}

	@Test
	void hmacAndUnsupportedExactMetadataFailLocallyAndObserversAreContained() throws Exception {
		AtomicInteger calls=new AtomicInteger();OidcIssuerPolicy policy=OidcIssuerPolicy.fromMicrosoftEntraMultiTenant(tenant->{calls.incrementAndGet();return true;});
		AtomicInteger enabled=new AtomicInteger();OidcObserver observer=new OidcObserver(){@Override public void didEnableMicrosoftEntraMultiTenant(){enabled.incrementAndGet();throw new AssertionError("ignored");}@Override public void didUseMicrosoftEntraMultiTenant(){throw new AssertionError("ignored");}};
		try(TestHttpsServer server=TestHttpsServer.start()){
			OidcClient built=client(server,policy).observer(observer).build();assertEquals(1,enabled.get());assertEquals(0,calls.get());assertEquals(0,server.getRequests().size());
			assertEquals(ACTUAL,login(server,built,TENANT).getIssuer());assertEquals(1,calls.get());
			assertThrows(IllegalArgumentException.class,()->client(server,policy).idTokenSigningAlgorithms(Set.of(JwsAlgorithm.HS256)).compatibility(Set.of(OidcCompatibilityMode.HMAC_ID_TOKENS)).build());
			assertEquals(1,enabled.get());
		}
	}

	@TestFactory
	@NonNull Stream<@NonNull DynamicTest> authenticationAgeAndAcrFailuresPrecedeApplicationTenantDecision() {
		return Stream.of("missing-auth-time", "old-auth-time", "insufficient-acr").map(mode -> DynamicTest.dynamicTest(mode, () -> {
			AtomicInteger calls = new AtomicInteger(); OidcIssuerPolicy policy = OidcIssuerPolicy.fromMicrosoftEntraMultiTenant(tenant -> { calls.incrementAndGet(); return true; });
			Map<String,String> claims = claims(TENANT, NONCE);
			if (mode.equals("old-auth-time")) claims.put("auth_time", Long.toString(NOW.minusSeconds(1).getEpochSecond()));
			OidcValidationException failure = assertThrows(OidcValidationException.class, () -> validator(COMMON, TEMPLATE, Algorithm.RS256, policy, CLOCK, OidcObserver.disabledInstance())
					.validate(sign(claims, Algorithm.RS256, false), NONCE, ACCESS, CODE, mode.equals("insufficient-acr") ? null : Duration.ZERO, mode.equals("insufficient-acr") ? Set.of("mfa") : Set.of()));
			assertEquals(mode.equals("insufficient-acr") ? OidcValidationException.Reason.INSUFFICIENT_ACR : mode.equals("old-auth-time") ? OidcValidationException.Reason.AUTHENTICATION_TOO_OLD : OidcValidationException.Reason.AUTH_TIME_MISSING, failure.getReason());
			assertEquals(0, calls.get());
		}));
	}

	@TestFactory
	@NonNull Stream<@NonNull DynamicTest> resultFacadeSeparatesTenantDenialFromPolicyInfrastructureFailure() {
		return Stream.of("denied", "unavailable").map(mode -> DynamicTest.dynamicTest(mode, () -> {
			try (TestHttpsServer server = TestHttpsServer.start()) {
				OidcIssuerPolicy policy = OidcIssuerPolicy.fromMicrosoftEntraMultiTenant(tenant -> { if (mode.equals("unavailable")) throw new IllegalStateException("TEST-ONLY-policy-secret"); return false; });
				OidcClient client = client(server, policy).build(); AuthorizationRedirect redirect = client.beginAuthentication();
				respond(server, "/token", "application/json", response(sign(claims(TENANT, nonce(redirect)), Algorithm.RS256, false)));
				if (mode.equals("denied")) {
					OidcAuthenticationResult result = client.completeAuthenticationResult(callback(redirect, null), sealed(redirect), CALLBACK);
					OidcAuthenticationResult.RejectedIdToken rejected = assertInstanceOf(OidcAuthenticationResult.RejectedIdToken.class, result);
					assertEquals(OidcValidationException.Reason.TENANT_NOT_ALLOWED, rejected.getReason()); assertFalse(rejected.toString().contains(ACCESS));
				} else {
					OAuthException failure = assertThrows(OAuthConfigurationException.class, () -> client.completeAuthenticationResult(callback(redirect, null), sealed(redirect), CALLBACK));
					assertEquals(OAuthException.Reason.ISSUER_POLICY_UNAVAILABLE, failure.getReason()); assertNull(failure.getCause()); assertFalse(failure.toString().contains("TEST-ONLY-policy-secret"));
				}
				assertEquals(1, server.getHitCount("/token"));
			}
		}));
	}

	private static @NonNull String issuer(@NonNull String tenant){return "https://login.microsoftonline.com/"+tenant+"/v2.0";}
	private static @NonNull String metadataJson(@NonNull String advertised,@NonNull String endpoints){return "{\"issuer\":"+JsonText.string(advertised)+",\"authorization_endpoint\":"+JsonText.string(endpoints+"/authorize")+",\"token_endpoint\":"+JsonText.string(endpoints+"/token")+",\"jwks_uri\":"+JsonText.string(endpoints+"/jwks")+",\"userinfo_endpoint\":"+JsonText.string(endpoints+"/userinfo")+",\"response_types_supported\":[\"code\"],\"subject_types_supported\":[\"public\"],\"id_token_signing_alg_values_supported\":[\"RS256\"]}";}
	private static @NonNull Map<@NonNull String,@NonNull String> claims(@NonNull String tenant,@NonNull String nonce){Map<String,String> claims=new LinkedHashMap<>();claims.put("iss",JsonText.string(issuer(tenant)));claims.put("tid",JsonText.string(tenant));claims.put("sub","\"subject\"");claims.put("aud","\"client\"");claims.put("iat",Long.toString(NOW.getEpochSecond()));claims.put("exp",Long.toString(NOW.plusSeconds(300).getEpochSecond()));claims.put("nonce",JsonText.string(nonce));return claims;}
	private static @NonNull String sign(@NonNull Map<@NonNull String,@NonNull String> claims,@NonNull Algorithm algorithm,boolean forged){return TestJws.withAlgorithm(algorithm).kid("key").payload(JsonText.object(new ArrayList<>(claims.entrySet()))).sign(forged?Fixture.NEGATIVE_ATTACKER_RSA_2048.getPrivateKey():Fixture.IDP_SIGNING_RSA_2048.getPrivateKey());}
	private static @NonNull String keyJson(@Nullable String issuer,@NonNull String algorithm){return TestJsonWebKeys.withFixture(Fixture.IDP_SIGNING_RSA_2048).kid("key").alg(algorithm).issuer(issuer).toKeySetJson();}
	private static @NonNull StaticJsonWebKeySource keys(@Nullable String issuer,@NonNull String algorithm){return StaticJsonWebKeySource.fromJsonWebKeySet(JsonWebKeySet.fromJson(keyJson(issuer,algorithm)));}
	private static @NonNull IdTokenValidator validator(@NonNull String trust,@Nullable String keyIssuer,@NonNull Algorithm algorithm,@NonNull OidcIssuerPolicy policy,@NonNull Clock clock,@NonNull OidcObserver observer){return new IdTokenValidator(trust,"client",keys(keyIssuer,algorithm.getWireValue()),Set.of(JwsAlgorithm.findByWireValue(algorithm.getWireValue()).orElseThrow()),Set.of(),Set.of(),Duration.ZERO,Duration.ofMinutes(5),clock,observer,false,policy);}
	private static OidcClient.@NonNull Builder configured(@NonNull OidcProviderMetadata metadata,@NonNull OidcIssuerPolicy policy){return OidcClient.withProviderMetadata(metadata).issuerPolicy(policy).clientId("client").redirectUri(CALLBACK).clock(CLOCK).jsonWebKeySource(keys(TEMPLATE,"RS256"));}
	private static OidcClient.@NonNull Builder client(@NonNull TestHttpsServer server,@NonNull OidcIssuerPolicy policy){OidcProviderMetadata metadata=OidcProviderMetadata.withIssuer(COMMON).authorizationEndpoint(server.uri("/authorize")).tokenEndpoint(server.uri("/token")).jwksUri(server.uri("/jwks")).userInfoEndpoint(server.uri("/userinfo")).build();return configured(metadata,policy).httpClient(TestTls.httpClient()).clockSkew(Duration.ZERO);}
	private static @NonNull OidcAuthentication login(@NonNull TestHttpsServer server,@NonNull OidcClient client,@NonNull String tenant)throws Exception{AuthorizationRedirect redirect=client.beginAuthentication();respond(server,"/token","application/json",response(sign(claims(tenant,nonce(redirect)),Algorithm.RS256,false)));return client.completeAuthentication(callback(redirect,null),sealed(redirect),CALLBACK);}
	private static @NonNull String response(@Nullable String compact){return "{\"access_token\":"+JsonText.string(ACCESS)+",\"refresh_token\":\"TEST-ONLY-refresh\",\"token_type\":\"Bearer\",\"expires_in\":300"+(compact==null?"":",\"id_token\":"+JsonText.string(compact))+"}";}
	private static void respond(@NonNull TestHttpsServer server,@NonNull String path,@NonNull String type,@NonNull String body){server.script(path,TestHttpsServer.Script.fromResponse(TestHttpsServer.Response.withStatus(200).header("Content-Type",type).body(body).build()));}
	private static @NonNull String nonce(@NonNull AuthorizationRedirect redirect)throws Exception{return QueryParameters.parse(redirect.getAuthorizationUri().getRawQuery()).getValues("nonce").get(0);}
	private static @NonNull PendingAuthorizationSource sealed(@NonNull AuthorizationRedirect redirect){StateSealer sealer=TestSealers.fromFixedKey();return PendingAuthorizationSource.fromSealedForm(redirect.getPendingAuthorization().toSealedForm(sealer,"entra"),sealer,"entra");}
	private static @NonNull AuthorizationResponse callback(@NonNull AuthorizationRedirect redirect,@Nullable String issuer)throws Exception{return AuthorizationResponse.fromQueryString("code="+CODE+"&state="+QueryParameters.parse(redirect.getAuthorizationUri().getRawQuery()).getValues("state").get(0)+(issuer==null?"":"&iss="+issuer));}
	private static @NonNull OidcObserver observer(@NonNull List<@NonNull String> events){return new OidcObserver(){@Override public void didEnableMicrosoftEntraMultiTenant(){events.add("enable");}@Override public void didUseMicrosoftEntraMultiTenant(){events.add("use");}};}

	/** Test-only mapping: real TLS/HTTP at a literal local endpoint, with no outbound Microsoft request. */
	@ThreadSafe
	private static final class LocalDiscoveryClient extends HttpClient {
		private final HttpClient delegate=TestTls.httpClient();private final URI local;
		LocalDiscoveryClient(@NonNull TestHttpsServer server){this.local=server.uri("/discovery");}
		private @NonNull HttpRequest map(@NonNull HttpRequest request){if(!request.uri().getHost().equals("login.microsoftonline.com"))return request;assertEquals(COMMON+"/.well-known/openid-configuration",request.uri().toString());HttpRequest.Builder builder=HttpRequest.newBuilder(this.local).method(request.method(),request.bodyPublisher().orElse(HttpRequest.BodyPublishers.noBody()));request.timeout().ifPresent(builder::timeout);request.headers().map().forEach((name,values)->values.forEach(value->builder.header(name,value)));return builder.build();}
		@Override public @NonNull Optional<@NonNull CookieHandler> cookieHandler(){return this.delegate.cookieHandler();}
		@Override public @NonNull Optional<@NonNull Duration> connectTimeout(){return this.delegate.connectTimeout();}
		@Override public @NonNull Redirect followRedirects(){return this.delegate.followRedirects();}
		@Override public @NonNull Optional<@NonNull ProxySelector> proxy(){return this.delegate.proxy();}
		@Override public @NonNull SSLContext sslContext(){return this.delegate.sslContext();}
		@Override public @NonNull SSLParameters sslParameters(){return this.delegate.sslParameters();}
		@Override public @NonNull Optional<@NonNull Authenticator> authenticator(){return this.delegate.authenticator();}
		@Override public @NonNull Version version(){return this.delegate.version();}
		@Override public @NonNull Optional<@NonNull Executor> executor(){return this.delegate.executor();}
		@Override public <T> @NonNull HttpResponse<@NonNull T> send(@NonNull HttpRequest request,HttpResponse.@NonNull BodyHandler<@NonNull T> handler)throws IOException,InterruptedException{return this.delegate.send(map(request),handler);}
		@Override public <T> @NonNull CompletableFuture<@NonNull HttpResponse<@NonNull T>> sendAsync(@NonNull HttpRequest request,HttpResponse.@NonNull BodyHandler<@NonNull T> handler){return this.delegate.sendAsync(map(request),handler);}
		@Override public <T> @NonNull CompletableFuture<@NonNull HttpResponse<@NonNull T>> sendAsync(@NonNull HttpRequest request,HttpResponse.@NonNull BodyHandler<@NonNull T> handler,HttpResponse.@NonNull PushPromiseHandler<@NonNull T> push){return this.delegate.sendAsync(map(request),handler,push);}
	}
}
