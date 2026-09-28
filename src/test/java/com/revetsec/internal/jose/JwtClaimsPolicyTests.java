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

package com.revetsec.internal.jose;

import com.revetsec.internal.json.JsonCodec;
import com.revetsec.internal.json.JsonLimits;
import com.revetsec.jose.JoseException;
import com.revetsec.jose.JwsAlgorithm;
import com.revetsec.json.JsonObject;
import com.revetsec.testing.TestJsonWebKeys;
import com.revetsec.testing.TestJsonWebKeys.Fixture;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;

import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.stream.Stream;

/**
 * {@link JwtClaimsPolicy}: steps 10 to 14 of the plan's "JOSE semantics": the exact issuer (RFC 7519 section 4.1.1;
 * OpenID Connect Discovery section 4.3), the key's JWK {@code issuer} member bound to {@code iss} (INV-C6) with Entra's
 * template (M2-11), the audience (section 4.1.3), the time checks with skew at their boundaries (sections 4.1.4 to
 * 4.1.6), the required claims, and {@code cnf} (RFC 7800; INV-G6), in that order.
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 */
final class JwtClaimsPolicyTests {
	private static final String ISSUER = "https://issuer.example.com";
	private static final Instant NOW = Instant.parse("2026-09-27T12:00:00Z");
	private static final String TENANT = "72f988bf-86f1-41af-91ab-2d7cd011db47";
	private static final String TENANT_ISSUER = "https://login.microsoftonline.com/" + TENANT + "/v2.0";
	private static final JwtClaimsPolicy POLICY = JwtClaimsPolicy.fromSettings(ISSUER, Set.of("api"), Set.of(),
			Duration.ofSeconds(60));

	// Valid claims pass, with or without a key, and with a key whose issuer member equals iss.
	@Test
	void validClaimsPass() throws Exception {
		POLICY.check(claims(base()), null, NOW);
		POLICY.check(claims(base()), key(null), NOW);
		POLICY.check(claims(base()), key(ISSUER), NOW);
	}

	// Step 10 (RFC 7519 section 4.1.1; Discovery section 4.3): iss absent is MISSING_CLAIM, and any difference from
	// the configured issuer, even a trailing slash, a case change or a Unicode look-alike, is ISSUER_MISMATCH.
	@Test
	void theIssuerIsComparedExactly() throws Exception {
		assertReason(JoseException.Reason.MISSING_CLAIM, POLICY, "{\"aud\":\"api\",\"exp\":" + (NOW.getEpochSecond() + 300)
				+ "}", null);
		for (String issuer : List.of(ISSUER + "/", "https://ISSUER.example.com", "HTTPS://issuer.example.com",
				ISSUER + " ", " " + ISSUER, "https://issuer.example.com:443", "https://issuer.example.com.",
				"https://issuer.examp\u217Ce.com", "https://issuer.example.com/.", ""))
			assertReason(JoseException.Reason.ISSUER_MISMATCH, POLICY, base().put("iss", issuer).toJson(), null);
	}

	// INV-C6: a key whose JWK issuer member differs from iss never verifies that issuer's tokens, however close the
	// two strings are; a key without the member is not bound. ISSUER_MISMATCH still comes first.
	@Test
	void aKeyIssuerMemberMustEqualTheIssuer() throws Exception {
		for (String keyIssuer : List.of(ISSUER + "/", "https://other.example.com", "https://ISSUER.example.com", ""))
			assertReason(JoseException.Reason.KEY_ISSUER_MISMATCH, POLICY, base().toJson(), key(keyIssuer));

		assertReason(JoseException.Reason.ISSUER_MISMATCH, POLICY, base().put("iss", "https://other.example.com").toJson(),
				key("https://other.example.com"));
	}

	// M2-11: a key whose issuer member is exactly Entra's template verifies a token whose tid is a lowercase GUID and
	// whose iss is the template with that tid, for a configured tenant issuer.
	@Test
	void entrasTemplateBindsTheKeyThroughTheTenantId() throws Exception {
		JwtClaimsPolicy tenant = JwtClaimsPolicy.fromSettings(TENANT_ISSUER, Set.of("api"), Set.of(), Duration.ZERO);

		tenant.check(claims(entra(TENANT_ISSUER).put("tid", TENANT)), key(JwtClaimsPolicy.ENTRA_ISSUER_TEMPLATE), NOW);
		tenant.check(claims(entra(TENANT_ISSUER).put("tid", TENANT)), key(TENANT_ISSUER), NOW);
		tenant.check(claims(entra(TENANT_ISSUER)), key(TENANT_ISSUER), NOW);
		tenant.check(claims(entra(TENANT_ISSUER)), key(null), NOW);
	}

	// M2-11 negatives: the tid must be a whole lowercase GUID string and must substitute into the template to give
	// exactly iss; otherwise KEY_ISSUER_MISMATCH, never a pass.
	@TestFactory
	Stream<DynamicTest> entrasTemplateNeedsAMatchingLowercaseTenantId() {
		Map<String, @Nullable String> tids = new LinkedHashMap<>();
		tids.put("absent", null);
		tids.put("a number", "123");
		tids.put("null", "null");
		tids.put("an array", "[\"" + TENANT + "\"]");
		tids.put("uppercase", "\"" + TENANT.toUpperCase(Locale.ROOT) + "\"");
		tids.put("braced", "\"{" + TENANT + "}\"");
		tids.put("not a GUID", "\"not-a-guid\"");
		tids.put("a GUID without dashes", "\"" + TENANT.replace("-", "") + "\"");
		tids.put("a GUID with a trailing newline", "\"" + TENANT + "\\n\"");
		tids.put("a GUID with a non-hex letter", "\"" + TENANT.replace('f', 'g') + "\"");
		tids.put("another tenant's GUID", "\"9188040d-6c67-4c5b-b112-36a304b66dad\"");
		tids.put("the empty string", "\"\"");
		JwtClaimsPolicy tenant = JwtClaimsPolicy.fromSettings(TENANT_ISSUER, Set.of("api"), Set.of(), Duration.ZERO);

		return tids.entrySet().stream().map(entry -> DynamicTest.dynamicTest(entry.getKey(), () -> {
			String json = entra(TENANT_ISSUER).toJson();
			String tid = entry.getValue();
			if (tid != null)
				json = json.substring(0, json.length() - 1) + ",\"tid\":" + tid + "}";
			assertReason(JoseException.Reason.KEY_ISSUER_MISMATCH, tenant, json, key(JwtClaimsPolicy.ENTRA_ISSUER_TEMPLATE));
		}));
	}

	// M2-11: the tid must be a lowercase GUID even when substituting it would give iss exactly: a configured issuer
	// that holds an uppercase or braced GUID, a domain name, or path characters never makes the template match.
	@TestFactory
	Stream<DynamicTest> theTenantIdMustBeAGuidEvenWhenTheSubstitutionMatches() {
		return Stream.of(TENANT.toUpperCase(Locale.ROOT), "{" + TENANT + "}", "contoso.onmicrosoft.com",
				TENANT + "/v2.0/..", "common", TENANT.substring(1)).map(tid -> DynamicTest.dynamicTest(tid, () -> {
			String issuer = JwtClaimsPolicy.ENTRA_ISSUER_PREFIX + tid + JwtClaimsPolicy.ENTRA_ISSUER_SUFFIX;
			JwtClaimsPolicy policy = JwtClaimsPolicy.fromSettings(issuer, Set.of("api"), Set.of(), Duration.ZERO);
			assertReason(JoseException.Reason.KEY_ISSUER_MISMATCH, policy, entra(issuer).put("tid", tid).toJson(),
					key(JwtClaimsPolicy.ENTRA_ISSUER_TEMPLATE));
			policy.check(claims(entra(issuer).put("tid", tid)), key(issuer), NOW);
		}));
	}

	// M2-11: only the exact template bytes are a template; another host, placeholder spelling, a doubled placeholder,
	// a trailing slash or an extra path is compared literally with iss, and so fails.
	@TestFactory
	Stream<DynamicTest> onlyTheExactTemplateIsATemplate() {
		List<String> lookAlikes = List.of("https://login.microsoftonline.us/{tenantid}/v2.0",
				"https://login.microsoftonline.com/{TENANTID}/v2.0", "https://login.microsoftonline.com/{tid}/v2.0",
				"https://login.microsoftonline.com/{tenantid}{tenantid}/v2.0",
				"https://login.microsoftonline.com/{tenantid}/v2.0/", "https://login.microsoftonline.com/{tenantid}/v2.0/x",
				"https://login.microsoftonline.com/{tenantid}/v2.0?x", "http://login.microsoftonline.com/{tenantid}/v2.0",
				"https://LOGIN.microsoftonline.com/{tenantid}/v2.0", "https://tenant.ciamlogin.com/{tenantid}/v2.0",
				"https://login.microsoftonline.com/{tenantid}/v1.0", "https://sts.windows.net/{tenantid}/");
		JwtClaimsPolicy tenant = JwtClaimsPolicy.fromSettings(TENANT_ISSUER, Set.of("api"), Set.of(), Duration.ZERO);

		return lookAlikes.stream().map(keyIssuer -> DynamicTest.dynamicTest(keyIssuer, () -> assertReason(
				JoseException.Reason.KEY_ISSUER_MISMATCH, tenant, entra(TENANT_ISSUER).put("tid", TENANT).toJson(),
				key(keyIssuer))));
	}

	// M2-11: the template never admits a token for an issuer other than the configured one: iss is checked first, so
	// a matching tid with another iss is ISSUER_MISMATCH, and a configured issuer on another host never matches.
	@Test
	void theTemplateNeverWidensTheConfiguredIssuer() throws Exception {
		String otherTenant = "9188040d-6c67-4c5b-b112-36a304b66dad";
		String otherIssuer = "https://login.microsoftonline.com/" + otherTenant + "/v2.0";
		JwtClaimsPolicy tenant = JwtClaimsPolicy.fromSettings(TENANT_ISSUER, Set.of("api"), Set.of(), Duration.ZERO);

		assertReason(JoseException.Reason.ISSUER_MISMATCH, tenant, entra(otherIssuer).put("tid", otherTenant).toJson(),
				key(JwtClaimsPolicy.ENTRA_ISSUER_TEMPLATE));
		// Another tenant's tid with iss equal to the configured issuer: the substitution does not give iss.
		assertReason(JoseException.Reason.KEY_ISSUER_MISMATCH, tenant, entra(TENANT_ISSUER).put("tid", otherTenant)
				.toJson(), key(JwtClaimsPolicy.ENTRA_ISSUER_TEMPLATE));
		// A consumer-tenant key never verifies an enterprise tenant's token.
		assertReason(JoseException.Reason.KEY_ISSUER_MISMATCH, tenant, entra(TENANT_ISSUER).put("tid", TENANT).toJson(),
				key(otherIssuer));

		JwtClaimsPolicy sovereign = JwtClaimsPolicy.fromSettings("https://login.microsoftonline.us/" + TENANT + "/v2.0",
				Set.of("api"), Set.of(), Duration.ZERO);
		assertReason(JoseException.Reason.KEY_ISSUER_MISMATCH, sovereign, entra("https://login.microsoftonline.us/"
				+ TENANT + "/v2.0").put("tid", TENANT).toJson(), key(JwtClaimsPolicy.ENTRA_ISSUER_TEMPLATE));
	}

	// M2-11: the template is never a literal issuer. An app that configures the template itself, as Entra's common
	// discovery document publishes it, never gets a template-keyed key to verify a token whose iss is the template,
	// whatever its tid, because no tid substitutes into the template to give the template back.
	@TestFactory
	Stream<DynamicTest> theTemplateItselfIsNeverALiteralIssuer() {
		String template = JwtClaimsPolicy.ENTRA_ISSUER_TEMPLATE;
		JwtClaimsPolicy policy = JwtClaimsPolicy.fromSettings(template, Set.of("api"), Set.of(), Duration.ZERO);
		Map<String, @Nullable String> tids = new LinkedHashMap<>();
		tids.put("absent", null);
		tids.put("not a GUID", "NOT-A-GUID");
		tids.put("a lowercase GUID", TENANT);
		tids.put("the placeholder", "{tenantid}");

		return tids.entrySet().stream().map(entry -> DynamicTest.dynamicTest(entry.getKey(), () -> {
			TestClaims claims = entra(template);
			String tid = entry.getValue();
			if (tid != null)
				claims.put("tid", tid);
			assertReason(JoseException.Reason.KEY_ISSUER_MISMATCH, policy, claims.toJson(), key(template));
			// The same claims pass with a key that has no issuer member: only the template binding refuses them.
			policy.check(claims(claims), key(null), NOW);
		}));
	}

	// The tenant ID check is a whole lowercase GUID, exactly 8-4-4-4-12 hexadecimal digits.
	@Test
	void theTenantIdIsAWholeLowercaseGuid() {
		Assertions.assertTrue(JwtClaimsPolicy.isLowercaseGuid(TENANT));
		Assertions.assertTrue(JwtClaimsPolicy.isLowercaseGuid("00000000-0000-0000-0000-000000000000"));
		Assertions.assertTrue(JwtClaimsPolicy.isLowercaseGuid("ffffffff-ffff-ffff-ffff-ffffffffffff"));
		for (String value : List.of("", "72f988bf86f141af91ab2d7cd011db47", "72f988bf-86f1-41af-91ab-2d7cd011db4",
				"72f988bf-86f1-41af-91ab-2d7cd011db477", "72f988bf-86f1-41af-91ab_2d7cd011db47",
				"72f988bf-86f141af-91ab-2d7cd011db47-", "72F988BF-86F1-41AF-91AB-2D7CD011DB47",
				"72f988bf-86f1-41af-91ab-2d7cd011db4g", "72f988bf-86f1-41af-91ab-2d7cd011db4/",
				"72f988bf-86f1-41af-91ab-2d7cd011db4:", "72f988bf-86f1-41af-91ab-2d7cd011db4`",
				"72f988bf-86f1-41af-91ab-2d7cd011db4\u0660", "-2f988bf-86f1-41af-91ab-2d7cd011db47",
				"72f988bf-86f1-41af-91ab-2d7c-011db47", "72f988bf+86f1-41af-91ab-2d7cd011db47",
				"72f988bf086f1041af091ab02d7cd011db47"))
			Assertions.assertFalse(JwtClaimsPolicy.isLowercaseGuid(value), value);

		// Each dash is required where it stands: a hexadecimal digit in its place, with the length unchanged, fails.
		for (int dash : List.of(8, 13, 18, 23)) {
			Assertions.assertEquals('-', TENANT.charAt(dash));
			String undashed = TENANT.substring(0, dash) + "0" + TENANT.substring(dash + 1);
			Assertions.assertFalse(JwtClaimsPolicy.isLowercaseGuid(undashed), undashed);
		}
	}

	// Step 11 (RFC 7519 section 4.1.3): unless any audience is accepted, aud absent is MISSING_CLAIM, and aud with no
	// expected audience is AUDIENCE_MISMATCH, compared exactly; extra audiences beside an expected one are allowed.
	@Test
	void anExpectedAudienceMustBeInAud() throws Exception {
		JwtClaimsPolicy two = JwtClaimsPolicy.fromSettings(ISSUER, Set.of("api", "other-api"), Set.of(), Duration.ZERO);

		two.check(claims(base().put("aud", "other-api")), null, NOW);
		two.check(claims(withAudience("[\"x\",\"api\",\"y\"]")), null, NOW);
		assertReason(JoseException.Reason.MISSING_CLAIM, two, withoutAudience(), null);
		for (String audience : List.of("\"API\"", "\"api \"", "\"\"", "[\"x\",\"y\"]", "\"api/\""))
			assertReason(JoseException.Reason.AUDIENCE_MISMATCH, two, withAudience(audience), null);

		JwtClaimsPolicy any = JwtClaimsPolicy.fromSettings(ISSUER, null, Set.of(), Duration.ZERO);
		any.check(claims(withoutAudience()), null, NOW);
		any.check(claims(withAudience("[\"anything\"]")), null, NOW);
		Assertions.assertTrue(any.findExpectedAudiences().isEmpty());
	}

	// Step 12 (RFC 7519 sections 4.1.4 to 4.1.6): with skew s, exp + s - 1 s passes and exp + s is EXPIRED; nbf and
	// iat at now + s pass and at now + s + 1 s fail; at skews 0, 60 s and 5 minutes.
	@TestFactory
	Stream<DynamicTest> theTimeChecksHoldAtTheirBoundariesForEverySkew() {
		return Stream.of(Duration.ZERO, Duration.ofSeconds(60), Duration.ofMinutes(5)).map(skew -> DynamicTest.dynamicTest(
				"skew " + skew, () -> {
					JwtClaimsPolicy policy = JwtClaimsPolicy.fromSettings(ISSUER, Set.of("api"), Set.of(), skew);
					long s = skew.toSeconds();

					policy.check(claims(base().put("exp", NOW.getEpochSecond() - s + 1)), null, NOW);
					assertReason(JoseException.Reason.EXPIRED, policy, base().put("exp", NOW.getEpochSecond() - s).toJson(),
							null);
					policy.check(claims(base().put("nbf", NOW.getEpochSecond() + s)), null, NOW);
					assertReason(JoseException.Reason.NOT_YET_VALID, policy, base().put("nbf", NOW.getEpochSecond() + s + 1)
							.toJson(), null);
					policy.check(claims(base().put("iat", NOW.getEpochSecond() + s)), null, NOW);
					assertReason(JoseException.Reason.ISSUED_IN_FUTURE, policy, base().put("iat", NOW.getEpochSecond() + s + 1)
							.toJson(), null);
				}));
	}

	// Step 12 at sub-second precision: a fractional exp is a NumericDate, and expiry is at exp + s exactly, to the
	// nanosecond.
	@Test
	void theTimeChecksUseTheFullPrecisionOfBothInstants() throws Exception {
		JwtClaimsPolicy policy = JwtClaimsPolicy.fromSettings(ISSUER, Set.of("api"), Set.of(), Duration.ofSeconds(60));
		RegisteredClaims fractional = claims(withExpiry("1790000000.5"));
		Instant expiresAt = Instant.ofEpochSecond(1_790_000_000L, 500_000_000L);

		policy.check(fractional, null, expiresAt.plusSeconds(60).minusNanos(1));
		JoseFailure failure = Assertions.assertThrows(JoseFailure.class, () -> policy.check(fractional, null,
				expiresAt.plusSeconds(60)));
		Assertions.assertEquals(JoseException.Reason.EXPIRED, failure.getReason());
	}

	// Step 12: exp is always required.
	@Test
	void anAbsentExpIsAMissingClaim() throws Exception {
		JwtClaimsPolicy any = JwtClaimsPolicy.fromSettings(ISSUER, null, Set.of(), Duration.ofSeconds(60));
		assertReason(JoseException.Reason.MISSING_CLAIM, any, "{\"iss\":\"" + ISSUER + "\"}", null);
	}

	// INV-G1: an instant the skew arithmetic cannot represent (possible only in claims a later profile builds itself,
	// since the reader bounds NumericDates to years -9999 to 9999) fails the time step as EXPIRED; nothing escapes.
	@Test
	void anUnrepresentableInstantFailsTheTimeStepClosed() {
		RegisteredClaims farFuture = new RegisteredClaims(JsonObject.emptyInstance(), ISSUER, null, List.of("api"),
				Instant.MAX, null, null, null);
		RegisteredClaims ancientNotBefore = new RegisteredClaims(JsonObject.emptyInstance(), ISSUER, null, List.of("api"),
				NOW.plusSeconds(300), null, Instant.MIN, null);

		for (RegisteredClaims claims : List.of(farFuture, ancientNotBefore)) {
			JoseFailure failure = Assertions.assertThrows(JoseFailure.class, () -> POLICY.check(claims, null, NOW));
			Assertions.assertEquals(JoseException.Reason.EXPIRED, failure.getReason());
		}
	}

	// Step 13: each required claim is present and not JSON null; false, 0, "" and {} count as present.
	@Test
	void requiredClaimsMustBePresentAndNotNull() throws Exception {
		JwtClaimsPolicy policy = JwtClaimsPolicy.fromSettings(ISSUER, Set.of("api"), Set.of("scope", "tenant"),
				Duration.ZERO);

		for (String values : List.of("\"scope\":false,\"tenant\":0", "\"scope\":\"\",\"tenant\":{}", "\"scope\":[],"
				+ "\"tenant\":\"t\""))
			policy.check(claims(with(values)), null, NOW);
		for (String values : List.of("\"scope\":\"s\"", "\"tenant\":\"t\"", "\"scope\":null,\"tenant\":\"t\"",
				"\"scope\":\"s\",\"tenant\":null", "\"Scope\":\"s\",\"tenant\":\"t\""))
			assertReason(JoseException.Reason.MISSING_CLAIM, policy, with(values), null);
	}

	// Step 14 (RFC 7800; INV-G6): cnf, with any value, is CONFIRMATION_NOT_VERIFIED, because no possession is proven.
	@Test
	void aConfirmationClaimIsNeverAcceptedAsABearerToken() throws Exception {
		for (String value : List.of("{\"jkt\":\"0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I\"}", "{}", "null", "\"x\""))
			assertReason(JoseException.Reason.CONFIRMATION_NOT_VERIFIED, POLICY, with("\"cnf\":" + value), null);
	}

	// The checks run in order (issuer, key issuer, audience, time, required claims, cnf), and the first failure
	// names the reason.
	@Test
	void theFirstFailingCheckNamesTheReason() throws Exception {
		JwtClaimsPolicy policy = JwtClaimsPolicy.fromSettings(ISSUER, Set.of("api"), Set.of("scope"), Duration.ZERO);
		String everythingWrong = "{\"iss\":\"x\",\"aud\":\"x\",\"exp\":1,\"cnf\":{}}";

		assertReason(JoseException.Reason.ISSUER_MISMATCH, policy, everythingWrong, key("y"));
		String issuerRight = everythingWrong.replace("\"iss\":\"x\"", "\"iss\":\"" + ISSUER + "\"");
		assertReason(JoseException.Reason.KEY_ISSUER_MISMATCH, policy, issuerRight, key("y"));
		assertReason(JoseException.Reason.AUDIENCE_MISMATCH, policy, issuerRight, null);
		String audienceRight = issuerRight.replace("\"aud\":\"x\"", "\"aud\":\"api\"");
		assertReason(JoseException.Reason.EXPIRED, policy, audienceRight, null);
		String timeRight = audienceRight.replace("\"exp\":1", "\"exp\":" + (NOW.getEpochSecond() + 1));
		assertReason(JoseException.Reason.MISSING_CLAIM, policy, timeRight, null);
		assertReason(JoseException.Reason.CONFIRMATION_NOT_VERIFIED, policy, timeRight.replace("\"cnf\"",
				"\"scope\":1,\"cnf\""), null);
	}

	// The settings: a non-empty issuer and audiences, no empty audience or claim name, a skew not negative; the sets
	// are copied.
	@Test
	void settingsOutOfRangeAreRefused() {
		Assertions.assertThrows(IllegalArgumentException.class, () -> JwtClaimsPolicy.fromSettings("", null, Set.of(),
				Duration.ZERO));
		Assertions.assertThrows(IllegalArgumentException.class, () -> JwtClaimsPolicy.fromSettings(ISSUER, Set.of(),
				Set.of(), Duration.ZERO));
		Assertions.assertThrows(IllegalArgumentException.class, () -> JwtClaimsPolicy.fromSettings(ISSUER, Set.of(""),
				Set.of(), Duration.ZERO));
		Assertions.assertThrows(IllegalArgumentException.class, () -> JwtClaimsPolicy.fromSettings(ISSUER, null,
				Set.of(""), Duration.ZERO));
		Assertions.assertThrows(IllegalArgumentException.class, () -> JwtClaimsPolicy.fromSettings(ISSUER, null,
				Set.of(), Duration.ofNanos(-1)));
		Set<String> withNull = new HashSet<>(Arrays.asList("api", null));
		Assertions.assertThrows(NullPointerException.class, () -> JwtClaimsPolicy.fromSettings(ISSUER, withNull,
				Set.of(), Duration.ZERO));

		Set<String> audiences = new HashSet<>(Set.of("api"));
		JwtClaimsPolicy policy = JwtClaimsPolicy.fromSettings(ISSUER, audiences, Set.of("b", "a"), Duration.ofSeconds(5));
		audiences.add("changed");
		Assertions.assertEquals(Set.of("api"), policy.findExpectedAudiences().orElseThrow());
		Assertions.assertEquals(ISSUER, policy.getIssuer());
		Assertions.assertEquals(Duration.ofSeconds(5), policy.getClockSkew());
		Assertions.assertEquals("JwtClaimsPolicy{issuer=" + ISSUER + ", expectedAudiences=[api], requiredClaims=[a, b], "
				+ "clockSkew=PT5S}", policy.toString());
		Assertions.assertEquals("JwtClaimsPolicy{issuer=" + ISSUER + ", expectedAudiences=any, requiredClaims=[], "
				+ "clockSkew=PT0S}", JwtClaimsPolicy.fromSettings(ISSUER, null, Set.of(), Duration.ZERO).toString());
	}

	private static TestClaims base() {
		return TestClaims.empty().put("iss", ISSUER).put("aud", "api").put("exp", NOW.getEpochSecond() + 300);
	}

	private static TestClaims entra(String issuer) {
		return base().put("iss", issuer);
	}

	private static String withoutAudience() {
		return "{\"iss\":\"" + ISSUER + "\",\"exp\":" + (NOW.getEpochSecond() + 300) + "}";
	}

	private static String withAudience(String audience) {
		return "{\"iss\":\"" + ISSUER + "\",\"aud\":" + audience + ",\"exp\":" + (NOW.getEpochSecond() + 300) + "}";
	}

	private static String withExpiry(String expiry) {
		return "{\"iss\":\"" + ISSUER + "\",\"aud\":\"api\",\"exp\":" + expiry + "}";
	}

	private static String with(String members) {
		return "{\"iss\":\"" + ISSUER + "\",\"aud\":\"api\",\"exp\":" + (NOW.getEpochSecond() + 300) + "," + members + "}";
	}

	private static RegisteredClaims claims(TestClaims claims) throws JoseFailure {
		return claims(claims.toJson());
	}

	private static RegisteredClaims claims(String json) throws JoseFailure {
		return JwtClaimsReader.read(json.getBytes(StandardCharsets.UTF_8), JsonLimits.jose(65_536));
	}

	private static VerificationKey key(@Nullable String issuer) throws Exception {
		VerificationKey key = JwkParser.parse((JsonObject) JsonCodec.parse(TestJsonWebKeys.withFixture(
				Fixture.IDP_SIGNING_RSA_2048).kid("k").toJson().getBytes(StandardCharsets.UTF_8), JsonLimits.jose(65_536)));
		return new VerificationKey(key.keyId(), key.keyType(), key.curve(), JwsAlgorithm.RS256, key.use(), issuer,
				key.thumbprintSha256(), key.publicKey());
	}

	private static void assertReason(JoseException.Reason reason,
																	 JwtClaimsPolicy policy,
																	 String json,
																	 @Nullable VerificationKey key) throws JoseFailure {
		RegisteredClaims claims = claims(json);
		JoseFailure failure = Assertions.assertThrows(JoseFailure.class, () -> policy.check(claims, key, NOW));
		Assertions.assertEquals(reason, failure.getReason(), json);
	}
}
