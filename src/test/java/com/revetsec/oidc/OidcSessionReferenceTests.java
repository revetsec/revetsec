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

import org.jspecify.annotations.NonNull;

import com.revetsec.*;
import com.revetsec.internal.json.*;
import com.revetsec.json.*;
import com.revetsec.testing.*;
import org.junit.jupiter.api.*;
import java.nio.charset.StandardCharsets;
import java.time.*;
import java.util.*;
import java.util.function.Consumer;
import java.util.stream.Stream;
import static org.junit.jupiter.api.Assertions.*;

final class OidcSessionReferenceTests {
	private static final Instant NOW=Instant.parse("2026-09-29T12:00:00Z");
	private static final Clock CLOCK=Clock.fixed(NOW,ZoneOffset.UTC);
	@Test
	void referenceFromValidatedAuthenticationRoundTripsWithoutCredentialsOrPersonalAttributes() throws Exception {
		try(TestHttpsServer server=TestHttpsServer.start()) {
			OidcRefreshTests.Login login=OidcRefreshTests.login(server,OidcRefreshTests.builder(server).build(),CLOCK);
			String storage=login.reference().toSerializedForm(); OidcSessionReference decoded=OidcSessionReference.fromSerializedForm(storage);
			assertEquals(storage,decoded.toSerializedForm()); assertEquals(login.reference().getSessionId(),decoded.getSessionId()); assertTrue(decoded.matchesNonce(login.nonce()));
			for(String secret:List.of(login.nonce(),login.refresh().getValue(),"TEST-ONLY-new-access","TEST-ONLY-identity-secret","\"exp\"","\"email\""))assertFalse(storage.contains(secret),"Reference retained non-continuity data");
			assertFalse(decoded.toString().contains("TEST-ONLY")); assertEquals(1,server.getRequests().size());
			for(var method:OidcSessionReference.class.getMethods()) assertFalse(Set.of(IdToken.class,OidcAuthentication.class,OidcUserInfo.class,com.revetsec.oauth.AccessToken.class,com.revetsec.oauth.RefreshToken.class).contains(method.getReturnType()),"Reference cannot return identity or credentials");
			JsonObject envelope=parse(storage);Map<String,JsonValue> fields=new LinkedHashMap<>(envelope.getMembers());Map<String,JsonValue> claims=new LinkedHashMap<>(((JsonObject)Objects.requireNonNull(fields.get("claims"))).getMembers());claims.put("sub",JsonString.fromValue("unverified-claimed-subject"));fields.put("claims",JsonObject.fromMembers(claims));
			// Parsing checks structure and never converts this changed comparison value into authenticated identity.
			OidcSessionReference changed=OidcSessionReference.fromSerializedForm(JsonObject.fromMembers(fields).toJson());assertTrue(changed.toSerializedForm().contains("unverified-claimed-subject"));assertFalse(changed.toString().contains("unverified-claimed-subject"));
		}
	}
	@Test
	void sealedReferenceBindsKeyContextAndLifetimeWithTheExistingUniformSealerFailure() throws Exception {
		try(TestHttpsServer server=TestHttpsServer.start()) {
			OidcSessionReference reference=OidcRefreshTests.login(server,OidcRefreshTests.builder(server).build(),CLOCK).reference();TestClock clock=TestClock.fromInstant(NOW);
			StateSealer sealer=StateSealer.withActiveKey(TestSealers.fixedKey("session-a")).clock(clock).build();String sealed=reference.toSealedForm(sealer,"oidc-session",Duration.ofSeconds(2));
			assertEquals(reference.toSerializedForm(),OidcSessionReference.fromSealedForm(sealed,sealer,"oidc-session").toSerializedForm());
			List<Runnable> failures=new ArrayList<>();failures.add(()->OidcSessionReference.fromSealedForm(sealed,sealer,"other-context"));failures.add(()->OidcSessionReference.fromSealedForm(sealed.substring(1),sealer,"oidc-session"));
			StateSealer other=StateSealer.withActiveKey(TestSealers.fixedKey("session-b")).clock(clock).build();failures.add(()->OidcSessionReference.fromSealedForm(sealed,other,"oidc-session"));
			for(Runnable action:failures){InvalidSealedStateException failure=assertThrows(InvalidSealedStateException.class,action::run);assertEquals("Sealed state is invalid.",failure.getMessage());assertNull(failure.getCause());assertEquals(0,failure.getSuppressed().length);assertFalse(failure.toString().contains(sealed));}
			clock.advance(Duration.ofSeconds(2));assertThrows(InvalidSealedStateException.class,()->OidcSessionReference.fromSealedForm(sealed,sealer,"oidc-session"));
			String wrongSchema=sealer.seal("{\"access_token\":\"TEST-ONLY-secret\"}","oidc-session",Duration.ofSeconds(2));assertEquals(OidcValidationException.Reason.SESSION_REFERENCE_INVALID,assertThrows(OidcValidationException.class,()->OidcSessionReference.fromSealedForm(wrongSchema,sealer,"oidc-session")).getReason());
			assertThrows(IllegalArgumentException.class,()->reference.toSealedForm(sealer,"oidc-session",Duration.ZERO));assertThrows(IllegalArgumentException.class,()->reference.toSealedForm(sealer,"oidc-session",Duration.ofDays(401)));
		}
	}
	@TestFactory
	@NonNull Stream<@NonNull DynamicTest> invalidSchemaDuplicatesVersionClaimTypesAndNonceDigestUseOneFixedReason() {
		record Case(@NonNull String name,@NonNull Consumer<@NonNull Map<@NonNull String,@NonNull JsonValue>> edit){}
		List<Case> cases=new ArrayList<>();
		for(String field:List.of("v","client_id","claims","nonce_digest")) {
			cases.add(new Case("missing "+field,m->m.remove(field)));cases.add(new Case("null "+field,m->m.put(field,JsonNull.defaultInstance())));
		}
		cases.add(new Case("future version",m->m.put("v",JsonNumber.fromValue(2L))));cases.add(new Case("string version",m->m.put("v",JsonString.fromValue("1"))));cases.add(new Case("empty client",m->m.put("client_id",JsonString.fromValue(""))));cases.add(new Case("client outside aud",m->m.put("client_id",JsonString.fromValue("other"))));cases.add(new Case("unknown field",m->m.put("access_token",JsonString.fromValue("TEST-ONLY-secret"))));
		for(String digest:List.of("","a","A".repeat(42),"A".repeat(44),"A".repeat(42)+"B","A".repeat(43)+"=","+/"))cases.add(new Case("invalid digest "+digest.length()+":"+digest, m->m.put("nonce_digest",JsonString.fromValue(digest))));
		for(String field:List.of("iss","sub","aud","iat")) {
			cases.add(new Case("missing claim "+field,m->editClaims(m,c->c.remove(field))));cases.add(new Case("wrong type "+field,m->editClaims(m,c->c.put(field,JsonNull.defaultInstance()))));
		}
		cases.add(new Case("empty issuer",m->editClaims(m,c->c.put("iss",JsonString.fromValue("")))));
		cases.add(new Case("empty subject",m->editClaims(m,c->c.put("sub",JsonString.fromValue("")))));cases.add(new Case("long subject",m->editClaims(m,c->c.put("sub",JsonString.fromValue("s".repeat(256))))));cases.add(new Case("unicode subject",m->editClaims(m,c->c.put("sub",JsonString.fromValue("é")))));
		cases.add(new Case("empty aud",m->editClaims(m,c->c.put("aud",JsonArray.fromElements(List.of())))));cases.add(new Case("mistyped aud element",m->editClaims(m,c->c.put("aud",JsonArray.fromElements(List.of(JsonNumber.fromValue(1L)))))));
		for(String field:List.of("azp","sid","auth_time"))cases.add(new Case("wrong optional type "+field,m->editClaims(m,c->c.put(field,JsonBoolean.trueInstance()))));
		cases.add(new Case("raw nonce",m->editClaims(m,c->c.put("nonce",JsonString.fromValue("TEST-ONLY-secret")))));cases.add(new Case("email field",m->editClaims(m,c->c.put("email",JsonString.fromValue("TEST-ONLY-secret")))));cases.add(new Case("iat outside supported range",m->editClaims(m,c->c.put("iat",JsonNumber.fromValue(Long.MAX_VALUE)))));
		return cases.stream().map(test->DynamicTest.dynamicTest(test.name(),()->{
			try(TestHttpsServer server=TestHttpsServer.start()) {
				OidcSessionReference reference=OidcRefreshTests.login(server,OidcRefreshTests.builder(server).build(),CLOCK).reference();Map<String,JsonValue> fields=new LinkedHashMap<>(parse(reference.toSerializedForm()).getMembers());test.edit().accept(fields);String changed=JsonObject.fromMembers(fields).toJson();assertInvalid(changed);
			}
		}));
	}
	@TestFactory
	@NonNull Stream<@NonNull DynamicTest> trustedReferenceSubjectAndStorageByteBoundsAreInclusive() {
		return Stream.of("s".repeat(255), "\u007f", "s".repeat(254) + "\u007f")
				.map(subject -> DynamicTest.dynamicTest("ASCII subject length " + subject.length(), () -> {
					try (TestHttpsServer server = TestHttpsServer.start()) {
						String storage = OidcRefreshTests.login(server, OidcRefreshTests.builder(server).build(), CLOCK).reference().toSerializedForm();
						Map<String, JsonValue> fields = new LinkedHashMap<>(parse(storage).getMembers());
						editClaims(fields, c -> c.put("sub", JsonString.fromValue(subject)));
						String changed = JsonObject.fromMembers(fields).toJson();
						assertEquals(changed, OidcSessionReference.fromSerializedForm(changed).toSerializedForm());
					}
				}));
	}

	@Test
	void trustedStorageAcceptsExactly64KibInAsciiAndUtf8AndRejectsOneByteMore() throws Exception {
		try (TestHttpsServer server = TestHttpsServer.start()) {
			String storage = OidcRefreshTests.login(server, OidcRefreshTests.builder(server).build(), CLOCK).reference().toSerializedForm();
			Map<String, JsonValue> fields = new LinkedHashMap<>(parse(storage).getMembers());
			for (String character : List.of("s", "é")) {
				editClaims(fields, c -> c.put("sid", JsonString.fromValue("")));
				int base = JsonObject.fromMembers(fields).toJson().getBytes(StandardCharsets.UTF_8).length;
				int width = character.getBytes(StandardCharsets.UTF_8).length;
				String padding = character.repeat((64 * 1_024 - base) / width) + "s".repeat((64 * 1_024 - base) % width);
				editClaims(fields, c -> c.put("sid", JsonString.fromValue(padding)));
				String exact = JsonObject.fromMembers(fields).toJson();
				assertEquals(64 * 1_024, exact.getBytes(StandardCharsets.UTF_8).length);
				assertEquals(exact, OidcSessionReference.fromSerializedForm(exact).toSerializedForm());
				editClaims(fields, c -> c.put("sid", JsonString.fromValue(padding + "s")));
				assertInvalid(JsonObject.fromMembers(fields).toJson());
			}
		}
	}

	@Test
	void malformedJsonUtf8ByteLimitsAndDuplicateKeysAreBoundedAndRedacted() throws Exception {
		for(String value:List.of("", "{}", "[]", "null", "{", "\ud800", "x".repeat(64*1024+1), "\""+"é".repeat(40*1024)+"\"", "{\"v\":1,\"v\":1}"))assertInvalid(value);
	}
	private static @NonNull JsonObject parse(@NonNull String value)throws Exception{return (JsonObject)JsonCodec.parse(value.getBytes(StandardCharsets.UTF_8),JsonLimits.protocolDocument(64*1024));}
	private static void editClaims(@NonNull Map<@NonNull String,@NonNull JsonValue> envelope,@NonNull Consumer<@NonNull Map<@NonNull String,@NonNull JsonValue>> edit){Map<String,JsonValue> claims=new LinkedHashMap<>(((JsonObject)Objects.requireNonNull(envelope.get("claims"))).getMembers());edit.accept(claims);envelope.put("claims",JsonObject.fromMembers(claims));}
	private static void assertInvalid(@NonNull String value){OidcValidationException failure=assertThrows(OidcValidationException.class,()->OidcSessionReference.fromSerializedForm(value));assertEquals(OidcValidationException.Reason.SESSION_REFERENCE_INVALID,failure.getReason());assertNull(failure.getCause());failure.addSuppressed(new IllegalArgumentException(value));assertEquals(0,failure.getSuppressed().length);assertFalse(failure.toString().contains("TEST-ONLY"));assertEquals("The OIDC session reference is invalid.",failure.getMessage());}
}
