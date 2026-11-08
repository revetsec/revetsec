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
import org.jspecify.annotations.Nullable;

import com.revetsec.OutboundUriPolicy;
import com.revetsec.StateSealer;
import com.revetsec.internal.encoding.QueryParameters;
import com.revetsec.json.JsonObject;
import com.revetsec.oauth.PendingAuthorizationSaveResult;
import com.revetsec.oauth.PendingAuthorizationStore;
import com.revetsec.testing.TestHttpsServer;
import com.revetsec.testing.TestJwk;
import com.revetsec.testing.TestJws;
import com.revetsec.testing.TestSealers;
import com.revetsec.testing.TestTls;
import org.junit.jupiter.api.Test;
import java.net.URI;
import java.security.Provider;
import java.security.ProviderException;
import java.security.SecureRandomSpi;
import java.security.Security;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import static org.junit.jupiter.api.Assertions.*;

final class OidcLogoutEdgeTests {
	private static final String BINDING="TEST-ONLY-logout-browser", SECRET="TEST-ONLY-logout-provider-secret", COMMON="https://login.microsoftonline.com/common/v2.0", TEMPLATE="https://login.microsoftonline.com/{tenantid}/v2.0", TENANT="11111111-2222-3333-4444-555555555555", ACTUAL="https://login.microsoftonline.com/"+TENANT+"/v2.0";
	@Test void endpointReservedAliasesAndMalformedQueriesAreRefusedBeforeEntropy() throws Exception {
		try(TestHttpsServer server=TestHttpsServer.start()) {
			Clock clock=Clock.fixed(OidcLogoutFixtures.NOW,ZoneOffset.UTC); OidcClient owner=OidcLogoutFixtures.builder(server,clock).build(); var login=OidcLogoutFixtures.login(server,owner,clock); var hint=owner.logoutHintFrom(login.authentication());
			Provider provider=new CountingProvider(); Security.insertProviderAt(provider,1); CountingRandom.calls.set(0);
			try {
				for(String name:List.of("id_token_hint","logout_hint","client_id","post_logout_redirect_uri","state","ui_locales")) for(String query:List.of(name+"=bad",name,"%"+Integer.toHexString(name.charAt(0))+name.substring(1)+"=bad")) {
					OidcClient client=OidcLogoutFixtures.builder(server,clock,server.uri("/logout?"+query)).build(); int before=CountingRandom.calls.get();assertReason(OidcLogoutException.Reason.ENDPOINT_NOT_PERMITTED,()->client.beginLogout(login.authentication().getSessionReference(),hint));assertEquals(before,CountingRandom.calls.get(),"invalid begin does not request entropy");
				}
				for(String query:List.of("a=1&a=2","a=1&%61=2","a=%C0%AF","a=%ED%A0%80","=value","a=1&","&a=1")) { OidcClient client=OidcLogoutFixtures.builder(server,clock,server.uri("/logout?"+query)).build(); int before=CountingRandom.calls.get();assertReason(OidcLogoutException.Reason.ENDPOINT_NOT_PERMITTED,()->client.beginLogout(login.authentication().getSessionReference(),hint));assertEquals(before,CountingRandom.calls.get(),"invalid begin does not request entropy"); }
				assertTrue(CountingRandom.calls.get()>0,"existing client construction performs its own initialization outside the measured begin");
			} finally {Security.removeProvider(provider.getName());}
		}
	}
	@Test void ordinaryEndpointQueryFlagsEmptyQueryAndNonReservedValuesArePreserved() throws Exception {
		try(TestHttpsServer server=TestHttpsServer.start()) {
			Clock clock=Clock.fixed(OidcLogoutFixtures.NOW,ZoneOffset.UTC); OidcClient owner=OidcLogoutFixtures.builder(server,clock).build();var login=OidcLogoutFixtures.login(server,owner,clock);var hint=owner.logoutHintFrom(login.authentication());
			for(String query:List.of("provider_mode=web&flag","","other=a%20b")) {URI endpoint=server.uri("/logout?"+query);OidcClient client=OidcLogoutFixtures.builder(server,clock,endpoint).build();var request=client.beginLogout(login.authentication().getSessionReference(),hint);assertEquals(endpoint,request.getFormAction());assertTrue(request.getRedirectUri().toASCIIString().startsWith(endpoint.toASCIIString()+(query.isEmpty()?"":"&")));assertFalse(request.getRedirectUri().toString().contains("?&"));assertEquals(4,request.getFormParameters().size());}
		}
	}
	@Test void missingAndUnsafeEndpointsDoNotGrantALogoutRequest() throws Exception {
		try(TestHttpsServer server=TestHttpsServer.start()) {
			Clock clock=Clock.fixed(OidcLogoutFixtures.NOW,ZoneOffset.UTC);OidcClient owner=OidcLogoutFixtures.builder(server,clock).build();var login=OidcLogoutFixtures.login(server,owner,clock);var hint=owner.logoutHintFrom(login.authentication());
			OidcClient missing=OidcLogoutFixtures.builder(server,clock,null).build();assertReason(OidcLogoutException.Reason.END_SESSION_UNSUPPORTED,()->missing.beginLogout(login.authentication().getSessionReference(),hint));
			for(URI endpoint:List.of(URI.create("http://idp.example/logout"),URI.create("https://user@idp.example/logout"),URI.create("https://idp.example/logout#fragment"),URI.create("/relative"),URI.create("https://idp.example:0/logout"),URI.create("https://idp.example:65536/logout"),URI.create("https://idp.example/"+"x".repeat(2048)))) {
				OidcClient client=OidcLogoutFixtures.builder(server,clock,endpoint).build();assertReason(OidcLogoutException.Reason.ENDPOINT_NOT_PERMITTED,()->client.beginLogout(login.authentication().getSessionReference(),hint));
			}
			assertEquals(0,server.getHitCount("/logout"));
		}
	}
	@Test void originalBindingMismatchPrecedesClockDiscoveryAndEntropy() throws Exception {
		try(TestHttpsServer server=TestHttpsServer.start()) {
			SwitchClock clock=new SwitchClock();OidcClient owner=OidcLogoutFixtures.builder(server,clock).build();var one=OidcLogoutFixtures.login(server,owner,clock);var two=OidcLogoutFixtures.login(server,owner,clock);var hint=owner.logoutHintFrom(one.authentication());
			clock.failure=true;OidcClient lazy=OidcClient.withIssuer(server.getBaseUri().toString()).clientId("client").redirectUri(OidcLogoutFixtures.LOGIN).postLogoutRedirectUri(OidcLogoutFixtures.LOGOUT).clock(clock).httpClient(TestTls.httpClient()).build();
			int clocks=clock.calls.get();Provider provider=new CountingProvider();Security.insertProviderAt(provider,1);CountingRandom.calls.set(0);
			try {assertReason(OidcLogoutException.Reason.HINT_MISMATCH,()->lazy.beginLogout(two.authentication().getSessionReference(),hint));assertEquals(clocks,clock.calls.get());assertEquals(0,CountingRandom.calls.get());assertEquals(0,server.getHitCount("/.well-known/openid-configuration"));}finally{Security.removeProvider(provider.getName());}
		}
	}
	@Test void configuredClockFailuresAndRollbackBeforeAndAfterConsumePreserveEffectKnowledge() throws Exception {
		try(TestHttpsServer server=TestHttpsServer.start()) {
			SwitchClock clock=new SwitchClock();OidcClient client=OidcLogoutFixtures.builder(server,clock).build();var login=OidcLogoutFixtures.login(server,client,clock);var hint=client.logoutHintFrom(login.authentication());var request=client.beginLogout(login.authentication().getSessionReference(),hint);
			Store never=saved(request);clock.failure=true;assertReason(OidcLogoutException.Reason.PROVIDER_UNAVAILABLE,()->client.completeLogoutResult(query(request),PendingOidcLogoutSource.fromStore(never,BINDING),OidcLogoutFixtures.LOGOUT));assertEquals(0,never.calls.get());assertNotNull(never.row.get());
			assertReason(OidcLogoutException.Reason.PROVIDER_UNAVAILABLE,()->client.beginLogout(login.authentication().getSessionReference(),hint));clock.failure=false;
			for(String mode:List.of("failure","rollback","expired")) {Store store=saved(request);store.after=()->{if(mode.equals("failure"))clock.failure=true;else clock.now.set(mode.equals("rollback")?OidcLogoutFixtures.NOW.minusNanos(1):request.getPending().getExpiresAt());};
				try {if(mode.equals("expired"))assertEquals(OidcLogoutResult.Reason.PENDING_EXPIRED,assertInstanceOf(OidcLogoutResult.Rejected.class,client.completeLogoutResult(query(request),PendingOidcLogoutSource.fromStore(store,BINDING),OidcLogoutFixtures.LOGOUT)).getReason());else assertReason(OidcLogoutException.Reason.STORE_INDETERMINATE,()->client.completeLogoutResult(query(request),PendingOidcLogoutSource.fromStore(store,BINDING),OidcLogoutFixtures.LOGOUT));assertEquals(1,store.calls.get());assertNull(store.row.get());}finally{clock.failure=false;clock.now.set(OidcLogoutFixtures.NOW);}
			}
		}
	}
	@Test void consumeLatePositiveAndEmptyOutcomesAreIndeterminateUnderTheOriginalBudget() throws Exception {
		try(TestHttpsServer server=TestHttpsServer.start()) {
			Clock clock=Clock.fixed(OidcLogoutFixtures.NOW,ZoneOffset.UTC);OidcClient owner=OidcLogoutFixtures.builder(server,clock).build();var login=OidcLogoutFixtures.login(server,owner,clock);var hint=owner.logoutHintFrom(login.authentication());var request=owner.beginLogout(login.authentication().getSessionReference(),hint);
			OidcClient bounded=OidcLogoutFixtures.builder(server,clock).requestTimeout(Duration.ofSeconds(1)).totalDeadline(Duration.ofSeconds(1)).build();
			for(boolean empty:List.of(false,true)) {Store store=saved(request);if(empty)store.row.set(null);store.after=()->pause(1150);assertReason(OidcLogoutException.Reason.STORE_INDETERMINATE,()->bounded.completeLogoutResult(query(request),PendingOidcLogoutSource.fromStore(store,BINDING),OidcLogoutFixtures.LOGOUT));assertEquals(1,store.calls.get());assertNull(store.row.get());}
		}
	}
	@Test void configuredHintSealerProviderFailuresNeverMasqueradeAsSizeConfigurationFailures() throws Exception {
		try(TestHttpsServer server=TestHttpsServer.start()) {
			SwitchClock clock=new SwitchClock();OidcClient client=OidcLogoutFixtures.builder(server,clock).build();var hint=client.logoutHintFrom(OidcLogoutFixtures.login(server,client,clock).authentication());StateSealer sealer=StateSealer.withActiveKey(TestSealers.fixedKey("logout-clock-failure")).clock(clock).build();String sealed=hint.toSealedForm(sealer,"hint",Duration.ofSeconds(2));clock.failure=true;
			assertReason(OidcLogoutException.Reason.PROVIDER_UNAVAILABLE,()->hint.toSealedForm(sealer,"hint",Duration.ofSeconds(2)));assertReason(OidcLogoutException.Reason.PROVIDER_UNAVAILABLE,()->OidcLogoutHint.fromSealedFormResult(sealed,sealer,"hint"));
		}
	}
	@Test void futureBeginsUseFreshMetadataButAnExistingReturnDoesNoDiscoveryOrJwks() throws Exception {
		try(TestHttpsServer server=TestHttpsServer.start()) {
			OidcLogoutFixtures.MutableClock clock=new OidcLogoutFixtures.MutableClock();String path="/.well-known/openid-configuration";discovery(server,path,server.uri("/logout-a"));
			OidcClient client=OidcClient.withIssuer(server.getBaseUri().toString()).clientId("client").redirectUri(OidcLogoutFixtures.LOGIN).postLogoutRedirectUri(OidcLogoutFixtures.LOGOUT).clock(clock).jwksSource(OidcLogoutFixtures.keys(null)).httpClient(TestTls.httpClient()).build();
			assertEquals(0,server.getHitCount(path));var login=OidcLogoutFixtures.login(server,client,clock);var hint=client.logoutHintFrom(login.authentication());var first=client.beginLogout(login.authentication().getSessionReference(),hint);assertEquals(server.uri("/logout-a"),first.getFormAction());
			clock.set(OidcLogoutFixtures.NOW.plusSeconds(61));discovery(server,path,server.uri("/logout-b"));var second=client.beginLogout(login.authentication().getSessionReference(),hint);assertEquals(server.uri("/logout-b"),second.getFormAction());assertEquals(server.uri("/logout-a"),first.getFormAction());int hits=server.getHitCount(path),tokens=server.getHitCount("/token");Store store=saved(first);
			server.script(path,TestHttpsServer.Script.fromResponse(TestHttpsServer.Response.fromJson(500,"{}")));assertInstanceOf(OidcLogoutResult.Returned.class,client.completeLogoutResult(query(first),PendingOidcLogoutSource.fromStore(store,BINDING),OidcLogoutFixtures.LOGOUT));assertEquals(hits,server.getHitCount(path));assertEquals(tokens,server.getHitCount("/token"));assertEquals(0,server.getHitCount("/jwks"));
		}
	}
	@Test void entraActualTenantIsRetainedAndCurrentPolicyAppliesOnlyBeforeBrowserPreparation() throws Exception {
		try(TestHttpsServer server=TestHttpsServer.start()) {
			Clock clock=Clock.fixed(OidcLogoutFixtures.NOW,ZoneOffset.UTC);AtomicBoolean allow=new AtomicBoolean(true);AtomicInteger decisions=new AtomicInteger();OidcIssuerPolicy policy=OidcIssuerPolicy.fromMicrosoftEntraMultiTenant(tenant->{assertEquals(TENANT,tenant);decisions.incrementAndGet();return allow.get();});OidcClient client=entra(server,clock,policy,Duration.ofSeconds(15));var login=OidcLogoutFixtures.login(server,client,clock,(now,nonce)->entraToken(now,nonce));var hint=client.logoutHintFrom(login.authentication());assertTrue(hint.toSerializedForm().contains(ACTUAL));var request=client.beginLogout(login.authentication().getSessionReference(),hint);assertEquals(COMMON,request.getPending().getIssuer());
			allow.set(false);assertReason(OidcLogoutException.Reason.HINT_MISMATCH,()->client.logoutHintFrom(login.authentication()));assertReason(OidcLogoutException.Reason.HINT_MISMATCH,()->client.beginLogout(login.authentication().getSessionReference(),hint));int before=decisions.get();Store store=saved(request);assertInstanceOf(OidcLogoutResult.Returned.class,client.completeLogoutResult(query(request),PendingOidcLogoutSource.fromStore(store,BINDING),OidcLogoutFixtures.LOGOUT));assertEquals(before,decisions.get(),"correlation return is no new tenant/identity decision");
		}
	}
	@Test void slowEntraPolicyCannotRestartTheOriginalMonotonicBudget() throws Exception {
		try(TestHttpsServer server=TestHttpsServer.start()) {
			Clock clock=Clock.fixed(OidcLogoutFixtures.NOW,ZoneOffset.UTC);AtomicBoolean slow=new AtomicBoolean();AtomicInteger decisions=new AtomicInteger();OidcIssuerPolicy policy=OidcIssuerPolicy.fromMicrosoftEntraMultiTenant(tenant->{decisions.incrementAndGet();if(slow.get())pause(1150);return true;});OidcClient client=entra(server,clock,policy,Duration.ofSeconds(1));var login=OidcLogoutFixtures.login(server,client,clock,(now,nonce)->entraToken(now,nonce));var hint=client.logoutHintFrom(login.authentication());slow.set(true);int before=decisions.get();assertReason(OidcLogoutException.Reason.BUDGET_EXHAUSTED,()->client.beginLogout(login.authentication().getSessionReference(),hint));assertEquals(before+1,decisions.get());assertEquals(0,server.getHitCount("/logout"));
		}
	}
	@Test void perOperationEntropyIsOwnedClearedAndNeverInventsAProviderSuccess() throws Exception {
		try(TestHttpsServer server=TestHttpsServer.start()) {
			Clock clock=Clock.fixed(OidcLogoutFixtures.NOW,ZoneOffset.UTC);OidcClient client=OidcLogoutFixtures.builder(server,clock).build();var login=OidcLogoutFixtures.login(server,client,clock);var hint=client.logoutHintFrom(login.authentication());Provider provider=new CountingProvider();Security.insertProviderAt(provider,1);CountingRandom.calls.set(0);CountingRandom.failure=false;
			try {var request=client.beginLogout(login.authentication().getSessionReference(),hint);assertEquals(1,CountingRandom.calls.get());assertNotNull(CountingRandom.retained);assertTrue(allZero(java.util.Objects.requireNonNull(CountingRandom.retained)));assertEquals(43,java.util.Objects.requireNonNull(request.getFormParameters().get("state")).length());CountingRandom.failure=true;assertReason(OidcLogoutException.Reason.PROVIDER_UNAVAILABLE,()->client.beginLogout(login.authentication().getSessionReference(),hint));assertEquals(2,CountingRandom.calls.get());assertTrue(allZero(java.util.Objects.requireNonNull(CountingRandom.retained)));}finally{CountingRandom.failure=false;CountingRandom.retained=null;Security.removeProvider(provider.getName());}
		}
	}
	@Test void nonfatalTrustedProviderErrorsAreFixedWhileVirtualMachineFailuresPropagateUnchanged() throws Exception {
		try(TestHttpsServer server=TestHttpsServer.start()) {
			Clock clock=Clock.fixed(OidcLogoutFixtures.NOW,ZoneOffset.UTC);OidcClient client=OidcLogoutFixtures.builder(server,clock).build();var login=OidcLogoutFixtures.login(server,client,clock);var hint=client.logoutHintFrom(login.authentication());var request=client.beginLogout(login.authentication().getSessionReference(),hint);String form=hint.toSerializedForm();ErrorClock providerClock=new ErrorClock();StateSealer sealer=StateSealer.withActiveKey(TestSealers.fixedKey("logout-nonfatal-error")).clock(providerClock).build();String sealed=hint.toSealedForm(sealer,"hint",Duration.ofSeconds(2));providerClock.failure=new AssertionError(SECRET);
			assertReason(OidcLogoutException.Reason.PROVIDER_UNAVAILABLE,()->hint.toSealedForm(sealer,"hint",Duration.ofSeconds(2)));assertReason(OidcLogoutException.Reason.PROVIDER_UNAVAILABLE,()->OidcLogoutHint.fromSealedFormResult(sealed,sealer,"hint"));
			TestVmFailure fatal=new TestVmFailure();providerClock.failure=fatal;assertSame(fatal,assertThrows(TestVmFailure.class,()->hint.toSealedForm(sealer,"hint",Duration.ofSeconds(2))));assertSame(fatal,assertThrows(TestVmFailure.class,()->OidcLogoutHint.fromSealedFormResult(sealed,sealer,"hint")));
			Provider entropyProvider=new CountingProvider();Security.insertProviderAt(entropyProvider,1);CountingRandom.nonfatalError=false;
			try {StateSealer entropySealer=StateSealer.withActiveKey(TestSealers.fixedKey("logout-entropy-error")).clock(clock).build();CountingRandom.nonfatalError=true;assertReason(OidcLogoutException.Reason.PROVIDER_UNAVAILABLE,()->hint.toSealedForm(entropySealer,"hint",Duration.ofSeconds(2)));assertReason(OidcLogoutException.Reason.PROVIDER_UNAVAILABLE,()->request.getPending().toSealedForm(entropySealer,"pending"));assertTrue(allZero(java.util.Objects.requireNonNull(CountingRandom.retained)));}finally{CountingRandom.nonfatalError=false;CountingRandom.retained=null;Security.removeProvider(entropyProvider.getName());}
			Provider provider=new OidcLogoutHintTests.FailingDigestProvider();OidcLogoutHintTests.FailingDigest.nonfatalError=true;Security.insertProviderAt(provider,1);
			try {assertReason(OidcLogoutException.Reason.PROVIDER_UNAVAILABLE,()->OidcLogoutHint.fromSerializedFormResult(form));assertReason(OidcLogoutException.Reason.PROVIDER_UNAVAILABLE,()->client.logoutHintFrom(login.authentication()));Store never=new Store();assertEquals(PendingAuthorizationSaveResult.UNAVAILABLE,request.getPending().saveToResult(never,BINDING));assertEquals(0,never.calls.get());assertNull(never.row.get());}finally{OidcLogoutHintTests.FailingDigest.nonfatalError=false;Security.removeProvider(provider.getName());}
		}
	}
	@Test void realEntraTenantCallbackFailuresRespectFixedCategoriesAndOriginalBudget() throws Exception {
		try(TestHttpsServer server=TestHttpsServer.start()) {
			Clock clock=Clock.fixed(OidcLogoutFixtures.NOW,ZoneOffset.UTC);AtomicReference<String> mode=new AtomicReference<>("pass");AtomicInteger decisions=new AtomicInteger();TestVmFailure fatal=new TestVmFailure();
			OidcIssuerPolicy policy=OidcIssuerPolicy.fromMicrosoftEntraMultiTenant(tenant->{assertEquals(TENANT,tenant);decisions.incrementAndGet();String action=java.util.Objects.requireNonNull(mode.get());if(action.equals("fatal"))throw fatal;if(action.equals("interrupt"))Thread.currentThread().interrupt();if(action.equals("slow"))pause(1150);if(action.equals("error")||action.equals("interrupt")||action.equals("slow"))throw new AssertionError(SECRET);return !action.equals("deny");});
			OidcClient client=entra(server,clock,policy,Duration.ofSeconds(1));var login=OidcLogoutFixtures.login(server,client,clock,(now,nonce)->entraToken(now,nonce));var hint=client.logoutHintFrom(login.authentication());OidcLogoutFixtures.respond(server,null);var refreshed=assertInstanceOf(OidcRefreshOutcome.Succeeded.class,client.refreshResult(login.authentication().getTokens().getRefreshToken().orElseThrow(),login.authentication().getSessionReference())).getRefreshResult();
			List<org.junit.jupiter.api.function.Executable> operations=List.of(()->client.logoutHintFrom(login.authentication()),()->client.logoutHintFrom(refreshed),()->client.beginLogout(login.authentication().getSessionReference(),hint));
			for(String action:List.of("error","deny","fatal","interrupt","slow")){mode.set(action);for(var operation:operations){int before=decisions.get();try{if(action.equals("fatal"))assertSame(fatal,assertThrows(TestVmFailure.class,operation));else assertReason(action.equals("error")?OidcLogoutException.Reason.PROVIDER_UNAVAILABLE:action.equals("deny")?OidcLogoutException.Reason.HINT_MISMATCH:action.equals("interrupt")?OidcLogoutException.Reason.INTERRUPTED:OidcLogoutException.Reason.BUDGET_EXHAUSTED,operation);if(action.equals("interrupt"))assertTrue(Thread.currentThread().isInterrupted());assertEquals(before+1,decisions.get(),"one application policy callback per operation");}finally{Thread.interrupted();}}}
			assertEquals(0,server.getHitCount("/logout"));assertEquals(0,server.getHitCount("/jwks"));
		}
	}

	private static final class ErrorClock extends Clock {private @Nullable Error failure;@Override public @NonNull ZoneId getZone(){return ZoneOffset.UTC;}@Override public @NonNull Clock withZone(@NonNull ZoneId zone){return this;}@Override public @NonNull Instant instant(){if(failure!=null)throw failure;return OidcLogoutFixtures.NOW;}}
	private static final class TestVmFailure extends VirtualMachineError {private static final long serialVersionUID=1L;}

	private static @NonNull OidcClient entra(@NonNull TestHttpsServer server,@NonNull Clock clock,@NonNull OidcIssuerPolicy policy,@NonNull Duration budget) {OidcProviderMetadata metadata=OidcProviderMetadata.withIssuer(COMMON).authorizationEndpoint(server.uri("/authorize")).tokenEndpoint(server.uri("/token")).jwksUri(server.uri("/jwks")).endSessionEndpoint(server.uri("/logout")).build();return OidcClient.withProviderMetadata(metadata).issuerPolicy(policy).clientId("client").redirectUri(OidcLogoutFixtures.LOGIN).postLogoutRedirectUri(OidcLogoutFixtures.LOGOUT).clock(clock).jwksSource(OidcLogoutFixtures.keys(TEMPLATE)).httpClient(TestTls.httpClient()).requestTimeout(Duration.ofSeconds(1)).totalDeadline(budget).build();}
	private static @NonNull String entraToken(@NonNull Instant now,@NonNull String nonce) {return TestJws.withAlgorithm(TestJws.Algorithm.RS256).kid("key").payload(JsonObject.builder().put("iss",ACTUAL).put("tid",TENANT).put("sub","TEST-ONLY-entra-logout-subject").put("aud","client").put("iat",now.getEpochSecond()).put("exp",now.plusSeconds(300).getEpochSecond()).put("nonce",nonce).build().toJson()).sign(TestJwk.Fixture.IDP_SIGNING_RSA_2048.getPrivateKey());}
	private static void discovery(@NonNull TestHttpsServer server,@NonNull String path,@NonNull URI endpoint) {String json=JsonObject.builder().put("issuer",server.getBaseUri().toString()).put("authorization_endpoint",server.uri("/authorize").toString()).put("token_endpoint",server.uri("/token").toString()).put("jwks_uri",server.uri("/jwks").toString()).put("end_session_endpoint",endpoint.toString()).put("response_types_supported",com.revetsec.json.JsonArray.fromElements(List.of(com.revetsec.json.JsonString.fromValue("code")))).put("subject_types_supported",com.revetsec.json.JsonArray.fromElements(List.of(com.revetsec.json.JsonString.fromValue("public")))).put("id_token_signing_alg_values_supported",com.revetsec.json.JsonArray.fromElements(List.of(com.revetsec.json.JsonString.fromValue("RS256")))).build().toJson();server.script(path,TestHttpsServer.Script.fromResponse(TestHttpsServer.Response.withStatus(200).header("Content-Type","application/json").header("Cache-Control","no-store").body(json).build()));}
	private static @NonNull String query(@NonNull OidcLogoutRequest request){return "state="+request.getFormParameters().get("state");}
	private static @NonNull Store saved(@NonNull OidcLogoutRequest request){Store store=new Store();assertEquals(PendingAuthorizationSaveResult.SAVED,request.getPending().saveToResult(store,BINDING));return store;}
	private static void assertReason(OidcLogoutException.@NonNull Reason reason,org.junit.jupiter.api.function.@NonNull Executable action){var failure=OidcLogoutHintTests.assertReason(reason,action);assertNull(failure.getCause());assertEquals(0,failure.getSuppressed().length);assertFalse(failure.toString().contains(SECRET));}
	private static void pause(long millis){try{Thread.sleep(millis);}catch(InterruptedException failure){Thread.currentThread().interrupt();}}
	private static boolean allZero(byte @NonNull [] value){for(byte b:value)if(b!=0)return false;return true;}
	private static final class SwitchClock extends Clock {final AtomicReference<Instant> now=new AtomicReference<>(OidcLogoutFixtures.NOW);final AtomicInteger calls=new AtomicInteger();boolean failure;@Override public @NonNull ZoneId getZone(){return ZoneOffset.UTC;}@Override public @NonNull Clock withZone(@NonNull ZoneId zone){return this;}@Override public @NonNull Instant instant(){calls.incrementAndGet();if(failure)throw new IllegalArgumentException(SECRET);return java.util.Objects.requireNonNull(now.get());}}
	private static final class Store implements PendingAuthorizationStore {final AtomicReference<String> row=new AtomicReference<>();final AtomicInteger calls=new AtomicInteger();Runnable after=()->{};@Override public @NonNull PendingAuthorizationSaveResult save(@NonNull String binding,@NonNull String state,@NonNull String value,@NonNull Instant expiry,@NonNull Duration remaining){row.set(value);return PendingAuthorizationSaveResult.SAVED;}@Override public @NonNull Optional<@NonNull String> consume(@NonNull String binding,@NonNull String state,@NonNull Duration remaining){calls.incrementAndGet();String value=row.getAndSet(null);after.run();return Optional.ofNullable(value);}}
	public static final class CountingProvider extends Provider {private static final long serialVersionUID=1L;public CountingProvider(){super("RevetsecLogoutEntropy","1.0","test-only delegated provider");put("SecureRandom.LogoutTest",CountingRandom.class.getName());}}
	public static final class CountingRandom extends SecureRandomSpi {private static final long serialVersionUID=1L;static final AtomicInteger calls=new AtomicInteger();static byte @Nullable [] retained;static boolean failure,nonfatalError;private final java.security.SecureRandom delegate=delegate();private static java.security.@NonNull SecureRandom delegate(){try{return java.security.SecureRandom.getInstance("SHA1PRNG","SUN");}catch(java.security.GeneralSecurityException unavailable){throw new ProviderException(SECRET);}}@Override protected void engineSetSeed(byte @NonNull [] seed){delegate.setSeed(seed);}@Override protected void engineNextBytes(byte @NonNull [] bytes){calls.incrementAndGet();retained=bytes;delegate.nextBytes(bytes);if(nonfatalError)throw new AssertionError(SECRET);if(failure)throw new ProviderException(SECRET);}@Override protected byte @NonNull [] engineGenerateSeed(int length){return delegate.generateSeed(length);}}
}
