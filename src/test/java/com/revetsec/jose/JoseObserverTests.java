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

package com.revetsec.jose;

import com.revetsec.ErrorCategory;
import com.revetsec.RevetsecException;
import com.revetsec.testing.RecordingObserver;
import com.revetsec.testing.Sentinels;
import com.revetsec.testing.TestClock;
import com.revetsec.testing.TestJsonWebKeys.Fixture;
import com.revetsec.testing.TestJws;
import com.revetsec.testing.TestJws.Algorithm;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.net.URI;
import java.time.Duration;
import java.util.List;
import java.util.Objects;
import java.util.Set;

/**
 * {@link JoseObserver} and the hooks {@link JwtValidator} fires (M2-3; G6-4): {@code didValidateJwt} on success,
 * {@code didFailToValidateJwt} with the very instance the caller receives, {@code didAcceptAnyAudience} at build and
 * before every validation, a throwing observer contained, and no token-derived string in any hook argument.
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 */
final class JoseObserverTests {
	// M2-3: nine default hooks that do nothing, plus disabledInstance(), which is shared and does nothing either.
	@Test
	void theObserverHasNineDefaultHooksAndASharedDisabledInstance() throws Exception {
		int hooks = 0;
		for (Method method : JoseObserver.class.getDeclaredMethods()) {
			if (Modifier.isStatic(method.getModifiers()))
				continue;
			Assertions.assertTrue(method.isDefault(), method.toString());
			Assertions.assertEquals(void.class, method.getReturnType(), method.toString());
			++hooks;
		}
		Assertions.assertEquals(9, hooks);

		JoseObserver disabled = JoseObserver.disabledInstance();
		Assertions.assertSame(disabled, JoseObserver.disabledInstance());
		Assertions.assertSame(DisabledJoseObserver.INSTANCE, disabled);
		Assertions.assertEquals("JoseObserver.disabledInstance()", disabled.toString());

		// Every default hook returns without effect, on the disabled instance and on a bare implementation.
		JoseObserver bare = new JoseObserver() {
		};
		for (JoseObserver observer : List.of(disabled, bare)) {
			URI uri = URI.create("https://idp.example.com/jwks");
			observer.willFetchJsonWebKeySet(uri);
			observer.didFetchJsonWebKeySet(uri, 1, 0, Duration.ofMinutes(1), Duration.ZERO);
			observer.didFailToFetchJsonWebKeySet(uri, JsonWebKeySetUnavailableException.fromCategory(
					ErrorCategory.TRANSPORT, true), false, Duration.ZERO);
			observer.didSuppressJsonWebKeySetFetch(uri, Duration.ofSeconds(30));
			observer.didSkipJsonWebKey(uri, 0, JsonWebKeySkipReason.MALFORMED_KEY);
			observer.didValidateJwt(JwsAlgorithm.RS256, Duration.ZERO);
			observer.didFailToValidateJwt(JwtValidationException.fromReason(JoseException.Reason.EXPIRED), Duration.ZERO);
			observer.didAcceptAnyAudience("issuer");
			observer.didUseUnpatchedRuntime("17.0.2");
		}
	}

	// M2-3: a successful validation fires didValidateJwt once, with the algorithm and the call's elapsed time, measured
	// with System.nanoTime(): between zero and the time measured around validate().
	@Test
	void aValidationFiresDidValidateJwt() {
		RecordingObserver<JoseObserver> recorder = RecordingObserver.fromInterface(JoseObserver.class);
		JwtValidator validator = JwtFixtures.validator(JwtFixtures.source(Fixture.IDP_SIGNING_EC_P256))
				.allowedAlgorithms(Set.of(JwsAlgorithm.ES256)).observer(recorder.getObserver()).build();
		Assertions.assertEquals(List.of(), recorder.getCalls());
		String token = JwtFixtures.signed(Fixture.IDP_SIGNING_EC_P256, Algorithm.ES256);

		long before = System.nanoTime();
		JwtFixtures.assertAccepted(validator, token);
		long after = System.nanoTime();

		Assertions.assertEquals(1, recorder.getCalls().size());
		RecordingObserver.Call call = recorder.getCalls().get(0);
		Assertions.assertEquals("didValidateJwt", call.getMethodName());
		Assertions.assertEquals(JwsAlgorithm.ES256, call.getArgument(0));
		JwtFixtures.assertElapsedWithin(call.getArgument(1), before, after);
		Assertions.assertSame(Thread.currentThread(), call.getThread());
	}

	// G6-4: a failed validation fires didFailToValidateJwt once, with the very exception the caller receives, from
	// every leaf, and the call's elapsed time.
	@Test
	void aFailureFiresDidFailToValidateJwtWithTheThrownInstance() {
		RecordingObserver<JoseObserver> recorder = RecordingObserver.fromInterface(JoseObserver.class);
		JwtValidator validator = JwtFixtures.validator(JwtFixtures.source(Fixture.IDP_SIGNING_RSA_2048))
				.observer(recorder.getObserver()).build();

		for (String token : List.of("x", "{}", JwtFixtures.signed(Fixture.NEGATIVE_ATTACKER_RSA_2048, Algorithm.RS256))) {
			long before = System.nanoTime();
			JoseException thrown = Assertions.assertThrows(JoseException.class, () -> validator.validate(token));
			long after = System.nanoTime();
			RecordingObserver.Call call = recorder.getCalls().get(recorder.getCalls().size() - 1);
			Assertions.assertEquals("didFailToValidateJwt", call.getMethodName());
			Assertions.assertSame(thrown, call.getArgument(0));
			JwtFixtures.assertElapsedWithin(call.getArgument(1), before, after);
		}
		Assertions.assertEquals(3, recorder.getCalls().size());
		Assertions.assertEquals(List.of(MalformedJoseInputException.class, UnsupportedJoseFeatureException.class,
				JwtValidationException.class), recorder.getCalls().stream().map(call -> Objects.requireNonNull(
				call.getArgument(0)).getClass())
				.toList());
	}

	// M2-3: the validation hooks' elapsed time covers the whole call, any key set fetch included. Over a remote source,
	// a validation that leads the first fetch, and a refusal that leads an unknown-key refetch, each report a time
	// within the one measured around validate() and at least the fetch's own, which the source reports to its observer.
	@Test
	void theValidationHooksIncludeTheKeySetFetch() {
		RecordingObserver<JoseObserver> sourceRecorder = RecordingObserver.fromInterface(JoseObserver.class);
		RecordingObserver<JoseObserver> validatorRecorder = RecordingObserver.fromInterface(JoseObserver.class);
		JwksCacheTests.MemoryHttpClient client = JwksCacheTests.MemoryHttpClient.answering(
				JwksCacheTests.Answer.fromKeySet(null, JwtFixtures.KID));
		RemoteJsonWebKeySource source = JwksCacheTests.source(client, TestClock.fromInstant(JwksCacheTests.START))
				.observer(sourceRecorder.getObserver()).build();
		JwtValidator validator = JwtFixtures.validator(source).observer(validatorRecorder.getObserver()).build();
		String accepted = JwtFixtures.signed(Fixture.IDP_SIGNING_RSA_2048, Algorithm.RS256);
		String unknown = TestJws.withAlgorithm(Algorithm.RS256).kid("unknown").payload(JwtFixtures.claims().toJson())
				.sign(Fixture.IDP_SIGNING_RSA_2048.getPrivateKey());

		long before = System.nanoTime();
		JwtFixtures.assertAccepted(validator, accepted);
		long after = System.nanoTime();
		Duration validation = JwtFixtures.assertElapsedWithin(validatorRecorder.getCalls("didValidateJwt").get(0)
				.getArgument(1), before, after);
		Duration fetch = JwtFixtures.assertElapsedWithin(sourceRecorder.getCalls("didFetchJsonWebKeySet").get(0)
				.getArgument(4), before, after);
		Assertions.assertTrue(validation.compareTo(fetch) >= 0, () -> validation + " is shorter than its fetch, " + fetch);

		before = System.nanoTime();
		JwtFixtures.assertRejected(JoseException.Reason.UNKNOWN_KEY, validator, unknown);
		after = System.nanoTime();
		Duration refusal = JwtFixtures.assertElapsedWithin(validatorRecorder.getCalls("didFailToValidateJwt").get(0)
				.getArgument(1), before, after);
		Duration refetch = JwtFixtures.assertElapsedWithin(sourceRecorder.getCalls("didFetchJsonWebKeySet").get(1)
				.getArgument(4), before, after);
		Assertions.assertTrue(refusal.compareTo(refetch) >= 0, () -> refusal + " is shorter than its fetch, " + refetch);
		Assertions.assertEquals(2, client.getSendCount());
	}

	// M2-4 (exit criterion 8): with any audience accepted, didAcceptAnyAudience fires at build and again before every
	// validation's outcome hook, success or failure.
	@Test
	void acceptingAnyAudienceIsObservedOnEveryValidation() {
		RecordingObserver<JoseObserver> recorder = RecordingObserver.fromInterface(JoseObserver.class);
		JwtValidator validator = JwtValidator.withIssuer(JwtFixtures.ISSUER).jsonWebKeySource(JwtFixtures.source(
				Fixture.IDP_SIGNING_RSA_2048)).acceptAnyAudience(true).clock(JwtFixtures.clock())
				.observer(recorder.getObserver()).build();

		JwtFixtures.assertAccepted(validator, JwtFixtures.signed(Fixture.IDP_SIGNING_RSA_2048, Algorithm.RS256));
		Assertions.assertThrows(JoseException.class, () -> validator.validate("x"));
		JwtFixtures.assertAccepted(validator, JwtFixtures.signed(Fixture.IDP_SIGNING_RSA_2048, Algorithm.RS256));

		Assertions.assertEquals(List.of("didAcceptAnyAudience", "didAcceptAnyAudience", "didValidateJwt",
				"didAcceptAnyAudience", "didFailToValidateJwt", "didAcceptAnyAudience", "didValidateJwt"),
				recorder.getCalls().stream().map(RecordingObserver.Call::getMethodName).toList());
		for (RecordingObserver.Call call : recorder.getCalls("didAcceptAnyAudience"))
			Assertions.assertEquals(List.of(JwtFixtures.ISSUER), call.getArguments());
	}

	// G6-4: an observer that throws from every hook changes no outcome: the token is still accepted or refused
	// exactly as without it, with the same reason.
	@Test
	void aThrowingObserverChangesNoOutcome() {
		RecordingObserver<JoseObserver> throwing = RecordingObserver.fromInterface(JoseObserver.class,
				() -> new IllegalStateException("observer failure"));
		JwtValidator validator = JwtValidator.withIssuer(JwtFixtures.ISSUER).jsonWebKeySource(JwtFixtures.source(
				Fixture.IDP_SIGNING_RSA_2048)).acceptAnyAudience(true).clock(JwtFixtures.clock())
				.observer(throwing.getObserver()).build();

		JwtFixtures.assertAccepted(validator, JwtFixtures.signed(Fixture.IDP_SIGNING_RSA_2048, Algorithm.RS256));
		JwtFixtures.assertRejected(JoseException.Reason.SIGNATURE_MISMATCH, validator, JwtFixtures.signed(
				Fixture.NEGATIVE_ATTACKER_RSA_2048, Algorithm.RS256));
		Assertions.assertEquals(5, throwing.getCalls().size());
	}

	// M2-3: no hook receives a string from the token; the only strings are the configured issuer's.
	@Test
	void noHookArgumentCarriesTokenContent() {
		RecordingObserver<JoseObserver> recorder = RecordingObserver.fromInterface(JoseObserver.class);
		JwtValidator validator = JwtValidator.withIssuer(JwtFixtures.ISSUER).jsonWebKeySource(JwtFixtures.source(
				Fixture.IDP_SIGNING_RSA_2048)).acceptAnyAudience(true).clock(JwtFixtures.clock())
				.observer(recorder.getObserver()).build();

		for (String token : List.of(Sentinels.compactJwt("RS256", 256), Sentinels.compactJwt("ES256", 64),
				Sentinels.compactJwtWithSentinelClaim(0), JwtFixtures.token(Algorithm.RS256).kid(Sentinels.JWT_KEY_ID)
						.sign(Fixture.IDP_SIGNING_RSA_2048.getPrivateKey())))
			Assertions.assertThrows(RevetsecException.class, () -> validator.validate(token));

		Assertions.assertFalse(recorder.getCalls().isEmpty());
		for (RecordingObserver.Call call : recorder.getCalls())
			Sentinels.assertAbsent(call.getArguments());
	}
}
