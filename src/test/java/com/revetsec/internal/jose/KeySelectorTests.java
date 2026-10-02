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

import org.jspecify.annotations.NonNull;

import com.revetsec.jose.JwsAlgorithm;
import com.revetsec.testing.TestJsonWebKeys;
import com.revetsec.testing.TestJsonWebKeys.Fixture;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;

import java.util.ArrayList;
import java.util.EnumMap;
import java.util.EnumSet;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Stream;

/**
 * {@link KeySelector}, {@link KeyQuery} and {@link KeySelection}: the plan's "Key selection" rules (INV-J3, INV-J9):
 * candidates by key type, curve and {@code alg}, the {@code EdDSA}/{@code Ed25519} alias on Ed25519 keys only (built on
 * RFC 9864 sections 2.2 and 5), RSA keys without {@code alg} only under one RSA algorithm (RFC 8725 section 3.1, G8-2),
 * the {@code kid} matched exactly (RFC 7517 section 4.5), a duplicate {@code kid} as ambiguous (Wycheproof JWK tcId 4),
 * and a {@code kid}-less token needing exactly one candidate (OpenID Connect Core section 10.1).
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 */
final class KeySelectorTests {
	private static final Set<JwsAlgorithm> PUBLIC_KEY_ALGORITHMS = EnumSet.complementOf(EnumSet.of(JwsAlgorithm.HS256,
			JwsAlgorithm.HS384, JwsAlgorithm.HS512));

	// A kid selects the one key with that kid that fits the token's algorithm.
	@Test
	void aKidSelectsTheOneKeyWithThatKidThatFitsTheAlgorithm() throws SkippedKeyException {
		VerificationKey rsa = key(Fixture.IDP_SIGNING_RSA_2048, "a", null);
		VerificationKey otherRsa = key(Fixture.NEGATIVE_ATTACKER_RSA_2048, "b", null);
		VerificationKey ec = key(Fixture.IDP_SIGNING_EC_P256, "c", null);
		List<VerificationKey> keys = List.of(rsa, otherRsa, ec);

		assertFound(otherRsa, keys, query(JwsAlgorithm.RS256, "b", JwsAlgorithm.RS256));
		assertFound(rsa, keys, query(JwsAlgorithm.RS256, "a", JwsAlgorithm.RS256));
		assertFound(ec, keys, query(JwsAlgorithm.ES256, "c", JwsAlgorithm.ES256, JwsAlgorithm.RS256));
	}

	// RFC 7517 section 4.5: kid values are case-sensitive strings, matched exactly; no key with the kid is unknown,
	// which a remote source may answer by refreshing.
	@Test
	void aKidNoKeyHasIsUnknown() throws SkippedKeyException {
		List<VerificationKey> keys = List.of(key(Fixture.IDP_SIGNING_RSA_2048, "Key-1", null),
				key(Fixture.IDP_SIGNING_EC_P256, "key-2", null));

		for (String kid : List.of("key-1", "KEY-1", "Key-", "Key-1 ", "Key-10", "k"))
			assertKind(KeySelection.Kind.UNKNOWN, keys, query(JwsAlgorithm.RS256, kid, JwsAlgorithm.RS256));
		assertKind(KeySelection.Kind.UNKNOWN, List.of(), query(JwsAlgorithm.RS256, "Key-1", JwsAlgorithm.RS256));
	}

	// Plan "Key selection": a token's kid examines only the keys with exactly that kid, so a key without a kid never
	// serves a token that names one, even as the only fitting key; that is UNKNOWN, as for any kid no key has. The
	// same key serves a token without a kid.
	@Test
	void aKidNeverSelectsAKeyWithoutAKid() throws SkippedKeyException {
		VerificationKey kidless = key(Fixture.IDP_SIGNING_RSA_2048, null, null);
		VerificationKey ec = key(Fixture.IDP_SIGNING_EC_P256, "ec", null);

		assertKind(KeySelection.Kind.UNKNOWN, List.of(kidless), query(JwsAlgorithm.RS256, "key-1", JwsAlgorithm.RS256));
		assertKind(KeySelection.Kind.UNKNOWN, List.of(ec, kidless), query(JwsAlgorithm.RS256, "key-1",
				JwsAlgorithm.RS256, JwsAlgorithm.ES256));
		assertFound(kidless, List.of(ec, kidless), query(JwsAlgorithm.RS256, null, JwsAlgorithm.RS256,
				JwsAlgorithm.ES256));
	}

	// Keys with the token's kid that do not fit its algorithm give ALGORITHM_MISMATCH, never UNKNOWN, so a remote
	// source never refreshes for them: another key type, another curve, or another alg.
	@Test
	void keysWithTheKidThatDoNotFitAreAnAlgorithmMismatch() throws SkippedKeyException {
		List<VerificationKey> keys = List.of(key(Fixture.IDP_SIGNING_RSA_2048, "rsa", null),
				key(Fixture.IDP_SIGNING_EC_P256, "p256", null), key(Fixture.IDP_SIGNING_RSA_3072, "rs256", "RS256"),
				key(Fixture.NEGATIVE_ATTACKER_RSA_2048, "ps256", "PS256"), key(Fixture.ED25519, "ed", null));

		assertKind(KeySelection.Kind.ALGORITHM_MISMATCH, keys, query(JwsAlgorithm.ES256, "rsa", JwsAlgorithm.ES256));
		assertKind(KeySelection.Kind.ALGORITHM_MISMATCH, keys, query(JwsAlgorithm.EDDSA, "rsa", JwsAlgorithm.EDDSA));
		assertKind(KeySelection.Kind.ALGORITHM_MISMATCH, keys, query(JwsAlgorithm.ES384, "p256", JwsAlgorithm.ES384));
		assertKind(KeySelection.Kind.ALGORITHM_MISMATCH, keys, query(JwsAlgorithm.RS256, "p256", JwsAlgorithm.RS256));
		assertKind(KeySelection.Kind.ALGORITHM_MISMATCH, keys, query(JwsAlgorithm.RS384, "rs256", JwsAlgorithm.RS384));
		assertKind(KeySelection.Kind.ALGORITHM_MISMATCH, keys, query(JwsAlgorithm.PS256, "rs256", JwsAlgorithm.PS256));
		assertKind(KeySelection.Kind.ALGORITHM_MISMATCH, keys, query(JwsAlgorithm.RS256, "ps256", JwsAlgorithm.RS256));
		assertKind(KeySelection.Kind.ALGORITHM_MISMATCH, keys, query(JwsAlgorithm.ES256, "ed", JwsAlgorithm.ES256));
	}

	// Plan M2-7: at most one key is ever tried, so two fitting keys that share a kid are ambiguous (Wycheproof JWK
	// tcId 4), in either order; a shared kid is fine when only one of the keys fits.
	@Test
	void twoFittingKeysWithOneKidAreAmbiguous() throws SkippedKeyException {
		VerificationKey rsa = key(Fixture.IDP_SIGNING_RSA_2048, "dup", null);
		VerificationKey otherRsa = key(Fixture.NEGATIVE_ATTACKER_RSA_2048, "dup", null);
		VerificationKey ec = key(Fixture.IDP_SIGNING_EC_P256, "dup", null);
		VerificationKey rs256 = key(Fixture.IDP_SIGNING_RSA_3072, "algs", "RS256");
		VerificationKey ps256 = key(Fixture.NEGATIVE_ATTACKER_RSA_2048, "algs", "PS256");
		KeyQuery rs256Query = query(JwsAlgorithm.RS256, "dup", JwsAlgorithm.RS256, JwsAlgorithm.ES256);

		assertKind(KeySelection.Kind.AMBIGUOUS, List.of(rsa, otherRsa), rs256Query);
		assertKind(KeySelection.Kind.AMBIGUOUS, List.of(otherRsa, ec, rsa), rs256Query);
		assertKind(KeySelection.Kind.AMBIGUOUS, List.of(rsa, rsa), rs256Query);
		assertFound(ec, List.of(rsa, ec), query(JwsAlgorithm.ES256, "dup", JwsAlgorithm.RS256, JwsAlgorithm.ES256));
		assertFound(rsa, List.of(ec, rsa), rs256Query);
		assertFound(rs256, List.of(ps256, rs256), query(JwsAlgorithm.RS256, "algs", JwsAlgorithm.RS256,
				JwsAlgorithm.PS256));
		assertFound(ps256, List.of(ps256, rs256), query(JwsAlgorithm.PS256, "algs", JwsAlgorithm.RS256,
				JwsAlgorithm.PS256));
	}

	// OpenID Connect Core section 10.1: without a kid, exactly one fitting key is used; none is unknown (never a
	// mismatch), and more than one is ambiguous, whatever kids the keys carry.
	@Test
	void withoutAKidExactlyOneFittingKeyIsUsed() throws SkippedKeyException {
		VerificationKey rsa = key(Fixture.IDP_SIGNING_RSA_2048, "a", null);
		VerificationKey otherRsa = key(Fixture.NEGATIVE_ATTACKER_RSA_2048, null, null);
		VerificationKey ec = key(Fixture.IDP_SIGNING_EC_P256, null, null);
		VerificationKey ed = key(Fixture.ED25519, "e", null);

		assertFound(rsa, List.of(rsa, ec, ed), query(JwsAlgorithm.RS256, null, JwsAlgorithm.RS256));
		assertFound(ec, List.of(rsa, ec, ed), query(JwsAlgorithm.ES256, null, JwsAlgorithm.ES256));
		assertFound(ed, List.of(rsa, ec, ed), query(JwsAlgorithm.ED25519, null, JwsAlgorithm.ED25519));
		assertKind(KeySelection.Kind.UNKNOWN, List.of(rsa, ec, ed), query(JwsAlgorithm.ES384, null, JwsAlgorithm.ES384));
		assertKind(KeySelection.Kind.UNKNOWN, List.of(ec), query(JwsAlgorithm.RS256, null, JwsAlgorithm.RS256));
		assertKind(KeySelection.Kind.UNKNOWN, List.of(), query(JwsAlgorithm.RS256, null, JwsAlgorithm.RS256));
		assertKind(KeySelection.Kind.AMBIGUOUS, List.of(rsa, ec, otherRsa), query(JwsAlgorithm.RS256, null,
				JwsAlgorithm.RS256));
	}

	// G8-2 and INV-J3 (RFC 8725 section 3.1, read 2026-09-28: each key MUST be used with exactly one algorithm, checked
	// when the cryptographic operation is performed): an RSA key without alg fits only while the effective set holds
	// exactly one RSA algorithm, which is then the token's; under two RSA algorithms it is a mismatch with a kid and
	// unknown without one. A key that names its alg is unaffected.
	@Test
	void anRsaKeyWithoutAlgFitsOnlyWhileOneRsaAlgorithmIsAllowed() throws SkippedKeyException {
		VerificationKey bare = key(Fixture.IDP_SIGNING_RSA_2048, "k", null);
		VerificationKey named = key(Fixture.IDP_SIGNING_RSA_3072, "n", "RS256");
		List<VerificationKey> keys = List.of(bare, named);

		assertFound(bare, keys, query(JwsAlgorithm.RS256, "k", JwsAlgorithm.RS256));
		assertFound(bare, keys, query(JwsAlgorithm.PS384, "k", JwsAlgorithm.PS384));
		assertFound(bare, keys, query(JwsAlgorithm.RS256, "k", JwsAlgorithm.RS256, JwsAlgorithm.ES256,
				JwsAlgorithm.ES512, JwsAlgorithm.EDDSA, JwsAlgorithm.ED25519));
		assertKind(KeySelection.Kind.ALGORITHM_MISMATCH, keys, query(JwsAlgorithm.RS256, "k", JwsAlgorithm.RS256,
				JwsAlgorithm.PS256));
		assertKind(KeySelection.Kind.ALGORITHM_MISMATCH, keys, query(JwsAlgorithm.PS256, "k", JwsAlgorithm.RS256,
				JwsAlgorithm.PS256));
		assertKind(KeySelection.Kind.ALGORITHM_MISMATCH, keys, query(JwsAlgorithm.RS256, "k", JwsAlgorithm.RS256,
				JwsAlgorithm.RS384));
		assertKind(KeySelection.Kind.UNKNOWN, List.of(bare), query(JwsAlgorithm.RS256, null, JwsAlgorithm.RS256,
				JwsAlgorithm.PS256));
		assertFound(named, keys, query(JwsAlgorithm.RS256, "n", JwsAlgorithm.RS256, JwsAlgorithm.PS256));
		assertFound(named, keys, query(JwsAlgorithm.RS256, null, JwsAlgorithm.RS256, JwsAlgorithm.PS256));
	}

	// EC and Ed25519 keys have one algorithm by their curve, so without alg they fit that algorithm under any set.
	@Test
	void curveKeysWithoutAlgFitTheirCurvesAlgorithmUnderAnySet() throws SkippedKeyException {
		VerificationKey p256 = key(Fixture.IDP_SIGNING_EC_P256, "p", null);
		VerificationKey ed = key(Fixture.ED25519, "e", null);
		List<VerificationKey> keys = List.of(p256, ed);

		assertFound(p256, keys, query(JwsAlgorithm.ES256, "p", PUBLIC_KEY_ALGORITHMS.toArray(new JwsAlgorithm[0])));
		assertFound(ed, keys, query(JwsAlgorithm.ED25519, "e", PUBLIC_KEY_ALGORITHMS.toArray(new JwsAlgorithm[0])));
		assertFound(ed, keys, query(JwsAlgorithm.EDDSA, "e", PUBLIC_KEY_ALGORITHMS.toArray(new JwsAlgorithm[0])));
	}

	// A key whose alg is EdDSA verifies Ed25519 tokens and the reverse, on Ed25519 keys; no other pair of algorithms is
	// an alias. RFC 9864 (read 2026-09-28) defines no alias: its section 2.2 registers Ed25519 as EdDSA with the Ed25519
	// parameter set, which is what EdDSA means on an Ed25519 key, section 4.1.2 deprecates EdDSA, and section 5 keeps
	// the key's representation but for its alg. Revetsec's alias rests on that reading.
	@Test
	void eddsaAndEd25519AreAliasesOnEd25519KeysOnly() throws SkippedKeyException {
		VerificationKey eddsa = key(Fixture.ED25519, "a", "EdDSA");
		VerificationKey ed25519 = key(Fixture.ED25519, "b", "Ed25519");

		assertFound(eddsa, List.of(eddsa), query(JwsAlgorithm.ED25519, "a", JwsAlgorithm.ED25519));
		assertFound(eddsa, List.of(eddsa), query(JwsAlgorithm.EDDSA, "a", JwsAlgorithm.EDDSA));
		assertFound(ed25519, List.of(ed25519), query(JwsAlgorithm.EDDSA, "b", JwsAlgorithm.EDDSA));
		assertFound(ed25519, List.of(ed25519), query(JwsAlgorithm.ED25519, "b", JwsAlgorithm.ED25519));

		for (JwsAlgorithm first : JwsAlgorithm.values())
			for (JwsAlgorithm second : JwsAlgorithm.values())
				Assertions.assertEquals(first != second && EnumSet.of(first, second).equals(EnumSet.of(JwsAlgorithm.EDDSA,
						JwsAlgorithm.ED25519)), Algorithms.isAlias(first, second), first + " and " + second);
	}

	// Every key type against every public-key algorithm, the token's algorithm alone allowed: a key fits exactly the
	// algorithms of its type and curve, and otherwise is a mismatch with a kid and unknown without one. No key from a
	// key set ever fits an HMAC algorithm.
	@TestFactory
	@NonNull Stream<@NonNull DynamicTest> everyKeyFitsExactlyTheAlgorithmsOfItsTypeAndCurve() throws SkippedKeyException {
		// In enum order, so the dynamic tests have the same order and numbering in every JVM.
		Map<Fixture, Set<JwsAlgorithm>> fits = new EnumMap<>(Map.of(
				Fixture.IDP_SIGNING_RSA_2048, EnumSet.of(JwsAlgorithm.RS256, JwsAlgorithm.RS384, JwsAlgorithm.RS512,
						JwsAlgorithm.PS256, JwsAlgorithm.PS384, JwsAlgorithm.PS512),
				Fixture.IDP_SIGNING_EC_P256, EnumSet.of(JwsAlgorithm.ES256),
				Fixture.IDP_SIGNING_EC_P384, EnumSet.of(JwsAlgorithm.ES384),
				Fixture.IDP_SIGNING_EC_P521, EnumSet.of(JwsAlgorithm.ES512),
				Fixture.ED25519, EnumSet.of(JwsAlgorithm.ED25519, JwsAlgorithm.EDDSA)));
		List<DynamicTest> tests = new ArrayList<>();

		for (Map.Entry<Fixture, Set<JwsAlgorithm>> entry : fits.entrySet()) {
			VerificationKey key = key(entry.getKey(), "kid", null);
			for (JwsAlgorithm algorithm : JwsAlgorithm.values())
				tests.add(DynamicTest.dynamicTest(entry.getKey() + " for " + algorithm.getWireValue(), () -> {
					boolean fit = entry.getValue().contains(algorithm);
					KeyQuery withKid = query(algorithm, "kid", algorithm);
					KeyQuery withoutKid = query(algorithm, null, algorithm);

					Assertions.assertEquals(fit, KeySelector.fits(key, withKid));
					if (fit) {
						assertFound(key, List.of(key), withKid);
						assertFound(key, List.of(key), withoutKid);
					} else {
						assertKind(KeySelection.Kind.ALGORITHM_MISMATCH, List.of(key), withKid);
						assertKind(KeySelection.Kind.UNKNOWN, List.of(key), withoutKid);
					}
				}));
		}

		return tests.stream();
	}

	// A key query holds its algorithm in its effective set, copies the set, and never shows the sender's kid.
	@Test
	void keyQueriesHoldTheirAlgorithmInTheirSetAndHideTheKid() {
		Set<JwsAlgorithm> allowed = new HashSet<>(Set.of(JwsAlgorithm.RS256, JwsAlgorithm.ES256));
		KeyQuery query = new KeyQuery(JwsAlgorithm.RS256, "secret-kid", allowed);
		allowed.clear();

		Assertions.assertEquals(Set.of(JwsAlgorithm.RS256, JwsAlgorithm.ES256), query.allowedAlgorithms());
		Assertions.assertTrue(query.allowsRsaKeyWithoutAlgorithm());
		Assertions.assertFalse(query.toString().contains("secret-kid"));
		Assertions.assertTrue(query.toString().contains("keyIdPresent=true"));
		Assertions.assertFalse(new KeyQuery(JwsAlgorithm.ES256, null, Set.of(JwsAlgorithm.ES256, JwsAlgorithm.RS256))
				.allowsRsaKeyWithoutAlgorithm(), "the token's algorithm must be the sole RSA one");
		Assertions.assertFalse(new KeyQuery(JwsAlgorithm.RS256, null, Set.of(JwsAlgorithm.RS256, JwsAlgorithm.PS512))
				.allowsRsaKeyWithoutAlgorithm());
		Assertions.assertThrows(IllegalArgumentException.class, () -> new KeyQuery(JwsAlgorithm.RS256, "k",
				Set.of(JwsAlgorithm.ES256)));
		Assertions.assertThrows(IllegalArgumentException.class, () -> new KeyQuery(JwsAlgorithm.RS256, "k", Set.of()));
	}

	// A selection carries a key only when found; the other kinds are shared, keyless values.
	@Test
	void selectionsCarryAKeyOnlyWhenFound() throws SkippedKeyException {
		VerificationKey key = key(Fixture.IDP_SIGNING_RSA_2048, "k", null);

		Assertions.assertEquals(KeySelection.Kind.FOUND, KeySelection.fromKey(key).getKind());
		Assertions.assertEquals(key, KeySelection.fromKey(key).findKey().orElseThrow());
		Assertions.assertEquals(KeySelection.fromKey(key), KeySelection.fromKey(key));
		Assertions.assertEquals(KeySelection.fromKey(key).hashCode(), KeySelection.fromKey(key).hashCode());
		Assertions.assertThrows(IllegalArgumentException.class, () -> KeySelection.fromKind(KeySelection.Kind.FOUND));
		for (KeySelection.Kind kind : List.of(KeySelection.Kind.UNKNOWN, KeySelection.Kind.AMBIGUOUS,
				KeySelection.Kind.ALGORITHM_MISMATCH)) {
			Assertions.assertSame(KeySelection.fromKind(kind), KeySelection.fromKind(kind));
			Assertions.assertEquals(kind, KeySelection.fromKind(kind).getKind());
			Assertions.assertTrue(KeySelection.fromKind(kind).findKey().isEmpty());
			Assertions.assertNotEquals(KeySelection.fromKey(key), KeySelection.fromKind(kind));
		}
		Assertions.assertFalse(KeySelection.fromKey(key).toString().contains("\"k\""));
	}

	// Descriptions show only public facts: a key's type, curve, alg and thumbprint (never its kid or issuer member),
	// whether a query has a kid, and a selection's kind with its key.
	@Test
	void descriptionsShowOnlyPublicFacts() throws SkippedKeyException {
		VerificationKey rsa = key(Fixture.IDP_SIGNING_RSA_2048, "secret-kid", null);
		VerificationKey ec = key(Fixture.IDP_SIGNING_EC_P256, "secret-kid", "ES256");

		Assertions.assertEquals("VerificationKey{kty=RSA, thumbprint=" + rsa.thumbprintSha256() + "}", rsa.toString());
		Assertions.assertEquals("VerificationKey{kty=EC, crv=P-256, alg=ES256, thumbprint=" + ec.thumbprintSha256() + "}",
				ec.toString());
		Assertions.assertEquals("KeyQuery{algorithm=ES256, keyIdPresent=false, allowedAlgorithms=[RS256, ES256]}",
				new KeyQuery(JwsAlgorithm.ES256, null, Set.of(JwsAlgorithm.ES256, JwsAlgorithm.RS256)).toString());
		Assertions.assertEquals("KeySelection{kind=UNKNOWN}", KeySelection.fromKind(KeySelection.Kind.UNKNOWN)
				.toString());
		Assertions.assertEquals("KeySelection{kind=FOUND, key=" + ec + "}", KeySelection.fromKey(ec).toString());

		KeySelection found = KeySelection.fromKey(rsa);
		Object same = found;
		Assertions.assertEquals(found, same);
		Assertions.assertNotEquals(found, KeySelection.fromKey(ec));
		Assertions.assertNotEquals(found, rsa);
	}

	private static @NonNull VerificationKey key(@NonNull Fixture fixture, @Nullable String kid, @Nullable String alg)
			throws SkippedKeyException {
		TestJsonWebKeys.Builder builder = TestJsonWebKeys.withFixture(fixture);
		if (kid != null)
			builder.kid(kid);
		if (alg != null)
			builder.alg(alg);
		return JwkParserTests.parse(builder.toJson());
	}

	private static @NonNull KeyQuery query(@NonNull JwsAlgorithm algorithm, @Nullable String kid, @NonNull JwsAlgorithm @NonNull ... allowed) {
		return new KeyQuery(algorithm, kid, Set.of(allowed));
	}

	private static void assertFound(@NonNull VerificationKey expected, @NonNull List<@NonNull VerificationKey> keys, @NonNull KeyQuery query) {
		KeySelection selection = KeySelector.select(keys, query);
		Assertions.assertEquals(KeySelection.Kind.FOUND, selection.getKind(), query::toString);
		Assertions.assertSame(expected, selection.findKey().orElseThrow());
	}

	private static void assertKind(KeySelection.@NonNull Kind kind, @NonNull List<@NonNull VerificationKey> keys, @NonNull KeyQuery query) {
		KeySelection selection = KeySelector.select(keys, query);
		Assertions.assertEquals(kind, selection.getKind(), query::toString);
		Assertions.assertTrue(selection.findKey().isEmpty());
	}
}
