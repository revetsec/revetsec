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

package com.revetsec;

import org.jspecify.annotations.NonNull;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import java.util.stream.IntStream;
import java.util.stream.Stream;

/**
 * Meta-tests: each contract checker must report exactly the violations seeded under
 * {@code src/test/resources/contract-fixtures/}, no more (the compliant controls there) and no fewer. A checker
 * that silently stops matching, or loses one of its alternatives, fails here instead of passing vacuously on the
 * real sources.
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 */
final class ContractMetaTests {
	private static final String BANNED_CALLS = "com/revetsec/BannedCallsFixture.java";
	private static final String INTERNAL_HTTP_USERS = "com.revetsec.internal.http may be used only by "
			+ "[com.revetsec.internal.oauth, com.revetsec.jose, com.revetsec.oauth, com.revetsec.oidc]";
	private static final String SIGNATURE_NAME_FIXTURE = "com/revetsec/internal/crypto/SignatureNameFixture.java";
	private static final String PROVIDED_ANNOTATION_FIXTURE = "com/revetsec/ProvidedAnnotationFixture.java";
	private static final String TEST_HOOK_CALLER_FIXTURE = "com/revetsec/jose/TestHookCallerFixture.java";

	/**
	 * Reviewed-exception lists for the public-api fixture, in place of the real ones: entries in the binary-name form
	 * that messages print, which exempt their types, plus canonical {@code Outer.Nested} spellings of other nested
	 * types, a missing type and (for {@code OPEN_ABSTRACT_TYPES}) a sealed class, which exempt nothing and must be
	 * reported as stale or misspelled.
	 */
	private static final Set<String> FIXTURE_VERIFIED_TYPE_SOURCES = Set.of(
			"com.revetsec.oidc.IdTokenValidatorFixture",
			"com.revetsec.oidc.IdTokenValidatorFixture$Completion",
			"com.revetsec.oidc.IdTokenValidatorFixture.Refresh",
			"com.revetsec.oidc.RenamedValidatorFixture");
	private static final Set<String> FIXTURE_R1_EXCEPTIONS = Set.of(
			"com.revetsec.scim.ScimErrorsFixture$LegacyError",
			"com.revetsec.scim.ScimErrorsFixture.RetiredError");
	private static final Set<String> FIXTURE_OPEN_ABSTRACT_TYPES = Set.of(
			"com.revetsec.RevetsecException",
			"com.revetsec.AbstractControlFixture",
			"com.revetsec.OpenAbstractHolder.NestedOpenFixture",
			"com.revetsec.oauth.OAuthFixtureException",
			"com.revetsec.RenamedAbstractFixture");
	/**
	 * The app-constructible exception factories for the public-api fixture, in place of the real (empty) list: one
	 * entry that exempts a factory, and stale entries for a missing method, an instance method and a canonical
	 * {@code Outer.Nested} spelling.
	 */
	private static final Set<String> FIXTURE_APP_CONSTRUCTIBLE_EXCEPTION_FACTORIES = Set.of(
			"com.revetsec.oauth.TokenFixtureException#fromStatus(java.lang.Integer)",
			"com.revetsec.oauth.TokenFixtureException#fromRetiredStatus(java.lang.Integer)",
			"com.revetsec.oauth.TokenFixtureException#getReason()",
			"com.revetsec.LeafFixtureException.Nested#describe(java.lang.Integer)");

	/**
	 * The mutable-static allowlist for the source-policy fixture, in place of the real (empty) one: a row that exempts
	 * a seeded field, then a duplicate of it, stale rows (a canonical {@code Outer.Nested} spelling, a field the rule
	 * does not report, a missing class) and malformed rows (too few values, a blank reason, surrounding whitespace),
	 * which exempt nothing; and last, a row that exempts one of two fields declared on the same line.
	 */
	private static final List<List<String>> FIXTURE_MUTABLE_STATIC_ALLOWLIST = List.of(
			List.of("com.revetsec.MutableStaticFixture$LookupTable", "VALUES",
					"private lookup table, never written after class initialization"),
			List.of("com.revetsec.MutableStaticFixture$LookupTable", "VALUES", "the same field again"),
			List.of("com.revetsec.MutableStaticFixture.LookupTable", "UNLISTED", "canonical spelling, exempts nothing"),
			List.of("com.revetsec.MutableStaticFixture$Controls", "LIMIT", "a field the rule does not report"),
			List.of("com.revetsec.RenamedFixture", "TABLE", "a class that no longer exists"),
			List.of("com.revetsec.MutableStaticFixture", "COUNT"),
			List.of("com.revetsec.MutableStaticFixture", "BUFFER", " "),
			List.of(" com.revetsec.MutableStaticFixture", "NAMES", "surrounding whitespace"),
			List.of("com.revetsec.MutableStaticBranchesFixture", "LEFT", "one of two fields declared on one line"));
	private static final String MUTABLE_STATIC_FIXTURE = "com/revetsec/MutableStaticFixture.java";
	private static final String MUTABLE_STATIC_BRANCHES_FIXTURE = "com/revetsec/MutableStaticBranchesFixture.java";
	private static final String MUTABLE_STATIC_ALLOWLIST = "mutable-static SourcePolicyTests.MUTABLE_STATIC_ALLOWLIST";

	private static @NonNull Path fixture(@NonNull String name) {
		Path fixture = ContractSupport.repositoryRoot().resolve("src/test/resources/contract-fixtures").resolve(name);
		Assertions.assertTrue(Files.isDirectory(fixture), () -> "Missing fixture directory " + fixture);
		return fixture;
	}

	@Test
	void publicApiContractReportsExactlyTheSeededViolations() throws IOException {
		// The rendering of an annotated type in a nullness message differs across JDKs, so it is left out.
		List<String> violations = PublicApiContractTests.findViolations(fixture("public-api"),
						FIXTURE_VERIFIED_TYPE_SOURCES, FIXTURE_R1_EXCEPTIONS, FIXTURE_OPEN_ABSTRACT_TYPES,
						FIXTURE_APP_CONSTRUCTIBLE_EXCEPTION_FACTORIES).stream()
				.map(violation -> violation.replaceFirst(" at .* \\(R2\\)$", " (R2)"))
				.toList();

		List<String> expected = new ArrayList<>(List.of(
				"PublicApiContractTests.R1_EXCEPTIONS entry \"com.revetsec.scim.ScimErrorsFixture.RetiredError\": "
						+ "stale or misspelled entry; use the binary name (Outer$Nested, as violation messages print it) "
						+ "of an exported type in the analyzed sources",
				"PublicApiContractTests.VERIFIED_TYPE_SOURCES entry "
						+ "\"com.revetsec.oidc.IdTokenValidatorFixture.Refresh\": stale or misspelled entry; use the "
						+ "binary name (Outer$Nested, as violation messages print it) of an accessible type in the "
						+ "analyzed sources",
				"PublicApiContractTests.VERIFIED_TYPE_SOURCES entry \"com.revetsec.oidc.RenamedValidatorFixture\": "
						+ "stale or misspelled entry; use the binary name (Outer$Nested, as violation messages print "
						+ "it) of an accessible type in the analyzed sources",
				"com.revetsec.MissingMarkerFixture: must declare exactly one jsr305 thread-safety marker "
						+ "(@ThreadSafe, @NotThreadSafe or @Immutable); found []",
				"com.revetsec.MissingNullnessFixture#createDefault(): static factories are named builder(), withX(), "
						+ "fromX(), *Instance() or fromDefaults(), never of*, create* or new* (R1, "
						+ "NAMING_CONVENTIONS.md)",
				"com.revetsec.MissingNullnessFixture#nullableOptionalValue() return type type argument 0 (nested): "
						+ "lacks @NonNull (R2)",
				"com.revetsec.MissingNullnessFixture#of(): static factories are named builder(), withX(), fromX(), "
						+ "*Instance() or fromDefaults(), never of*, create* or new* (R1, NAMING_CONVENTIONS.md)",
				"com.revetsec.MissingNullnessFixture#unannotated(java.lang.String) parameter 0: lacks exactly one "
						+ "JSpecify @NonNull/@Nullable (R2)",
				"com.revetsec.MissingNullnessFixture#unannotated(java.lang.String) return type: lacks exactly one "
						+ "JSpecify @NonNull/@Nullable (R2)",
				"com.revetsec.MissingNullnessFixture#unannotatedTypeArgument() return type type argument 0 (nested): "
						+ "lacks exactly one JSpecify @NonNull/@Nullable (R2)",
				"com.revetsec.PublicRecordFixture#PublicRecordFixture(java.lang.String): implicit public or "
						+ "protected constructor; declare every constructor explicitly (R1: public concrete types "
						+ "have private constructors)",
				"com.revetsec.PublicRecordFixture: exported types must not be records; use a final class with getX() "
						+ "accessors (R1)",
				"com.revetsec.TwoMarkersFixture: must declare exactly one jsr305 thread-safety marker (@ThreadSafe, "
						+ "@NotThreadSafe or @Immutable); found [javax.annotation.concurrent.Immutable, "
						+ "javax.annotation.concurrent.ThreadSafe]",
				"com.revetsec.UndocumentedFixture (type): missing Javadoc (R20)",
				"com.revetsec.UndocumentedFixture#UndocumentedFixture(): implicit public or protected constructor; "
						+ "declare every constructor explicitly (R1: public concrete types have private constructors)",
				"com.revetsec.UndocumentedFixture#undated(): Javadoc has no @since tag (D28)",
				"com.revetsec.UndocumentedFixture#undocumented(): missing Javadoc (R20)",
				"com.revetsec.UndocumentedFixture: public concrete types are final, or sealed with only final or "
						+ "sealed permitted subclasses (R1)",
				"com.revetsec.internal.jose.JwtFactoryFixture#forge(): public or protected method returns a verified "
						+ "type; only validators may create one (R17)",
				"com.revetsec.internal.jose.JwtFactoryFixture#forgedIdToken(): public or protected method returns a "
						+ "verified type; only validators may create one (R17)",
				"com.revetsec.internal.jose.JwtFactoryFixture#fromCompactSerialization(java.lang.String): public or "
						+ "protected method returns a verified type; only validators may create one (R17)",
				"com.revetsec.internal.jose.JwtFactoryFixture#tryParse(java.lang.String): public or protected method "
						+ "returns a verified type; only validators may create one (R17)",
				"com.revetsec.jose.JoseApi#newToken() (inherited from com.revetsec.jose.AbstractJoseBase): static "
						+ "factories are named builder(), withX(), fromX(), *Instance() or fromDefaults(), never "
						+ "of*, create* or new* (R1, NAMING_CONVENTIONS.md)",
				"com.revetsec.jose.JoseApi#parse(java.lang.String) (inherited from "
						+ "com.revetsec.jose.AbstractJoseBase): public or protected method returns a verified type; "
						+ "only validators may create one (R17)",
				"com.revetsec.jose.JoseApi#undated() (inherited from com.revetsec.jose.AbstractJoseBase): Javadoc "
						+ "has no @since tag (D28)",
				"com.revetsec.jose.JoseApi#undocumented(java.lang.String) (inherited from "
						+ "com.revetsec.jose.AbstractJoseBase) parameter 0: lacks exactly one JSpecify "
						+ "@NonNull/@Nullable (R2)",
				"com.revetsec.jose.JoseApi#undocumented(java.lang.String) (inherited from "
						+ "com.revetsec.jose.AbstractJoseBase) return type: lacks exactly one JSpecify "
						+ "@NonNull/@Nullable (R2)",
				"com.revetsec.jose.JoseApi#undocumented(java.lang.String) (inherited from "
						+ "com.revetsec.jose.AbstractJoseBase): missing Javadoc (R20)",
				"com.revetsec.jose.Jwt#Jwt(): public concrete types have private constructors (R1)",
				"com.revetsec.jose.Jwt#Jwt(): verified type has a public or protected constructor (R17)",
				"com.revetsec.jose.Jwt$Builder: verified type exposes a Builder (R17)",
				"com.revetsec.jose.JwtBuilderFixture#TEMPLATE: public or protected field holds a verified type; only "
						+ "validators may create one (R17)",
				"com.revetsec.jose.JwtBuilderFixture#build(): public or protected method returns a verified type; "
						+ "only validators may create one (R17)",
				"com.revetsec.jose.PublicConstructorFixture#PublicConstructorFixture(): public concrete types have "
						+ "private constructors (R1)",
				"com.revetsec.jose.PublicConstructorFixture#PublicConstructorFixture(java.lang.String): public "
						+ "concrete types have private constructors (R1)",
				"com.revetsec.oidc.ForgedIdToken#ForgedIdToken(): public concrete types have private constructors (R1)",
				"com.revetsec.oidc.ForgedIdToken#ForgedIdToken(): verified type has a public or protected "
						+ "constructor (R17)",
				"com.revetsec.oidc.IdToken: public concrete types are final, or sealed with only final or sealed "
						+ "permitted subclasses (R1)",
				"com.revetsec.oidc.IdToken: verified types are final, or sealed with only non-public permitted "
						+ "subclasses (R17)",
				"com.revetsec.oidc.IdTokenValidatorFixture#LAST_VALIDATED: public or protected field holds a verified "
						+ "type; only validators may create one; VERIFIED_TYPE_SOURCES exempts instance members only "
						+ "(R17)",
				"com.revetsec.oidc.IdTokenValidatorFixture#fromTrustedStorage(java.lang.String): public or protected "
						+ "method returns a verified type; only validators may create one; VERIFIED_TYPE_SOURCES "
						+ "exempts instance members only (R17)",
				"com.revetsec.oidc.IdTokenValidatorFixture$Refresh#getIdToken(): public or protected method returns a "
						+ "verified type; only validators may create one (R17)",
				"com.revetsec.saml.SamlAuthentication: verified type permits the public or protected subclass "
						+ "com.revetsec.saml.ExposedSamlAuthentication (R17)",
				"com.revetsec.scim.OpenSealedFixture: sealed public concrete type permits the non-sealed subclass "
						+ "com.revetsec.scim.OpenSubclassFixture; every permitted subclass must be final or sealed (R1)",
				"com.revetsec.scim.ScimErrorsFixture$LegacyError#LegacyError(java.lang.String): public concrete types "
						+ "have private constructors (R1)",
				"com.revetsec.scim.ScimErrorsFixture$RetiredError: public concrete types are final, or sealed with only "
						+ "final or sealed permitted subclasses (R1)"));
		expected.addAll(m1PublicApiViolations());
		expected.addAll(m2PublicApiViolations());
		expected.sort(null);
		Assertions.assertEquals(expected, violations);
	}

	/**
	 * The public-api fixture's seeded violations of the rules M1 added (M1 plan, "Contract-list changes" item 2):
	 * open abstract classes (G6-1), exported Throwables (G6-1) and observer interfaces (G6-4), with the stale entries of
	 * their reviewed lists. The controls (the fixture's RevetsecException and AbstractControlFixture, both listed; the
	 * sealed OAuthFixtureException and its final TokenFixtureException, whose listed fromStatus factory, package-private
	 * factory and instance accessor are allowed; LegacyTokenFixtureException, whose inherited ReopenedFixtureException
	 * factory is reported on ReopenedFixtureException only; CompliantObserver, which uses every allowlisted hook
	 * parameter type; ExtendedObserver, which extends it; LeakyChildObserver, whose inherited LeakyObserver members are
	 * reported on LeakyObserver only; and ExportedHooks, which is not an observer) are reported nowhere. Members an
	 * observer inherits from an interface that is not an exported observer (a package-private one, or an exported one
	 * with another name) are reported on the observer.
	 */
	private static @NonNull List<@NonNull String> m1PublicApiViolations() {
		String openAbstract = ": exported abstract classes are sealed, so only Revetsec extends them; an open one needs "
				+ "a reviewed entry in OPEN_ABSTRACT_TYPES (G6-1)";
		String staleOpenAbstract = "\": stale or misspelled entry; use the binary name (Outer$Nested, as violation "
				+ "messages print it) of an unsealed exported abstract class in the analyzed sources";
		String staticMethod = ": exported exceptions have no public or protected static methods, because Revetsec "
				+ "creates them; a factory applications need is a reviewed entry in APP_CONSTRUCTIBLE_EXCEPTION_FACTORIES "
				+ "(G6-1)";
		String staleFactory = "\": stale or misspelled entry; name a public or protected static method of an exported "
				+ "exception as violation messages print it (Outer$Nested#method(erased parameter types))";
		String observerStatic = ": an observer's only static method is disabledInstance(), which takes no arguments and "
				+ "returns the observer (G6-4)";
		String abstractHook = ": observer hooks are default methods that do nothing, so an application overrides only "
				+ "the hooks it needs (G6-4)";
		String hookParameter = ": observer hook parameters are enums, boxed numbers or Boolean, Duration, Instant, URI, "
				+ "String or Revetsec exceptions, not ";
		String serialVersionUid = "#serialVersionUID: declare it private static final long; serialization ignores one "
				+ "that is not static and final, the specification requires a long, and private keeps it out of the API "
				+ "(G6-1)";

		List<String> violations = new ArrayList<>(List.of(
				"PublicApiContractTests.OPEN_ABSTRACT_TYPES entry \"com.revetsec.OpenAbstractHolder.NestedOpenFixture"
						+ staleOpenAbstract,
				"PublicApiContractTests.OPEN_ABSTRACT_TYPES entry \"com.revetsec.RenamedAbstractFixture" + staleOpenAbstract,
				"PublicApiContractTests.OPEN_ABSTRACT_TYPES entry \"com.revetsec.oauth.OAuthFixtureException"
						+ staleOpenAbstract,
				"com.revetsec.OpenAbstractFixture" + openAbstract,
				"com.revetsec.OpenAbstractHolder$NestedOpenFixture" + openAbstract,
				"com.revetsec.oauth.ReopenedFixtureException" + openAbstract,
				"com.revetsec.RogueFixtureException: every exported Throwable extends com.revetsec.RevetsecException (G6-1)",
				"com.revetsec.UnversionedFixtureException: exported Throwable declares no serialVersionUID; declare "
						+ "private static final long serialVersionUID (G6-1)",
				"com.revetsec.MisversionedFixtureException" + serialVersionUid,
				"com.revetsec.SerialVersionFixtures$UnfinalFixtureException" + serialVersionUid,
				"com.revetsec.SerialVersionFixtures$InstanceFixtureException" + serialVersionUid,
				"com.revetsec.SerialVersionFixtures$UnprivateFixtureException" + serialVersionUid,
				"com.revetsec.oauth.TokenFixtureException#fromDescription(java.lang.String)" + staticMethod,
				"com.revetsec.oauth.ReopenedFixtureException#fromLegacyStatus(java.lang.Integer)" + staticMethod,
				"com.revetsec.LeafFixtureException#describe(java.lang.Integer) (inherited from "
						+ "com.revetsec.BaseFixtureException)" + staticMethod,
				"PublicApiContractTests.APP_CONSTRUCTIBLE_EXCEPTION_FACTORIES entry "
						+ "\"com.revetsec.LeafFixtureException.Nested#describe(java.lang.Integer)" + staleFactory,
				"PublicApiContractTests.APP_CONSTRUCTIBLE_EXCEPTION_FACTORIES entry "
						+ "\"com.revetsec.oauth.TokenFixtureException#fromRetiredStatus(java.lang.Integer)" + staleFactory,
				"PublicApiContractTests.APP_CONSTRUCTIBLE_EXCEPTION_FACTORIES entry "
						+ "\"com.revetsec.oauth.TokenFixtureException#getReason()" + staleFactory,
				"com.revetsec.oauth.LeakyObserver#NAME: observer interfaces declare no fields, only default void hooks and "
						+ "a static disabledInstance() (G6-4)",
				"com.revetsec.oauth.LeakyObserver#disabledInstance()" + observerStatic,
				"com.revetsec.oauth.LeakyObserver#fromDefaults()" + observerStatic,
				"com.revetsec.oauth.LeakyObserver#didStart(java.lang.String)" + abstractHook,
				"com.revetsec.oauth.LeakyObserver#didFinish(): observer hooks return void (G6-4)",
				"com.revetsec.oauth.LeakyObserver#didSee(java.lang.Object) parameter 0" + hookParameter
						+ "type variable T (G6-4)",
				"com.revetsec.oauth.SilentObserver#didHide(java.lang.String) (inherited from "
						+ "com.revetsec.oauth.HiddenHooks)" + abstractHook,
				"com.revetsec.oauth.SilentObserver#disabledInstance(java.lang.String)" + observerStatic,
				"com.revetsec.oauth.SilentObserver: observer interfaces declare a static disabledInstance() (G6-4)",
				"com.revetsec.oauth.InheritingObserver#didRotate(java.lang.String) (inherited from "
						+ "com.revetsec.oauth.ExportedHooks)" + abstractHook,
				"com.revetsec.oauth.InheritingObserver#didConceal(java.lang.String) (inherited from "
						+ "com.revetsec.oauth.HiddenObserver)" + abstractHook));

		// One seeded violation per kind of type outside the hook allowlist.
		String didFail = "com.revetsec.oauth.LeakyObserver#didFail(int,java.lang.String[],java.util.List,"
				+ "java.util.Optional,java.lang.Object,java.io.IOException,java.math.BigDecimal,java.lang.Character,"
				+ "com.revetsec.CompliantFixture,com.revetsec.RogueFixtureException)";
		List<String> disallowedTypes = List.of("int", "java.lang.String[]", "java.util.List", "java.util.Optional",
				"java.lang.Object", "java.io.IOException", "java.math.BigDecimal", "java.lang.Character",
				"com.revetsec.CompliantFixture", "com.revetsec.RogueFixtureException");
		for (int index = 0; index < disallowedTypes.size(); ++index)
			violations.add(didFail + " parameter " + index + hookParameter + disallowedTypes.get(index) + " (G6-4)");
		return violations;
	}

	/**
	 * The public-api fixture's seeded violations of the M2 changes (M2 plan, "Contract-list changes" item 1): a public
	 * factory on JwtClaims, now a verified type (M2-5); non-sealed subtypes of exported sealed types, found by walking
	 * the permitted subtypes, package-private ones and ones behind a sealed intermediate included (M2-10 item 6); and
	 * public and protected constructors on an abstract sealed class, where an implicit one is reported once, by R1's
	 * implicit-constructor check (ImplicitHolderFixture). The controls (JoseFixtureException's
	 * package-private constructor and its final exported leaf, ExposedFixtureException's final package-private
	 * subclass, KeySourceFixture's final exported implementation and its package-private record and enum, and the
	 * sealed ScimPatchResult and SamlAuthentication, whose subclasses are final and whose constructors are
	 * package-private) are not reported by these rules.
	 */
	private static @NonNull List<@NonNull String> m2PublicApiViolations() {
		String nonSealedSubtype = ", which reopens its hierarchy; every permitted subtype must be final or sealed (G6-1)";
		String constructor = ": exported abstract sealed classes have package-private constructors, because only their "
				+ "permitted subclasses call them (G6-1)";
		return List.of(
				"com.revetsec.jose.JwtClaims#fromJson(java.lang.String): public or protected method returns a verified "
						+ "type; only validators may create one (R17)",
				"com.revetsec.jose.JoseFixtureException: exported sealed abstract class permits the non-sealed subtype "
						+ "com.revetsec.jose.LenientFixtureException" + nonSealedSubtype,
				"com.revetsec.jose.JoseFixtureException: exported sealed abstract class permits the non-sealed subtype "
						+ "com.revetsec.jose.LooseFixtureException" + nonSealedSubtype,
				"com.revetsec.oauth.OAuthFixtureException: exported sealed abstract class permits the non-sealed subtype "
						+ "com.revetsec.oauth.ReopenedFixtureException" + nonSealedSubtype,
				"com.revetsec.jose.KeySourceFixture: exported sealed interface permits the non-sealed subtype "
						+ "com.revetsec.jose.OpenKeySourceFixture" + nonSealedSubtype,
				"com.revetsec.jose.KeySourceFixture: exported sealed interface permits the non-sealed subtype "
						+ "com.revetsec.jose.WideKeySourceFixture" + nonSealedSubtype,
				"com.revetsec.jose.ExposedFixtureException#ExposedFixtureException()" + constructor,
				"com.revetsec.jose.ExposedFixtureException#ExposedFixtureException(java.lang.String)" + constructor,
				"com.revetsec.jose.ImplicitHolderFixture#ImplicitHolderFixture(): implicit public or protected "
						+ "constructor; declare every constructor explicitly (R1: public concrete types have private "
						+ "constructors)");
	}

	@Test
	void packageDependencyContractReportsExactlyTheSeededViolations() throws IOException {
		Assertions.assertEquals(Stream.of(
				"com.revetsec.extra: package is not in the package dependency graph; add it to "
						+ "PackageDependencyTests deliberately",
				"com.revetsec.internal.json uses com.revetsec.jose "
						+ "(com/revetsec/internal/json/InternalJsonUsesJoseFixture.java:19): "
						+ "com.revetsec.internal.json (part of com.revetsec.json) may depend only on [com.revetsec], "
						+ "not on com.revetsec.jose",
				"com.revetsec.internal.pem: package-info.java is not annotated @NullMarked (R2)",
				"com.revetsec.jose.JoseApiFixture #helper() (inherited from com.revetsec.jose.JoseBaseFixture) "
						+ "return type: exported signature mentions internal type "
						+ "com.revetsec.internal.jose.InternalJoseFixture (plan 6)",
				"com.revetsec.jose.JoseApiFixture #marked(java.lang.String) parameter 0: exported API carries the "
						+ "internal annotation @com.revetsec.internal.jose.InternalDocumentedFixture, which is "
						+ "@Documented or runtime-retained (plan 6)",
				"com.revetsec.jose.JoseApiFixture #marked(java.lang.String): exported API carries the internal "
						+ "annotation @com.revetsec.internal.jose.InternalRuntimeFixture, which is @Documented or "
						+ "runtime-retained (plan 6)",
				"com.revetsec.jose.JoseApiFixture supertype com.revetsec.internal.jose.InternalBaseFixture: exported "
						+ "signature mentions internal type com.revetsec.internal.jose.InternalBaseFixture (plan 6)",
				"com.revetsec.jose.JoseApiFixture: exported API carries the internal annotation "
						+ "@com.revetsec.internal.jose.InternalDocumentedFixture, which is @Documented or "
						+ "runtime-retained (plan 6)",
				"com.revetsec.jose.LeakyFixture #accept(java.util.List) parameter 0: exported signature mentions "
						+ "internal type com.revetsec.internal.jose.InternalJoseFixture (plan 6)",
				"com.revetsec.jose.LeakyFixture #helper() return type: exported signature mentions internal type "
						+ "com.revetsec.internal.jose.InternalJoseFixture (plan 6)",
				"com.revetsec.json uses com.revetsec.jose (com/revetsec/json/JsonUsesJoseFixture.java:27): "
						+ "com.revetsec.json may depend only on [com.revetsec], not on com.revetsec.jose",
				"com.revetsec.oidc: package has no package-info.java (R20)",
				"com.revetsec.saml uses com.revetsec.jose (com/revetsec/saml/SamlStaticImportFixture.java:21): "
						+ "com.revetsec.saml may depend only on [com.revetsec], not on com.revetsec.jose",
				"com.revetsec.saml uses com.revetsec.oauth (com/revetsec/saml/SamlImportsOAuthFixture.java:19): "
						+ "com.revetsec.saml may depend only on [com.revetsec], not on com.revetsec.oauth",
				"com.revetsec.scim uses com.revetsec.internal.xml (com/revetsec/scim/ScimUsesXmlFixture.java:19): "
						+ "com.revetsec.internal.xml may be used only by [com.revetsec.saml]",
				"com.revetsec.scim uses com.revetsec.internal.xml (com/revetsec/scim/ScimUsesXmlFixture.java:19): "
						+ "com.revetsec.scim may depend only on [com.revetsec, com.revetsec.json], not on "
						+ "com.revetsec.internal.xml (part of "
						+ "com.revetsec.saml)",
				// Only jose, oauth, oidc and internal.oauth may use internal.http; each of those four has a control that
				// is not reported. internal.jose, a permitted user until G8-11, is now a seeded violation.
				"com.revetsec.internal.jose uses com.revetsec.internal.http "
						+ "(com/revetsec/internal/jose/InternalJoseUsesHttpFixture.java:19): " + INTERNAL_HTTP_USERS,
				"com.revetsec.json uses com.revetsec.internal.http (com/revetsec/json/JsonUsesHttpFixture.java:27): "
						+ INTERNAL_HTTP_USERS,
				"com.revetsec.saml uses com.revetsec.internal.http (com/revetsec/saml/SamlUsesHttpFixture.java:19): "
						+ INTERNAL_HTTP_USERS,
				"com.revetsec.scim uses com.revetsec.internal.http (com/revetsec/scim/ScimUsesHttpFixture.java:19): "
						+ INTERNAL_HTTP_USERS).sorted().toList(),
				PackageDependencyTests.findViolations(fixture("package-dependencies")));
	}

	@Test
	void sourcePolicyReportsExactlyTheSeededViolations() throws IOException {
		List<String> expected = new ArrayList<>();
		expect(expected, "background-work", BANNED_CALLS, 29, 30, 31, 32, 33, 34, 35, 40, 41, 43, 45, 46, 47, 48, 50,
				51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 175, 178, 184);
		expect(expected, "print-stack-trace", BANNED_CALLS, 67, 68, 69);
		expect(expected, "locale-less-case-conversion", BANNED_CALLS, 70, 71, 72, 74);
		expect(expected, "xml-factory-outside-internal-xml", BANNED_CALLS, 75, 77, 79, 80, 81, 82, 83, 84, 85);
		expect(expected, "multi-argument-uri", BANNED_CALLS, 86);
		expect(expected, "default-http-client", BANNED_CALLS, 87, 88);
		expect(expected, "java-deserialization", BANNED_CALLS, 90, 91);
		expect(expected, "set-accessible", BANNED_CALLS, 92, 93, 94);
		expect(expected, "sun-internal-api", BANNED_CALLS, 95);
		expect(expected, "mime-base64-decoder", BANNED_CALLS, 96);
		expect(expected, "service-loader", BANNED_CALLS, 97, 156);
		expect(expected, "console-output", BANNED_CALLS, 98, 99, 100, 157);
		expect(expected, "insecure-random", BANNED_CALLS, 102, 103, 104, 105, 106, 107, 108);
		expect(expected, "jvm-global-mutation", BANNED_CALLS, IntStream.rangeClosed(113, 147).toArray());
		expect(expected, "markdown-doc-comment", BANNED_CALLS, 150, 152, 158);
		expect(expected, "insecure-random", "com/revetsec/InsecureRandomFixture.java", 19, 20, 21, 22, 23, 31, 32, 33,
				34, 35);
		expect(expected, "synchronized", "com/revetsec/SynchronizedFixture.java", 32, 36, 42, 43);
		expect(expected, "background-work", SourcePolicyTests.DEFAULT_HTTP_CLIENT_HOLDER, 28);
		expect(expected, "package-path-mismatch", "com/revetsec/internal/xml/MisplacedXmlFixture.java", 17);
		expect(expected, "xpath-in-saml", "com/revetsec/internal/xml/XmlFixture.java", 19, 28);
		expect(expected, "non-namespace-dom-lookup", "com/revetsec/internal/xml/XmlFixture.java", 29);
		expect(expected, "xml-factory-outside-internal-xml", "com/revetsec/saml/SamlFixture.java", 25);
		expect(expected, "non-namespace-dom-lookup", "com/revetsec/saml/SamlFixture.java", 26, 27);
		// R10: internal.crypto and the two sealer files. json/ScopeControlFixture.java is the out-of-scope control.
		expect(expected, "constant-time-comparison", "com/revetsec/internal/crypto/ComparisonFixture.java", 27, 28, 29,
				30, 31, 32);
		expect(expected, "constant-time-comparison", "com/revetsec/StateSealer.java", 24);
		expect(expected, "constant-time-comparison", "com/revetsec/SealingKey.java", 24);
		expect(expected, "constant-time-comparison", "com/revetsec/oauth/PendingAuthorizationResolver.java", 22);
		expect(expected, "byte-comparison", "com/revetsec/oauth/PendingAuthorizationResolver.java", 23);
		// G7-7: scim and internal.json.
		expect(expected, "ascii-case-fold", "com/revetsec/scim/CaseFoldFixture.java", 26, 27, 28, 29, 30, 31, 32);
		expect(expected, "ascii-case-fold", "com/revetsec/internal/json/JsonCaseFoldFixture.java", 19, 27, 28);
		// G6-4: internal/ObserverDispatch.java is exempt from logging only.
		expect(expected, "logging", "com/revetsec/LoggingFixture.java", 27, 28, 29, 30, 31, 32, 33, 34, 35);
		expect(expected, "console-output", "com/revetsec/internal/ObserverDispatch.java", 33);
		// M2-10 item 1: internal.jose; json/ScopeControlFixture.java is the out-of-scope control.
		expect(expected, "byte-comparison", "com/revetsec/internal/jose/ByteComparisonFixture.java", 29, 30, 31, 32,
				33, 34, 35, 36, 37, 38, 39, 40, 41);
		// M2-10 item 8: internal.jose joins scim and internal.json.
		expect(expected, "ascii-case-fold", "com/revetsec/internal/jose/TypeHeaderFixture.java", 25, 26, 27);
		// M2-10 item 4: internal.jose and internal.crypto; json/ScopeControlFixture.java is the out-of-scope control.
		// Lines 50 to 55 name a provider outside getInstance, which a getInstance-only check would miss: the
		// certificate, CRL and encrypted-key methods that have Provider overloads, and the three that have none.
		expect(expected, "jca-provider-argument", "com/revetsec/internal/jose/ProviderArgumentFixture.java", 36, 37, 38,
				39, 40, 41, 42, 43, 44, 50, 51, 52, 53, 54, 55);
		expect(expected, "jca-provider-argument", SIGNATURE_NAME_FIXTURE, 49);
		expect(expected, "jca-provider-argument", "com/revetsec/jose/JwsSigner.java", 28, 31);
		// M2-10 item 3: everywhere, in string constants and (line 63, an enum constant) in identifiers.
		expect(expected, "p1363-signature-name", SIGNATURE_NAME_FIXTURE, 33, 36, 37, 38, 39, 40, 42, 44, 45, 46, 47,
				63);
		// M2-10 item 5: everywhere except internal.encoding (internal/encoding/UrlDecoderControlFixture.java).
		expect(expected, "raw-base64url-decoder", "com/revetsec/internal/jose/SegmentDecoderFixture.java", 28, 29, 30);
		expect(expected, "raw-base64url-decoder", PROVIDED_ANNOTATION_FIXTURE, 37);
		// M2-10 item 2: files of exported packages only; internal/http/GuardedExchangeFixture.java is the control.
		expect(expected, "provided-annotation-with-element", "com/revetsec/jose/GuardedStateFixture.java", 33, 35, 36,
				39, 45);
		expect(expected, "provided-annotation-with-element", PROVIDED_ANNOTATION_FIXTURE, 26, 32);
		// G8-4's test hooks: a *ForTests method is called only in the file that declares it. Line 41 is a hook call
		// passed as an argument, and line 58 an unqualified call to an inherited hook. The same package is not the same
		// file (TestHookNeighborFixture), and neither is the same file and class name in another package
		// (internal/TestHookFixture.java, whose own hook is not reported); internal/http/TestHookFixture.java, which
		// declares and calls its own hooks, also from a second top-level class, is the control.
		expect(expected, "for-tests-call", TEST_HOOK_CALLER_FIXTURE, 35, 36, 37, 38, 39, 41, 58);
		expect(expected, "for-tests-call", "com/revetsec/internal/http/TestHookNeighborFixture.java", 25);
		expect(expected, "for-tests-call", "com/revetsec/internal/TestHookFixture.java", 26);
		// R4, G6-10: LookupTable.VALUES (line 49) is allowlisted; the stale, duplicate and malformed rows are reported.
		expect(expected, "mutable-static", MUTABLE_STATIC_FIXTURE, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38,
				45, 50, 84, 86);
		// Each branch of a conditional or switch initializer is checked, and EnumSet.of is not an immutable factory.
		expect(expected, "mutable-static", MUTABLE_STATIC_BRANCHES_FIXTURE, 35, 36, 37, 38, 42, 48, 54, 55, 56);
		expected.addAll(List.of(
				MUTABLE_STATIC_ALLOWLIST + " entry \"com.revetsec.MutableStaticFixture$LookupTable#VALUES\"",
				MUTABLE_STATIC_ALLOWLIST + " entry \"com.revetsec.MutableStaticFixture.LookupTable#UNLISTED\"",
				MUTABLE_STATIC_ALLOWLIST + " entry \"com.revetsec.MutableStaticFixture$Controls#LIMIT\"",
				MUTABLE_STATIC_ALLOWLIST + " entry \"com.revetsec.RenamedFixture#TABLE\"",
				MUTABLE_STATIC_ALLOWLIST + " row 6",
				MUTABLE_STATIC_ALLOWLIST + " row 7",
				MUTABLE_STATIC_ALLOWLIST + " row 8"));

		List<String> reported = SourcePolicyTests.findViolations(fixture("source-policy"),
						FIXTURE_MUTABLE_STATIC_ALLOWLIST).stream()
				.map(violation -> violation.substring(0, violation.indexOf(": ")))
				.sorted()
				.toList();
		Assertions.assertEquals(expected.stream().sorted().toList(), reported);
	}

	/**
	 * Allowlist rows are checked like the other reviewed-exception lists: a repeated row, one that names no reported
	 * field (misspelled, renamed or no longer mutable) and a malformed one are each reported with the reason, and a
	 * reported field names itself in the form a row uses.
	 */
	@Test
	void mutableStaticAllowlistRowsAreCheckedForStalenessAndForm() throws IOException {
		List<String> violations = SourcePolicyTests.findViolations(fixture("source-policy"),
				FIXTURE_MUTABLE_STATIC_ALLOWLIST);
		String stale = ": stale or misspelled entry; name a field that mutable-static reports, by the binary name of "
				+ "its class (Outer$Nested, as violation messages print it) and its name";
		String malformed = ": malformed row; expected {\"<binary class name>\", \"<field name>\", \"<why it is "
				+ "safe>\"}, with no blank value and no surrounding whitespace";

		Assertions.assertEquals(List.of(
				MUTABLE_STATIC_ALLOWLIST + " entry \"com.revetsec.MutableStaticFixture$LookupTable#VALUES\": "
						+ "duplicate entry; list each field once",
				MUTABLE_STATIC_ALLOWLIST + " entry \"com.revetsec.MutableStaticFixture.LookupTable#UNLISTED\"" + stale,
				MUTABLE_STATIC_ALLOWLIST + " entry \"com.revetsec.MutableStaticFixture$Controls#LIMIT\"" + stale,
				MUTABLE_STATIC_ALLOWLIST + " entry \"com.revetsec.RenamedFixture#TABLE\"" + stale,
				MUTABLE_STATIC_ALLOWLIST + " row 6" + malformed,
				MUTABLE_STATIC_ALLOWLIST + " row 7" + malformed,
				MUTABLE_STATIC_ALLOWLIST + " row 8" + malformed), violations.stream()
				.filter(violation -> violation.startsWith(MUTABLE_STATIC_ALLOWLIST))
				.toList());
		assertReported(violations, "mutable-static " + MUTABLE_STATIC_FIXTURE
				+ ":50: com.revetsec.MutableStaticFixture$LookupTable#UNLISTED: no mutable static state");
		assertReported(violations, "mutable-static " + MUTABLE_STATIC_FIXTURE
				+ ":45: com.revetsec.MutableStaticFixture$Constants#VALUES: ");
		assertNotReported(violations, "com.revetsec.MutableStaticFixture$LookupTable#VALUES: no mutable static state");
	}

	/**
	 * A line that declares several reported fields names each of them, so every allowlist row the line needs can be
	 * written from one run; a field that a row exempts drops out of its line (R4, G6-10).
	 */
	@Test
	void mutableStaticNamesEveryReportedFieldOnALine() throws IOException {
		List<String> violations = SourcePolicyTests.findViolations(fixture("source-policy"),
				FIXTURE_MUTABLE_STATIC_ALLOWLIST);

		assertReported(violations, "mutable-static " + MUTABLE_STATIC_BRANCHES_FIXTURE
				+ ":54: com.revetsec.MutableStaticBranchesFixture#first, "
				+ "com.revetsec.MutableStaticBranchesFixture#second: no mutable static state");
		assertReported(violations, "mutable-static " + MUTABLE_STATIC_BRANCHES_FIXTURE
				+ ":55: com.revetsec.MutableStaticBranchesFixture#RIGHT: no mutable static state");
		assertNotReported(violations, "com.revetsec.MutableStaticBranchesFixture#LEFT");
	}

	/**
	 * Each M2 rule reports its own reason (M2-10, and for-tests-call for G8-4's test hooks), and
	 * constant-time-comparison's reason covers the helpers M2 adds to internal.crypto (M2-7), so a rule wired to another
	 * rule's reason, or left with M1's sealer-only reason, fails here.
	 */
	@Test
	void m2RulesReportTheirOwnReasons() throws IOException {
		List<String> violations = SourcePolicyTests.findViolations(fixture("source-policy"),
				FIXTURE_MUTABLE_STATIC_ALLOWLIST);

		assertReported(violations, "byte-comparison com/revetsec/internal/jose/ByteComparisonFixture.java:29: compare "
				+ "bytes through internal.crypto.ConstantTime");
		assertReported(violations, "byte-comparison com/revetsec/oauth/PendingAuthorizationResolver.java:23: compare "
				+ "bytes through internal.crypto.ConstantTime");
		assertNotReported(violations, "PublicIdentifierComparisonFixture");
		assertReported(violations, "ascii-case-fold com/revetsec/internal/jose/TypeHeaderFixture.java:25: fold case "
				+ "with internal.json.AsciiCase");
		assertReported(violations, "jca-provider-argument com/revetsec/internal/jose/ProviderArgumentFixture.java:36: "
				+ "name the algorithm and let the JCA choose the provider");
		assertReported(violations, "p1363-signature-name " + SIGNATURE_NAME_FIXTURE + ":38: verify ECDSA through the "
				+ "DER-encoded SHAxxxwithECDSA names");
		assertReported(violations, "raw-base64url-decoder com/revetsec/internal/jose/SegmentDecoderFixture.java:28: "
				+ "decode base64url through internal.encoding.Base64Url");
		assertReported(violations, "provided-annotation-with-element com/revetsec/jose/GuardedStateFixture.java:33: no "
				+ "provided-scope annotation whose type has elements");
		assertReported(violations, "for-tests-call " + TEST_HOOK_CALLER_FIXTURE + ":35: a *ForTests method is a test "
				+ "hook, public only so that tests in other packages can reach it; main code calls one only in the file "
				+ "that declares it");
		assertReported(violations, "constant-time-comparison com/revetsec/internal/crypto/ComparisonFixture.java:27: "
				+ "String and Arrays equality return at the first difference");
		// Tags, Hmac's included, go through ConstantTime; BigInteger.compareTo is only for the helpers' public values.
		assertReported(violations, "compare keys, tags (Hmac's included), kids and other sealed state through "
				+ "internal.crypto.ConstantTime (MessageDigest.isEqual), and names through enums or switch; only the "
				+ "public-key and signature helpers (EcdsaSignatures, EcCurve, EcPublicKeys, RsaPublicKeys, "
				+ "Ed25519PublicKeys and SignatureVerifier) may also range-check public values with BigInteger.compareTo "
				+ "(R10, M2-7)");
		assertNotReported(violations, "Hmac, EcdsaSignatures");
	}

	/**
	 * Each regular-expression alternative, table entry and special check must have a seeded line that it alone
	 * reports, so dropping or breaking any one of them changes the exact result above.
	 */
	@Test
	void everySourcePolicyAlternativeHasItsOwnSeededLine() throws IOException {
		Map<String, List<String>> alternativesByLine = SourcePolicyTests.alternativeIdsByKey(
				SourcePolicyTests.findDetections(fixture("source-policy"), FIXTURE_MUTABLE_STATIC_ALLOWLIST));

		List<String> unexercised = SourcePolicyTests.alternativeIds().stream()
				.filter(alternative -> !alternativesByLine.containsValue(List.of(alternative)))
				.toList();
		Assertions.assertEquals(List.of(), unexercised,
				"Alternatives without a seeded line that only they report: " + unexercised);
		List<String> reportedRules = alternativesByLine.keySet().stream()
				.map(key -> key.substring(0, key.indexOf(' ')))
				.distinct()
				.sorted()
				.toList();
		Assertions.assertEquals(SourcePolicyTests.ruleIds().stream().sorted().toList(), reportedRules,
				"Every rule needs a seeded violation");
	}

	@Test
	void unicodeEscapesTranslateAsJavacTranslatesThem() {
		Assertions.assertEquals("System", translated("\\u0053ystem"));
		Assertions.assertEquals("System", translated("\\uuu0053ystem"));
		Assertions.assertEquals("\\\\u0053", translated("\\\\u0053"), "an escaped backslash does not start an escape");
		Assertions.assertEquals("\\\\S", translated("\\\\\\u0053"),
				"a backslash after an even number of backslashes does");
		Assertions.assertEquals("\\u00zz", translated("\\u00zz"));

		ContractSupport.TranslatedSource escapedNewline = ContractSupport.translateUnicodeEscapes("a\\u000ab");
		Assertions.assertEquals("a b", escapedNewline.getText(), "line numbers must not move");
		Assertions.assertTrue(escapedNewline.isEscapedLineTerminator(1));
		Assertions.assertFalse(escapedNewline.isEscapedLineTerminator(0));
		Assertions.assertEquals("  x", ContractSupport.stripCommentsAndStrings(
				ContractSupport.translateUnicodeEscapes("// comment \\u000a x")),
				"an escaped newline ends a line comment");

		// U+FFFF, escaped or not, is an ordinary character: it neither ends a literal nor a comment.
		for (String noncharacter : List.of("\\uFFFF", "\uFFFF")) {
			ContractSupport.TranslatedSource source = ContractSupport.translateUnicodeEscapes(
					"a(\"" + noncharacter + "\") || b(\"System.out\"); // " + noncharacter + " System.err");
			Assertions.assertEquals("a(\"\") || b(\"\"); ", ContractSupport.stripCommentsAndStrings(source));
			Assertions.assertFalse(source.isEscapedLineTerminator(3));
		}
	}

	private static @NonNull String translated(@NonNull String source) {
		return ContractSupport.translateUnicodeEscapes(source).getText();
	}

	@Test
	void bannedHostnameScanSearchesTextBinaryAndBase64Content(@TempDir @NonNull Path repository) throws IOException {
		String hostname = String.join(".", "saml" + "test", "id");
		byte[] certificate = derLike(hostname);
		write(repository, "docs/partners.md", "Line one\nSee https://" + hostname + "/idp\n");
		write(repository, "clean.txt", "Nothing to see.\n");
		write(repository, "binary.bin", new byte[]{0, 1, 2, 's', 'a', 'm', 'l'});
		write(repository, "fixtures/idp/idp-cert.der", certificate);
		write(repository, "fixtures/idp/metadata-utf16le.xml",
				("<EntityDescriptor entityID=\"https://" + hostname + "/\"/>").getBytes(StandardCharsets.UTF_16LE));
		write(repository, "fixtures/idp/metadata-utf16be.xml",
				("<EntityDescriptor entityID=\"https://" + hostname + "/\"/>").getBytes(StandardCharsets.UTF_16));
		write(repository, "fixtures/idp/idp-cert.pem", "-----BEGIN CERTIFICATE-----\n"
				+ Base64.getMimeEncoder().encodeToString(certificate) + "\n-----END CERTIFICATE-----\n");
		write(repository, "fixtures/idp/metadata.xml", "<md:EntityDescriptor>\n<ds:X509Certificate>"
				+ Base64.getEncoder().encodeToString(certificate) + "</ds:X509Certificate>\n</md:EntityDescriptor>\n");
		write(repository, "fixtures/other-cert.pem", "-----BEGIN CERTIFICATE-----\n"
				+ Base64.getEncoder().encodeToString(derLike("example.com")) + "\n-----END CERTIFICATE-----\n");
		// Without a git listing, build-output directories are skipped wherever they are.
		write(repository, "target/ignored.txt", hostname);
		write(repository, "fixtures/idp/target/ignored.txt", hostname);

		Assertions.assertEquals(List.of(
				"docs/partners.md:2",
				"fixtures/idp/idp-cert.der (binary)",
				"fixtures/idp/idp-cert.pem:1 (base64 block)",
				"fixtures/idp/metadata-utf16be.xml (binary)",
				"fixtures/idp/metadata-utf16le.xml (binary)",
				"fixtures/idp/metadata.xml:2 (base64 block)"), SourcePolicyTests.findBannedHostnames(repository));
	}

	@Test
	void repositoryScansFollowWhatGitWouldTrack(@TempDir @NonNull Path repository) throws IOException {
		Assumptions.assumeTrue(git(repository, "init", "-q") && git(repository, "config", "core.excludesFile",
				".git/no-global-excludes"), "git is not available");
		String hostname = String.join(".", "saml" + "test", "id");
		write(repository, ".gitignore", "/target/\n");
		write(repository, "target/ignored.txt", hostname);
		write(repository, "fixtures/idp/target/metadata.xml", "<EntityDescriptor entityID=\"https://" + hostname
				+ "/\"/>\n");
		write(repository, "tools/node_modules/sample/README.md", "Mirror of https://" + hostname + "\n");

		Assertions.assertEquals(List.of(
				"fixtures/idp/target/metadata.xml:1",
				"tools/node_modules/sample/README.md:1"), SourcePolicyTests.findBannedHostnames(repository));
	}

	@Test
	void licenseHeaderCheckDetectsMissingHeader(@TempDir @NonNull Path sourceRoot) throws IOException {
		Files.createDirectories(sourceRoot.resolve("com/revetsec"));
		Files.writeString(sourceRoot.resolve("com/revetsec/WithHeader.java"),
				ContractSupport.LICENSE_HEADER + "\npackage com.revetsec;\n", StandardCharsets.UTF_8);
		Files.writeString(sourceRoot.resolve("com/revetsec/WithoutHeader.java"), "package com.revetsec;\n",
				StandardCharsets.UTF_8);

		Assertions.assertEquals(List.of("com/revetsec/WithoutHeader.java"),
				SourcePolicyTests.findMissingLicenseHeaders(sourceRoot));
	}

	@Test
	void claimsLintReportsExactlyTheSeededClaimsAndAllowlistProblems(@TempDir @NonNull Path repository) throws IOException {
		copyFixture("claims", repository);
		Files.createDirectories(repository.resolve("target"));
		Files.writeString(repository.resolve("target/ignored.md"), "Excluded build output: certified.\n",
				StandardCharsets.UTF_8);
		Files.createDirectories(repository.resolve("docs/images"));
		Files.write(repository.resolve("docs/images/openid-certified-mark.png"), new byte[]{(byte) 0x89, 'P', 'N', 'G'});
		Files.write(repository.resolve("docs/images/openid-connect-login-flow.svg"), new byte[]{'<', 's', 'v', 'g', '>'});

		// The context quoted after " in " is for readers; it is left out here.
		List<String> violations = ClaimsLintTests.findViolations(repository).stream()
				.map(violation -> violation.contains(" in \"") ? violation.substring(0, violation.indexOf(" in \""))
						: violation)
				.toList();

		Assertions.assertEquals(List.of(
				"docs/images/openid-certified-mark.png: OpenID Foundation logo files are not allowed without a "
						+ "certification (plan 19)",
				"claims-allowlist.txt:7: malformed entry; expected <relative-path>|<exact "
						+ "substring>|<evidence-or-reason>",
				"claims-allowlist.txt:8 (README.md|independently): too broad; quote the approved wording, with at "
						+ "least 2 words besides the banned terms, so the entry cannot allow later uses of the term "
						+ "(plan 19)",
				"claims-allowlist.txt:9 (README.md|been independently audited): too broad; quote the approved "
						+ "wording, with at least 2 words besides the banned terms, so the entry cannot allow later "
						+ "uses of the term (plan 19)",
				"claims-allowlist.txt:4 (README.md|This sentence does not appear anywhere.): stale; the substring no "
						+ "longer appears in README.md",
				"claims-allowlist.txt:5 (README.md|the conformance suite): stale; the substring contains no banned "
						+ "term",
				"claims-allowlist.txt:6 (docs/missing.md|anything): stale; docs/missing.md does not exist or is not "
						+ "a scanned file",
				"README.md:3: banned claim term 'production-ready'",
				"README.md:8: banned claim term 'battle-tested'",
				"README.md:13: banned claim term 'FIPS'",
				"README.md:17: banned claim term 'production-ready'",
				"README.md:18: banned claim term 'battle-tested'",
				"README.md:21: banned claim term 'production-ready'",
				"README.md:21: banned claim term 'production-proven'",
				"README.md:23: banned claim term 'production-ready'",
				"README.md:23: banned claim term 'pen-tested'",
				"docs/guide.md:3: banned claim term 'more secure than'",
				"docs/guide.md:5: banned claim term 'more secure than'",
				"pom.xml:8: banned claim term 'battle-tested'",
				"src/main/java/com/revetsec/DocFixture.java:20: banned claim term 'compliant'",
				"src/main/java/com/revetsec/DocFixture.java:21: banned claim term 'production-ready'",
				"src/main/java/com/revetsec/DocFixture.java:22: banned claim term 'pen-tested'",
				"src/main/java/com/revetsec/DocFixture.java:33: banned claim term 'conformant'",
				"src/main/java/com/revetsec/doc-files/notes.html:3: banned claim term 'battle-tested'",
				"src/main/java/com/revetsec/package.html:3: banned claim term 'audited'",
				"src/main/javadoc/overview.html:4: banned claim term 'certified'",
				"src/main/javadoc/overview.html:5: banned claim term 'production-ready'"), violations);
	}

	@Test
	void claimsLintTreatsMissingAllowlistAsEmpty(@TempDir @NonNull Path repository) throws IOException {
		copyFixture("claims", repository);
		Files.delete(repository.resolve(ClaimsLintTests.ALLOWLIST_FILE));

		List<String> violations = ClaimsLintTests.findViolations(repository);

		assertReported(violations, "README.md:5: banned claim term 'independently'");
		assertReported(violations, "README.md:6: banned claim term 'audited'");
		assertNotReported(violations, ClaimsLintTests.ALLOWLIST_FILE);
	}

	@Test
	void claimsLintCoversEveryPlannedTerm() {
		Assertions.assertEquals(
				List.of("FIPS", "audited", "battle-tested", "certified", "compliant", "conformant", "independently",
						"more secure than", "pen-tested", "production-proven", "production-ready"),
				List.copyOf(ClaimsLintTests.bannedTermNames()));
	}

	private static void expect(@NonNull List<@NonNull String> expected, @NonNull String ruleId, @NonNull String path, int @NonNull ... lines) {
		for (int line : lines)
			expected.add(ruleId + " " + path + ":" + line);
	}

	/**
	 * A few bytes shaped like a DER certificate, with {@code name} as an ASCII string inside.
	 */
	private static byte @NonNull [] derLike(@NonNull String name) {
		ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
		outputStream.writeBytes(new byte[]{0x30, (byte) 0x82, 0x01, 0x0a, 0x30, 0x00, 0x13, (byte) name.length()});
		outputStream.writeBytes(name.getBytes(StandardCharsets.US_ASCII));
		outputStream.writeBytes(new byte[]{0x00, 0x01, 0x02});
		return outputStream.toByteArray();
	}

	private static void write(@NonNull Path root, @NonNull String relativePath, @NonNull String content) throws IOException {
		write(root, relativePath, content.getBytes(StandardCharsets.UTF_8));
	}

	private static void write(@NonNull Path root, @NonNull String relativePath, byte @NonNull [] content) throws IOException {
		Path file = root.resolve(relativePath);
		Files.createDirectories(file.getParent());
		Files.write(file, content);
	}

	/**
	 * Runs git in {@code directory}; returns whether it ran and succeeded.
	 */
	private static boolean git(@NonNull Path directory, @NonNull String @NonNull ... arguments) {
		List<String> command = new ArrayList<>(List.of("git", "-C", directory.toString()));
		command.addAll(List.of(arguments));
		try {
			Process process = new ProcessBuilder(command).redirectErrorStream(true)
					.redirectOutput(ProcessBuilder.Redirect.DISCARD).start();
			if (!process.waitFor(60, TimeUnit.SECONDS)) {
				process.destroyForcibly();
				return false;
			}
			return process.exitValue() == 0;
		} catch (IOException e) {
			return false;
		} catch (InterruptedException e) {
			Thread.currentThread().interrupt();
			return false;
		}
	}

	private static void copyFixture(@NonNull String name, @NonNull Path target) throws IOException {
		Path source = fixture(name);
		try (Stream<Path> paths = Files.walk(source)) {
			for (Path path : paths.toList()) {
				Path destination = target.resolve(ContractSupport.relativePath(source, path));
				if (Files.isDirectory(path))
					Files.createDirectories(destination);
				else
					Files.copy(path, destination);
			}
		}
	}

	private static void assertReported(@NonNull List<@NonNull String> violations, @NonNull String expectedFragment) {
		Assertions.assertTrue(violations.stream().anyMatch(violation -> violation.contains(expectedFragment)),
				() -> "Expected a violation containing \"" + expectedFragment + "\" but found:\n - "
						+ String.join("\n - ", violations));
	}

	private static void assertNotReported(@NonNull List<@NonNull String> violations, @NonNull String unexpectedFragment) {
		Assertions.assertTrue(violations.stream().noneMatch(violation -> violation.contains(unexpectedFragment)),
				() -> "Expected no violation containing \"" + unexpectedFragment + "\" but found:\n - "
						+ String.join("\n - ", violations));
	}
}
