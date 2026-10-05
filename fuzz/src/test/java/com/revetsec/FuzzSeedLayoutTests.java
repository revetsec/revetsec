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

import com.code_intelligence.jazzer.junit.FuzzTest;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.jspecify.annotations.NonNull;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.net.URISyntaxException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.function.Predicate;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * The fuzz module's seed layout (M1 plan, WP-8 and exit criterion 18; M2 plan, WP-10). Jazzer's replay and
 * {@code .clusterfuzzlite/build.sh} find a target's seeds only by the path
 * {@code <package>/<SimpleClassName>Inputs/<method>/} on the test class path, which the hand-written seed directories
 * and the fuzz pom's {@code targetPath} entries spell out as plain strings. Without these checks, renaming or moving a
 * target drops its seeds silently: the replay passes with fewer inputs, and ClusterFuzzLite starts the target from
 * nothing.
 * <p>
 * The JOSE packages hold targets of both kinds, so every {@code byte[]} target there must be listed as reading JSON
 * text (a decoded JOSE header, a JWK Set document), which then needs the JSON corpora, or as reading something else (a
 * compact serialization, a signing program). A new JOSE target that is on neither list fails the replay.
 * <p>
 * This is a plain JUnit class, not a fuzz target, so the pom's Surefire includes name it next to the
 * {@code *FuzzTests} pattern, and {@code build.sh}, which looks only for {@code *FuzzTests} classes, never sees it.
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 */
final class FuzzSeedLayoutTests {
	private static final String INPUTS_SUFFIX = "Inputs";
	private static final String FUZZ_TESTS_SUFFIX = "FuzzTests";
	private static final String CLASS_FILE_SUFFIX = ".class";

	/**
	 * The packages whose {@code byte[]} targets read JSON text, so each must be seeded with the core JSON corpus and
	 * JSONTestSuite.
	 */
	private static final Set<String> JSON_TEXT_PACKAGES = Set.of("com.revetsec.json", "com.revetsec.internal.json", "com.revetsec.oidc");

	/**
	 * The packages whose {@code byte[]} targets must each be listed below as reading JSON text or not, because they
	 * hold both kinds.
	 */
	private static final Set<String> JOSE_PACKAGES = Set.of("com.revetsec.jose", "com.revetsec.internal.jose");

	/**
	 * The JOSE {@code byte[]} targets that read JSON text (a decoded JOSE header, a JWK Set document), so each must be
	 * seeded with the core JSON corpus and JSONTestSuite like the JSON targets.
	 */
	private static final Set<String> JOSE_JSON_TEXT_TARGETS = Set.of(
			"com.revetsec.internal.jose.CompactJwsFuzzTests#headerChecksAgreeWithAnIndependentOracleForP3ToP8",
			"com.revetsec.internal.jose.JsonWebKeyFuzzTests#keySetDocumentsSkipExactlyTheKeysAnIndependentOracleRefuses");

	/**
	 * The JOSE {@code byte[]} targets that read something else: compact serializations and signing programs.
	 */
	private static final Set<String> JOSE_OTHER_TARGETS = Set.of(
			"com.revetsec.jose.JwsSignerFuzzTests#signingMatchesIndependentGrammarAndSignature",
			"com.revetsec.internal.jose.CompactJwsFuzzTests#"
					+ "compactSerializationsSplitIntoThreeCanonicalSegmentsOrFailInStepOrder",
			"com.revetsec.jose.JwtValidatorFuzzTests#validateAcceptsOnlyWhatTheJdkVerifiersAccept",
			"com.revetsec.jose.JwtValidatorFuzzTests#signedTokensAreJudgedLikeTheOracleWhateverTheirHeaderAndClaims");

	private static final Set<String> RESOURCE_JSON_TEXT_TARGETS = Set.of(
			"com.revetsec.oauth.ResourceServerFuzzTests#metadataKeepsRolesAndRawResourceIdentifiers",
			"com.revetsec.oauth.ResourceServerFuzzTests#signedAccessTokensRespectStrictAndUntypedProfiles",
			"com.revetsec.oauth.ResourceServerFuzzTests#introspectionResponsesAreTypedAudienceCheckedAndUncached");

	private static final List<MappedCorpus> JSON_TEXT_CORPORA = List.of(
			new MappedCorpus("src/test/resources/com/revetsec/internal/json/corpus", "",
					relative -> relative.startsWith("parse/") || relative.startsWith("round-trip/")),
			new MappedCorpus("src/test/resources/vectors/jsontestsuite/test_parsing", "jsontestsuite/",
					relative -> relative.indexOf('/') < 0 && relative.endsWith(".json")));

	/**
	 * The JWK Set target reads JSON text, and also gets the Entra key-set captures, real key sets with {@code x5c}
	 * chains and templated {@code issuer} members.
	 */
	private static final List<MappedCorpus> KEY_SET_CORPORA = List.of(JSON_TEXT_CORPORA.get(0), JSON_TEXT_CORPORA.get(1),
			new MappedCorpus("src/test/resources/com/revetsec/jose/entra/2026-09-27", "entra/",
					relative -> relative.indexOf('/') < 0 && relative.endsWith("-keys.json")));

	private static final List<MappedCorpus> PEM_TEXT_CORPORA = List.of(
			new MappedCorpus("src/test/resources/fixtures/pem", "fixtures-pem/",
					relative -> relative.indexOf('/') < 0 && relative.endsWith(".pem")),
			new MappedCorpus("src/test/resources/fixtures/keys", "fixtures-keys/",
					relative -> relative.indexOf('/') < 0 && relative.endsWith(".pem")));

	/**
	 * Every target the fuzz pom maps a core corpus into, with the corpora it maps (its {@code testResource} entries).
	 */
	private static final Map<String, List<MappedCorpus>> MAPPED_TARGETS = Map.ofEntries(
			Map.entry("com.revetsec.internal.json.JsonCodecFuzzTests#"
					+ "parseRejectsOnlyWithJsonParseExceptionAndAcceptsOnlyValuesInsideTheProfile", JSON_TEXT_CORPORA),
			Map.entry("com.revetsec.internal.json.JsonCodecFuzzTests#acceptedValuesRoundTripUnderTheMaximumCapProfile", JSON_TEXT_CORPORA),
			Map.entry("com.revetsec.internal.json.JsonCodecFuzzTests#scimAcceptsOnlyWhatTheExactNameProfileAccepts", JSON_TEXT_CORPORA),
			Map.entry("com.revetsec.json.JsonModelFuzzTests#parsedValuesKeepEqualityUnderReorderingAndRescaling", JSON_TEXT_CORPORA),
			Map.entry("com.revetsec.internal.json.Rfc7638FuzzTests#canonicalJwkAgreesWithAnIndependentEncoder", JSON_TEXT_CORPORA),
			Map.entry("com.revetsec.internal.pem.PemFuzzTests#pemParsersRejectOnlyWithPemExceptionAndAcceptAtMostOneLabel", PEM_TEXT_CORPORA),
			Map.entry("com.revetsec.internal.jose.CompactJwsFuzzTests#headerChecksAgreeWithAnIndependentOracleForP3ToP8", JSON_TEXT_CORPORA),
			Map.entry("com.revetsec.internal.jose.JsonWebKeyFuzzTests#keySetDocumentsSkipExactlyTheKeysAnIndependentOracleRefuses", KEY_SET_CORPORA),
			Map.entry("com.revetsec.oidc.OidcFuzzTests#signedClaimsRespectInitialAndRefreshProfiles", JSON_TEXT_CORPORA),
			Map.entry("com.revetsec.oidc.OidcFuzzTests#metadataRequiresExactIssuerAndCapabilities", JSON_TEXT_CORPORA),
			Map.entry("com.revetsec.oidc.OidcFuzzTests#userInfoRequiresTheVerifiedSubject", JSON_TEXT_CORPORA),
			Map.entry("com.revetsec.oidc.OidcFuzzTests#sessionReferencesRoundTripWithoutCredentials", JSON_TEXT_CORPORA),
			Map.entry("com.revetsec.oauth.ResourceServerFuzzTests#metadataKeepsRolesAndRawResourceIdentifiers", JSON_TEXT_CORPORA),
			Map.entry("com.revetsec.oauth.ResourceServerFuzzTests#signedAccessTokensRespectStrictAndUntypedProfiles", JSON_TEXT_CORPORA),
			Map.entry("com.revetsec.oauth.ResourceServerFuzzTests#introspectionResponsesAreTypedAudienceCheckedAndUncached", JSON_TEXT_CORPORA));

	// A seed directory whose class or method no longer exists (after a rename or a move) is never replayed or zipped.
	@Test
	void everyInputsDirectoryBelongsToAFuzzTestMethodOfItsClass() throws IOException {
		Path root = testClassesRoot();
		List<String> orphans = new ArrayList<>();
		int directories = 0;

		for (Path inputs : inputsDirectories(root)) {
			String className = className(root, inputs);
			Set<String> methods = fuzzTestMethodNames(className);

			try (Stream<Path> children = Files.list(inputs)) {
				for (Path child : children.sorted().toList()) {
					++directories;
					if (!Files.isDirectory(child) || !methods.contains(child.getFileName().toString()))
						orphans.add(root.relativize(child).toString());
				}
			}
		}

		Assertions.assertTrue(directories > 0, "no inputs directory was found under " + root);
		Assertions.assertEquals(List.of(), orphans, "seed directories with no matching @FuzzTest method");
	}

	// Every target starts from at least one seed, in the Maven replay and in ClusterFuzzLite's seed zip.
	@Test
	void everyFuzzTestMethodHasAtLeastOneSeed() throws IOException {
		Path root = testClassesRoot();
		Map<String, Long> seedCounts = new TreeMap<>();

		for (String target : fuzzTargets(root))
			seedCounts.put(target, countFiles(inputsDirectory(root, target)));

		Assertions.assertTrue(seedCounts.size() >= MAPPED_TARGETS.size(), seedCounts::toString);
		Assertions.assertEquals(Map.of(), seedCounts.entrySet().stream().filter(entry -> entry.getValue() == 0)
				.collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue)), "targets with no seed");
	}

	// Each mapped corpus reaches its target whole and unchanged, every JSON-text target is mapped, and no mapping names
	// a method that is gone.
	@Test
	void everyMappedCorpusReachesItsTargetWhole() throws IOException {
		Path root = testClassesRoot();
		Path core = coreBasedir(root);
		Set<String> targets = fuzzTargets(root);

		Set<String> unmappedJsonTextTargets = new TreeSet<>();
		for (String target : targets)
			if (readsJsonText(target) && !MAPPED_TARGETS.containsKey(target))
				unmappedJsonTextTargets.add(target);
		Assertions.assertEquals(Set.of(), unmappedJsonTextTargets, "JSON-text targets without the mapped corpora");

		for (Map.Entry<String, List<MappedCorpus>> entry : MAPPED_TARGETS.entrySet()) {
			Assertions.assertTrue(targets.contains(entry.getKey()), () -> "no @FuzzTest method " + entry.getKey());
			Path inputs = inputsDirectory(root, entry.getKey());

			for (MappedCorpus corpus : entry.getValue()) {
				List<String> sources = corpus.sourceFiles(core);
				Assertions.assertFalse(sources.isEmpty(), () -> "no source files in " + core.resolve(corpus.source));

				for (String relative : sources) {
					Path mapped = inputs.resolve(corpus.target + relative);
					Assertions.assertTrue(Files.isRegularFile(mapped), () -> entry.getKey() + " lacks " + mapped);
					Assertions.assertEquals(-1L, Files.mismatch(core.resolve(corpus.source).resolve(relative), mapped),
							() -> mapped + " differs from its source");
				}
			}
		}
	}

	// Every byte[] target in a JOSE package is listed as reading JSON text or not, so a new one cannot miss the JSON
	// corpora by accident, and no listed target is gone.
	@Test
	void everyJoseByteTargetIsListedAsReadingJsonTextOrNot() throws IOException {
		Path root = testClassesRoot();
		Set<String> byteTargets = new TreeSet<>();

		for (String target : fuzzTargets(root))
			if (JOSE_PACKAGES.contains(loadClass(className(target)).getPackageName()) && takesBytes(target))
				byteTargets.add(target);

		Set<String> listed = new TreeSet<>(JOSE_JSON_TEXT_TARGETS);
		listed.addAll(JOSE_OTHER_TARGETS);

		Assertions.assertEquals(listed, byteTargets, "the JOSE byte[] targets and the two lists differ");
		Assertions.assertTrue(JOSE_JSON_TEXT_TARGETS.stream().noneMatch(JOSE_OTHER_TARGETS::contains),
				"a JOSE target is listed as both");
	}

	// Jazzer finds a target by reflecting over its class's declared methods, which loads every type their signatures
	// name before fuzzing starts. In ClusterFuzzLite's base image (its own Jazzer on Temurin 17.0.16), a record loaded
	// that early fails on its first construction with NoSuchFieldError on one of its own fields, which only the
	// ClusterFuzzLite build check would show. So no method of a fuzz target class names a record in its signature.
	@Test
	void noFuzzTargetClassNamesARecordInAMethodSignature() throws IOException {
		Path root = testClassesRoot();
		Set<String> violations = new TreeSet<>();

		for (String target : fuzzTargets(root)) {
			Class<?> type = loadClass(className(target));

			for (Method method : type.getDeclaredMethods()) {
				List<Class<?>> named = new ArrayList<>(Arrays.asList(method.getParameterTypes()));
				named.add(method.getReturnType());

				for (Class<?> signatureType : named) {
					Class<?> element = signatureType;

					while (element.isArray())
						element = element.getComponentType();

					if (element.isRecord())
						violations.add(type.getName() + "#" + method.getName() + " names " + element.getName());
				}
			}
		}

		Assertions.assertEquals(Set.of(), violations, "fuzz target methods that name a record in their signature");
	}

	/**
	 * Every {@code <SimpleClassName>Inputs} directory on the test class path: each lives in its class's package
	 * directory. The core test tree, which this module compiles in, has none.
	 */
	private static @NonNull List<@NonNull Path> inputsDirectories(@NonNull Path root) throws IOException {
		try (Stream<Path> paths = Files.walk(root)) {
			return paths.filter(Files::isDirectory)
					.filter(path -> !path.equals(root) && path.getFileName().toString().endsWith(INPUTS_SUFFIX))
					.sorted()
					.toList();
		}
	}

	/**
	 * Every {@code @FuzzTest} method, as {@code <binary class name>#<method>}, of every top-level {@code *FuzzTests}
	 * class on the test class path, which is the set {@code build.sh} makes targets of.
	 */
	private static @NonNull Set<@NonNull String> fuzzTargets(@NonNull Path root) throws IOException {
		Set<String> targets = new TreeSet<>();

		try (Stream<Path> paths = Files.walk(root)) {
			for (Path classFile : paths.filter(Files::isRegularFile)
					.filter(path -> path.getFileName().toString().endsWith(FUZZ_TESTS_SUFFIX + CLASS_FILE_SUFFIX))
					.sorted()
					.toList()) {
				String relative = root.relativize(classFile).toString().replace('\\', '/');
				String className = relative.substring(0, relative.length() - CLASS_FILE_SUFFIX.length()).replace('/', '.');

				for (String method : fuzzTestMethodNames(className))
					targets.add(className + "#" + method);
			}
		}

		Assertions.assertFalse(targets.isEmpty(), "no @FuzzTest method was found under " + root);
		return targets;
	}

	private static @NonNull Set<@NonNull String> fuzzTestMethodNames(@NonNull String className) {
		Class<?> type = loadClass(className);
		return Arrays.stream(type.getDeclaredMethods())
				.filter(method -> method.isAnnotationPresent(FuzzTest.class))
				.map(Method::getName)
				.collect(Collectors.toCollection(TreeSet::new));
	}

	/**
	 * A {@code byte[]} target in a JSON package, or a JOSE target on the JSON-text list, reads JSON text, so it is
	 * seeded with the JSON corpora.
	 */
	private static boolean readsJsonText(@NonNull String target) {
		// This target consumes bounded model control bytes, not raw metadata JSON.
		if (target.equals("com.revetsec.oidc.EntraIssuerFuzzTests#entraMatchesMetadataKeyTenantAndSessionModel")) return false;
		if (JOSE_JSON_TEXT_TARGETS.contains(target) || RESOURCE_JSON_TEXT_TARGETS.contains(target))
			return true;

		return JSON_TEXT_PACKAGES.contains(loadClass(className(target)).getPackageName()) && takesBytes(target);
	}

	/**
	 * Whether the target is a public method whose one parameter is {@code byte[]}.
	 */
	private static boolean takesBytes(@NonNull String target) {
		String methodName = target.substring(target.indexOf('#') + 1);

		for (Method method : loadClass(className(target)).getDeclaredMethods())
			if (method.getName().equals(methodName) && Modifier.isPublic(method.getModifiers())
					&& Arrays.equals(method.getParameterTypes(), new Class<?>[]{byte[].class}))
				return true;

		return false;
	}

	private static @NonNull String className(@NonNull String target) {
		return target.substring(0, target.indexOf('#'));
	}

	private static @NonNull Class<@NonNull ?> loadClass(@NonNull String className) {
		try {
			return Class.forName(className, false, FuzzSeedLayoutTests.class.getClassLoader());
		} catch (ClassNotFoundException e) {
			throw new AssertionError("No class " + className + " for its seed directory", e);
		}
	}

	private static @NonNull Path inputsDirectory(@NonNull Path root, @NonNull String target) {
		String className = target.substring(0, target.indexOf('#'));
		String methodName = target.substring(target.indexOf('#') + 1);
		return root.resolve(className.replace('.', '/') + INPUTS_SUFFIX).resolve(methodName);
	}

	private static @NonNull String className(@NonNull Path root, @NonNull Path inputs) {
		String relative = root.relativize(inputs).toString().replace('\\', '/');
		return relative.substring(0, relative.length() - INPUTS_SUFFIX.length()).replace('/', '.');
	}

	private static long countFiles(@NonNull Path directory) throws IOException {
		if (!Files.isDirectory(directory))
			return 0;

		try (Stream<Path> paths = Files.walk(directory)) {
			return paths.filter(Files::isRegularFile).count();
		}
	}

	/**
	 * The directory the test classes were loaded from: {@code fuzz/target/test-classes}.
	 */
	private static @NonNull Path testClassesRoot() {
		try {
			Path root = Path.of(FuzzSeedLayoutTests.class.getProtectionDomain().getCodeSource().getLocation().toURI());
			Assertions.assertTrue(Files.isDirectory(root), () -> "the test classes are not in a directory: " + root);
			return root;
		} catch (URISyntaxException e) {
			throw new IllegalStateException(e);
		}
	}

	/**
	 * The core checkout the fuzz pom maps its corpora from: the {@code revetsec.core.basedir} Surefire passes, or,
	 * outside Maven, the checkout that holds {@code fuzz/target/test-classes}.
	 */
	private static @NonNull Path coreBasedir(@NonNull Path testClassesRoot) {
		String configured = System.getProperty("revetsec.core.basedir");
		Path core = configured == null || configured.isBlank()
				? testClassesRoot.getParent().getParent().getParent()
				: Path.of(configured);
		Assertions.assertTrue(Files.isDirectory(core.resolve("src/test/resources")),
				() -> "not a Revetsec core checkout: " + core);
		return core.toAbsolutePath().normalize();
	}

	/**
	 * One core corpus the fuzz pom maps into a target's inputs directory: its source directory in the core checkout,
	 * the subdirectory it lands in, and which of its files the pom's includes select.
	 */
	private static final class MappedCorpus {
		private final String source;
		private final String target;
		private final Predicate<String> included;

		private MappedCorpus(@NonNull String source, @NonNull String target, @NonNull Predicate<@NonNull String> included) {
			this.source = source;
			this.target = target;
			this.included = included;
		}

		/**
		 * The included files, as paths relative to the source directory with {@code /} separators.
		 */
		private @NonNull List<@NonNull String> sourceFiles(@NonNull Path core) {
			Path directory = core.resolve(this.source);

			try (Stream<Path> paths = Files.walk(directory)) {
				return paths.filter(Files::isRegularFile)
						.map(path -> directory.relativize(path).toString().replace('\\', '/'))
						.filter(this.included)
						.sorted()
						.toList();
			} catch (IOException e) {
				throw new UncheckedIOException(e);
			}
		}
	}
}
