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

import com.revetsec.FuzzSeedGenerator.Seed;
import com.revetsec.FuzzSeedGenerator.Vectors;
import com.revetsec.internal.json.JsonCodec;
import com.revetsec.internal.json.JsonFuzzSupport;
import com.revetsec.jose.JwtValidatorFuzzSupport;
import com.revetsec.json.JsonString;
import com.revetsec.json.JsonValue;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * The provenance of the seeds nobody wrote by hand (M2 plan, WP-10; NOTICE's Wycheproof paragraph):
 * <ul>
 *   <li>every {@code wycheproof-<file>-tc<tcId>-<field>} seed is still exactly the field its name gives in the
 *   vendored file: a test's {@code jws} string (as UTF-8), a test's {@code sig} octets (decoded from hex), or its
 *   group's {@code public} or {@code private} key or key set (as the same JSON value). This check reads the name and
 *   the vendored file only, apart from the generator's selection;</li>
 *   <li>every {@code generated-*} seed, and the JwtValidator target's fixture key set, is what
 *   {@link FuzzSeedGenerator} makes now from the TEST ONLY fixture keys and the vendored files, and nothing named as
 *   generated is left over. Deterministic signatures (RSASSA-PKCS1-v1_5, Ed25519, HMAC) and every key set must match
 *   byte for byte. A randomized signature (RSASSA-PSS, ECDSA) must have the same signing input and still verify with
 *   the fixture key, or, once damaged, the same signing input and length.</li>
 * </ul>
 * It reads the vendored files and fixtures from the core checkout Surefire names, as {@link FuzzSeedLayoutTests} does
 * for the mapped corpora, so it never goes through a core test helper and also runs under
 * {@code -Drevetsec.fuzz.mainSourcesOnly}. A plain JUnit class, not a fuzz target.
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 */
final class FuzzSeedProvenanceTests {
	private static final Pattern WYCHEPROOF_SEED = Pattern.compile(
			"wycheproof-([a-z0-9_]+)-tc([0-9]+)-(jws|sig|public|private)\\.(txt|bin|json)");
	private static final String GENERATED_PREFIX = "generated-";
	private static final String WYCHEPROOF_PREFIX = "wycheproof-";

	// M4 semantic seeds are authored here; every file is named in the checked-in SHA-256 manifest.
	@Test
	void oidcSemanticSeedsMatchTheirCompleteManifest() throws Exception {
		Path resources = coreBasedir().resolve(FuzzSeedGenerator.FUZZ_RESOURCES);
		Path root = resources.resolve("com/revetsec/oidc/OidcFuzzTestsInputs");
		Set<String> expected = new TreeSet<>();
		for (String line : Files.readAllLines(resources.resolve("com/revetsec/oidc/oidc-seeds.sha256"))) {
			Assertions.assertTrue(line.matches("[0-9a-f]{64}  .+"));
			String relative = line.substring(66);
			Path file = root.resolve(relative).normalize();
			Assertions.assertTrue(file.startsWith(root));
			Assertions.assertTrue(expected.add(relative), "duplicate manifest path");
			Assertions.assertEquals(line.substring(0, 64), HexFormat.of().formatHex(
					java.security.MessageDigest.getInstance("SHA-256").digest(Files.readAllBytes(file))), relative);
		}
		try (Stream<Path> files = Files.walk(root)) {
			Assertions.assertEquals(expected, files.filter(Files::isRegularFile)
					.map(root::relativize).map(Path::toString).collect(Collectors.toCollection(TreeSet::new)));
		}
	}

	// NOTICE and M2-9: each Wycheproof-derived seed copies one field out of the vendored files, unmodified.
	@Test
	void everyWycheproofSeedIsTheVendoredFieldItsNameGives() throws Exception {
		Path core = coreBasedir();
		List<Path> seeds = seedFiles(core, WYCHEPROOF_PREFIX);
		Assertions.assertFalse(seeds.isEmpty(), "no wycheproof-* seed was found");
		Map<String, Vectors> files = new HashMap<>();

		for (Path seed : seeds) {
			String name = seed.getFileName().toString();
			Matcher matcher = WYCHEPROOF_SEED.matcher(name);
			Assertions.assertTrue(matcher.matches(), () -> "a Wycheproof seed name that names no field: " + name);

			Vectors vectors = files.get(matcher.group(1));

			if (vectors == null) {
				vectors = Vectors.read(core, matcher.group(1));
				files.put(matcher.group(1), vectors);
			}

			JsonValue field = vectors.field(Integer.parseInt(matcher.group(2)), matcher.group(3))
					.orElseThrow(() -> new AssertionError(name + " names a field its vector does not have"));
			byte[] actual = Files.readAllBytes(seed);

			switch (matcher.group(4)) {
				case "txt" -> Assertions.assertArrayEquals(((JsonString) field).getValue().getBytes(StandardCharsets.UTF_8),
						actual, () -> name + " differs from its vendored string");
				case "bin" -> Assertions.assertArrayEquals(HexFormat.of().parseHex(((JsonString) field).getValue()), actual,
						() -> name + " differs from its vendored octets");
				default -> Assertions.assertEquals(field, JsonCodec.parse(actual, JsonFuzzSupport.maximumCaps()),
						() -> name + " differs from its vendored key or key set");
			}
		}
	}

	// The seeds signed with the TEST ONLY fixture keys, and the fixture key set, are still what the generator makes.
	@Test
	void everyGeneratedSeedIsWhatTheGeneratorMakesFromTheFixtures() throws Exception {
		Path core = coreBasedir();
		Path resources = core.resolve(FuzzSeedGenerator.FUZZ_RESOURCES);
		Set<String> generatedPaths = new TreeSet<>();

		for (Seed seed : FuzzSeedGenerator.seeds(core)) {
			generatedPaths.add(seed.getPath());
			Path file = resources.resolve(seed.getPath());
			Assertions.assertTrue(Files.isRegularFile(file), () -> "the generator makes " + seed.getPath()
					+ ", which is not in the tree");
			byte[] actual = Files.readAllBytes(file);

			switch (seed.getCheck()) {
				case EXACT -> Assertions.assertArrayEquals(seed.getBytes(), actual, () -> seed.getPath()
						+ " is not what the generator makes");
				case SIGNATURE_VERIFIES -> {
					requireSameSigningInput(seed, actual);
					Assertions.assertTrue(seed.verifies(new String(actual, StandardCharsets.US_ASCII)),
							() -> seed.getPath() + " no longer verifies with its fixture key");
				}
				default -> {
					requireSameSigningInput(seed, actual);
					String expected = new String(seed.getBytes(), StandardCharsets.US_ASCII);
					String committed = new String(actual, StandardCharsets.US_ASCII);
					Assertions.assertEquals(expected.length() - expected.lastIndexOf('.'),
							committed.length() - committed.lastIndexOf('.'), () -> seed.getPath()
									+ " has another signature length than the generator's");
				}
			}
		}

		Set<String> committed = new TreeSet<>();

		for (Path file : seedFiles(core, GENERATED_PREFIX))
			committed.add(resources.relativize(file).toString().replace('\\', '/'));

		for (Path file : seedFiles(core, WYCHEPROOF_PREFIX))
			committed.add(resources.relativize(file).toString().replace('\\', '/'));

		committed.add("com/revetsec/jose/" + JwtValidatorFuzzSupport.FIXTURE_KEY_SET_RESOURCE);
		Assertions.assertEquals(committed, generatedPaths, "generated seeds the generator no longer makes, or does not "
				+ "make yet");
	}

	private static void requireSameSigningInput(Seed seed, byte[] actual) {
		String expected = new String(seed.getBytes(), StandardCharsets.US_ASCII);
		String committed = new String(actual, StandardCharsets.US_ASCII);
		Assertions.assertEquals(expected.substring(0, expected.lastIndexOf('.')),
				committed.substring(0, committed.lastIndexOf('.')), () -> seed.getPath()
						+ " has another header or payload than the generator's");
	}

	/**
	 * Every seed file under {@code fuzz/src/test/resources} whose name starts with {@code prefix}.
	 */
	private static List<Path> seedFiles(Path core, String prefix) throws IOException {
		try (Stream<Path> paths = Files.walk(core.resolve(FuzzSeedGenerator.FUZZ_RESOURCES))) {
			return paths.filter(Files::isRegularFile)
					.filter(path -> path.getFileName().toString().startsWith(prefix))
					.sorted()
					.collect(Collectors.toList());
		}
	}

	/**
	 * The core checkout: the {@code revetsec.core.basedir} Surefire passes, or else the parent of the working
	 * directory, which Maven sets to {@code fuzz/}.
	 */
	private static Path coreBasedir() {
		String configured = System.getProperty("revetsec.core.basedir");
		Path core = (configured == null || configured.isBlank() ? Path.of("..") : Path.of(configured)).toAbsolutePath()
				.normalize();
		Assertions.assertTrue(Files.isDirectory(core.resolve(FuzzSeedGenerator.WYCHEPROOF_VECTORS)),
				() -> "not a Revetsec core checkout with the vendored Wycheproof files: " + core);
		return core;
	}
}
