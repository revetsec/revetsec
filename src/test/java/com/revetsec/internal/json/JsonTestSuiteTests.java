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

package com.revetsec.internal.json;

import com.revetsec.internal.Limits;
import com.revetsec.internal.json.JsonParseException.Kind;
import com.revetsec.json.JsonArray;
import com.revetsec.json.JsonObject;
import com.revetsec.json.JsonValue;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DynamicContainer;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.net.URISyntaxException;
import java.net.URL;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Deque;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.SortedMap;
import java.util.TreeMap;
import java.util.function.Consumer;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static java.util.Objects.requireNonNull;

/**
 * JSONTestSuite through the codec (M1 plan G7-9 and exit criterion 1): {@code nst/JSONTestSuite}'s
 * {@code test_parsing/} at {@code 1ef36fa01286573e846ac449e8683f8833c5b26a}, vendored under
 * {@code src/test/resources/vectors/jsontestsuite/} (see its {@code SOURCE.txt}).
 * <p>
 * Before any file is parsed, {@code MANIFEST.sha256} is checked in both directions (every line matches its file, and
 * every file but the manifest is listed), and {@code DEVIATIONS.txt} and {@code I_DECISIONS.txt} are checked for
 * form and staleness. Any problem fails the build. Then each file runs as its own dynamic test under the protocol
 * profile ({@link JsonLimits#protocolDocument(Integer)}) and the SCIM profile
 * ({@link JsonLimits#scim(Integer, Integer)} with the default node count), each with a 256 KiB input limit, which fits
 * the largest file (250,001 bytes):
 * <ul>
 *   <li>every {@code y_} file is accepted, except the {@code DEVIATIONS.txt} files, which must be exactly the
 *   {@code y_} files that repeat a member name (found by a scanner that shares no code with the codec) and must each
 *   fail with {@link Kind#DUPLICATE_MEMBER};</li>
 *   <li>every {@code n_} file fails with {@link JsonParseException} and nothing else (INV-G1);</li>
 *   <li>every {@code i_} file has the outcome its {@code I_DECISIONS.txt} line records: accepted, or rejected with
 *   that exact {@link Kind}.</li>
 * </ul>
 * Every rejection has its kind's fixed message, no cause, nothing suppressed and an offset inside the input, and none
 * is {@link Kind#INPUT_SIZE}, so every file reaches the parser. Every accepted value round-trips: its
 * {@code toJson()} text parses under the maximum-cap profile to an equal value with an equal hash (G7-6). The file
 * counts and each profile's outcome counts are pinned, so an emptied or partial directory cannot pass.
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 */
final class JsonTestSuiteTests {
	private static final String RELATIVE_SOURCE = "src/test/resources/vectors/jsontestsuite";
	private static final String RESOURCE = "/vectors/jsontestsuite";
	private static final String MANIFEST = "MANIFEST.sha256";
	private static final String DEVIATIONS = "DEVIATIONS.txt";
	private static final String I_DECISIONS = "I_DECISIONS.txt";
	private static final String TEST_PARSING = "test_parsing/";

	/**
	 * The input limit of both profiles: 256 KiB, at least the largest file ({@code n_structure_open_array_object.json},
	 * 250,001 bytes), so no file is rejected for its size before the parser sees it.
	 */
	private static final int MAX_INPUT_BYTES = 256 * 1_024;

	/**
	 * The profiles, in the order of the outcome columns of {@code I_DECISIONS.txt}.
	 */
	private static final List<Profile> PROFILES = List.of(
			new Profile("protocol", JsonLimits.protocolDocument(MAX_INPUT_BYTES), 0),
			new Profile("scim", JsonLimits.scim(MAX_INPUT_BYTES, Limits.SCIM_JSON_NODES.getDefaultIntValue()), 1));

	private static final JsonLimits MAXIMUM = JsonLimits.maximumCaps();

	private static final String ACCEPT = "accept";
	private static final String REJECT = "reject:";
	private static final Set<String> KIND_NAMES = Arrays.stream(Kind.values()).map(Kind::name)
			.collect(Collectors.toUnmodifiableSet());

	/**
	 * Each profile's outcomes over all 318 files, as measured on 17, 21, 25, 26 and 27 with 0 mismatches (M1 plan,
	 * Results > Phase 2): 93 {@code y_} and 6 {@code i_} files accepted, and the rest rejected.
	 */
	private static final Map<String, Integer> OUTCOME_COUNTS = Map.of(
			ACCEPT, 99,
			REJECT + Kind.SYNTAX.name(), 167,
			REJECT + Kind.INVALID_UTF8.name(), 25,
			REJECT + Kind.UNPAIRED_SURROGATE.name(), 16,
			REJECT + Kind.EXPONENT.name(), 4,
			REJECT + Kind.DEPTH.name(), 3,
			REJECT + Kind.BOM.name(), 2,
			REJECT + Kind.DUPLICATE_MEMBER.name(), 2);

	/**
	 * A manifest line: {@code <64 lowercase hex digits><two spaces><path>}, as {@code sha256sum} writes it.
	 */
	private static final Pattern MANIFEST_LINE = Pattern.compile("([0-9a-f]{64})  (.*)");

	/**
	 * A path the manifest may list: a file at the top of the directory or directly in {@code test_parsing/}.
	 */
	private static final Pattern PATH = Pattern.compile("(?:test_parsing/)?[A-Za-z0-9_+#-][A-Za-z0-9._+#-]*");

	/**
	 * A file name in {@code test_parsing/}, as {@code DEVIATIONS.txt} and {@code I_DECISIONS.txt} write it.
	 */
	private static final Pattern FILE_NAME = Pattern.compile("[A-Za-z0-9_+#-][A-Za-z0-9._+#-]*");

	// ---------------------------------------------------------------------------------------------------------------
	// The vendored suite
	// ---------------------------------------------------------------------------------------------------------------

	// G7-9 and exit criterion 1: the manifest matches every file in both directions, and both lists are well formed
	// and current, before any file is parsed. Each factory below loads the suite the same way before it creates a
	// single test, so a problem here stops every vector from running.
	@Test
	void checksTheManifestInBothDirectionsAndBothListsBeforeAnyFileIsParsed() {
		Suite suite = Suite.load();

		Assertions.assertEquals(322, suite.checkedFiles, "the manifest covers every file but itself");
		Assertions.assertEquals(Set.of("y_object_duplicated_key.json", "y_object_duplicated_key_and_value.json"),
				suite.deviations);
		Assertions.assertEquals(35, suite.decisions.size());
	}

	// RFC 8259 and G7-9: every y_ file is accepted, except the DEVIATIONS.txt files. Those are exactly the y_ files
	// that repeat a member name (RFC 8259 section 4 says names SHOULD be unique; Revetsec requires it, and SCIM also
	// compares them ignoring ASCII case, G7-7), and each fails with DUPLICATE_MEMBER. Every accepted value keeps each
	// member name the file writes and round-trips under the maximum-cap profile (G7-6).
	@TestFactory
	Stream<DynamicContainer> acceptsEveryYFileExceptTheDuplicateMemberDeviations() {
		Suite suite = Suite.load();

		return PROFILES.stream().map(profile -> DynamicContainer.dynamicContainer(profile.name,
				suite.names("y_").map(name -> DynamicTest.dynamicTest(name, () -> {
					String where = where(name, profile);
					byte[] input = suite.vector(name);
					NameScan scan = scan(input, where);
					boolean repeats = profile.limits.isAsciiCaseVariantNamesRejected()
							? scan.repeatsIgnoringAsciiCase() : scan.repeatsExactly();
					boolean listed = suite.deviations.contains(name);

					Assertions.assertEquals(repeats, listed, () -> where + (repeats
							? "an object repeats a member name, so " + DEVIATIONS + " must list the file"
							: DEVIATIONS + " lists the file, but no object in it repeats a member name"));

					Result result = parse(input, profile, where);

					if (listed) {
						Assertions.assertEquals(REJECT + Kind.DUPLICATE_MEMBER.name(), result.outcome,
								() -> where + "a " + DEVIATIONS + " file must fail with DUPLICATE_MEMBER");
					} else {
						Assertions.assertEquals(ACCEPT, result.outcome, () -> where + "a y_ file must be accepted");
						JsonValue value = requireNonNull(result.value);
						Assertions.assertEquals(scan.names, memberCount(value),
								() -> where + "the value keeps every member name the file writes");
						assertRoundTrips(value, where);
					}
				}))));
	}

	// RFC 8259 and INV-G1: every n_ file is rejected, and the only thing that escapes the codec is a
	// JsonParseException with its kind's fixed message, no cause and an offset inside the input.
	@TestFactory
	Stream<DynamicContainer> rejectsEveryNFileWithAJsonParseExceptionAndNothingElse() {
		Suite suite = Suite.load();

		return PROFILES.stream().map(profile -> DynamicContainer.dynamicContainer(profile.name,
				suite.names("n_").map(name -> DynamicTest.dynamicTest(name, () -> {
					String where = where(name, profile);
					Result result = parse(suite.vector(name), profile, where);

					Assertions.assertTrue(result.outcome.startsWith(REJECT),
							() -> where + "an n_ file must be rejected, but it was accepted");
				}))));
	}

	// G7-9: every i_ file has the outcome its I_DECISIONS.txt line records for the profile: accepted (and then it
	// round-trips, G7-6), or rejected with that exact Kind.
	@TestFactory
	Stream<DynamicContainer> decidesEveryIFileAsItsIDecisionsLineRecords() {
		Suite suite = Suite.load();

		return PROFILES.stream().map(profile -> DynamicContainer.dynamicContainer(profile.name,
				suite.names("i_").map(name -> DynamicTest.dynamicTest(name, () -> {
					String where = where(name, profile);
					String expected = requireNonNull(suite.decisions.get(name)).get(profile.column);
					Result result = parse(suite.vector(name), profile, where);

					Assertions.assertEquals(expected, result.outcome,
							() -> where + "the outcome must be the one " + I_DECISIONS + " records");

					JsonValue value = result.value;

					if (value != null)
						assertRoundTrips(value, where);
				}))));
	}

	// Exit criterion 1: the file counts at 1ef36fa0 (SOURCE.txt) and each profile's outcome counts (OUTCOME_COUNTS)
	// are pinned, so a missing, emptied or partial directory cannot pass.
	@Test
	void pinsTheFileCountsAndEachProfilesOutcomeCounts() {
		Suite suite = Suite.load();

		Assertions.assertEquals(318, suite.vectors.size());
		Assertions.assertEquals(95L, suite.names("y_").count());
		Assertions.assertEquals(188L, suite.names("n_").count());
		Assertions.assertEquals(35L, suite.names("i_").count());
		Assertions.assertEquals(250_001, suite.vector("n_structure_open_array_object.json").length);
		Assertions.assertTrue(suite.vectors.values().stream().allMatch(input -> input.length <= MAX_INPUT_BYTES),
				"both profiles fit every file");

		for (Profile profile : PROFILES) {
			Map<String, Integer> counts = new TreeMap<>();

			for (Map.Entry<String, byte[]> vector : suite.vectors.entrySet())
				counts.merge(parse(vector.getValue(), profile, where(vector.getKey(), profile)).outcome, 1, Integer::sum);

			Assertions.assertEquals(new TreeMap<>(OUTCOME_COUNTS), counts, profile.name + " profile outcome counts");
		}
	}

	// ---------------------------------------------------------------------------------------------------------------
	// The checks themselves: each kind of stale or malformed metadata is reported, so each one fails the build
	// ---------------------------------------------------------------------------------------------------------------

	// G7-9: the manifest is sha256sum output for every other file, sorted by the paths' UTF-8 bytes, with LF line
	// endings. A changed, missing, unlisted or repeated file, a malformed or misordered line, or a line for the
	// manifest itself is reported.
	@TestFactory
	Stream<DynamicTest> reportsEveryStaleOrMalformedManifestLine() {
		byte[] license = utf8("MIT\n");
		byte[] vector = utf8("[]");
		String licenseLine = sha256(license) + "  LICENSE\n";
		String vectorLine = sha256(vector) + "  test_parsing/y_a.json\n";
		SortedMap<String, byte[]> present = files("LICENSE", license, "test_parsing/y_a.json", vector);

		return Stream.of(
				manifestCase("a manifest that lists every file with its digest, in order", licenseLine + vectorLine, present),
				manifestCase("a changed file", licenseLine + vectorLine,
						files("LICENSE", license, "test_parsing/y_a.json", utf8("{}")),
						"MANIFEST.sha256 line 2 does not match the SHA-256 of test_parsing/y_a.json"),
				manifestCase("a listed file that is missing", licenseLine + vectorLine,
						files("test_parsing/y_a.json", vector),
						"MANIFEST.sha256 line 1 lists a file that does not exist: LICENSE"),
				manifestCase("a file that is not listed", licenseLine + vectorLine,
						files("LICENSE", license, "test_parsing/n_b.json", vector, "test_parsing/y_a.json", vector),
						"MANIFEST.sha256 does not list test_parsing/n_b.json"),
				manifestCase("an uppercase digest", "A" + licenseLine.substring(1) + vectorLine, present,
						malformedManifestLine(1), "MANIFEST.sha256 does not list LICENSE"),
				manifestCase("one space before the path", licenseLine.replace("  ", " ") + vectorLine, present,
						malformedManifestLine(1), "MANIFEST.sha256 does not list LICENSE"),
				manifestCase("a CRLF line ending", licenseLine.replace("\n", "\r\n") + vectorLine, present,
						malformedManifestLine(1), "MANIFEST.sha256 does not list LICENSE"),
				manifestCase("a path that leaves the directory", licenseLine + sha256(license) + "  ../LICENSE\n"
						+ vectorLine, present, malformedManifestLine(2)),
				manifestCase("no final line feed", licenseLine + vectorLine.substring(0, vectorLine.length() - 1), present,
						"MANIFEST.sha256 does not end with a line feed"),
				manifestCase("lines out of order", vectorLine + licenseLine, present,
						"MANIFEST.sha256 line 2 is out of order: LICENSE"),
				manifestCase("a repeated line", licenseLine + licenseLine + vectorLine, present,
						"MANIFEST.sha256 line 2 repeats LICENSE"),
				manifestCase("a line for the manifest itself", licenseLine + sha256(utf8("")) + "  MANIFEST.sha256\n"
						+ vectorLine, present, "MANIFEST.sha256 line 2 lists MANIFEST.sha256 itself"),
				manifestCase("an empty manifest", "", present, "MANIFEST.sha256 is empty",
						"MANIFEST.sha256 does not list LICENSE", "MANIFEST.sha256 does not list test_parsing/y_a.json"));
	}

	// G7-9: DEVIATIONS.txt names y_ files in test_parsing/, one per line, with '#' comments and blank lines ignored.
	// A file that does not exist, a file that is not a y_ file, a repeated line and a malformed line are reported.
	@TestFactory
	Stream<DynamicTest> reportsEveryStaleOrMalformedDeviationsLine() {
		Set<String> vectors = Set.of("y_a.json", "y_b.json", "n_c.json");

		return Stream.of(
				DynamicTest.dynamicTest("comments, blank lines and two file names", () -> {
					List<String> problems = new ArrayList<>();

					Assertions.assertEquals(Set.of("y_a.json", "y_b.json"),
							deviations(utf8("# note\n\ny_a.json\n  \ny_b.json\n"), vectors, problems));
					Assertions.assertEquals(List.of(), problems);
				}),
				deviationsCase("a file that does not exist", "y_z.json\n", vectors,
						"DEVIATIONS.txt line 1 names a file that does not exist: y_z.json"),
				deviationsCase("a file that is not a y_ file", "# note\nn_c.json\n", vectors,
						"DEVIATIONS.txt line 2 names a file that is not a y_ file: n_c.json"),
				deviationsCase("a repeated line", "y_a.json\ny_a.json\n", vectors, "DEVIATIONS.txt line 2 repeats y_a.json"),
				deviationsCase("leading whitespace", " y_a.json\n", vectors, malformedDeviationsLine(1)),
				deviationsCase("trailing whitespace", "y_a.json\t\n", vectors, malformedDeviationsLine(1)),
				deviationsCase("a path instead of a name", "test_parsing/y_a.json\n", vectors, malformedDeviationsLine(1)),
				deviationsCase("two names on a line", "y_a.json y_b.json\n", vectors, malformedDeviationsLine(1)),
				deviationsCase("a CRLF line ending", "y_a.json\r\n", vectors,
						"DEVIATIONS.txt contains a carriage return (lines end with LF only)", malformedDeviationsLine(1)),
				deviationsCase("no final line feed", "y_a.json", vectors, "DEVIATIONS.txt does not end with a line feed"),
				DynamicTest.dynamicTest("ill-formed UTF-8", () -> assertProblems(
						problems -> deviations(new byte[]{'#', (byte) 0xC0, (byte) 0x80, '\n'}, vectors, problems),
						"DEVIATIONS.txt is not well-formed UTF-8")),
				DynamicTest.dynamicTest("a missing file", () -> assertProblems(
						problems -> deviations(null, vectors, problems), "DEVIATIONS.txt is missing")));
	}

	// G7-9: I_DECISIONS.txt has one line per i_ file, sorted by name: <file><TAB><protocol outcome><TAB><SCIM outcome>,
	// where an outcome is "accept" or "reject:<Kind>". A line for a file that does not exist or is not an i_ file, an
	// i_ file with no line, a repeated, misordered or malformed line, and an unknown Kind are reported.
	@TestFactory
	Stream<DynamicTest> reportsEveryStaleOrMalformedIDecisionsLine() {
		Set<String> vectors = Set.of("i_a.json", "i_b.json", "y_c.json");
		String lineA = "i_a.json\taccept\treject:DEPTH\n";
		String lineB = "i_b.json\treject:SYNTAX\taccept\n";

		return Stream.of(
				DynamicTest.dynamicTest("comments, blank lines and a line for each i_ file", () -> {
					List<String> problems = new ArrayList<>();

					Assertions.assertEquals(Map.of("i_a.json", List.of(ACCEPT, "reject:DEPTH"),
									"i_b.json", List.of("reject:SYNTAX", ACCEPT)),
							decisions(utf8("# note\n\n" + lineA + lineB), vectors, problems));
					Assertions.assertEquals(List.of(), problems);
				}),
				decisionsCase("a file that does not exist", lineA + lineB + "i_z.json\taccept\taccept\n", vectors,
						"I_DECISIONS.txt line 3 names a file that does not exist: i_z.json"),
				decisionsCase("a file that is not an i_ file", lineA + lineB + "y_c.json\taccept\taccept\n", vectors,
						"I_DECISIONS.txt line 3 names a file that is not an i_ file: y_c.json"),
				decisionsCase("an i_ file with no line", lineA, vectors, "I_DECISIONS.txt has no line for i_b.json"),
				decisionsCase("a repeated line", lineA + lineA + lineB, vectors, "I_DECISIONS.txt line 2 repeats i_a.json"),
				decisionsCase("lines out of order", lineB + lineA, vectors,
						"I_DECISIONS.txt line 2 is out of order: i_a.json"),
				decisionsCase("one outcome", "i_a.json\taccept\n" + lineB, vectors, malformedDecisionsLine(1),
						"I_DECISIONS.txt has no line for i_a.json"),
				decisionsCase("three outcomes", "i_a.json\taccept\taccept\taccept\n" + lineB, vectors,
						malformedDecisionsLine(1), "I_DECISIONS.txt has no line for i_a.json"),
				decisionsCase("spaces instead of tabs", "i_a.json accept accept\n" + lineB, vectors,
						malformedDecisionsLine(1), "I_DECISIONS.txt has no line for i_a.json"),
				decisionsCase("a trailing tab", "i_a.json\taccept\taccept\t\n" + lineB, vectors,
						malformedDecisionsLine(1), "I_DECISIONS.txt has no line for i_a.json"),
				decisionsCase("an outcome in the wrong case", "i_a.json\tAccept\taccept\n" + lineB, vectors,
						malformedDecisionsLine(1), "I_DECISIONS.txt has no line for i_a.json"),
				decisionsCase("a rejection without a Kind", "i_a.json\taccept\treject:\n" + lineB, vectors,
						malformedDecisionsLine(1), "I_DECISIONS.txt has no line for i_a.json"),
				decisionsCase("an unknown Kind", "i_a.json\taccept\treject:OVERFLOW\n" + lineB, vectors,
						malformedDecisionsLine(1), "I_DECISIONS.txt has no line for i_a.json"),
				decisionsCase("a Kind in the wrong case", "i_a.json\treject:depth\taccept\n" + lineB, vectors,
						malformedDecisionsLine(1), "I_DECISIONS.txt has no line for i_a.json"),
				decisionsCase("a path instead of a name", "test_parsing/i_a.json\taccept\taccept\n" + lineB, vectors,
						malformedDecisionsLine(1), "I_DECISIONS.txt has no line for i_a.json"),
				decisionsCase("a CRLF line ending", lineA.replace("\n", "\r\n") + lineB, vectors,
						"I_DECISIONS.txt contains a carriage return (lines end with LF only)", malformedDecisionsLine(1),
						"I_DECISIONS.txt has no line for i_a.json"),
				decisionsCase("no final line feed", lineA + lineB.substring(0, lineB.length() - 1), vectors,
						"I_DECISIONS.txt does not end with a line feed"),
				DynamicTest.dynamicTest("a missing file", () -> assertProblems(
						problems -> decisions(null, vectors, problems), "I_DECISIONS.txt is missing",
						"I_DECISIONS.txt has no line for i_a.json", "I_DECISIONS.txt has no line for i_b.json")));
	}

	// RFC 8259 section 4 and G7-7: the scanner that decides which y_ files DEVIATIONS.txt must list compares member
	// names within each object only, after unescaping, exactly and ignoring ASCII case only; it ignores anything
	// inside a string and strings that are not names.
	@TestFactory
	Stream<DynamicTest> theIndependentNameScannerComparesNamesPerObjectAfterUnescaping() {
		return Stream.of(
				scanCase("{\"a\":1,\"a\":2}", 2, true, true),
				scanCase("{\"a\":1,\"b\":{\"a\":2}}", 3, false, false),
				scanCase("[{\"a\":1},{\"a\":1}]", 2, false, false),
				scanCase("{\"a\":[1,{\"b\":1,\"b\":2}]}", 3, true, true),
				scanCase("{\"a\\u0062\":1,\"ab\":2}", 2, true, true),
				scanCase("{\"a\" : {\"\\\"\":1, \"\\\"\"\t:2}}", 3, true, true),
				scanCase("{\"\\ud834\\udd1e\":1,\"\uD834\uDD1E\":2}", 2, true, true),
				scanCase("{\"id\":1,\"ID\":2}", 2, false, true),
				scanCase("{\"\u0131d\":1,\"id\":2}", 2, false, false),
				scanCase("{\"x\":\"{\\\"a\\\":1,\\\"a\\\":2}\"}", 1, false, false),
				scanCase("[\"a\",\"a\",{}]", 0, false, false));
	}

	// ---------------------------------------------------------------------------------------------------------------
	// Parsing and round trips
	// ---------------------------------------------------------------------------------------------------------------

	/**
	 * Parses a vector under a profile. A rejection must be a {@link JsonParseException} with its kind's fixed message,
	 * no cause, nothing suppressed and an offset inside the input, and never {@link Kind#INPUT_SIZE}; any other
	 * {@link Throwable} fails the test (INV-G1). Every failure message starts with {@code where}, which names the file
	 * and the profile.
	 */
	private static Result parse(byte[] input, Profile profile, String where) {
		Assertions.assertTrue(input.length <= profile.limits.getMaxInputBytes(),
				() -> where + "the profile's input limit must fit the file, so the parser sees it");

		try {
			return new Result(ACCEPT, JsonCodec.parse(input, profile.limits));
		} catch (JsonParseException exception) {
			Kind kind = exception.getKind();
			int offset = exception.getByteOffset();

			Assertions.assertNotEquals(Kind.INPUT_SIZE, kind, () -> where + "no file is rejected for its size alone");
			Assertions.assertEquals(JsonFailures.PARSE_MESSAGES.get(kind), exception.getMessage(),
					() -> where + "the kind's fixed message (R9)");
			Assertions.assertNull(exception.getCause(), () -> where + "no cause (G7-3)");
			Assertions.assertEquals(0, exception.getSuppressed().length, () -> where + "nothing suppressed");
			Assertions.assertTrue(offset >= 0 && offset <= input.length,
					() -> where + "the offset must be inside the input, not " + offset);
			return new Result(REJECT + kind.name(), null);
		} catch (Throwable throwable) {
			throw new AssertionError(where + "the codec threw " + throwable.getClass().getName()
					+ ", not a JsonParseException (INV-G1)", throwable);
		}
	}

	/**
	 * G7-6: the value's {@code toJson()} text is the codec's own UTF-8 output, and it parses under the maximum-cap
	 * profile to an equal value with an equal hash and the same text.
	 */
	private static void assertRoundTrips(JsonValue value, String where) {
		String json = value.toJson();
		byte[] written;
		JsonValue again;

		try {
			ByteBuffer encoded = StandardCharsets.UTF_8.newEncoder()
					.onMalformedInput(CodingErrorAction.REPORT)
					.onUnmappableCharacter(CodingErrorAction.REPORT)
					.encode(CharBuffer.wrap(json));
			written = new byte[encoded.remaining()];
			encoded.get(written);
			again = JsonCodec.parse(written, MAXIMUM);
		} catch (JsonParseException exception) {
			throw new AssertionError(where + "the round trip must parse under the maximum-cap profile, but it failed "
					+ "with " + exception.getKind().name(), exception);
		} catch (Throwable throwable) {
			throw new AssertionError(where + "the round trip threw " + throwable.getClass().getName(), throwable);
		}

		Assertions.assertArrayEquals(JsonCodec.toUtf8Bytes(value), written,
				() -> where + "toJson() must be the codec's UTF-8 output");
		Assertions.assertEquals(value, again, () -> where + "the round trip must give an equal value");
		Assertions.assertEquals(value.hashCode(), again.hashCode(),
				() -> where + "the round trip must give an equal hash");
		Assertions.assertEquals(json, again.toJson(), () -> where + "the canonical text must be stable");
	}

	/**
	 * Scans a {@code y_} file's member names with {@link NameScan}, which reads only well-formed JSON text.
	 */
	private static NameScan scan(byte[] input, String where) {
		try {
			return NameScan.of(input);
		} catch (CharacterCodingException | RuntimeException exception) {
			throw new AssertionError(where + "the name scanner reads only well-formed UTF-8 JSON text", exception);
		}
	}

	/**
	 * The prefix of every failure message about one file under one profile.
	 */
	private static String where(String name, Profile profile) {
		return name + " under the " + profile.name + " profile: ";
	}

	/**
	 * The number of members in every object of a value.
	 */
	private static int memberCount(JsonValue value) {
		int count = 0;

		if (value instanceof JsonObject object) {
			for (JsonValue member : object.getMembers().values())
				count += 1 + memberCount(member);
		} else if (value instanceof JsonArray array) {
			for (JsonValue element : array.getElements())
				count += memberCount(element);
		}

		return count;
	}

	// ---------------------------------------------------------------------------------------------------------------
	// Metadata checks
	// ---------------------------------------------------------------------------------------------------------------

	/**
	 * Every problem with the manifest, given every other file in the directory by its relative path: a malformed,
	 * misordered or repeated line, a line for the manifest itself, a listed file that is missing or whose SHA-256
	 * differs, and a file that is not listed.
	 */
	static List<String> manifestProblems(byte[] manifest, SortedMap<String, byte[]> files) {
		List<String> problems = new ArrayList<>();
		Set<String> listed = new HashSet<>();
		// ISO-8859-1 maps each byte to one character, so a non-ASCII byte makes its line malformed.
		String text = new String(manifest, StandardCharsets.ISO_8859_1);

		if (text.isEmpty()) {
			problems.add(MANIFEST + " is empty");
		} else {
			boolean terminated = text.endsWith("\n");

			if (!terminated)
				problems.add(MANIFEST + " does not end with a line feed");

			String[] lines = (terminated ? text.substring(0, text.length() - 1) : text).split("\n", -1);
			String previous = "";

			for (int index = 0; index < lines.length; ++index) {
				String where = MANIFEST + " line " + (index + 1);
				Matcher matcher = MANIFEST_LINE.matcher(lines[index]);

				if (!matcher.matches() || !PATH.matcher(matcher.group(2)).matches()) {
					problems.add(malformedManifestLine(index + 1));
					continue;
				}

				String path = matcher.group(2);
				byte[] content = files.get(path);

				if (path.equals(MANIFEST))
					problems.add(where + " lists " + MANIFEST + " itself");
				else if (!listed.add(path))
					problems.add(where + " repeats " + path);
				else if (content == null)
					problems.add(where + " lists a file that does not exist: " + path);
				else if (!matcher.group(1).equals(sha256(content)))
					problems.add(where + " does not match the SHA-256 of " + path);

				if (compareUtf8(previous, path) > 0)
					problems.add(where + " is out of order: " + path);

				previous = path;
			}
		}

		for (String path : files.keySet())
			if (!listed.contains(path))
				problems.add(MANIFEST + " does not list " + path);

		return problems;
	}

	/**
	 * The files {@code DEVIATIONS.txt} lists, adding each problem to {@code problems}: a malformed or repeated line, a
	 * file that does not exist in {@code vectors}, or one that is not a {@code y_} file.
	 */
	static Set<String> deviations(byte @Nullable [] content, Set<String> vectors, List<String> problems) {
		Set<String> deviations = new LinkedHashSet<>();

		for (Line line : contentLines(DEVIATIONS, content, problems)) {
			String where = DEVIATIONS + " line " + line.number;

			if (!FILE_NAME.matcher(line.text).matches())
				problems.add(malformedDeviationsLine(line.number));
			else if (!line.text.startsWith("y_"))
				problems.add(where + " names a file that is not a y_ file: " + line.text);
			else if (!vectors.contains(line.text))
				problems.add(where + " names a file that does not exist: " + line.text);
			else if (!deviations.add(line.text))
				problems.add(where + " repeats " + line.text);
		}

		return deviations;
	}

	/**
	 * The outcomes {@code I_DECISIONS.txt} records, by file, one per profile in {@link #PROFILES} order, adding each
	 * problem to {@code problems}: a malformed, repeated or misordered line, a file that does not exist in
	 * {@code vectors} or is not an {@code i_} file, and an {@code i_} file with no line.
	 */
	static Map<String, List<String>> decisions(byte @Nullable [] content, Set<String> vectors, List<String> problems) {
		Map<String, List<String>> decisions = new LinkedHashMap<>();
		String previous = "";

		for (Line line : contentLines(I_DECISIONS, content, problems)) {
			String where = I_DECISIONS + " line " + line.number;
			String[] fields = line.text.split("\t", -1);

			if (fields.length != 1 + PROFILES.size() || !FILE_NAME.matcher(fields[0]).matches()
					|| !Arrays.stream(fields, 1, fields.length).allMatch(JsonTestSuiteTests::isOutcome)) {
				problems.add(malformedDecisionsLine(line.number));
				continue;
			}

			String name = fields[0];

			if (!name.startsWith("i_"))
				problems.add(where + " names a file that is not an i_ file: " + name);
			else if (!vectors.contains(name))
				problems.add(where + " names a file that does not exist: " + name);
			else if (decisions.putIfAbsent(name, List.of(Arrays.copyOfRange(fields, 1, fields.length))) != null)
				problems.add(where + " repeats " + name);

			if (compareUtf8(previous, name) > 0)
				problems.add(where + " is out of order: " + name);

			previous = name;
		}

		vectors.stream().filter(name -> name.startsWith("i_") && !decisions.containsKey(name)).sorted()
				.forEach(name -> problems.add(I_DECISIONS + " has no line for " + name));

		return decisions;
	}

	/**
	 * The lines of a list file that are neither blank nor {@code #} comments, adding a problem if the file is missing,
	 * is not well-formed UTF-8, contains a carriage return or does not end with a line feed.
	 */
	private static List<Line> contentLines(String file, byte @Nullable [] content, List<String> problems) {
		List<Line> lines = new ArrayList<>();

		if (content == null) {
			problems.add(file + " is missing");
			return lines;
		}

		String text;

		try {
			text = StandardCharsets.UTF_8.newDecoder()
					.onMalformedInput(CodingErrorAction.REPORT)
					.onUnmappableCharacter(CodingErrorAction.REPORT)
					.decode(ByteBuffer.wrap(content))
					.toString();
		} catch (CharacterCodingException exception) {
			problems.add(file + " is not well-formed UTF-8");
			return lines;
		}

		if (text.indexOf('\r') >= 0)
			problems.add(file + " contains a carriage return (lines end with LF only)");
		if (!text.isEmpty() && !text.endsWith("\n"))
			problems.add(file + " does not end with a line feed");

		String[] raw = text.split("\n", -1);

		for (int index = 0; index < raw.length; ++index)
			if (!raw[index].isBlank() && !raw[index].startsWith("#"))
				lines.add(new Line(index + 1, raw[index]));

		return lines;
	}

	private static boolean isOutcome(String field) {
		return field.equals(ACCEPT)
				|| (field.startsWith(REJECT) && KIND_NAMES.contains(field.substring(REJECT.length())));
	}

	private static String malformedManifestLine(int number) {
		return MANIFEST + " line " + number + " is malformed (expected <64 lowercase hex digits><two spaces><path>)";
	}

	private static String malformedDeviationsLine(int number) {
		return DEVIATIONS + " line " + number + " is malformed (expected one file name in test_parsing/)";
	}

	private static String malformedDecisionsLine(int number) {
		return I_DECISIONS + " line " + number + " is malformed (expected <file><TAB><protocol outcome><TAB><SCIM "
				+ "outcome>, where an outcome is accept or reject:<Kind>)";
	}

	// ---------------------------------------------------------------------------------------------------------------
	// Helpers
	// ---------------------------------------------------------------------------------------------------------------

	private static DynamicTest manifestCase(String name, String manifest, SortedMap<String, byte[]> files,
																					String... expected) {
		return DynamicTest.dynamicTest(name, () -> Assertions.assertEquals(List.of(expected),
				manifestProblems(utf8(manifest), files)));
	}

	private static DynamicTest deviationsCase(String name, String content, Set<String> vectors, String... expected) {
		return DynamicTest.dynamicTest(name, () -> assertProblems(
				problems -> deviations(utf8(content), vectors, problems), expected));
	}

	private static DynamicTest decisionsCase(String name, String content, Set<String> vectors, String... expected) {
		return DynamicTest.dynamicTest(name, () -> assertProblems(
				problems -> decisions(utf8(content), vectors, problems), expected));
	}

	private static void assertProblems(Consumer<List<String>> check, String... expected) {
		List<String> problems = new ArrayList<>();
		check.accept(problems);
		Assertions.assertEquals(List.of(expected), problems);
	}

	private static DynamicTest scanCase(String json, int names, boolean exactly, boolean ignoringAsciiCase) {
		return DynamicTest.dynamicTest(json, () -> {
			NameScan scan = NameScan.of(utf8(json));

			Assertions.assertEquals(names, scan.names, "member names");
			Assertions.assertEquals(exactly, scan.repeatsExactly(), "an exact repeat");
			Assertions.assertEquals(ignoringAsciiCase, scan.repeatsIgnoringAsciiCase(), "a repeat ignoring ASCII case");
		});
	}

	private static SortedMap<String, byte[]> files(Object... pathsAndContents) {
		SortedMap<String, byte[]> files = new TreeMap<>();

		for (int index = 0; index < pathsAndContents.length; index += 2)
			files.put((String) pathsAndContents[index], (byte[]) pathsAndContents[index + 1]);

		return files;
	}

	private static byte[] utf8(String text) {
		return text.getBytes(StandardCharsets.UTF_8);
	}

	private static String sha256(byte[] content) {
		try {
			return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(content));
		} catch (NoSuchAlgorithmException exception) {
			throw new IllegalStateException(exception);
		}
	}

	private static int compareUtf8(String first, String second) {
		return Arrays.compareUnsigned(utf8(first), utf8(second));
	}

	/**
	 * The vendored directory. Tests read the source directory when they run from a checkout, so the manifest check
	 * covers exactly what is committed, not a build copy; otherwise they read the copy on the test class path.
	 */
	private static Path root() {
		try {
			// target/test-classes -> target -> the module root.
			Path testClasses = Path.of(JsonTestSuiteTests.class.getProtectionDomain().getCodeSource().getLocation()
					.toURI());
			Path moduleRoot = testClasses.getParent() == null ? null : testClasses.getParent().getParent();

			if (moduleRoot != null && Files.isDirectory(moduleRoot.resolve(RELATIVE_SOURCE)))
				return moduleRoot.resolve(RELATIVE_SOURCE);

			URL resource = JsonTestSuiteTests.class.getResource(RESOURCE);

			if (resource == null)
				throw new IllegalStateException("The vendored JSONTestSuite is not on the test class path");

			return Path.of(resource.toURI());
		} catch (URISyntaxException exception) {
			throw new IllegalStateException(exception);
		}
	}

	/**
	 * Every regular file under {@code root}, by its path relative to {@code root} with {@code /} separators.
	 */
	private static SortedMap<String, byte[]> readTree(Path root) {
		SortedMap<String, byte[]> files = new TreeMap<>();

		try (Stream<Path> paths = Files.walk(root)) {
			for (Path path : paths.filter(Files::isRegularFile).toList())
				files.put(root.relativize(path).toString().replace('\\', '/'), Files.readAllBytes(path));
		} catch (IOException exception) {
			throw new UncheckedIOException(exception);
		}

		return files;
	}

	/**
	 * A profile under which every file runs, and its outcome column in {@code I_DECISIONS.txt}.
	 */
	private static final class Profile {
		private final String name;
		private final JsonLimits limits;
		private final int column;

		private Profile(String name, JsonLimits limits, int column) {
			this.name = name;
			this.limits = limits;
			this.column = column;
		}
	}

	/**
	 * A parse outcome ({@code accept} or {@code reject:<Kind>}) and the accepted value, if any.
	 */
	private static final class Result {
		private final String outcome;
		private final @Nullable JsonValue value;

		private Result(String outcome, @Nullable JsonValue value) {
			this.outcome = outcome;
			this.value = value;
		}
	}

	/**
	 * A content line of a list file, with its 1-based line number.
	 */
	private static final class Line {
		private final int number;
		private final String text;

		private Line(int number, String text) {
			this.number = number;
			this.text = text;
		}
	}

	/**
	 * The vendored suite, loaded only after the manifest and both lists pass every check.
	 */
	private static final class Suite {
		/**
		 * The {@code test_parsing/} files by name.
		 */
		private final SortedMap<String, byte[]> vectors;
		private final Set<String> deviations;
		private final Map<String, List<String>> decisions;

		/**
		 * How many files the manifest covers: every file in the directory but the manifest.
		 */
		private final int checkedFiles;

		private Suite(SortedMap<String, byte[]> vectors, Set<String> deviations, Map<String, List<String>> decisions,
									int checkedFiles) {
			this.vectors = vectors;
			this.deviations = deviations;
			this.decisions = decisions;
			this.checkedFiles = checkedFiles;
		}

		/**
		 * Reads the directory, checks the manifest in both directions and both lists, and fails with every problem
		 * found before any file is parsed.
		 */
		static Suite load() {
			SortedMap<String, byte[]> files = readTree(root());
			byte[] manifest = files.remove(MANIFEST);
			List<String> problems = new ArrayList<>();

			if (manifest == null)
				problems.add(MANIFEST + " is missing");
			else
				problems.addAll(manifestProblems(manifest, files));

			SortedMap<String, byte[]> vectors = new TreeMap<>();

			for (Map.Entry<String, byte[]> file : files.entrySet())
				if (file.getKey().startsWith(TEST_PARSING))
					vectors.put(file.getKey().substring(TEST_PARSING.length()), file.getValue());

			Set<String> deviations = deviations(files.get(DEVIATIONS), vectors.keySet(), problems);
			Map<String, List<String>> decisions = decisions(files.get(I_DECISIONS), vectors.keySet(), problems);

			if (!problems.isEmpty())
				Assertions.fail("The vendored JSONTestSuite under " + RELATIVE_SOURCE + " fails its checks (see its "
						+ "SOURCE.txt; regenerate " + MANIFEST + " after editing a list):\n  " + String.join("\n  ", problems));

			return new Suite(vectors, deviations, decisions, files.size());
		}

		/**
		 * The names of the files with a prefix ({@code y_}, {@code n_} or {@code i_}), sorted.
		 */
		Stream<String> names(String prefix) {
			return this.vectors.keySet().stream().filter(name -> name.startsWith(prefix));
		}

		byte[] vector(String name) {
			return requireNonNull(this.vectors.get(name), name);
		}
	}

	/**
	 * An independent oracle for {@code DEVIATIONS.txt}: the member names of every object in well-formed JSON text,
	 * found by a scanner that shares no code with the codec. Names are compared within each object after unescaping,
	 * exactly and ignoring ASCII case only (G7-7).
	 */
	private static final class NameScan {
		private final int names;
		private final boolean exactRepeat;
		private final boolean asciiCaseRepeat;

		private NameScan(int names, boolean exactRepeat, boolean asciiCaseRepeat) {
			this.names = names;
			this.exactRepeat = exactRepeat;
			this.asciiCaseRepeat = asciiCaseRepeat;
		}

		static NameScan of(byte[] input) throws CharacterCodingException {
			String text = StandardCharsets.UTF_8.newDecoder()
					.onMalformedInput(CodingErrorAction.REPORT)
					.onUnmappableCharacter(CodingErrorAction.REPORT)
					.decode(ByteBuffer.wrap(input))
					.toString();
			Deque<Container> open = new ArrayDeque<>();
			int names = 0;
			boolean exactRepeat = false;
			boolean asciiCaseRepeat = false;
			int index = 0;

			while (index < text.length()) {
				char character = text.charAt(index);

				if (character == '"') {
					StringBuilder decoded = new StringBuilder();
					index = readString(text, index + 1, decoded);
					int next = index;

					while (next < text.length() && " \t\r\n".indexOf(text.charAt(next)) >= 0)
						++next;

					if (next < text.length() && text.charAt(next) == ':') {
						Container object = open.peek();

						if (object == null || !object.isObject)
							throw new IllegalArgumentException("a member name outside an object");

						String name = decoded.toString();
						boolean newName = object.exactNames.add(name);
						boolean newFoldedName = object.foldedNames.add(foldAsciiCase(name));

						++names;
						exactRepeat |= !newName;
						asciiCaseRepeat |= !newFoldedName;
					}

					continue;
				}

				if (character == '{' || character == '[')
					open.push(new Container(character == '{'));
				else if (character == '}' || character == ']')
					open.pop();

				++index;
			}

			if (!open.isEmpty())
				throw new IllegalArgumentException("an unclosed object or array");

			return new NameScan(names, exactRepeat, asciiCaseRepeat);
		}

		boolean repeatsExactly() {
			return this.exactRepeat;
		}

		boolean repeatsIgnoringAsciiCase() {
			return this.asciiCaseRepeat;
		}

		/**
		 * Unescapes the string that starts at {@code start} (just past its opening quotation mark) into {@code out},
		 * and returns the index just past its closing quotation mark.
		 */
		private static int readString(String text, int start, StringBuilder out) {
			int index = start;

			while (true) {
				char character = text.charAt(index++);

				if (character == '"')
					return index;

				if (character != '\\') {
					out.append(character);
					continue;
				}

				char escape = text.charAt(index++);

				switch (escape) {
					case '"', '\\', '/' -> out.append(escape);
					case 'b' -> out.append('\b');
					case 'f' -> out.append('\f');
					case 'n' -> out.append('\n');
					case 'r' -> out.append('\r');
					case 't' -> out.append('\t');
					case 'u' -> {
						out.append((char) Integer.parseInt(text.substring(index, index + 4), 16));
						index += 4;
					}
					default -> throw new IllegalArgumentException("not a JSON escape");
				}
			}
		}

		/**
		 * Lowercases ASCII letters only, by arithmetic, as {@code AsciiCase} does (it is not called, to keep this scanner
		 * independent of the codec).
		 */
		private static String foldAsciiCase(String name) {
			char[] characters = name.toCharArray();

			for (int index = 0; index < characters.length; ++index)
				if (characters[index] >= 'A' && characters[index] <= 'Z')
					characters[index] = (char) (characters[index] - 'A' + 'a');

			return new String(characters);
		}

		/**
		 * An open object or array, and the names seen so far in an object.
		 */
		private static final class Container {
			private final boolean isObject;
			private final Set<String> exactNames = new HashSet<>();
			private final Set<String> foldedNames = new HashSet<>();

			private Container(boolean isObject) {
				this.isObject = isObject;
			}
		}
	}
}
