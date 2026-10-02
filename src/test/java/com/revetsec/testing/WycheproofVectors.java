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

package com.revetsec.testing;

import org.jspecify.annotations.NonNull;

import com.revetsec.internal.json.JsonCodec;
import com.revetsec.internal.json.JsonLimits;
import com.revetsec.internal.json.JsonParseException;
import com.revetsec.json.JsonArray;
import com.revetsec.json.JsonNumber;
import com.revetsec.json.JsonObject;
import com.revetsec.json.JsonValue;
import org.jspecify.annotations.Nullable;

import javax.annotation.concurrent.Immutable;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.net.URISyntaxException;
import java.net.URL;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.EnumMap;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.Optional;
import java.util.Set;
import java.util.SortedMap;
import java.util.TreeMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;

import static java.util.Objects.requireNonNull;

/**
 * The vendored Project Wycheproof test vectors (M2 plan M2-9 and exit criterion 3): 28 files of
 * {@code C2SP/wycheproof}'s {@code testvectors_v1/} at the pinned commit, under
 * {@code src/test/resources/vectors/wycheproof/} (see its {@code SOURCE.txt}), loaded with Revetsec's own
 * {@link JsonCodec} under the protocol-document profile.
 * <p>
 * <strong>Checks first.</strong> {@link #fromVendoredFiles()} and {@link #fromFiles(SortedMap)} hand out no vector
 * until every check below passes; otherwise they fail with one {@link AssertionError} that lists every problem, in this
 * order ({@link #findProblems(SortedMap)} returns the same list):
 * <ol>
 *   <li><strong>{@code MANIFEST.sha256}</strong> is {@code sha256sum} output for every other file in the tree, in both
 *   directions: every line matches its file, and every other file has a line. Lines are sorted by the paths' UTF-8
 *   bytes and end with LF, and no line lists the manifest itself.</li>
 *   <li><strong>The file set</strong> is {@code LICENSE}, {@code SOURCE.txt}, {@code MANIFEST.sha256} and at least one
 *   {@code testvectors_v1/<name>.json}, with {@code <name>} in lowercase letters, digits and underscores, and nothing
 *   else: no README or other Markdown (plan 19's claims lint scans every {@code *.md} file), and no subdirectory.</li>
 *   <li><strong>Each vector file</strong> is strict UTF-8 JSON under {@link JsonLimits#protocolDocument(Integer)} with
 *   a {@value #MAXIMUM_FILE_BYTES}-byte limit, and has the structure the views rely on: a string {@code schema}, an
 *   optional string {@code algorithm}, a whole-number {@code numberOfTests}, a {@code header} array of strings, a
 *   {@code notes} object and a {@code testGroups} array; each group an object with a string {@code type} and a
 *   {@code tests} array; each test an object with a positive whole-number {@code tcId}, a string {@code comment}, a
 *   {@code flags} array of strings that {@code notes} defines, and a {@code result} of {@code valid},
 *   {@code invalid} or {@code acceptable}. The file holds exactly {@code numberOfTests} tests, and their tcIds run
 *   from 1 to that number, each once.</li>
 *   <li><strong>{@code SOURCE.txt}</strong> is UTF-8 text with LF line endings and one {@code Commit:} line of 40
 *   lowercase hex digits. Its file table has one row per file but itself and the manifest, sorted by path, then a
 *   {@code total} row over the vector files. Each column is recomputed from the files: the size in bytes and the git
 *   blob SHA-1 ({@code SHA-1("blob <size>\0" + content)}) of every file, and for every vector file the number of tests
 *   and how many are {@code valid}, {@code invalid} and {@code acceptable}. A vector file with a structure problem
 *   has no counts to compare (its problem already fails the check), and the total row's counts are compared only
 *   when every vector file has them.</li>
 * </ol>
 * The manifest makes the files tamper-evident; the {@code SOURCE.txt} counts and the per-file structure checks make a
 * silent re-vendor or a codec misread visible, and {@code WycheproofManifestTests} pins the counts at the commit.
 * <p>
 * <strong>Views.</strong> {@link VectorFile}, {@link TestGroup} and {@link TestVector} expose the checked structure,
 * plus each JSON object as it is ({@code getJson()}) and typed lookups of the members that vary by schema, such as
 * {@code publicKeyJwk}, {@code sha}, {@code keySize}, {@code msg}, {@code sig} or {@code jws}. Every getter of a
 * checked member is total. A lookup of an absent member through {@code getX(name)} throws
 * {@link NoSuchElementException} naming the file and the group index or tcId; {@code findX(name)} returns an empty
 * {@link Optional} instead. Revetsec's expected outcomes are not here: each runner keeps its own expectation manifest.
 * <p>
 * Each call reads and checks the files again (about 7 MB), so a runner loads once per test factory, not per vector.
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 */
@Immutable
public final class WycheproofVectors {
	/**
	 * The vendored directory, relative to the module root.
	 */
	public static final String RELATIVE_SOURCE = "src/test/resources/vectors/wycheproof";

	/**
	 * The largest vector file the loader parses, in bytes: 1 MiB, above the largest vendored file (605,484 bytes).
	 */
	public static final int MAXIMUM_FILE_BYTES = 1_024 * 1_024;

	private static final String RESOURCE = "/vectors/wycheproof";
	private static final String MANIFEST = "MANIFEST.sha256";
	private static final String SOURCE = "SOURCE.txt";
	private static final String LICENSE = "LICENSE";
	private static final String VECTOR_DIRECTORY = "testvectors_v1/";

	/**
	 * A manifest line: {@code <64 lowercase hex digits><two spaces><path>}, as {@code sha256sum} writes it.
	 */
	private static final Pattern MANIFEST_LINE = Pattern.compile("([0-9a-f]{64})  (.*)");

	/**
	 * A path the manifest may list: a file at the top of the directory or directly in {@code testvectors_v1/}.
	 */
	private static final Pattern MANIFEST_PATH = Pattern.compile("(?:testvectors_v1/)?[A-Za-z0-9_+#-][A-Za-z0-9._+#-]*");

	/**
	 * A vector file's path.
	 */
	private static final Pattern VECTOR_PATH = Pattern.compile("testvectors_v1/[a-z0-9_]+\\.json");

	/**
	 * The {@code Commit:} line of {@code SOURCE.txt}.
	 */
	private static final Pattern COMMIT_LINE = Pattern.compile("Commit: +([0-9a-f]{40})");

	/**
	 * The start of any line of {@code SOURCE.txt} that tries to be the {@code Commit:} line.
	 */
	private static final String COMMIT_PREFIX = "Commit:";

	/**
	 * The start of a line that tries to be a row of the {@code SOURCE.txt} file table.
	 */
	private static final Pattern ROW_START = Pattern.compile("  (?:LICENSE|total|testvectors_v1/)");

	private static final String COUNT = "(0|[1-9][0-9]{0,8})";
	private static final String BLOB = "([0-9a-f]{40})";
	private static final Pattern LICENSE_ROW = Pattern.compile("  (LICENSE) +" + COUNT + " +- +- +- +- +" + BLOB);
	private static final Pattern VECTOR_ROW = Pattern.compile("  (testvectors_v1/[a-z0-9_]+\\.json) +" + COUNT + " +"
			+ COUNT + " +" + COUNT + " +" + COUNT + " +" + COUNT + " +" + BLOB);
	private static final Pattern TOTAL_ROW = Pattern.compile("  total +" + COUNT + " +" + COUNT + " +" + COUNT + " +"
			+ COUNT + " +" + COUNT + " +-");

	private final String commit;
	private final List<VectorFile> files;
	private final Map<String, VectorFile> filesByName;
	private final Integer checkedFileCount;

	private WycheproofVectors(@NonNull String commit, @NonNull List<@NonNull VectorFile> files, @NonNull Integer checkedFileCount) {
		this.commit = commit;
		this.files = List.copyOf(files);
		Map<String, VectorFile> filesByName = new LinkedHashMap<>();

		for (VectorFile file : this.files)
			filesByName.put(file.getName(), file);

		this.filesByName = Collections.unmodifiableMap(filesByName);
		this.checkedFileCount = checkedFileCount;
	}

	/**
	 * Reads the vendored directory, checks it (see the class documentation) and returns its views. When the tests run
	 * from a checkout, the source directory is read, so the checks cover exactly what is committed rather than a build
	 * copy; otherwise the copy on the test class path is.
	 *
	 * @return the checked vectors
	 * @throws AssertionError if any check fails; its message lists every problem
	 */
	public static @NonNull WycheproofVectors fromVendoredFiles() {
		Path root = root();
		return fromFiles(readTree(root), root.toString());
	}

	/**
	 * Checks a directory tree given in memory (see the class documentation) and returns its views. Tests of the checks
	 * themselves use it with synthetic trees.
	 *
	 * @param files every regular file of the tree, by its path relative to the tree with {@code /} separators
	 * @return the checked vectors
	 * @throws AssertionError if any check fails; its message lists every problem
	 */
	public static @NonNull WycheproofVectors fromFiles(@NonNull SortedMap<@NonNull String, byte @NonNull []> files) {
		return fromFiles(files, "the given tree");
	}

	/**
	 * Every problem the checks find in a directory tree given in memory, in the order of the class documentation;
	 * empty if there is none. Each problem is one line naming the file, and the line where there is one.
	 *
	 * @param files every regular file of the tree, by its path relative to the tree with {@code /} separators
	 * @return the problems
	 */
	public static @NonNull List<@NonNull String> findProblems(@NonNull SortedMap<@NonNull String, byte @NonNull []> files) {
		return List.copyOf(new Check(requireNonNull(files)).problems);
	}

	private static @NonNull WycheproofVectors fromFiles(@NonNull SortedMap<@NonNull String, byte @NonNull []> files, @NonNull String location) {
		requireNonNull(files);
		Check check = new Check(files);

		if (!check.problems.isEmpty())
			throw new AssertionError("The vendored Wycheproof vectors in " + location + " fail their checks (see "
					+ SOURCE + " there; regenerate " + MANIFEST + " after a deliberate change):\n  "
					+ String.join("\n  ", check.problems));

		List<VectorFile> vectorFiles = new ArrayList<>();

		for (Map.Entry<String, JsonObject> parsed : check.parsed.entrySet())
			vectorFiles.add(new VectorFile(parsed.getKey(), requireNonNull(files.get(parsed.getKey())),
					parsed.getValue()));

		return new WycheproofVectors(requireNonNull(check.commit), vectorFiles, files.size() - 1);
	}

	/**
	 * The upstream commit that {@code SOURCE.txt} records.
	 *
	 * @return 40 lowercase hex digits
	 */
	public @NonNull String getCommit() {
		return this.commit;
	}

	/**
	 * The vector files, sorted by name.
	 *
	 * @return an unmodifiable list
	 */
	public @NonNull List<@NonNull VectorFile> getFiles() {
		return this.files;
	}

	/**
	 * A vector file by name.
	 *
	 * @param name the file name in {@code testvectors_v1/}, such as {@code ed25519_test.json}
	 * @return the file, or empty if no such file is vendored
	 */
	public @NonNull Optional<@NonNull VectorFile> findFile(@NonNull String name) {
		requireNonNull(name);
		return Optional.ofNullable(this.filesByName.get(name));
	}

	/**
	 * A vector file by name.
	 *
	 * @param name the file name in {@code testvectors_v1/}, such as {@code ed25519_test.json}
	 * @return the file
	 * @throws NoSuchElementException if no such file is vendored
	 */
	public @NonNull VectorFile getFile(@NonNull String name) {
		return findFile(name).orElseThrow(() -> new NoSuchElementException("No vendored Wycheproof file " + name));
	}

	/**
	 * How many files the manifest covers: every file in the tree but the manifest itself.
	 *
	 * @return the count
	 */
	public @NonNull Integer getCheckedFileCount() {
		return this.checkedFileCount;
	}

	@Override
	public @NonNull String toString() {
		return "WycheproofVectors{commit=" + this.commit + ", files=" + this.files.size() + "}";
	}

	/**
	 * A test's verdict upstream.
	 */
	@Immutable
	public enum Result {
		/**
		 * {@code valid}: a correct implementation accepts the test.
		 */
		VALID("valid"),
		/**
		 * {@code invalid}: a correct implementation rejects the test.
		 */
		INVALID("invalid"),
		/**
		 * {@code acceptable}: legacy, weak or unusual input that an implementation may accept or reject; its flags say
		 * why.
		 */
		ACCEPTABLE("acceptable");

		private final String wireValue;

		Result(@NonNull String wireValue) {
			this.wireValue = wireValue;
		}

		/**
		 * The value of the {@code result} member.
		 *
		 * @return {@code valid}, {@code invalid} or {@code acceptable}
		 */
		public @NonNull String getWireValue() {
			return this.wireValue;
		}

		/**
		 * The result whose wire value is exactly {@code wireValue}.
		 *
		 * @param wireValue the value of a {@code result} member
		 * @return the result, or empty if there is none
		 */
		public static @NonNull Optional<@NonNull Result> findByWireValue(@NonNull String wireValue) {
			requireNonNull(wireValue);
			return Arrays.stream(values()).filter(result -> result.wireValue.equals(wireValue)).findFirst();
		}
	}

	/**
	 * One vendored vector file: its top-level members and its groups.
	 */
	@Immutable
	public static final class VectorFile {
		private final String path;
		private final byte[] content;
		private final JsonObject json;
		private final List<TestGroup> groups;
		private final List<TestVector> tests;
		private final Map<Integer, TestVector> testsByTcId;

		private VectorFile(@NonNull String path, byte @NonNull [] content, @NonNull JsonObject json) {
			this.path = path;
			this.content = content.clone();
			this.json = json;
			List<TestGroup> groups = new ArrayList<>();
			List<TestVector> tests = new ArrayList<>();
			Map<Integer, TestVector> testsByTcId = new LinkedHashMap<>();
			List<JsonValue> groupValues = array(json, "testGroups").getElements();

			for (int index = 0; index < groupValues.size(); ++index) {
				TestGroup group = new TestGroup(this, index, (JsonObject) groupValues.get(index));
				groups.add(group);

				for (TestVector test : group.getTests()) {
					tests.add(test);
					testsByTcId.put(test.getTcId(), test);
				}
			}

			this.groups = List.copyOf(groups);
			this.tests = List.copyOf(tests);
			this.testsByTcId = Collections.unmodifiableMap(testsByTcId);
		}

		/**
		 * The file name in {@code testvectors_v1/}.
		 *
		 * @return the name, such as {@code ed25519_test.json}
		 */
		public @NonNull String getName() {
			return this.path.substring(VECTOR_DIRECTORY.length());
		}

		/**
		 * The path relative to the vendored directory.
		 *
		 * @return the path, such as {@code testvectors_v1/ed25519_test.json}
		 */
		public @NonNull String getPath() {
			return this.path;
		}

		/**
		 * The file's size.
		 *
		 * @return the size in bytes
		 */
		public @NonNull Integer getSize() {
			return this.content.length;
		}

		/**
		 * The file's bytes, exactly as vendored.
		 *
		 * @return a new array
		 */
		public byte @NonNull [] getContent() {
			return this.content.clone();
		}

		/**
		 * The whole file as parsed.
		 *
		 * @return the top-level object
		 */
		public @NonNull JsonObject getJson() {
			return this.json;
		}

		/**
		 * The {@code schema} member.
		 *
		 * @return the schema file name, such as {@code eddsa_verify_schema_v1.json}
		 */
		public @NonNull String getSchema() {
			return string(this.json, "schema");
		}

		/**
		 * The {@code algorithm} member, which the JOSE files do not have.
		 *
		 * @return the algorithm, such as {@code ECDSA}, or empty
		 */
		public @NonNull Optional<@NonNull String> findAlgorithm() {
			return this.json.findString("algorithm");
		}

		/**
		 * The {@code numberOfTests} member, which the checks made equal to the number of tests.
		 *
		 * @return the number of tests
		 */
		public @NonNull Integer getNumberOfTests() {
			return this.tests.size();
		}

		/**
		 * The {@code header} member.
		 *
		 * @return an unmodifiable list of lines
		 */
		public @NonNull List<@NonNull String> getHeader() {
			return this.json.findStringList("header").orElseThrow();
		}

		/**
		 * The {@code notes} member: each flag's {@code bugType}, {@code description} and so on.
		 *
		 * @return the notes, by flag
		 */
		public @NonNull JsonObject getNotes() {
			return object(this.json, "notes");
		}

		/**
		 * The test groups, in file order.
		 *
		 * @return an unmodifiable list
		 */
		public @NonNull List<@NonNull TestGroup> getGroups() {
			return this.groups;
		}

		/**
		 * Every test, in file order.
		 *
		 * @return an unmodifiable list
		 */
		public @NonNull List<@NonNull TestVector> getTests() {
			return this.tests;
		}

		/**
		 * The tests with one upstream verdict, in file order.
		 *
		 * @param result the verdict
		 * @return an unmodifiable list
		 */
		public @NonNull List<@NonNull TestVector> getTests(@NonNull Result result) {
			requireNonNull(result);
			return this.tests.stream().filter(test -> test.getResult() == result).toList();
		}

		/**
		 * A test by its tcId.
		 *
		 * @param tcId the tcId
		 * @return the test, or empty if the file has no such tcId
		 */
		public @NonNull Optional<@NonNull TestVector> findTest(@NonNull Integer tcId) {
			requireNonNull(tcId);
			return Optional.ofNullable(this.testsByTcId.get(tcId));
		}

		/**
		 * A test by its tcId.
		 *
		 * @param tcId the tcId
		 * @return the test
		 * @throws NoSuchElementException if the file has no such tcId
		 */
		public @NonNull TestVector getTest(@NonNull Integer tcId) {
			return findTest(tcId).orElseThrow(() -> new NoSuchElementException(getName() + " has no tcId " + tcId));
		}

		@Override
		public @NonNull String toString() {
			return getName();
		}
	}

	/**
	 * One test group: the members its tests share, such as the key and the hash, and its tests.
	 */
	@Immutable
	public static final class TestGroup {
		private final VectorFile file;
		private final Integer index;
		private final JsonObject json;
		private final List<TestVector> tests;

		private TestGroup(@NonNull VectorFile file, @NonNull Integer index, @NonNull JsonObject json) {
			this.file = file;
			this.index = index;
			this.json = json;
			List<TestVector> tests = new ArrayList<>();

			for (JsonValue test : array(json, "tests").getElements())
				tests.add(new TestVector(this, (JsonObject) test));

			this.tests = List.copyOf(tests);
		}

		/**
		 * The file this group belongs to.
		 *
		 * @return the file
		 */
		public @NonNull VectorFile getFile() {
			return this.file;
		}

		/**
		 * This group's position in the file's {@code testGroups}.
		 *
		 * @return the zero-based index
		 */
		public @NonNull Integer getIndex() {
			return this.index;
		}

		/**
		 * The {@code type} member.
		 *
		 * @return the type, such as {@code EcdsaP1363Verify}
		 */
		public @NonNull String getType() {
			return string(this.json, "type");
		}

		/**
		 * The whole group object, its {@code tests} included.
		 *
		 * @return the object
		 */
		public @NonNull JsonObject getJson() {
			return this.json;
		}

		/**
		 * The group's tests, in file order.
		 *
		 * @return an unmodifiable list
		 */
		public @NonNull List<@NonNull TestVector> getTests() {
			return this.tests;
		}

		/**
		 * A string member, such as {@code sha} or {@code mgf}.
		 *
		 * @param name the member name
		 * @return the value, or empty if the member is absent or not a string
		 */
		public @NonNull Optional<@NonNull String> findString(@NonNull String name) {
			return this.json.findString(requireNonNull(name));
		}

		/**
		 * A string member, such as {@code sha} or {@code mgf}.
		 *
		 * @param name the member name
		 * @return the value
		 * @throws NoSuchElementException if the member is absent or not a string
		 */
		public @NonNull String getString(@NonNull String name) {
			return findString(name).orElseThrow(() -> absent(toString(), "string", name));
		}

		/**
		 * A whole-number member in the range of {@code int}, such as {@code keySize}, {@code sLen} or {@code tagSize}.
		 *
		 * @param name the member name
		 * @return the value, or empty if the member is absent, not a number, not whole or out of range
		 */
		public @NonNull Optional<@NonNull Integer> findInteger(@NonNull String name) {
			return integer(this.json, requireNonNull(name));
		}

		/**
		 * A whole-number member in the range of {@code int}, such as {@code keySize}, {@code sLen} or {@code tagSize}.
		 *
		 * @param name the member name
		 * @return the value
		 * @throws NoSuchElementException if the member is absent, not a number, not whole or out of range
		 */
		public @NonNull Integer getInteger(@NonNull String name) {
			return findInteger(name).orElseThrow(() -> absent(toString(), "whole-number", name));
		}

		/**
		 * An object member, such as {@code publicKey}, {@code publicKeyJwk}, {@code keyJwk}, {@code public} or
		 * {@code private}.
		 *
		 * @param name the member name
		 * @return the value, or empty if the member is absent or not an object
		 */
		public @NonNull Optional<@NonNull JsonObject> findObject(@NonNull String name) {
			return optionalObject(this.json, requireNonNull(name));
		}

		/**
		 * An object member, such as {@code publicKey}, {@code publicKeyJwk}, {@code keyJwk}, {@code public} or
		 * {@code private}.
		 *
		 * @param name the member name
		 * @return the value
		 * @throws NoSuchElementException if the member is absent or not an object
		 */
		public @NonNull JsonObject getObject(@NonNull String name) {
			return findObject(name).orElseThrow(() -> absent(toString(), "object", name));
		}

		/**
		 * A hex string member decoded, such as {@code publicKeyDer}.
		 *
		 * @param name the member name
		 * @return a new array
		 * @throws NoSuchElementException   if the member is absent or not a string
		 * @throws IllegalArgumentException if the member is not an even-length hex string
		 */
		public byte @NonNull [] getHexBytes(@NonNull String name) {
			return hex(toString(), name, getString(name));
		}

		/**
		 * Names the group in failure messages.
		 *
		 * @return the file name and the group's index, such as {@code ed25519_test.json testGroups[3]}
		 */
		@Override
		public @NonNull String toString() {
			return this.file.getName() + " testGroups[" + this.index + "]";
		}
	}

	/**
	 * One test: its tcId, comment, flags and upstream verdict, and its inputs.
	 */
	@Immutable
	public static final class TestVector {
		private final TestGroup group;
		private final JsonObject json;

		private TestVector(@NonNull TestGroup group, @NonNull JsonObject json) {
			this.group = group;
			this.json = json;
		}

		/**
		 * The group this test belongs to, which holds its key and parameters.
		 *
		 * @return the group
		 */
		public @NonNull TestGroup getGroup() {
			return this.group;
		}

		/**
		 * The file this test belongs to.
		 *
		 * @return the file
		 */
		public @NonNull VectorFile getFile() {
			return this.group.getFile();
		}

		/**
		 * The {@code tcId} member, unique in the file.
		 *
		 * @return the tcId, from 1 to the file's number of tests
		 */
		public @NonNull Integer getTcId() {
			return integer(this.json, "tcId").orElseThrow();
		}

		/**
		 * The {@code comment} member.
		 *
		 * @return the comment, which may be empty
		 */
		public @NonNull String getComment() {
			return string(this.json, "comment");
		}

		/**
		 * The {@code flags} member: keys of the file's {@link VectorFile#getNotes() notes}.
		 *
		 * @return an unmodifiable list, in file order
		 */
		public @NonNull List<@NonNull String> getFlags() {
			return this.json.findStringList("flags").orElseThrow();
		}

		/**
		 * The {@code result} member.
		 *
		 * @return the upstream verdict
		 */
		public @NonNull Result getResult() {
			return Result.findByWireValue(string(this.json, "result")).orElseThrow();
		}

		/**
		 * The whole test object.
		 *
		 * @return the object
		 */
		public @NonNull JsonObject getJson() {
			return this.json;
		}

		/**
		 * A string member, such as {@code jws}.
		 *
		 * @param name the member name
		 * @return the value, or empty if the member is absent or not a string
		 */
		public @NonNull Optional<@NonNull String> findString(@NonNull String name) {
			return this.json.findString(requireNonNull(name));
		}

		/**
		 * A string member, such as {@code jws}.
		 *
		 * @param name the member name
		 * @return the value
		 * @throws NoSuchElementException if the member is absent or not a string
		 */
		public @NonNull String getString(@NonNull String name) {
			return findString(name).orElseThrow(() -> absent(where(), "string", name));
		}

		/**
		 * A hex string member decoded, such as {@code msg}, {@code sig}, {@code key} or {@code tag}.
		 *
		 * @param name the member name
		 * @return a new array, empty for an empty string
		 * @throws NoSuchElementException   if the member is absent or not a string
		 * @throws IllegalArgumentException if the member is not an even-length hex string
		 */
		public byte @NonNull [] getHexBytes(@NonNull String name) {
			return hex(where(), name, getString(name));
		}

		/**
		 * Names the test in lookup failures.
		 */
		private @NonNull String where() {
			return getFile().getName() + " tcId " + getTcId();
		}

		/**
		 * Names the test for a dynamic test's display name or a failure message.
		 *
		 * @return the file, tcId, verdict, flags and comment, such as
		 * {@code ed25519_test.json tcId 37 (invalid) [SignatureMalleability]: comment}
		 */
		@Override
		public @NonNull String toString() {
			return getFile().getName() + " tcId " + getTcId() + " (" + getResult().getWireValue() + ") " + getFlags()
					+ ": " + getComment();
		}
	}

	// ---------------------------------------------------------------------------------------------------------------
	// The checks
	// ---------------------------------------------------------------------------------------------------------------

	/**
	 * One run of every check over a tree, in the order of the class documentation.
	 */
	private static final class Check {
		private final List<String> problems = new ArrayList<>();

		/**
		 * The vector files that passed their structure checks, by path.
		 */
		private final SortedMap<String, JsonObject> parsed = new TreeMap<>();

		/**
		 * The counts of the vector files that passed their structure checks, by path.
		 */
		private final Map<String, Counts> counts = new LinkedHashMap<>();

		private @Nullable String commit;

		private Check(@NonNull SortedMap<@NonNull String, byte @NonNull []> files) {
			SortedMap<String, byte[]> others = new TreeMap<>(files);
			byte @Nullable [] manifest = others.remove(MANIFEST);

			if (manifest == null)
				this.problems.add(MANIFEST + " is missing");
			else
				this.problems.addAll(manifestProblems(manifest, others));

			checkFileSet(others);

			for (Map.Entry<String, byte[]> file : others.entrySet())
				if (VECTOR_PATH.matcher(file.getKey()).matches())
					checkVectorFile(file.getKey(), file.getValue());

			byte @Nullable [] source = others.get(SOURCE);

			if (source == null)
				this.problems.add(SOURCE + " is missing");
			else
				checkSource(source, others);
		}

		private void checkFileSet(@NonNull SortedMap<@NonNull String, byte @NonNull []> others) {
			boolean anyVectorFile = false;

			for (String path : others.keySet()) {
				if (VECTOR_PATH.matcher(path).matches())
					anyVectorFile = true;
				else if (!path.equals(LICENSE) && !path.equals(SOURCE))
					this.problems.add(path + " does not belong here: only " + LICENSE + ", " + SOURCE + ", " + MANIFEST
							+ " and " + VECTOR_DIRECTORY + "<name>.json are vendored");
			}

			if (!others.containsKey(LICENSE))
				this.problems.add(LICENSE + " is missing");
			if (!anyVectorFile)
				this.problems.add(VECTOR_DIRECTORY + " holds no vector files");
		}

		/**
		 * Parses a vector file and checks its structure; records it and its counts only if every check passes.
		 */
		private void checkVectorFile(@NonNull String path, byte @NonNull [] content) {
			JsonValue value;

			try {
				value = JsonCodec.parse(content, JsonLimits.protocolDocument(MAXIMUM_FILE_BYTES));
			} catch (JsonParseException exception) {
				this.problems.add(path + " does not parse as strict JSON under the protocol-document profile: "
						+ exception.getKind().name() + " at byte " + exception.getByteOffset());
				return;
			}

			if (!(value instanceof JsonObject root)) {
				this.problems.add(path + " is not a JSON object");
				return;
			}

			List<String> found = new ArrayList<>();

			if (root.findString("schema").isEmpty())
				found.add(path + " has no string member schema");
			if (root.find("algorithm").isPresent() && root.findString("algorithm").isEmpty())
				found.add(path + " has a member algorithm that is not a string");

			Optional<Integer> numberOfTests = integer(root, "numberOfTests");

			if (numberOfTests.isEmpty())
				found.add(path + " has no whole-number member numberOfTests");
			if (root.findStringList("header").isEmpty())
				found.add(path + " has no member header that is an array of strings");

			Optional<JsonObject> notes = optionalObject(root, "notes");

			if (notes.isEmpty())
				found.add(path + " has no object member notes");

			Optional<JsonArray> groups = optionalArray(root, "testGroups");

			if (groups.isEmpty()) {
				found.add(path + " has no array member testGroups");
				this.problems.addAll(found);
				return;
			}

			Set<String> flagsDefined = notes.map(object -> object.getMembers().keySet()).orElse(Set.of());
			List<Integer> tcIds = new ArrayList<>();
			Map<Result, Integer> results = new EnumMap<>(Result.class);
			List<JsonValue> groupValues = groups.get().getElements();

			for (int groupIndex = 0; groupIndex < groupValues.size(); ++groupIndex) {
				String where = path + " testGroups[" + groupIndex + "]";

				if (!(groupValues.get(groupIndex) instanceof JsonObject group)) {
					found.add(where + " is not an object");
					continue;
				}

				if (group.findString("type").isEmpty())
					found.add(where + " has no string member type");

				Optional<JsonArray> tests = optionalArray(group, "tests");

				if (tests.isEmpty()) {
					found.add(where + " has no array member tests");
					continue;
				}

				List<JsonValue> testValues = tests.get().getElements();

				for (int testIndex = 0; testIndex < testValues.size(); ++testIndex) {
					String at = where + ".tests[" + testIndex + "]";

					if (!(testValues.get(testIndex) instanceof JsonObject test)) {
						found.add(at + " is not an object");
						continue;
					}

					Optional<Integer> tcId = integer(test, "tcId").filter(id -> id > 0);

					if (tcId.isEmpty())
						found.add(at + " has no positive whole-number member tcId");
					else
						tcIds.add(tcId.get());

					if (test.findString("comment").isEmpty())
						found.add(at + " has no string member comment");

					Optional<List<String>> flags = test.findStringList("flags");

					if (flags.isEmpty())
						found.add(at + " has no member flags that is an array of strings");
					else
						for (String flag : flags.get())
							if (!flagsDefined.contains(flag))
								found.add(at + " has a flag that notes does not define: " + flag);

					Optional<Result> result = test.findString("result").flatMap(Result::findByWireValue);

					if (result.isEmpty())
						found.add(at + " has no member result that is valid, invalid or acceptable");
					else
						results.merge(result.get(), 1, Integer::sum);
				}
			}

			int testCount = groupValues.stream()
					.filter(JsonObject.class::isInstance)
					.mapToInt(group -> optionalArray((JsonObject) group, "tests").map(tests -> tests.getElements().size())
							.orElse(0))
					.sum();

			if (numberOfTests.isPresent() && numberOfTests.get() != testCount)
				found.add(path + " has " + testCount + " tests, but its numberOfTests is " + numberOfTests.get());

			Set<Integer> seen = new HashSet<>();
			boolean repeats = false;

			for (Integer tcId : tcIds) {
				if (!seen.add(tcId)) {
					found.add(path + " repeats tcId " + tcId);
					repeats = true;
				}
			}

			if (!repeats && tcIds.size() == testCount && tcIds.stream().anyMatch(tcId -> tcId > testCount))
				found.add(path + "'s tcIds do not run from 1 to " + testCount);

			if (!found.isEmpty()) {
				this.problems.addAll(found);
				return;
			}

			this.parsed.put(path, root);
			this.counts.put(path, new Counts(testCount, results.getOrDefault(Result.VALID, 0),
					results.getOrDefault(Result.INVALID, 0), results.getOrDefault(Result.ACCEPTABLE, 0)));
		}

		/**
		 * Checks {@code SOURCE.txt}: its form, its {@code Commit:} line, and its file table against the files.
		 */
		private void checkSource(byte @NonNull [] source, @NonNull SortedMap<@NonNull String, byte @NonNull []> others) {
			String text;

			try {
				text = StandardCharsets.UTF_8.newDecoder()
						.onMalformedInput(CodingErrorAction.REPORT)
						.onUnmappableCharacter(CodingErrorAction.REPORT)
						.decode(ByteBuffer.wrap(source))
						.toString();
			} catch (CharacterCodingException exception) {
				this.problems.add(SOURCE + " is not well-formed UTF-8");
				return;
			}

			if (text.indexOf('\r') >= 0) {
				this.problems.add(SOURCE + " contains a carriage return (lines end with LF only)");
				return;
			}

			if (!text.endsWith("\n"))
				this.problems.add(SOURCE + " does not end with a line feed");

			String[] lines = (text.endsWith("\n") ? text.substring(0, text.length() - 1) : text).split("\n", -1);
			Set<String> rows = new HashSet<>();
			String previous = "";
			boolean totalSeen = false;

			for (int index = 0; index < lines.length; ++index) {
				String line = lines[index];
				String where = SOURCE + " line " + (index + 1);

				if (line.startsWith(COMMIT_PREFIX)) {
					Matcher matcher = COMMIT_LINE.matcher(line);

					if (!matcher.matches())
						this.problems.add(where + " is malformed (expected " + COMMIT_PREFIX + " and 40 lowercase hex "
								+ "digits)");
					else if (this.commit != null)
						this.problems.add(where + " repeats the " + COMMIT_PREFIX + " line");
					else
						this.commit = matcher.group(1);

					continue;
				}

				if (!ROW_START.matcher(line).lookingAt())
					continue;

				Matcher total = TOTAL_ROW.matcher(line);

				if (total.matches()) {
					if (totalSeen)
						this.problems.add(where + " repeats the total row");
					else
						checkTotal(where, total, others);

					totalSeen = true;
					continue;
				}

				Matcher vector = VECTOR_ROW.matcher(line);
				boolean isVector = vector.matches();
				Matcher row = isVector ? vector : LICENSE_ROW.matcher(line);

				if (!isVector && !row.matches()) {
					this.problems.add(where + " is malformed (expected a file table row: <path> <bytes> <tests> <valid> "
							+ "<invalid> <acceptable> <git blob SHA-1>, with - for each count of " + LICENSE + ", or the "
							+ "total row)");
					continue;
				}

				String path = row.group(1);
				byte @Nullable [] content = others.get(path);

				if (totalSeen)
					this.problems.add(where + " comes after the total row: " + path);
				else if (compareUtf8(previous, path) > 0)
					this.problems.add(where + " is out of order: " + path);

				previous = path;

				if (!rows.add(path)) {
					this.problems.add(where + " repeats " + path);
					continue;
				}

				if (content == null) {
					this.problems.add(where + " lists a file that does not exist: " + path);
					continue;
				}

				checkNumber(where, path + " has", "bytes", Integer.parseInt(row.group(2)), content.length);

				if (isVector) {
					@Nullable Counts counts = this.counts.get(path);

					if (counts != null) {
						checkNumber(where, path + " has", "tests", Integer.parseInt(row.group(3)), counts.tests);
						checkNumber(where, path + " has", "valid tests", Integer.parseInt(row.group(4)), counts.valid);
						checkNumber(where, path + " has", "invalid tests", Integer.parseInt(row.group(5)), counts.invalid);
						checkNumber(where, path + " has", "acceptable tests", Integer.parseInt(row.group(6)),
								counts.acceptable);
					}
				}

				String blob = gitBlobSha1(content);
				String recorded = row.group(isVector ? 7 : 3);

				if (!recorded.equals(blob))
					this.problems.add(where + " says the git blob SHA-1 of " + path + " is " + recorded + ", but it is "
							+ blob);
			}

			for (String path : others.keySet())
				if ((path.equals(LICENSE) || VECTOR_PATH.matcher(path).matches()) && !rows.contains(path))
					this.problems.add(SOURCE + " has no row for " + path);

			if (!totalSeen)
				this.problems.add(SOURCE + " has no total row");
			if (this.commit == null)
				this.problems.add(SOURCE + " has no " + COMMIT_PREFIX + " line");
		}

		/**
		 * Checks the total row against the vector files: their bytes always, their counts only when every vector file
		 * has counts.
		 */
		private void checkTotal(@NonNull String where, @NonNull Matcher total, @NonNull SortedMap<@NonNull String, byte @NonNull []> others) {
			long bytes = 0;
			int vectorFiles = 0;

			for (Map.Entry<String, byte[]> file : others.entrySet()) {
				if (VECTOR_PATH.matcher(file.getKey()).matches()) {
					bytes += file.getValue().length;
					++vectorFiles;
				}
			}

			checkNumber(where, "the vector files total", "bytes", Long.parseLong(total.group(1)), bytes);

			if (this.counts.size() != vectorFiles)
				return;

			long tests = 0;
			long valid = 0;
			long invalid = 0;
			long acceptable = 0;

			for (Counts counts : this.counts.values()) {
				tests += counts.tests;
				valid += counts.valid;
				invalid += counts.invalid;
				acceptable += counts.acceptable;
			}

			checkNumber(where, "the vector files total", "tests", Long.parseLong(total.group(2)), tests);
			checkNumber(where, "the vector files total", "valid tests", Long.parseLong(total.group(3)), valid);
			checkNumber(where, "the vector files total", "invalid tests", Long.parseLong(total.group(4)), invalid);
			checkNumber(where, "the vector files total", "acceptable tests", Long.parseLong(total.group(5)),
					acceptable);
		}

		/**
		 * Adds {@code <where> says <subject> <recorded> <unit>, but the files give <actual>} when the two differ.
		 */
		private void checkNumber(@NonNull String where, @NonNull String subject, @NonNull String unit, long recorded, long actual) {
			if (recorded != actual)
				this.problems.add(where + " says " + subject + " " + recorded + " " + unit + ", but the files give "
						+ actual);
		}
	}

	/**
	 * A vector file's test counts: all its tests, and those upstream marks valid, invalid and acceptable.
	 */
	private static final class Counts {
		private final int tests;
		private final int valid;
		private final int invalid;
		private final int acceptable;

		private Counts(int tests, int valid, int invalid, int acceptable) {
			this.tests = tests;
			this.valid = valid;
			this.invalid = invalid;
			this.acceptable = acceptable;
		}
	}

	/**
	 * Every problem with the manifest, given every other file in the tree by its relative path: a malformed,
	 * misordered or repeated line, a line for the manifest itself, a listed file that is missing or whose SHA-256
	 * differs, and a file that is not listed.
	 */
	private static @NonNull List<@NonNull String> manifestProblems(byte @NonNull [] manifest, @NonNull SortedMap<@NonNull String, byte @NonNull []> files) {
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

				if (!matcher.matches() || !MANIFEST_PATH.matcher(matcher.group(2)).matches()) {
					problems.add(where + " is malformed (expected <64 lowercase hex digits><two spaces><path>)");
					continue;
				}

				String path = matcher.group(2);
				byte @Nullable [] content = files.get(path);

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

	// ---------------------------------------------------------------------------------------------------------------
	// Helpers
	// ---------------------------------------------------------------------------------------------------------------

	private static @NonNull String string(@NonNull JsonObject object, @NonNull String name) {
		return object.findString(name).orElseThrow();
	}

	private static @NonNull JsonObject object(@NonNull JsonObject object, @NonNull String name) {
		return optionalObject(object, name).orElseThrow();
	}

	private static @NonNull JsonArray array(@NonNull JsonObject object, @NonNull String name) {
		return optionalArray(object, name).orElseThrow();
	}

	private static @NonNull Optional<@NonNull JsonObject> optionalObject(@NonNull JsonObject object, @NonNull String name) {
		return object.find(name).filter(JsonObject.class::isInstance).map(JsonObject.class::cast);
	}

	private static @NonNull Optional<@NonNull JsonArray> optionalArray(@NonNull JsonObject object, @NonNull String name) {
		return object.find(name).filter(JsonArray.class::isInstance).map(JsonArray.class::cast);
	}

	/**
	 * A whole-number member in the range of {@code int}.
	 */
	private static @NonNull Optional<@NonNull Integer> integer(@NonNull JsonObject object, @NonNull String name) {
		return object.find(name)
				.filter(JsonNumber.class::isInstance)
				.map(JsonNumber.class::cast)
				.flatMap(JsonNumber::getLongValueExact)
				.filter(value -> value >= Integer.MIN_VALUE && value <= Integer.MAX_VALUE)
				.map(Long::intValue);
	}

	private static @NonNull NoSuchElementException absent(@NonNull String where, @NonNull String kind, @NonNull String name) {
		return new NoSuchElementException(where + " has no " + kind + " member " + name);
	}

	private static byte @NonNull [] hex(@NonNull String where, @NonNull String name, @NonNull String value) {
		try {
			return HexFormat.of().parseHex(value);
		} catch (IllegalArgumentException exception) {
			throw new IllegalArgumentException(where + " member " + name + " is not an even-length hex string",
					exception);
		}
	}

	private static @NonNull String sha256(byte @NonNull [] content) {
		return HexFormat.of().formatHex(digest("SHA-256", content));
	}

	/**
	 * The git blob SHA-1 of a file's content: the SHA-1 of {@code "blob <size>\0"} followed by the content, which is
	 * how git names a blob, and how the upstream tree listing identifies each file.
	 */
	private static @NonNull String gitBlobSha1(byte @NonNull [] content) {
		byte[] prefix = ("blob " + content.length + "\0").getBytes(StandardCharsets.US_ASCII);
		byte[] blob = Arrays.copyOf(prefix, prefix.length + content.length);
		System.arraycopy(content, 0, blob, prefix.length, content.length);
		return HexFormat.of().formatHex(digest("SHA-1", blob));
	}

	private static byte @NonNull [] digest(@NonNull String algorithm, byte @NonNull [] content) {
		try {
			return MessageDigest.getInstance(algorithm).digest(content);
		} catch (NoSuchAlgorithmException exception) {
			throw new IllegalStateException(exception);
		}
	}

	private static int compareUtf8(@NonNull String first, @NonNull String second) {
		return Arrays.compareUnsigned(first.getBytes(StandardCharsets.UTF_8), second.getBytes(StandardCharsets.UTF_8));
	}

	/**
	 * The vendored directory. Tests read the source directory when they run from a checkout, so the checks cover
	 * exactly what is committed, not a build copy; otherwise they read the copy on the test class path.
	 */
	private static @NonNull Path root() {
		try {
			// target/test-classes -> target -> the module root.
			Path testClasses = Path.of(WycheproofVectors.class.getProtectionDomain().getCodeSource().getLocation()
					.toURI());
			Path target = testClasses.getParent();
			Path moduleRoot = target == null ? null : target.getParent();

			if (moduleRoot != null && Files.isDirectory(moduleRoot.resolve(RELATIVE_SOURCE)))
				return moduleRoot.resolve(RELATIVE_SOURCE);

			URL resource = WycheproofVectors.class.getResource(RESOURCE);

			if (resource == null)
				throw new IllegalStateException("The vendored Wycheproof vectors are not on the test class path");

			return Path.of(resource.toURI());
		} catch (URISyntaxException exception) {
			throw new IllegalStateException(exception);
		}
	}

	/**
	 * Every regular file under {@code root}, by its path relative to {@code root} with {@code /} separators.
	 */
	private static @NonNull SortedMap<@NonNull String, byte @NonNull []> readTree(@NonNull Path root) {
		SortedMap<String, byte[]> files = new TreeMap<>();

		try (Stream<Path> paths = Files.walk(root)) {
			for (Path path : paths.filter(Files::isRegularFile).toList())
				files.put(root.relativize(path).toString().replace('\\', '/'), Files.readAllBytes(path));
		} catch (IOException exception) {
			throw new UncheckedIOException(exception);
		}

		return files;
	}
}
