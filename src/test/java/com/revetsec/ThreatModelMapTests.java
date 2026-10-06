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

import com.sun.source.tree.AnnotationTree;
import com.sun.source.tree.ClassTree;
import com.sun.source.tree.CompilationUnitTree;
import com.sun.source.tree.IdentifierTree;
import com.sun.source.tree.MemberSelectTree;
import com.sun.source.tree.MethodTree;
import com.sun.source.tree.Tree;
import com.sun.source.util.JavacTask;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;

import javax.tools.Diagnostic;
import javax.tools.DiagnosticCollector;
import javax.tools.JavaCompiler;
import javax.tools.JavaFileObject;
import javax.tools.StandardJavaFileManager;
import javax.tools.ToolProvider;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.TreeSet;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;

/**
 * Checks the map from Revetsec's security invariants to the tests that enforce them (plan 14.6, as amended by M2-10
 * item 7): every {@code INV-} row of {@value #THREAT_MODEL} is checked by a test that exists, or, for the one
 * allowlisted row, by build checks that exist, and the "Security Invariants" list of {@value #SECURITY} names the
 * same invariants in the same order.
 * <p>
 * <strong>The rows.</strong> An invariant row is a Markdown table line whose first cell starts with {@code INV-},
 * however the line is spaced. It has exactly three cells: the ID ({@code INV-} followed by an upper-case letter and a
 * number), the invariant, and the "Checked by" cell, which must not be empty. IDs are unique, and every invariant ID
 * either document mentions, in a row, a list or prose, is the ID of a row. In {@value #SECURITY}'s section, an entry
 * reads {@code - **INV-…**}, and a list item that starts with an ID in any other form is reported, not skipped.
 * <p>
 * <strong>The citation grammar</strong> (M2-10 item 7), applied to every backticked token of a "Checked by" cell, each
 * token matched whole:
 * <ul>
 *   <li>a token matching {@code (?:[a-z]+\.)*[A-Z]\w*Tests(?:\.\w+)?} cites a test class, named relative to
 *   {@code src/test/java/com/revetsec/} (or, for a fuzz target, {@code fuzz/src/test/java/com/revetsec/}), or a class
 *   and one of its test methods. The class must declare at least one test method, and a cited method must be one of
 *   them: a method of the top-level class annotated {@code @Test}, {@code @TestFactory} or {@code @FuzzTest};</li>
 *   <li>a lower-camel token ({@code [a-z]\w*}) names a test method of the nearest class cited before it in the same
 *   cell, where a {@code Class.method} citation counts as a citation of its class;</li>
 *   <li>every other token is ignored: JDK types such as {@code SecureRandom}, rule names such as
 *   {@code constant-time-comparison}, paths and code such as {@code toString()}.</li>
 * </ul>
 * Every citation must resolve, so a renamed or deleted test fails the build instead of leaving a stale row, and every
 * row needs at least one. The one exception is the per-row allowlist of non-test evidence,
 * {@link #ALLOWLISTED_ARTIFACTS}: INV-L1 is checked by the Maven Enforcer's {@code <bannedDependencies>} rule and two
 * verification scripts, which the row must name in backticks and which must exist.
 * <p>
 * Test methods are read from the test sources with javac's parser, so the fuzz module's targets resolve too, although
 * they are not on this module's class path. {@link #theCitationGrammarResolvesExactlyWhatExists()} runs the resolver
 * against cells whose outcome is known, so a resolver that accepted everything, or nothing, would fail there first.
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 */
final class ThreatModelMapTests {
	static final String THREAT_MODEL = "docs/threat-model.md";
	static final String SECURITY = "SECURITY.md";
	static final String SECURITY_INVARIANTS_HEADING = "## Security Invariants";

	/**
	 * Where cited test classes are resolved, in order: the core test tree, then the fuzz module's.
	 */
	static final List<String> TEST_SOURCE_ROOTS = List.of("src/test/java/com/revetsec",
			"fuzz/src/test/java/com/revetsec");

	/**
	 * The annotations, by simple name, that make a method a test method.
	 */
	static final Set<String> TEST_ANNOTATIONS = Set.of("Test", "TestFactory", "FuzzTest");

	/**
	 * The per-row allowlist of non-test evidence (M2-10 item 7): the row's ID and the artifacts, relative to the
	 * repository root, that its "Checked by" cell must name in backticks.
	 */
	static final Map<String, List<String>> ALLOWLISTED_ARTIFACTS = Map.of("INV-L1", List.of("pom.xml",
			"verification/verify-published-pom.py", "verification/packaged-consumer/verify-packaged-consumer.py"));

	/**
	 * The Maven Enforcer rule that INV-L1's {@code pom.xml} evidence stands for.
	 */
	static final String BANNED_DEPENDENCIES_RULE = "<bannedDependencies>";

	private static final Pattern CITATION = Pattern.compile("((?:[a-z]+\\.)*[A-Z]\\w*Tests)(?:\\.(\\w+))?");
	private static final Pattern METHOD = Pattern.compile("[a-z]\\w*");
	private static final Pattern BACKTICKED = Pattern.compile("`([^`]+)`");
	private static final Pattern INVARIANT_ID = Pattern.compile("INV-[A-Z]\\d+");
	private static final Pattern MENTIONED_ID = Pattern.compile("\\bINV-[A-Z]\\d+\\b");
	private static final Pattern SECURITY_ENTRY = Pattern.compile("^- \\*\\*(INV-[A-Z]\\d+)\\*\\*");
	/**
	 * A top-level list item whose text starts with an invariant ID, in any emphasis: in the "Security Invariants"
	 * section it must be an entry ({@link #SECURITY_ENTRY}).
	 */
	private static final Pattern SECURITY_ITEM_WITH_ID = Pattern.compile("^(?:[-*+]|\\d+[.)])\\s+[*_`]*INV-");

	// M2-10 item 7: every row has an ID, an invariant and a "Checked by" cell, in exactly three cells, and no ID
	// repeats.
	@Test
	void everyInvariantRowHasThreeCellsAndAUniqueId() throws IOException {
		List<String> problems = new ArrayList<>();
		List<InvariantRow> rows = invariantRows(read(THREAT_MODEL), problems);
		ContractSupport.assertNoViolations("Malformed invariant rows in " + THREAT_MODEL, problems);

		Assertions.assertFalse(rows.isEmpty(), "the threat model lists invariants");
		Set<String> seen = new HashSet<>();
		for (InvariantRow row : rows) {
			Assertions.assertTrue(INVARIANT_ID.matcher(row.getId()).matches(), row::getId);
			Assertions.assertTrue(seen.add(row.getId()), () -> row.getId() + " is listed twice");
			Assertions.assertFalse(row.getInvariant().isEmpty(), () -> row.getId() + " states no invariant");
			Assertions.assertFalse(row.getCheckedBy().isEmpty(), () -> row.getId() + " has an empty Checked-by cell");
		}
	}

	// M2-10 item 7 and plan 14.6: every row cites at least one test that exists, every citation in it resolves to a
	// test class or test method, and the allowlisted row names build checks that exist.
	@TestFactory
	@NonNull Stream<@NonNull DynamicTest> everyInvariantIsCheckedByATestThatExists() throws IOException {
		Path root = ContractSupport.repositoryRoot();
		List<String> problems = new ArrayList<>();
		List<InvariantRow> rows = invariantRows(read(THREAT_MODEL), problems);
		ContractSupport.assertNoViolations("Malformed invariant rows in " + THREAT_MODEL, problems);
		Assertions.assertFalse(rows.isEmpty(), "the threat model lists invariants");
		TestSources testSources = TestSources.fromCells(root, rows.stream().map(InvariantRow::getCheckedBy).toList());

		return rows.stream().map(row -> DynamicTest.dynamicTest(row.getId(), () -> {
			CellCheck check = testSources.check(row.getCheckedBy());
			List<String> rowProblems = new ArrayList<>(check.getProblems());
			List<String> artifacts = ALLOWLISTED_ARTIFACTS.getOrDefault(row.getId(), List.of());
			rowProblems.addAll(artifactProblems(root, row, artifacts));

			if (check.getResolved().isEmpty() && artifacts.isEmpty())
				rowProblems.add("cites no test");
			ContractSupport.assertNoViolations(row.getId() + "'s Checked-by cell", rowProblems);
		}));
	}

	// M2-10 item 7: the allowlist has one entry today, INV-L1's pom.xml enforcer rule and verification scripts, and
	// an entry whose row is gone is stale.
	@Test
	void theAllowlistNamesOnlyRowsThatExist() throws IOException {
		List<String> problems = new ArrayList<>();
		Set<String> ids = new HashSet<>();
		for (InvariantRow row : invariantRows(read(THREAT_MODEL), problems))
			ids.add(row.getId());
		ContractSupport.assertNoViolations("Malformed invariant rows in " + THREAT_MODEL, problems);

		Assertions.assertEquals(Set.of("INV-L1"), ALLOWLISTED_ARTIFACTS.keySet());
		for (String id : ALLOWLISTED_ARTIFACTS.keySet())
			Assertions.assertTrue(ids.contains(id), () -> "stale allowlist entry " + id);
	}

	// SECURITY.md's "Security Invariants" section lists the threat model's invariants, the same IDs in the same
	// order, and nothing else.
	@Test
	void securityMdListsTheSameInvariantsInTheSameOrder() throws IOException {
		List<String> problems = new ArrayList<>();
		List<String> threatModelIds = invariantRows(read(THREAT_MODEL), problems).stream().map(InvariantRow::getId)
				.toList();
		ContractSupport.assertNoViolations("Malformed invariant rows in " + THREAT_MODEL, problems);

		List<String> securityIds = securityInvariantIds(read(SECURITY), problems);
		ContractSupport.assertNoViolations("Malformed invariant entries in " + SECURITY, problems);
		Assertions.assertFalse(securityIds.isEmpty(), () -> SECURITY + " lists invariants");
		Assertions.assertEquals(threatModelIds, securityIds,
				() -> SECURITY + "'s \"Security Invariants\" list must equal " + THREAT_MODEL + "'s rows, in order");
	}

	// Every invariant ID that the threat model or SECURITY.md mentions, in a row, a list or prose, is the ID of a
	// threat-model row, so neither document can refer to an invariant that was renamed, removed or never mapped.
	@Test
	void everyInvariantTheDocumentsMentionHasARow() throws IOException {
		List<String> problems = new ArrayList<>();
		Set<String> ids = new HashSet<>();
		for (InvariantRow row : invariantRows(read(THREAT_MODEL), problems))
			ids.add(row.getId());
		ContractSupport.assertNoViolations("Malformed invariant rows in " + THREAT_MODEL, problems);

		List<String> unmapped = new ArrayList<>();
		for (String document : List.of(THREAT_MODEL, SECURITY))
			for (String id : mentionedIds(read(document)))
				if (!ids.contains(id))
					unmapped.add(document + " mentions " + id + ", which has no row");
		ContractSupport.assertNoViolations("Invariant IDs without a row in " + THREAT_MODEL, unmapped);
	}

	// Positive and negative controls for the citation grammar (M2-10 item 7), on cells whose outcome is known: real
	// classes and test methods resolve, in either tree; a bare method binds to the nearest class before it, the class
	// part of a Class.method included; a missing class, a missing or non-test method, and a bare method with no class
	// before it are each a problem; and tokens that only contain a citation, such as String.contentEquals, are ignored.
	@TestFactory
	@NonNull Stream<@NonNull DynamicTest> theCitationGrammarResolvesExactlyWhatExists() throws IOException {
		Path root = ContractSupport.repositoryRoot();
		List<GrammarCase> cases = List.of(
				new GrammarCase("a class and a bare method of it", "`FrozenLimitsTests` and its `everyApprovedRowIsPinned`",
						List.of("FrozenLimitsTests", "FrozenLimitsTests.everyApprovedRowIsPinned"), 0),
				new GrammarCase("a Class.method citation and a bare method after it",
						"`FrozenLimitsTests.theRegistryHoldsExactlyTheApprovedRowsInOrder` and "
								+ "`zeroIsAllowedForExactlyTheApprovedZeroRows`",
						List.of("FrozenLimitsTests.theRegistryHoldsExactlyTheApprovedRowsInOrder",
								"FrozenLimitsTests.zeroIsAllowedForExactlyTheApprovedZeroRows"), 0),
				new GrammarCase("a qualified class", "`internal.LimitsTests`", List.of("internal.LimitsTests"), 0),
				new GrammarCase("a fuzz target", "`internal.json.JsonCodecFuzzTests`",
						List.of("internal.json.JsonCodecFuzzTests"), 0),
				new GrammarCase("a bare method binds to the nearest class, not an earlier one",
						"`FrozenLimitsTests`, `ThreatModelMapTests` and `everyApprovedRowIsPinned`",
						List.of("FrozenLimitsTests", "ThreatModelMapTests"), 1),
				new GrammarCase("a class that does not exist", "`NoSuchTests`", List.of(), 1),
				new GrammarCase("a qualified class in the wrong package", "`internal.FrozenLimitsTests`", List.of(), 1),
				new GrammarCase("a method that does not exist", "`FrozenLimitsTests.noSuchTest`", List.of(), 1),
				new GrammarCase("a method that is not a test", "`ThreatModelMapTests.invariantRows`", List.of(), 1),
				new GrammarCase("a bare method with no class before it", "`everyApprovedRowIsPinned`", List.of(), 1),
				new GrammarCase("a bare method after a class that does not resolve",
						"`NoSuchTests` and `everyApprovedRowIsPinned`", List.of(), 2),
				new GrammarCase("tokens that are not citations",
						"`Math.random`, `java.util.Random`, `String.contentEquals`, `SecureRandom`, `toString()`, "
								+ "`n_*.json`, `constant-time-comparison`, `<bannedDependencies>` and `pom.xml`",
						List.of(), 0),
				new GrammarCase("text outside backticks", "FrozenLimitsTests and NoSuchTests.method", List.of(), 0));

		TestSources testSources = TestSources.fromCells(root, cases.stream().map(GrammarCase::getCell).toList());
		return cases.stream().map(grammarCase -> DynamicTest.dynamicTest(grammarCase.getName(), () -> {
			CellCheck check = testSources.check(grammarCase.getCell());
			Assertions.assertEquals(grammarCase.getResolved(), check.getResolved(), grammarCase::getCell);
			Assertions.assertEquals(grammarCase.getProblemCount(), check.getProblems().size(),
					() -> grammarCase.getCell() + ": " + check.getProblems());
		}));
	}

	// Controls for the readers: a row is read however its line is spaced, and a row with a stray '|' or without its
	// closing '|' is a problem, never skipped; the SECURITY.md reader takes entries from the "Security Invariants"
	// section only, and reports a list item there that starts with an ID in another form; and every ID mentioned is
	// found, but not one that runs into other text.
	@Test
	void theReadersFindRowsAndEntriesOnlyWhereTheyBelong() {
		List<String> problems = new ArrayList<>();
		List<InvariantRow> rows = invariantRows("""
				| ID | Invariant | Checked by |
				|---|---|---|
				| INV-G1 | One. | `FrozenLimitsTests` |
				| INV-G2 | Two | with a stray pipe. | `FrozenLimitsTests` |
				Text that mentions | INV-G3 | in passing.
				| INV-G4 | Four. | |
				|INV-G5|Five, unspaced.|`FrozenLimitsTests`|
				   | INV-G6 | Six, indented. | `FrozenLimitsTests` |
				| INV-G7 | Seven, unclosed. | `FrozenLimitsTests`
				""", problems);
		Assertions.assertEquals(List.of("INV-G1", "INV-G4", "INV-G5", "INV-G6"), rows.stream().map(InvariantRow::getId)
				.toList());
		Assertions.assertEquals("`FrozenLimitsTests`", rows.get(0).getCheckedBy());
		Assertions.assertEquals("", rows.get(1).getCheckedBy());
		Assertions.assertEquals("`FrozenLimitsTests`", rows.get(2).getCheckedBy());
		Assertions.assertEquals(2, problems.size(), problems::toString);
		Assertions.assertTrue(problems.get(0).contains("INV-G2"), problems::toString);
		Assertions.assertTrue(problems.get(1).contains("line 9"), problems::toString);

		List<String> securityProblems = new ArrayList<>();
		Assertions.assertEquals(List.of("INV-G1", "INV-J1"), securityInvariantIds("""
				# Policy
				- **INV-X1** Before the section.
				## Security Invariants

				Some text that mentions INV-G1.
				- **INV-G1** One.
				  - **INV-G9** An indented line is not an entry.
				- **INV-J1** Two.
				- INV-J2 An entry without emphasis.
				* **INV-J3** An entry with another marker.
				- A list item that mentions INV-J4 later.
				## Next Section
				- INV-X2 After the section.
				""", securityProblems));
		Assertions.assertEquals(2, securityProblems.size(), securityProblems::toString);
		Assertions.assertTrue(securityProblems.get(0).contains("INV-J2"), securityProblems::toString);
		Assertions.assertTrue(securityProblems.get(1).contains("INV-J3"), securityProblems::toString);

		Assertions.assertEquals(List.of("INV-G1", "INV-J9", "INV-C6", "INV-L1"), mentionedIds(
				"INV-G1, (INV-J9), `INV-C6`, **INV-L1**; not INV-G1a, INV-g2, INV-G or XINV-G3."));
	}

	/**
	 * The invariant rows of a threat model's text, in order: the table lines whose first cell starts with
	 * {@code INV-}. A row without its closing {@code |}, or with other than three cells, is reported to
	 * {@code problems} and left out.
	 */
	static @NonNull List<@NonNull InvariantRow> invariantRows(@NonNull String text, @NonNull List<@NonNull String> problems) {
		List<InvariantRow> rows = new ArrayList<>();
		int lineNumber = 0;
		for (String line : text.lines().toList()) {
			++lineNumber;
			String trimmed = line.strip();
			if (!trimmed.startsWith("|") || !trimmed.substring(1).stripLeading().startsWith("INV-"))
				continue;
			if (!trimmed.endsWith("|")) {
				problems.add("line " + lineNumber + ": the row does not end with '|'");
				continue;
			}
			String[] cells = trimmed.substring(1, trimmed.length() - 1).split("\\|", -1);
			if (cells.length != 3) {
				problems.add("line " + lineNumber + " (" + cells[0].strip() + "): " + cells.length
						+ " cells, not 3; a cell may not contain '|'");
				continue;
			}
			rows.add(new InvariantRow(cells[0].strip(), cells[1].strip(), cells[2].strip()));
		}
		return List.copyOf(rows);
	}

	/**
	 * The IDs of the {@code - **INV-…**} entries in the "Security Invariants" section of a SECURITY.md text, from its
	 * heading to the next level-2 heading, in order. A top-level list item there that starts with an ID in another
	 * form is reported to {@code problems} and left out.
	 */
	static @NonNull List<@NonNull String> securityInvariantIds(@NonNull String text, @NonNull List<@NonNull String> problems) {
		List<String> ids = new ArrayList<>();
		boolean inSection = false;
		int lineNumber = 0;
		for (String line : text.lines().toList()) {
			++lineNumber;
			if (line.startsWith("## ")) {
				inSection = line.strip().equals(SECURITY_INVARIANTS_HEADING);
				continue;
			}
			if (!inSection)
				continue;
			Matcher matcher = SECURITY_ENTRY.matcher(line);
			if (matcher.find())
				ids.add(matcher.group(1));
			else if (SECURITY_ITEM_WITH_ID.matcher(line).find())
				problems.add("line " + lineNumber + " (" + line.strip() + "): an invariant entry reads `- **INV-…**`");
		}
		return List.copyOf(ids);
	}

	/**
	 * Every invariant ID a text mentions, in order, each a whole word.
	 */
	static @NonNull List<@NonNull String> mentionedIds(@NonNull String text) {
		List<String> ids = new ArrayList<>();
		Matcher matcher = MENTIONED_ID.matcher(text);
		while (matcher.find())
			ids.add(matcher.group());
		return List.copyOf(ids);
	}

	private static @NonNull List<@NonNull String> artifactProblems(@NonNull Path root, @NonNull InvariantRow row, @NonNull List<@NonNull String> artifacts) {
		List<String> problems = new ArrayList<>();
		Set<String> tokens = new LinkedHashSet<>(backtickedTokens(row.getCheckedBy()));
		for (String artifact : artifacts) {
			if (!tokens.contains(artifact))
				problems.add("the allowlisted artifact `" + artifact + "` is not named");
			Path file = root.resolve(artifact);
			if (!Files.isRegularFile(file)) {
				problems.add("the allowlisted artifact " + artifact + " does not exist");
				continue;
			}
			if (artifact.equals("pom.xml")) {
				if (!tokens.contains(BANNED_DEPENDENCIES_RULE))
					problems.add("the pom.xml evidence does not name `" + BANNED_DEPENDENCIES_RULE + "`");
				try {
					if (!Files.readString(file, StandardCharsets.UTF_8).contains(BANNED_DEPENDENCIES_RULE))
						problems.add("pom.xml has no " + BANNED_DEPENDENCIES_RULE + " rule");
				} catch (IOException e) {
					problems.add("pom.xml cannot be read: " + e.getClass().getName());
				}
			}
		}
		return problems;
	}

	private static @NonNull List<@NonNull String> backtickedTokens(@NonNull String cell) {
		List<String> tokens = new ArrayList<>();
		Matcher matcher = BACKTICKED.matcher(cell);
		while (matcher.find())
			tokens.add(matcher.group(1));
		return tokens;
	}

	private static @NonNull String read(@NonNull String relativePath) throws IOException {
		return Files.readString(ContractSupport.repositoryRoot().resolve(relativePath), StandardCharsets.UTF_8);
	}

	/**
	 * One invariant row: its ID, the invariant and the "Checked by" cell, each stripped.
	 */
	static final class InvariantRow {
		private final String id;
		private final String invariant;
		private final String checkedBy;

		InvariantRow(@NonNull String id, @NonNull String invariant, @NonNull String checkedBy) {
			this.id = id;
			this.invariant = invariant;
			this.checkedBy = checkedBy;
		}

		@NonNull String getId() {
			return this.id;
		}

		@NonNull String getInvariant() {
			return this.invariant;
		}

		@NonNull String getCheckedBy() {
			return this.checkedBy;
		}
	}

	/**
	 * What checking one cell found: the citations that resolved, as {@code Class} or {@code Class.method} (a bare
	 * method written with its class), and the problems.
	 */
	static final class CellCheck {
		private final List<String> resolved;
		private final List<String> problems;

		CellCheck(@NonNull List<@NonNull String> resolved, @NonNull List<@NonNull String> problems) {
			this.resolved = List.copyOf(resolved);
			this.problems = List.copyOf(problems);
		}

		@NonNull List<@NonNull String> getResolved() {
			return this.resolved;
		}

		@NonNull List<@NonNull String> getProblems() {
			return this.problems;
		}
	}

	/**
	 * The test methods of the test classes some cells cite, read once from the test sources with javac's parser.
	 */
	static final class TestSources {
		private final Path root;
		private final Map<String, Optional<Set<String>>> testMethodsByClass;

		private TestSources(@NonNull Path root, @NonNull Map<@NonNull String, @NonNull Optional<@NonNull Set<@NonNull String>>> testMethodsByClass) {
			this.root = root;
			this.testMethodsByClass = Map.copyOf(testMethodsByClass);
		}

		/**
		 * Parses the source of every class the cells cite; a class whose source is missing maps to empty.
		 */
		static @NonNull TestSources fromCells(@NonNull Path root, @NonNull List<@NonNull String> cells) throws IOException {
			Map<String, Path> sources = new LinkedHashMap<>();
			Map<String, Optional<Set<String>>> testMethodsByClass = new LinkedHashMap<>();
			for (String cell : cells) {
				for (String token : backtickedTokens(cell)) {
					Matcher matcher = CITATION.matcher(token);
					if (!matcher.matches() || sources.containsKey(matcher.group(1))
							|| testMethodsByClass.containsKey(matcher.group(1)))
						continue;
					String className = matcher.group(1);
					@Nullable Path source = findSource(root, className);
					if (source == null)
						testMethodsByClass.put(className, Optional.empty());
					else
						sources.put(className, source);
				}
			}
			testMethodsByClass.putAll(parseTestMethods(sources));
			return new TestSources(root, testMethodsByClass);
		}

		/**
		 * Applies the citation grammar to one cell.
		 */
		@NonNull CellCheck check(@NonNull String cell) {
			List<String> resolved = new ArrayList<>();
			List<String> problems = new ArrayList<>();
			@Nullable String nearestClass = null;
			boolean nearestClassResolved = false;

			for (String token : backtickedTokens(cell)) {
				Matcher citation = CITATION.matcher(token);
				if (citation.matches()) {
					nearestClass = citation.group(1);
					@Nullable String method = citation.group(2);
					Optional<Set<String>> testMethods = testMethods(nearestClass);
					nearestClassResolved = testMethods.isPresent();
					if (testMethods.isEmpty()) {
						problems.add("`" + token + "`: no test class " + nearestClass + " under " + TEST_SOURCE_ROOTS);
					} else if (method == null) {
						resolved.add(nearestClass);
					} else if (testMethods.get().contains(method)) {
						resolved.add(nearestClass + "." + method);
					} else {
						problems.add("`" + token + "`: " + method + " is not a test method of " + nearestClass);
					}
				} else if (METHOD.matcher(token).matches()) {
					if (nearestClass == null)
						problems.add("`" + token + "`: a bare method with no class cited before it");
					else if (!nearestClassResolved)
						problems.add("`" + token + "`: a bare method after " + nearestClass + ", which does not resolve");
					else if (testMethods(nearestClass).orElseThrow().contains(token))
						resolved.add(nearestClass + "." + token);
					else
						problems.add("`" + token + "`: " + token + " is not a test method of " + nearestClass);
				}
			}
			return new CellCheck(resolved, problems);
		}

		private @NonNull Optional<@NonNull Set<@NonNull String>> testMethods(@NonNull String className) {
			return Objects.requireNonNull(this.testMethodsByClass.get(className),
					() -> className + " was not read from " + this.root);
		}

		private static @Nullable Path findSource(@NonNull Path root, @NonNull String className) {
			for (String sourceRoot : TEST_SOURCE_ROOTS) {
				Path source = root.resolve(sourceRoot).resolve(className.replace('.', '/') + ".java");
				if (Files.isRegularFile(source))
					return source;
			}
			return null;
		}

		/**
		 * The test methods of each class, by parsing its source file: the methods of the top-level class named like
		 * the file that carry a test annotation. A class with no test method maps to empty.
		 */
		private static @NonNull Map<@NonNull String, @NonNull Optional<@NonNull Set<@NonNull String>>> parseTestMethods(@NonNull Map<@NonNull String, @NonNull Path> sources)
				throws IOException {
			Map<String, Optional<Set<String>>> testMethods = new LinkedHashMap<>();
			if (sources.isEmpty())
				return testMethods;

			JavaCompiler compiler = ToolProvider.getSystemJavaCompiler();
			Assertions.assertNotNull(compiler, "ThreatModelMapTests requires a full JDK (javax.tools.JavaCompiler)");
			DiagnosticCollector<JavaFileObject> diagnostics = new DiagnosticCollector<>();

			try (StandardJavaFileManager fileManager = compiler.getStandardFileManager(diagnostics, Locale.ROOT,
					StandardCharsets.UTF_8)) {
				JavacTask task = (JavacTask) compiler.getTask(null, fileManager, diagnostics, List.of("-proc:none"), null,
						fileManager.getJavaFileObjectsFromPaths(List.copyOf(sources.values())));
				Map<Path, Set<String>> methodsByFile = new LinkedHashMap<>();

				for (CompilationUnitTree compilationUnit : task.parse()) {
					Path file = Path.of(compilationUnit.getSourceFile().toUri()).toAbsolutePath().normalize();
					String simpleName = ContractSupport.fileName(file).replaceFirst("\\.java$", "");
					Set<String> methods = new TreeSet<>();
					for (Tree declaration : compilationUnit.getTypeDecls())
						if (declaration instanceof ClassTree type && type.getSimpleName().contentEquals(simpleName))
							for (Tree member : type.getMembers())
								if (member instanceof MethodTree method && isTestMethod(method))
									methods.add(method.getName().toString());
					methodsByFile.put(file, methods);
				}

				List<String> errors = diagnostics.getDiagnostics().stream()
						.filter(diagnostic -> diagnostic.getKind() == Diagnostic.Kind.ERROR)
						.map(Object::toString)
						.toList();
				Assertions.assertTrue(errors.isEmpty(), () -> "Unable to parse cited test sources:\n"
						+ String.join("\n", errors));

				sources.forEach((className, source) -> {
					Set<String> methods = methodsByFile.getOrDefault(source.toAbsolutePath().normalize(), Set.of());
					testMethods.put(className, methods.isEmpty() ? Optional.empty() : Optional.of(Set.copyOf(methods)));
				});
			}
			return testMethods;
		}

		private static boolean isTestMethod(@NonNull MethodTree method) {
			for (AnnotationTree annotation : method.getModifiers().getAnnotations()) {
				Tree type = annotation.getAnnotationType();
				String simpleName = type instanceof MemberSelectTree memberSelect ? memberSelect.getIdentifier().toString()
						: type instanceof IdentifierTree identifier ? identifier.getName().toString() : "";
				if (TEST_ANNOTATIONS.contains(simpleName))
					return true;
			}
			return false;
		}
	}

	/**
	 * A cell whose outcome is known: the citations it resolves, in order, and how many problems it has.
	 */
	private static final class GrammarCase {
		private final String name;
		private final String cell;
		private final List<String> resolved;
		private final int problemCount;

		private GrammarCase(@NonNull String name, @NonNull String cell, @NonNull List<@NonNull String> resolved, int problemCount) {
			this.name = name;
			this.cell = cell;
			this.resolved = List.copyOf(resolved);
			this.problemCount = problemCount;
		}

		@NonNull String getName() {
			return this.name;
		}

		@NonNull String getCell() {
			return this.cell;
		}

		@NonNull List<@NonNull String> getResolved() {
			return this.resolved;
		}

		int getProblemCount() {
			return this.problemCount;
		}
	}
}
