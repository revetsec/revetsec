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

import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestReporter;
import org.junit.jupiter.api.io.TempDir;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.CountDownLatch;
import java.util.jar.Attributes;
import java.util.jar.JarOutputStream;
import java.util.jar.Manifest;
import java.util.regex.Pattern;

/**
 * Tests {@link ChildJvm} (A-2; M1 plan, open question 6): a child JVM runs a trivial main with the test JVM's class
 * path under Surefire, output and exit codes are captured, the code-source fallback works, class loading can be
 * logged, and a child that outlives its timeout is killed.
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 */
final class ChildJvmTests {
	private static final String MARKER_PROPERTY = "revetsec.child.marker";
	private static final String EXIT_PROPERTY = "revetsec.child.exit";

	@Test
	void runsATrivialMainWithTheTestClassPathAndCapturesItsOutputAndExitCode(TestReporter testReporter)
			throws Exception {
		ChildJvm.Result result = ChildJvm.withMainClass(Echo.class)
				.jvmOptions(List.of("-D" + MARKER_PROPERTY + "=present", "-D" + EXIT_PROPERTY + "=3"))
				.arguments(List.of("one", "two words"))
				.build()
				.run();

		// Open question 6: record which class path Surefire's fork let the child use.
		@Nullable String javaClassPath = System.getProperty("java.class.path");
		testReporter.publishEntry("childJvmClassPathSource", result.getClassPathSource().name());
		testReporter.publishEntry("javaClassPathEntries", String.valueOf(javaClassPath == null ? 0
				: Pattern.compile(Pattern.quote(File.pathSeparator)).split(javaClassPath, -1).length));
		testReporter.publishEntry("javaClassPathLooksLikeSurefireBooter", String.valueOf(javaClassPath != null
				&& javaClassPath.contains("surefirebooter")));

		Assertions.assertFalse(result.isTimedOut(), result::toString);
		Assertions.assertEquals(3, result.getExitCode(), result::toString);
		Assertions.assertEquals("argument:one\nargument:two words\n", normalizeLineEnds(result.getStandardOutput()),
				result::toString);
		Assertions.assertEquals("stderr:present\n", normalizeLineEnds(result.getStandardErrorWithoutJvmNotices()),
				result::toString);
		Assertions.assertTrue(result.getLoadedClasses().isEmpty(), "class-load logging was off");
		Assertions.assertTrue(result.getCommand().contains(Echo.class.getName()), result::toString);
	}

	@Test
	void fallsBackToAClassPathBuiltFromCodeSources() throws Exception {
		ChildJvm.Result result = ChildJvm.withMainClass(Echo.class)
				.classPathSource(ChildJvm.ClassPathSource.CODE_SOURCES)
				.arguments(List.of("fallback"))
				.build()
				.run();

		Assertions.assertEquals(ChildJvm.ClassPathSource.CODE_SOURCES, result.getClassPathSource());
		Assertions.assertEquals(0, result.getExitCode(), result::toString);
		Assertions.assertEquals("argument:fallback\n", normalizeLineEnds(result.getStandardOutput()),
				result::toString);

		String classPath = result.getCommand().get(result.getCommand().indexOf("-cp") + 1);
		Assertions.assertTrue(classPath.contains(ChildJvm.codeSource(ChildJvmTests.class).toString()), classPath);
		Assertions.assertTrue(classPath.contains(ChildJvm.codeSource(Assertions.class).toString()), classPath);
	}

	@Test
	void logsEveryLoadedClassWhenAskedSoATestCanProveAClassWasNeverLoaded() throws Exception {
		ChildJvm.Result result = ChildJvm.withMainClass(Echo.class)
				.classLoadLogging(true)
				.build()
				.run();

		Assertions.assertEquals(0, result.getExitCode(), result::toString);
		Set<String> loadedClasses = result.getLoadedClasses();
		Assertions.assertTrue(loadedClasses.contains("java.lang.Object"), () -> "loaded " + loadedClasses.size());
		Assertions.assertTrue(loadedClasses.contains(Echo.class.getName()), () -> "loaded " + loadedClasses.size());
		// Exit criterion 14 asserts this for Revetsec builders; a trivial main never loads the JDK HTTP client.
		Assertions.assertFalse(loadedClasses.contains("jdk.internal.net.http.HttpClientImpl"));
		Assertions.assertFalse(result.getStandardOutput().contains("source:"), "the log goes to its own file");
	}

	@Test
	void killsAChildThatOutlivesItsTimeout() throws Exception {
		Duration timeout = Duration.ofSeconds(1);
		ChildJvm.Result result = ChildJvm.withMainClass(Hang.class)
				.timeout(timeout)
				.build()
				.run();

		Assertions.assertTrue(result.isTimedOut(), result::toString);
		Assertions.assertNull(result.getExitCode());
		Assertions.assertTrue(result.getElapsed().compareTo(timeout) >= 0, result::toString);
		Assertions.assertTrue(result.getElapsed().compareTo(timeout.plus(ChildJvm.KILL_TIMEOUT)) < 0,
				result::toString);
	}

	@Test
	void reachesTheEntriesOfAManifestOnlyJarTransitively(@TempDir Path directory) throws IOException {
		// Surefire's default fork puts one JAR on java.class.path whose manifest lists the real class path.
		Path classes = Files.createDirectories(directory.resolve("classes"));
		Path transitive = Files.createDirectories(directory.resolve("transitive"));
		Path library = Files.createDirectories(directory.resolve("lib dir")).resolve("library.jar");
		writeJar(library, "../transitive/");
		Path absolute = Files.createDirectories(directory.resolve("absolute"));
		Path booter = directory.resolve("booter.jar");
		writeJar(booter, "classes/ " + "lib%20dir/library.jar " + absolute.toUri() + " missing/");

		Set<Path> reachable = ChildJvm.reachableLocations(booter.toString());

		Assertions.assertTrue(reachable.contains(booter.toAbsolutePath().normalize()), reachable::toString);
		Assertions.assertTrue(reachable.contains(classes.toAbsolutePath().normalize()), reachable::toString);
		Assertions.assertTrue(reachable.contains(library.toAbsolutePath().normalize()), reachable::toString);
		Assertions.assertTrue(reachable.contains(absolute.toAbsolutePath().normalize()), reachable::toString);
		Assertions.assertTrue(reachable.contains(transitive.toAbsolutePath().normalize()), reachable::toString);
		Assertions.assertFalse(reachable.contains(directory.resolve("missing").toAbsolutePath().normalize()),
				"a location that does not exist is not reachable");
	}

	@Test
	void automaticResolutionInThisJvmUsesJavaClassPathExactlyWhenItReachesEveryRequiredLocation() {
		// Open question 6: Surefire 3.6.0 launches its fork from a manifest-only surefirebooter JAR but sets
		// java.class.path to the real entries (observed on 17, 21, 25 and 27), so this is JAVA_CLASS_PATH under Maven;
		// the check holds whichever source a runner leads to.
		List<Class<?>> codeSourceClasses = List.of(Assertions.class);
		String javaClassPath = System.getProperty("java.class.path", "");
		boolean reachesEverything = ChildJvm.reachableLocations(javaClassPath)
				.containsAll(ChildJvm.requiredLocations(Echo.class, codeSourceClasses));

		ChildJvm.ResolvedClassPath automatic = ChildJvm.resolveClassPath(Echo.class, codeSourceClasses, null);

		Assertions.assertEquals(reachesEverything ? ChildJvm.ClassPathSource.JAVA_CLASS_PATH
				: ChildJvm.ClassPathSource.CODE_SOURCES, automatic.getSource(), javaClassPath);
		if (reachesEverything)
			Assertions.assertEquals(javaClassPath, automatic.getValue());
		Assertions.assertTrue(ChildJvm.reachableLocations(automatic.getValue())
				.containsAll(ChildJvm.requiredLocations(Echo.class, codeSourceClasses)), automatic::getValue);
	}

	@Test
	void fallsBackToCodeSourcesWhenJavaClassPathMissesARequiredLocation() {
		Path testClasses = ChildJvm.codeSource(ChildJvmTests.class);
		Path mainClasses = Objects.requireNonNull(ChildJvm.codeSourceOfResource(ChildJvm.MAIN_CLASSES_MARKER),
				"Revetsec's main classes are on the test class path");
		Assertions.assertNotEquals(testClasses, mainClasses);
		// The test classes alone do not reach Revetsec's main classes, and a missing or blank value reaches nothing.
		List<@Nullable String> javaClassPaths = Arrays.asList(testClasses.toString(), "", " ", null);

		for (@Nullable String javaClassPath : javaClassPaths) {
			ChildJvm.ResolvedClassPath automatic = ChildJvm.resolveClassPath(Echo.class, List.of(), null,
					javaClassPath);
			Assertions.assertEquals(ChildJvm.ClassPathSource.CODE_SOURCES, automatic.getSource(),
					String.valueOf(javaClassPath));
			Set<Path> reachable = ChildJvm.reachableLocations(automatic.getValue());
			Assertions.assertTrue(reachable.contains(testClasses), automatic::getValue);
			Assertions.assertTrue(reachable.contains(mainClasses), automatic::getValue);
			Assertions.assertThrows(IllegalStateException.class, () -> ChildJvm.resolveClassPath(Echo.class,
					List.of(), ChildJvm.ClassPathSource.JAVA_CLASS_PATH, javaClassPath));
		}
	}

	@Test
	void keepsAManifestOnlyJavaClassPathThatReachesEveryRequiredLocation(@TempDir Path directory) throws IOException {
		// Surefire's manifest-only JAR: java.class.path is one JAR whose Class-Path lists the real entries.
		Set<Path> required = ChildJvm.requiredLocations(Echo.class, List.of());
		StringBuilder manifestClassPath = new StringBuilder();
		for (Path location : required)
			manifestClassPath.append(location.toUri()).append(' ');
		Path booter = directory.resolve("surefirebooter.jar");
		writeJar(booter, manifestClassPath.toString().strip());

		ChildJvm.ResolvedClassPath automatic = ChildJvm.resolveClassPath(Echo.class, List.of(), null,
				booter.toString());
		ChildJvm.ResolvedClassPath forced = ChildJvm.resolveClassPath(Echo.class, List.of(),
				ChildJvm.ClassPathSource.JAVA_CLASS_PATH, booter.toString());

		Assertions.assertEquals(ChildJvm.ClassPathSource.JAVA_CLASS_PATH, automatic.getSource());
		Assertions.assertEquals(booter.toString(), automatic.getValue());
		Assertions.assertEquals(booter.toString(), forced.getValue());
		Assertions.assertEquals(ChildJvm.ClassPathSource.CODE_SOURCES, ChildJvm.resolveClassPath(Echo.class,
				List.of(), ChildJvm.ClassPathSource.CODE_SOURCES, booter.toString()).getSource());
	}

	@Test
	void aCodeSourcesChildCanUseJunitAssertionsIncludingAFailingOne() throws Exception {
		// A failing assertion needs JUnit Platform Commons (its message) and opentest4j (its type) at run time.
		ChildJvm.Builder builder = ChildJvm.withMainClass(AssertingMain.class)
				.classPathSource(ChildJvm.ClassPathSource.CODE_SOURCES);

		ChildJvm.Result passing = builder.arguments(List.of("expected")).build().run();
		ChildJvm.Result failing = builder.arguments(List.of("actual")).build().run();

		Assertions.assertEquals(0, passing.getExitCode(), passing::toString);
		Assertions.assertEquals(1, failing.getExitCode(), failing::toString);
		Assertions.assertTrue(failing.getStandardError().contains(
				"org.opentest4j.AssertionFailedError: expected: <expected> but was: <actual>"), failing::toString);
		Assertions.assertFalse(failing.getStandardError().contains("NoClassDefFoundError"), failing::toString);
	}

	@Test
	void rejectsATimeoutThatIsNotPositive() {
		ChildJvm.Builder builder = ChildJvm.withMainClass(Echo.class);
		Assertions.assertThrows(IllegalArgumentException.class, () -> builder.timeout(Duration.ZERO));
		Assertions.assertThrows(IllegalArgumentException.class, () -> builder.timeout(Duration.ofSeconds(-1)));
	}

	private static void writeJar(Path jar, String classPath) throws IOException {
		Manifest manifest = new Manifest();
		manifest.getMainAttributes().put(Attributes.Name.MANIFEST_VERSION, "1.0");
		if (!classPath.isEmpty())
			manifest.getMainAttributes().put(Attributes.Name.CLASS_PATH, classPath);
		try (JarOutputStream jarOutputStream = new JarOutputStream(Files.newOutputStream(jar), manifest)) {
			jarOutputStream.flush();
		}
	}

	private static String normalizeLineEnds(String text) {
		return text.replace("\r\n", "\n");
	}

	/**
	 * A child main: prints each argument, then {@value #MARKER_PROPERTY} to standard error, then exits with
	 * {@value #EXIT_PROPERTY} (0 by default).
	 */
	public static final class Echo {
		private Echo() {
			// Only main runs.
		}

		public static void main(String[] arguments) {
			for (String argument : arguments)
				System.out.println("argument:" + argument);
			System.err.println("stderr:" + System.getProperty(MARKER_PROPERTY, "absent"));
			System.out.flush();
			System.err.flush();
			System.exit(Integer.getInteger(EXIT_PROPERTY, 0));
		}
	}

	/**
	 * A child main that asserts, with JUnit, that its first argument is {@code expected}.
	 */
	public static final class AssertingMain {
		private AssertingMain() {
			// Only main runs.
		}

		public static void main(String[] arguments) {
			Assertions.assertEquals("expected", arguments[0]);
		}
	}

	/**
	 * A child main that waits forever without sleeping, so only the timeout ends it.
	 */
	public static final class Hang {
		private Hang() {
			// Only main runs.
		}

		public static void main(String[] arguments) throws InterruptedException {
			new CountDownLatch(1).await();
		}
	}
}
