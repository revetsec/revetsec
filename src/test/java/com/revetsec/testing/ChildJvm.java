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

import org.jspecify.annotations.Nullable;

import javax.annotation.concurrent.Immutable;
import javax.annotation.concurrent.NotThreadSafe;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.InvalidPathException;
import java.nio.file.Path;
import java.security.CodeSource;
import java.time.Duration;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import java.util.jar.Attributes;
import java.util.jar.JarFile;
import java.util.jar.Manifest;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import static java.util.Objects.requireNonNull;

/**
 * Runs a main class in a child JVM (plan 14.1 as amended by A-2), for tests that need a fresh JVM: JVM-global
 * startup failures, class-loading assertions and thread counts (exit criteria 13 and 14).
 * <p>
 * The child uses the same {@code java.home} and the same class path as the test JVM, with the JVM options and
 * arguments the test gives. Its standard output and standard error are captured to temporary files, so a chatty
 * child can never block on a full pipe, and read back (at most {@value #MAXIMUM_CAPTURED_BYTES} bytes each) once it
 * exits. Its standard input is closed. A child still running at the timeout is killed and reported as timed out.
 * The environment is inherited, so a {@code JAVA_TOOL_OPTIONS} locale leg reaches the child too (and the JVM notes
 * it on standard error; see {@link Result#getStandardErrorWithoutJvmNotices()}).
 * <p>
 * <strong>Class path</strong> (M1 plan, open question 6). By default ({@link ClassPathSource} left unset), the child
 * gets {@code java.class.path} unchanged if it reaches every required location: the main class's code source, the
 * code sources of the classes given to {@link Builder#codeSourceClasses(List)}, the test classes and Revetsec's main
 * classes. Surefire's default manifest-only JAR is followed through its {@code Class-Path} manifest attribute for this
 * check, as the child JVM itself would follow it. Otherwise the child gets a class path built from those code sources
 * plus the JARs JUnit's assertions need at run time (the Jupiter API, JUnit Platform Commons and opentest4j), if
 * present ({@link ClassPathSource#CODE_SOURCES}).
 * {@link Result#getClassPathSource()} says which was used; a test may also force either one.
 * <p>
 * <strong>Class loading.</strong> With {@link Builder#classLoadLogging(Boolean)}, the child runs with
 * {@code -Xlog:class+load=info} written to a temporary file, and {@link Result#getLoadedClasses()} returns the binary
 * name of every class it loaded, so a test can assert that a class was never loaded.
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 */
@Immutable
public final class ChildJvm {
	/**
	 * How long {@link #run()} waits for the child unless {@link Builder#timeout(Duration)} says otherwise.
	 */
	public static final Duration DEFAULT_TIMEOUT = Duration.ofSeconds(60);

	/**
	 * The most bytes of standard output, and separately of standard error, that a {@link Result} keeps.
	 */
	public static final int MAXIMUM_CAPTURED_BYTES = 16 * 1024 * 1024;

	/**
	 * How long {@link #run()} waits for a killed child to exit.
	 */
	static final Duration KILL_TIMEOUT = Duration.ofSeconds(10);

	/**
	 * A class file that exists only in Revetsec's main output ({@code target/classes}), used to find that directory.
	 */
	static final String MAIN_CLASSES_MARKER = "com/revetsec/package-info.class";

	/**
	 * Class files whose code sources join a {@link ClassPathSource#CODE_SOURCES} class path when present, so a child
	 * main can use JUnit's assertions: a failing assertion builds its message with JUnit Platform Commons'
	 * {@code StringUtils} and throws opentest4j's {@code AssertionFailedError}.
	 */
	static final List<String> SUPPORT_CLASS_FILES = List.of("org/junit/jupiter/api/Assertions.class",
			"org/junit/platform/commons/util/StringUtils.class", "org/opentest4j/AssertionFailedError.class");

	private static final Pattern PATH_SEPARATOR = Pattern.compile(Pattern.quote(File.pathSeparator));
	private static final Pattern WHITESPACE = Pattern.compile("\\s+");
	private static final String JVM_NOTICE_PREFIX_PICKED_UP = "Picked up ";
	private static final String JVM_NOTICE_PREFIX_NOTE = "NOTE: Picked up ";

	/**
	 * Where the child's class path comes from.
	 */
	@Immutable
	public enum ClassPathSource {
		/**
		 * The test JVM's {@code java.class.path}, unchanged (Surefire's manifest-only JAR included).
		 */
		JAVA_CLASS_PATH,
		/**
		 * A class path built from the code sources of the main class, the classes the test names, the test classes,
		 * Revetsec's main classes, and what JUnit's assertions need at run time (the Jupiter API, JUnit Platform
		 * Commons and opentest4j).
		 */
		CODE_SOURCES
	}

	private final Class<?> mainClass;
	private final List<String> arguments;
	private final List<String> jvmOptions;
	private final Boolean classLoadLogging;
	private final Duration timeout;
	private final @Nullable ClassPathSource classPathSource;
	private final List<Class<?>> codeSourceClasses;

	private ChildJvm(@NonNull Builder builder) {
		this.mainClass = builder.mainClass;
		this.arguments = builder.arguments;
		this.jvmOptions = builder.jvmOptions;
		this.classLoadLogging = builder.classLoadLogging;
		this.timeout = builder.timeout;
		this.classPathSource = builder.classPathSource;
		this.codeSourceClasses = builder.codeSourceClasses;
	}

	/**
	 * Starts configuring a child JVM that runs {@code mainClass}'s {@code public static void main(String[])}.
	 *
	 * @param mainClass the class whose {@code main} the child runs; a nested class works
	 * @return a new builder
	 */
	public static @NonNull Builder withMainClass(@NonNull Class<?> mainClass) {
		return new Builder(mainClass);
	}

	/**
	 * Starts the child, waits for it to exit or for the timeout (then kills it), and collects its output.
	 *
	 * @return what the child did
	 * @throws IOException if the child cannot be started or its output cannot be read
	 * @throws InterruptedException if this thread is interrupted while waiting; the child is killed first
	 */
	public @NonNull Result run() throws IOException, InterruptedException {
		ResolvedClassPath classPath = resolveClassPath(this.mainClass, this.codeSourceClasses, this.classPathSource);
		Path directory = Files.createTempDirectory("revetsec-child-jvm-");
		try {
			Path standardOutput = directory.resolve("stdout.txt");
			Path standardError = directory.resolve("stderr.txt");
			Path classLoadLog = directory.resolve("class-load.log");

			List<String> command = new ArrayList<>();
			command.add(javaExecutable().toString());
			command.addAll(this.jvmOptions);
			if (this.classLoadLogging)
				command.add("-Xlog:class+load=info:file=\"" + classLoadLog + "\":none:filecount=0");
			command.add("-cp");
			command.add(classPath.getValue());
			command.add(this.mainClass.getName());
			command.addAll(this.arguments);

			long started = System.nanoTime();
			Process process = new ProcessBuilder(command)
					.redirectOutput(standardOutput.toFile())
					.redirectError(standardError.toFile())
					.start();
			boolean exited;
			try {
				process.getOutputStream().close();
				exited = process.waitFor(this.timeout.toNanos(), TimeUnit.NANOSECONDS);
			} catch (IOException | InterruptedException | RuntimeException e) {
				process.destroyForcibly();
				throw e;
			}
			if (!exited) {
				process.destroyForcibly();
				if (!process.waitFor(KILL_TIMEOUT.toNanos(), TimeUnit.NANOSECONDS))
					throw new IOException("The child JVM did not exit within " + KILL_TIMEOUT + " of being killed");
			}
			Duration elapsed = Duration.ofNanos(System.nanoTime() - started);

			Set<String> loadedClasses = this.classLoadLogging && Files.isRegularFile(classLoadLog)
					? loadedClasses(classLoadLog) : Set.of();
			return new Result(List.copyOf(command), classPath.getSource(), exited ? process.exitValue() : null,
					readCapped(standardOutput), readCapped(standardError), loadedClasses, elapsed);
		} finally {
			deleteRecursively(directory);
		}
	}

	/**
	 * Resolves the class path for a child that runs {@code mainClass}, from this JVM's {@code java.class.path} (see
	 * the class documentation).
	 *
	 * @throws IllegalStateException if {@code requested} is {@link ClassPathSource#JAVA_CLASS_PATH} and
	 * {@code java.class.path} does not reach every required location
	 */
	static @NonNull ResolvedClassPath resolveClassPath(@NonNull Class<?> mainClass, @NonNull List<@NonNull Class<?>> codeSourceClasses,
			@Nullable ClassPathSource requested) {
		return resolveClassPath(mainClass, codeSourceClasses, requested, System.getProperty("java.class.path"));
	}

	/**
	 * Resolves the class path for a child that runs {@code mainClass}, given the value of {@code java.class.path}, so
	 * tests can check the fallback decision without changing the system property.
	 *
	 * @throws IllegalStateException if {@code requested} is {@link ClassPathSource#JAVA_CLASS_PATH} and
	 * {@code javaClassPath} does not reach every required location
	 */
	static @NonNull ResolvedClassPath resolveClassPath(@NonNull Class<?> mainClass, @NonNull List<@NonNull Class<?>> codeSourceClasses,
			@Nullable ClassPathSource requested, @Nullable String javaClassPath) {
		Set<Path> required = requiredLocations(mainClass, codeSourceClasses);

		if (requested != ClassPathSource.CODE_SOURCES) {
			if (javaClassPath != null && !javaClassPath.isBlank()
					&& reachableLocations(javaClassPath).containsAll(required))
				return new ResolvedClassPath(ClassPathSource.JAVA_CLASS_PATH, javaClassPath);
			if (requested == ClassPathSource.JAVA_CLASS_PATH)
				throw new IllegalStateException("java.class.path does not reach every required location " + required
						+ ": " + javaClassPath);
		}

		Set<Path> locations = new LinkedHashSet<>(required);
		for (String supportClassFile : SUPPORT_CLASS_FILES) {
			@Nullable Path location = codeSourceOfResource(supportClassFile);
			if (location != null)
				locations.add(location);
		}
		return new ResolvedClassPath(ClassPathSource.CODE_SOURCES, locations.stream()
				.map(Path::toString)
				.collect(Collectors.joining(File.pathSeparator)));
	}

	/**
	 * The locations a child that runs {@code mainClass} needs: the code sources of {@code mainClass} and of
	 * {@code codeSourceClasses}, the test classes (this class's code source) and Revetsec's main classes.
	 */
	static @NonNull Set<@NonNull Path> requiredLocations(@NonNull Class<?> mainClass, @NonNull List<@NonNull Class<?>> codeSourceClasses) {
		Set<Path> required = new LinkedHashSet<>();
		required.add(codeSource(mainClass));
		for (Class<?> type : codeSourceClasses)
			required.add(codeSource(type));
		required.add(codeSource(ChildJvm.class));
		@Nullable Path mainClasses = codeSourceOfResource(MAIN_CLASSES_MARKER);
		if (mainClasses != null)
			required.add(mainClasses);
		return required;
	}

	/**
	 * Every location a JVM started with {@code -cp classPath} can load from: each entry, plus, for each JAR, the
	 * entries of its {@code Class-Path} manifest attribute, followed transitively.
	 */
	static @NonNull Set<@NonNull Path> reachableLocations(@NonNull String classPath) {
		Set<Path> reachable = new LinkedHashSet<>();
		Deque<Path> pending = new ArrayDeque<>();
		for (String entry : PATH_SEPARATOR.split(classPath, -1)) {
			@Nullable Path location = entry.isEmpty() ? null : classPathEntry(entry);
			if (location != null)
				pending.add(location);
		}
		while (!pending.isEmpty()) {
			Path location = pending.removeFirst();
			if (!Files.exists(location) || !reachable.add(location))
				continue;
			if (Files.isRegularFile(location))
				pending.addAll(manifestClassPath(location));
		}
		return reachable;
	}

	private static @NonNull List<@NonNull Path> manifestClassPath(@NonNull Path jar) {
		List<Path> entries = new ArrayList<>();
		try (JarFile jarFile = new JarFile(jar.toFile())) {
			@Nullable Manifest manifest = jarFile.getManifest();
			if (manifest == null)
				return entries;
			@Nullable String classPath = manifest.getMainAttributes().getValue(Attributes.Name.CLASS_PATH);
			if (classPath == null)
				return entries;
			URI base = jar.toUri();
			for (String entry : WHITESPACE.split(classPath.strip(), -1)) {
				@Nullable Path location = entry.isEmpty() ? null : manifestClassPathEntry(base, entry);
				if (location != null)
					entries.add(location);
			}
		} catch (IOException e) {
			// Not a JAR the JVM could read either, so it adds nothing reachable.
			entries.clear();
		}
		return entries;
	}

	/**
	 * A {@code java.class.path} entry as an absolute path, or {@code null} if it is not a usable path (the JVM skips
	 * such an entry, and so does this check).
	 */
	private static @Nullable Path classPathEntry(@NonNull String entry) {
		try {
			return Path.of(entry).toAbsolutePath().normalize();
		} catch (InvalidPathException e) {
			return null;
		}
	}

	/**
	 * A manifest {@code Class-Path} entry (a URL, relative to the JAR's own) as an absolute path, or {@code null} if it
	 * does not parse or is not a local file (the JVM ignores such an entry, and so does this check).
	 */
	private static @Nullable Path manifestClassPathEntry(@NonNull URI jar, @NonNull String entry) {
		try {
			URI resolved = jar.resolve(new URI(entry));
			return "file".equals(resolved.getScheme()) ? Path.of(resolved).toAbsolutePath().normalize() : null;
		} catch (URISyntaxException | IllegalArgumentException e) {
			return null;
		}
	}

	/**
	 * The directory or JAR that {@code type} was loaded from.
	 */
	static @NonNull Path codeSource(@NonNull Class<?> type) {
		@Nullable CodeSource codeSource = type.getProtectionDomain().getCodeSource();
		@Nullable URL location = codeSource == null ? null : codeSource.getLocation();
		if (location == null)
			throw new IllegalArgumentException(type.getName() + " has no code source (a JDK class?)");
		try {
			return Path.of(location.toURI()).toAbsolutePath().normalize();
		} catch (URISyntaxException | IllegalArgumentException e) {
			throw new IllegalArgumentException("Unable to use the code source of " + type.getName() + ": " + location,
					e);
		}
	}

	/**
	 * The directory or JAR that holds the class-path resource {@code resourceName}, or {@code null} if it is not on
	 * the class path.
	 */
	static @Nullable Path codeSourceOfResource(@NonNull String resourceName) {
		@Nullable ClassLoader classLoader = ChildJvm.class.getClassLoader();
		@Nullable URL url = classLoader == null ? null : classLoader.getResource(resourceName);
		if (url == null)
			return null;
		try {
			if ("file".equals(url.getProtocol())) {
				Path root = Path.of(url.toURI());
				for (long depth = resourceName.chars().filter(character -> character == '/').count() + 1; depth > 0;
						--depth)
					root = requireNonNull(root.getParent());
				return root.toAbsolutePath().normalize();
			}
			if ("jar".equals(url.getProtocol())) {
				String spec = url.toString().substring("jar:".length());
				int separator = spec.indexOf("!/");
				URI jar = new URI(separator < 0 ? spec : spec.substring(0, separator));
				return Path.of(jar).toAbsolutePath().normalize();
			}
		} catch (URISyntaxException | IllegalArgumentException e) {
			return null;
		}
		return null;
	}

	private static @NonNull Path javaExecutable() {
		@Nullable String javaHome = System.getProperty("java.home");
		if (javaHome == null)
			throw new IllegalStateException("java.home is not set");
		@Nullable String osName = System.getProperty("os.name");
		boolean windows = osName != null && osName.toLowerCase(Locale.ROOT).startsWith("windows");
		return Path.of(javaHome, "bin", windows ? "java.exe" : "java");
	}

	private static @NonNull Set<@NonNull String> loadedClasses(@NonNull Path classLoadLog) throws IOException {
		// With the "none" decorator each line is "<binary name> source: <where>".
		Set<String> loadedClasses = new LinkedHashSet<>();
		for (String line : Files.readAllLines(classLoadLog, StandardCharsets.UTF_8)) {
			int space = line.indexOf(' ');
			String name = space < 0 ? line.strip() : line.substring(0, space);
			if (!name.isEmpty())
				loadedClasses.add(name);
		}
		return Set.copyOf(loadedClasses);
	}

	private static @NonNull String readCapped(@NonNull Path file) throws IOException {
		try (InputStream inputStream = Files.newInputStream(file)) {
			return new String(inputStream.readNBytes(MAXIMUM_CAPTURED_BYTES), StandardCharsets.UTF_8);
		}
	}

	/**
	 * Deletes the capture directory, best effort: a failure here must not hide the run's own outcome, and a leftover
	 * directory in the temporary area is harmless.
	 */
	private static void deleteRecursively(@NonNull Path directory) {
		try (var paths = Files.walk(directory)) {
			for (Path path : paths.sorted((first, second) -> second.getNameCount() - first.getNameCount()).toList())
				Files.deleteIfExists(path);
		} catch (IOException | RuntimeException e) {
			directory.toFile().deleteOnExit();
		}
	}

	/**
	 * A resolved class path and where it came from.
	 */
	@Immutable
	static final class ResolvedClassPath {
		private final ClassPathSource source;
		private final String value;

		ResolvedClassPath(@NonNull ClassPathSource source, @NonNull String value) {
			this.source = source;
			this.value = value;
		}

		@NonNull ClassPathSource getSource() {
			return this.source;
		}

		@NonNull String getValue() {
			return this.value;
		}
	}

	/**
	 * Configures a {@link ChildJvm}. Collection setters replace the previous value; {@code null} restores the default.
	 */
	@NotThreadSafe
	public static final class Builder {
		private final Class<?> mainClass;
		private List<String> arguments = List.of();
		private List<String> jvmOptions = List.of();
		private Boolean classLoadLogging = false;
		private Duration timeout = DEFAULT_TIMEOUT;
		private @Nullable ClassPathSource classPathSource;
		private List<Class<?>> codeSourceClasses = List.of();

		private Builder(@NonNull Class<?> mainClass) {
			this.mainClass = requireNonNull(mainClass);
		}

		/**
		 * The arguments passed to {@code main}.
		 *
		 * @param arguments the arguments, or {@code null} for none
		 * @return this builder
		 */
		public @NonNull Builder arguments(@Nullable List<@NonNull String> arguments) {
			this.arguments = arguments == null ? List.of() : List.copyOf(arguments);
			return this;
		}

		/**
		 * JVM options placed before the main class, such as {@code -Djavax.net.ssl.keyStore=/nonexistent}.
		 *
		 * @param jvmOptions the options, or {@code null} for none
		 * @return this builder
		 */
		public @NonNull Builder jvmOptions(@Nullable List<@NonNull String> jvmOptions) {
			this.jvmOptions = jvmOptions == null ? List.of() : List.copyOf(jvmOptions);
			return this;
		}

		/**
		 * Whether to record every loaded class (see {@link Result#getLoadedClasses()}).
		 *
		 * @param classLoadLogging {@code true} to log class loading, or {@code null} for the default, {@code false}
		 * @return this builder
		 */
		public @NonNull Builder classLoadLogging(@Nullable Boolean classLoadLogging) {
			this.classLoadLogging = classLoadLogging == null ? Boolean.FALSE : classLoadLogging;
			return this;
		}

		/**
		 * How long to wait for the child before killing it.
		 *
		 * @param timeout a positive duration, or {@code null} for {@link #DEFAULT_TIMEOUT}
		 * @return this builder
		 * @throws IllegalArgumentException if {@code timeout} is zero or negative
		 */
		public @NonNull Builder timeout(@Nullable Duration timeout) {
			if (timeout != null && (timeout.isZero() || timeout.isNegative()))
				throw new IllegalArgumentException("The timeout must be positive: " + timeout);
			this.timeout = timeout == null ? DEFAULT_TIMEOUT : timeout;
			return this;
		}

		/**
		 * Forces where the class path comes from.
		 *
		 * @param classPathSource the source, or {@code null} to choose automatically (see {@link ChildJvm})
		 * @return this builder
		 */
		public @NonNull Builder classPathSource(@Nullable ClassPathSource classPathSource) {
			this.classPathSource = classPathSource;
			return this;
		}

		/**
		 * Classes whose code sources the child needs besides the main class, the test classes and Revetsec's main
		 * classes. Automatic resolution checks that {@code java.class.path} reaches them, and a
		 * {@link ClassPathSource#CODE_SOURCES} class path includes them.
		 *
		 * @param codeSourceClasses the classes, or {@code null} for none
		 * @return this builder
		 */
		public @NonNull Builder codeSourceClasses(@Nullable List<@NonNull Class<?>> codeSourceClasses) {
			this.codeSourceClasses = codeSourceClasses == null ? List.of() : List.copyOf(codeSourceClasses);
			return this;
		}

		/**
		 * Builds the configuration; nothing starts until {@link ChildJvm#run()}.
		 *
		 * @return a new child JVM configuration
		 */
		public @NonNull ChildJvm build() {
			return new ChildJvm(this);
		}
	}

	/**
	 * What a child JVM did.
	 */
	@Immutable
	public static final class Result {
		private final List<String> command;
		private final ClassPathSource classPathSource;
		private final @Nullable Integer exitCode;
		private final String standardOutput;
		private final String standardError;
		private final Set<String> loadedClasses;
		private final Duration elapsed;

		private Result(@NonNull List<@NonNull String> command, @NonNull ClassPathSource classPathSource, @Nullable Integer exitCode,
				@NonNull String standardOutput, @NonNull String standardError, @NonNull Set<@NonNull String> loadedClasses, @NonNull Duration elapsed) {
			this.command = command;
			this.classPathSource = classPathSource;
			this.exitCode = exitCode;
			this.standardOutput = standardOutput;
			this.standardError = standardError;
			this.loadedClasses = loadedClasses;
			this.elapsed = elapsed;
		}

		/**
		 * The command line that started the child.
		 *
		 * @return the command and its arguments
		 */
		public @NonNull List<@NonNull String> getCommand() {
			return this.command;
		}

		/**
		 * Where the child's class path came from.
		 *
		 * @return the class path source
		 */
		public @NonNull ClassPathSource getClassPathSource() {
			return this.classPathSource;
		}

		/**
		 * Whether the child was still running at the timeout and was killed.
		 *
		 * @return {@code true} if the child timed out
		 */
		public @NonNull Boolean isTimedOut() {
			return this.exitCode == null;
		}

		/**
		 * The child's exit code.
		 *
		 * @return the exit code, or {@code null} if the child timed out and was killed
		 */
		public @Nullable Integer getExitCode() {
			return this.exitCode;
		}

		/**
		 * The child's standard output, decoded as UTF-8.
		 *
		 * @return the output, at most {@value ChildJvm#MAXIMUM_CAPTURED_BYTES} bytes of it
		 */
		public @NonNull String getStandardOutput() {
			return this.standardOutput;
		}

		/**
		 * The child's standard error, decoded as UTF-8.
		 *
		 * @return the output, at most {@value ChildJvm#MAXIMUM_CAPTURED_BYTES} bytes of it
		 */
		public @NonNull String getStandardError() {
			return this.standardError;
		}

		/**
		 * The child's standard error without the lines the launcher and JVM print about inherited option variables
		 * ({@code Picked up JAVA_TOOL_OPTIONS: ...}, {@code NOTE: Picked up JDK_JAVA_OPTIONS: ...}), which the
		 * locale legs cause.
		 *
		 * @return the remaining standard error
		 */
		public @NonNull String getStandardErrorWithoutJvmNotices() {
			return this.standardError.lines()
					.filter(line -> !line.startsWith(JVM_NOTICE_PREFIX_PICKED_UP)
							&& !line.startsWith(JVM_NOTICE_PREFIX_NOTE))
					.map(line -> line + "\n")
					.collect(Collectors.joining());
		}

		/**
		 * The binary name of every class the child loaded, if class-load logging was on.
		 *
		 * @return the class names; empty if logging was off
		 */
		public @NonNull Set<@NonNull String> getLoadedClasses() {
			return this.loadedClasses;
		}

		/**
		 * The wall-clock time from start to exit (or to the kill), measured with {@link System#nanoTime()}.
		 *
		 * @return the elapsed time
		 */
		public @NonNull Duration getElapsed() {
			return this.elapsed;
		}

		@Override
		public @NonNull String toString() {
			return "ChildJvm.Result[exitCode=" + this.exitCode + ", classPathSource=" + this.classPathSource
					+ ", elapsed=" + this.elapsed + ", stdout=" + abbreviated(this.standardOutput) + ", stderr="
					+ abbreviated(this.standardError) + "]";
		}

		private static @NonNull String abbreviated(@NonNull String text) {
			return text.length() <= 4_096 ? text : text.substring(0, 4_096) + "... (" + text.length() + " characters)";
		}
	}
}
