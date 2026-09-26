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

import javax.annotation.concurrent.ThreadSafe;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.nio.charset.StandardCharsets;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Deque;
import java.util.IdentityHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.logging.LogRecord;
import java.util.logging.SimpleFormatter;
import java.util.regex.Pattern;

import static java.util.Objects.requireNonNull;

/**
 * Sentinel secrets, and a walker that looks for them in everything Revetsec renders (R9, R16; exit criterion 17).
 * <p>
 * <strong>Sentinels.</strong> Every sentinel is {@code MARKER-label-MARKER}, for example
 * {@code sentinel7f3a9c-client-secret-sentinel7f3a9c}. It uses only ASCII letters, digits and {@code -}, so it
 * survives JSON string escaping, percent-encoding, form encoding and HTTP header values unchanged, and a leak is
 * found whatever the label. A partial echo is found too if it covers either end's {@link #MARKER}. Tests that plant a
 * secret use {@link #secret(String)} or one of the named constants.
 * <p>
 * <strong>The walker</strong> ({@link #findIn(Object)}) reports every rendering of {@code root} that contains
 * {@link #MARKER}, compared case-insensitively. It never reads private fields; it reads what a log line, an error
 * page or a debugger would print:
 * <ul>
 *   <li>a {@link CharSequence}: its text;</li>
 *   <li>a {@link Throwable}: {@code getMessage()}, {@code getLocalizedMessage()}, {@code toString()}, the printed
 *   stack trace (which also renders every cause, suppressed exception and stack frame), and then each suppressed
 *   exception and the cause, walked the same way;</li>
 *   <li>a JSON value: any object whose class is in {@code com.revetsec.json}. The walker reads its public
 *   {@code toString()} and, when it has one, its public no-argument {@code toJson()}, through reflection;</li>
 *   <li>a {@link LogRecord}: its raw message, its parameters (walked), the thrown exception (walked), and the message
 *   and full line as {@link SimpleFormatter} renders them;</li>
 *   <li>a {@link RecordingObserver} or one of its {@link RecordingObserver.Call}s: every recorded call's method name
 *   and arguments (walked), so exception graphs passed to hooks are covered;</li>
 *   <li>an {@link Optional}, {@link Map} (keys and values), {@link Collection} or object array: the elements,
 *   walked. Other {@link Iterable}s, such as {@link java.nio.file.Path}, are values and render with
 *   {@code toString()};</li>
 *   <li>a {@code byte[]} (read as ISO-8859-1, so ASCII inside UTF-8 is found) or {@code char[]}: its text;</li>
 *   <li>anything else: {@code toString()}.</li>
 * </ul>
 * The walk is iterative, visits each object once (so causal cycles end), and fails with
 * {@link IllegalStateException} past {@value #MAXIMUM_VISITS} objects. A rendering method that throws fails the walk:
 * a {@code toString()} that throws is a bug in its own right.
 * <p>
 * <strong>JSON values are found by package, through reflection,</strong> rather than by {@code instanceof JsonValue}.
 * This lets {@code SentinelsTests} check how {@code toJson()} is found with its own stand-in classes, including a
 * non-public class that exposes {@code toJson()} through a public interface. The default package is
 * {@code com.revetsec.json}.
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 */
@ThreadSafe
public final class Sentinels {
	/**
	 * The marker at both ends of every sentinel. The walker looks for it, case-insensitively.
	 */
	public static final String MARKER = "sentinel7f3a9c";

	// Declared before the sentinels below, which static initialization builds in textual order.
	private static final Pattern LABEL = Pattern.compile("[a-z0-9]+(?:-[a-z0-9]+)*");
	private static final int MAXIMUM_LABEL_LENGTH = 64;

	/**
	 * A client secret.
	 */
	public static final String CLIENT_SECRET = secret("client-secret");

	/**
	 * An OAuth access token.
	 */
	public static final String ACCESS_TOKEN = secret("access-token");

	/**
	 * An OAuth refresh token.
	 */
	public static final String REFRESH_TOKEN = secret("refresh-token");

	/**
	 * An OpenID Connect ID token.
	 */
	public static final String ID_TOKEN = secret("id-token");

	/**
	 * An OAuth authorization code.
	 */
	public static final String AUTHORIZATION_CODE = secret("authorization-code");

	/**
	 * A PKCE code verifier.
	 */
	public static final String CODE_VERIFIER = secret("code-verifier");

	/**
	 * A password.
	 */
	public static final String PASSWORD = secret("password");

	/**
	 * Plaintext that an application seals with {@code StateSealer}.
	 */
	public static final String SEALED_PLAINTEXT = secret("sealed-plaintext");

	/**
	 * Every named sentinel above.
	 */
	public static final List<String> NAMED_SENTINELS = List.of(CLIENT_SECRET, ACCESS_TOKEN, REFRESH_TOKEN, ID_TOKEN,
			AUTHORIZATION_CODE, CODE_VERIFIER, PASSWORD, SEALED_PLAINTEXT);

	/**
	 * The package whose objects the walker renders with {@code toJson()} as well as {@code toString()}.
	 */
	static final String JSON_PACKAGE = "com.revetsec.json";

	/**
	 * The most objects one walk visits before it gives up.
	 */
	static final int MAXIMUM_VISITS = 1_000_000;

	private Sentinels() {
		// Static helpers only.
	}

	/**
	 * A sentinel secret: {@code MARKER-label-MARKER}.
	 *
	 * @param label 1 to 64 characters of lowercase ASCII letters and digits, in groups joined by single hyphens
	 * @return the sentinel
	 * @throws IllegalArgumentException if {@code label} has another form
	 */
	public static String secret(String label) {
		requireNonNull(label);
		if (label.length() > MAXIMUM_LABEL_LENGTH || !LABEL.matcher(label).matches())
			throw new IllegalArgumentException("A sentinel label is 1 to " + MAXIMUM_LABEL_LENGTH
					+ " lowercase ASCII letters, digits and single inner hyphens");
		return MARKER + "-" + label + "-" + MARKER;
	}

	/**
	 * Whether {@code text} contains {@link #MARKER}, compared case-insensitively.
	 *
	 * @param text the text to check, or {@code null}
	 * @return {@code true} if a sentinel (or either end of one) appears in {@code text}
	 */
	public static Boolean containsSentinel(@Nullable CharSequence text) {
		return text != null && text.toString().toLowerCase(Locale.ROOT).contains(MARKER);
	}

	/**
	 * Every rendering of {@code root}, and of what it reaches, that contains a sentinel (see the class
	 * documentation for what the walker reads).
	 *
	 * @param root what to walk, or {@code null}
	 * @return where each sentinel was found, such as {@code $.getCause().getSuppressed()[0].getMessage()}, in walk
	 * order; empty if none was
	 */
	public static List<String> findIn(@Nullable Object root) {
		return findIn(root, Set.of(JSON_PACKAGE));
	}

	/**
	 * Fails unless no rendering of {@code root} contains a sentinel.
	 *
	 * @param root what to walk, or {@code null}
	 * @throws AssertionError listing where each sentinel was found
	 */
	public static void assertAbsent(@Nullable Object root) {
		List<String> locations = findIn(root);
		if (!locations.isEmpty())
			throw new AssertionError("Sentinel secret rendered at " + locations.size() + " location(s):\n - "
					+ String.join("\n - ", locations));
	}

	/**
	 * Fails unless some rendering of {@code root} contains a sentinel. Positive controls use it to prove that the
	 * walker reaches what a test relies on.
	 *
	 * @param root what to walk, or {@code null}
	 * @throws AssertionError if no sentinel was found
	 */
	public static void assertPresent(@Nullable Object root) {
		if (findIn(root).isEmpty())
			throw new AssertionError("No sentinel secret was found; the positive control did not reach it");
	}

	/**
	 * {@link #findIn(Object)} with the packages whose objects are treated as JSON values. Tests of the walker itself
	 * pass their own package, so they can use stand-in JSON classes.
	 */
	static List<String> findIn(@Nullable Object root, Set<String> jsonPackages) {
		requireNonNull(jsonPackages);
		return new Walker(jsonPackages).walk(root);
	}

	/**
	 * One walk. Not thread-safe; each call to {@link #findIn(Object, Set)} makes its own.
	 */
	private static final class Walker {
		private final Set<String> jsonPackages;
		private final Set<Object> visited = Collections.newSetFromMap(new IdentityHashMap<>());
		private final Deque<Pending> pending = new ArrayDeque<>();
		private final List<String> locations = new ArrayList<>();

		private Walker(Set<String> jsonPackages) {
			this.jsonPackages = Set.copyOf(jsonPackages);
		}

		private List<String> walk(@Nullable Object root) {
			enqueue(root, "$");
			while (!this.pending.isEmpty()) {
				Pending next = this.pending.removeFirst();
				visit(next.value, next.path);
			}
			return List.copyOf(this.locations);
		}

		private void enqueue(@Nullable Object value, String path) {
			if (value == null)
				return;
			if (!(value instanceof CharSequence) && !this.visited.add(value))
				return;
			if (this.visited.size() > MAXIMUM_VISITS)
				throw new IllegalStateException("The sentinel walk visited more than " + MAXIMUM_VISITS + " objects");
			this.pending.addLast(new Pending(value, path));
		}

		private void check(@Nullable CharSequence text, String path) {
			if (containsSentinel(text))
				this.locations.add(path);
		}

		private void visit(Object value, String path) {
			if (value instanceof CharSequence text) {
				check(text, path);
			} else if (value instanceof Throwable throwable) {
				visitThrowable(throwable, path);
			} else if (value instanceof RecordingObserver<?> observer) {
				enqueue(observer.getCalls(), path + ".getCalls()");
			} else if (value instanceof RecordingObserver.Call call) {
				check(call.getMethodName(), path + ".getMethodName()");
				List<@Nullable Object> arguments = call.getArguments();
				for (int index = 0; index < arguments.size(); ++index)
					enqueue(arguments.get(index), path + ".getArguments()[" + index + "]");
			} else if (value instanceof LogRecord logRecord) {
				visitLogRecord(logRecord, path);
			} else if (isJsonValue(value)) {
				visitJsonValue(value, path);
			} else if (value instanceof Optional<?> optional) {
				optional.ifPresent(element -> enqueue(element, path + ".get()"));
			} else if (value instanceof Map<?, ?> map) {
				int index = 0;
				for (Map.Entry<?, ?> entry : map.entrySet()) {
					enqueue(entry.getKey(), path + ".keys()[" + index + "]");
					enqueue(entry.getValue(), path + ".values()[" + index + "]");
					++index;
				}
			} else if (value instanceof Collection<?> collection) {
				int index = 0;
				for (Object element : collection)
					enqueue(element, path + "[" + index++ + "]");
			} else if (value instanceof Object[] array) {
				for (int index = 0; index < array.length; ++index)
					enqueue(array[index], path + "[" + index + "]");
			} else if (value instanceof byte[] bytes) {
				check(new String(bytes, StandardCharsets.ISO_8859_1), path);
			} else if (value instanceof char[] chars) {
				check(new String(chars), path);
			} else {
				check(value.toString(), path + ".toString()");
			}
		}

		private void visitThrowable(Throwable throwable, String path) {
			check(throwable.getMessage(), path + ".getMessage()");
			check(throwable.getLocalizedMessage(), path + ".getLocalizedMessage()");
			check(throwable.toString(), path + ".toString()");
			check(printedStackTrace(throwable), path + " (printed stack trace)");
			Throwable[] suppressed = throwable.getSuppressed();
			for (int index = 0; index < suppressed.length; ++index)
				enqueue(suppressed[index], path + ".getSuppressed()[" + index + "]");
			enqueue(throwable.getCause(), path + ".getCause()");
		}

		private void visitLogRecord(LogRecord logRecord, String path) {
			check(logRecord.getMessage(), path + ".getMessage()");
			SimpleFormatter formatter = new SimpleFormatter();
			check(formatter.formatMessage(logRecord), path + " (formatted message)");
			check(formatter.format(logRecord), path + " (formatted line)");
			Object @Nullable [] parameters = logRecord.getParameters();
			if (parameters != null)
				enqueue(parameters, path + ".getParameters()");
			enqueue(logRecord.getThrown(), path + ".getThrown()");
		}

		private boolean isJsonValue(Object value) {
			return this.jsonPackages.contains(value.getClass().getPackageName());
		}

		private void visitJsonValue(Object value, String path) {
			check(value.toString(), path + ".toString()");
			@Nullable Method toJson = publicNoArgumentMethod(value.getClass(), "toJson");
			if (toJson == null || toJson.getReturnType() != String.class)
				return;
			try {
				check((String) toJson.invoke(value), path + ".toJson()");
			} catch (IllegalAccessException e) {
				throw new IllegalStateException("Unable to call toJson() on " + value.getClass().getName(), e);
			} catch (InvocationTargetException e) {
				throw new IllegalStateException(value.getClass().getName() + ".toJson() threw", e.getCause());
			}
		}
	}

	/**
	 * A public no-argument method named {@code name}, looked up on a public class or interface in {@code type}'s
	 * hierarchy so it can be invoked without access checks failing; {@code null} if there is none.
	 */
	private static @Nullable Method publicNoArgumentMethod(Class<?> type, String name) {
		Deque<Class<?>> candidates = new ArrayDeque<>();
		candidates.add(type);
		Set<Class<?>> seen = Collections.newSetFromMap(new IdentityHashMap<>());
		while (!candidates.isEmpty()) {
			Class<?> candidate = candidates.removeFirst();
			if (!seen.add(candidate))
				continue;
			if (Modifier.isPublic(candidate.getModifiers())) {
				// getMethod also searches every supertype's public methods, so a miss here is final for this branch.
				try {
					return candidate.getMethod(name);
				} catch (NoSuchMethodException e) {
					continue;
				}
			}
			@Nullable Class<?> superclass = candidate.getSuperclass();
			if (superclass != null)
				candidates.addLast(superclass);
			candidates.addAll(List.of(candidate.getInterfaces()));
		}
		return null;
	}

	private static String printedStackTrace(Throwable throwable) {
		StringWriter stringWriter = new StringWriter();
		try (PrintWriter printWriter = new PrintWriter(stringWriter)) {
			throwable.printStackTrace(printWriter);
		}
		return stringWriter.toString();
	}

	private static final class Pending {
		private final Object value;
		private final String path;

		private Pending(Object value, String path) {
			this.value = value;
			this.path = path;
		}
	}
}
