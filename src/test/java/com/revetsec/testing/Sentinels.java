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

import javax.annotation.concurrent.ThreadSafe;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.nio.charset.StandardCharsets;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collection;
import java.util.Collections;
import java.util.Deque;
import java.util.HexFormat;
import java.util.IdentityHashMap;
import java.util.LinkedHashSet;
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
 * Sentinel secrets, and a walker that looks for them in everything Revetsec renders (R9, R16; M1 exit criterion 17,
 * M2 exit criterion 20).
 * <p>
 * <strong>Sentinels.</strong> Every sentinel is {@code MARKER-label-MARKER}, for example
 * {@code sentinel7f3a9c-client-secret-sentinel7f3a9c}. It uses only ASCII letters, digits and {@code -}, so it
 * survives JSON string escaping, percent-encoding, form encoding and HTTP header values unchanged, and a leak is
 * found whatever the label. A partial echo is found too if it covers either end's {@link #MARKER}. Tests that plant a
 * secret use {@link #secret(String)} or one of the named constants. Those characters are all in the base64url
 * alphabet too, so a sentinel can stand in for a JWK member such as {@code d} or {@code k}.
 * <p>
 * <strong>Encoded forms.</strong> A secret inside a compact JWT, an {@code x5c} or a PEM block is base64-encoded, so
 * its plain text never appears (plan M2, "the sentinel blind spot"). {@link #containsSentinel(CharSequence)}
 * therefore also finds {@link #MARKER}
 * <ul>
 *   <li>base64url- or standard-base64-encoded at each of the three alignments: when the marker starts at byte offset
 *   o, its encoding always contains the characters that depend on the marker's bits alone, one fixed 18-character
 *   core for each value of o mod 3 ({@link #ENCODED_MARKERS}); cores are matched case-sensitively, in the text as
 *   is and with its whitespace removed, so a line-wrapped PEM or MIME body is covered;</li>
 *   <li>hex-encoded, in either case.</li>
 * </ul>
 * A core covers the marker's inner octets fully but only part of its first and last, so a string that differs from
 * the marker only in the low bits of its last octet (or the high bits of its first) matches too; such near-markers do
 * not occur by accident. Base64 of base64, percent-encoded {@code +} and {@code /}, and JSON's {@code \/} escape are
 * not decoded.
 * {@link #sentinelClaimsJson(Integer)} and {@link #compactJwtWithSentinelClaim(Integer)} are the positive controls:
 * each carries {@link #MARKER} exactly once, at a chosen alignment, and only in base64url form.
 * <p>
 * <strong>Sentinel tokens.</strong> {@link #compactJwt(String, Integer)} is a JWT-shaped string with a sentinel in its
 * header's {@code kid}, in a claim and, literally, in its signature segment, which decodes to exactly the requested
 * number of octets. It has no valid signature: it drives the failure paths up to and including signature
 * verification.
 * <p>
 * <strong>The walker</strong> ({@link #findIn(Object)}) reports every rendering of {@code root} that
 * {@link #containsSentinel(CharSequence)}. It never reads private fields; it reads what a log line, an error page or a
 * debugger would print:
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
	 * A private JWK member's value ({@code d} of an RSA, EC or OKP key, and the RSA CRT members). Its 48 characters
	 * are canonical base64url for 36 octets, so a parser that decodes before it rejects meets a well-formed value.
	 */
	public static final String PRIVATE_KEY_MEMBER = secret("private-key-member");

	/**
	 * A symmetric JWK's {@code k}. Its 43 characters are canonical base64url for 32 octets.
	 */
	public static final String SYMMETRIC_KEY = secret("symmetric-key");

	/**
	 * An HMAC secret. Its 64 UTF-8 octets are long enough for HS512, and its characters are canonical base64url for 48
	 * octets.
	 */
	public static final String HMAC_SECRET = secret("hmac-secret-long-enough-for-hs-512");

	/**
	 * The {@code kid} in {@link #compactJwt(String, Integer)}'s header.
	 */
	public static final String JWT_KEY_ID = secret("jwt-key-id");

	/**
	 * The {@code sub} claim in {@link #compactJwt(String, Integer)}'s payload.
	 */
	public static final String JWT_CLAIM = secret("jwt-claim");

	/**
	 * The text {@link #signatureSegment(Integer)} repeats to fill a signature segment.
	 */
	public static final String JWT_SIGNATURE = secret("jwt-signature");

	/**
	 * Every named sentinel above.
	 */
	public static final List<String> NAMED_SENTINELS = List.of(CLIENT_SECRET, ACCESS_TOKEN, REFRESH_TOKEN, ID_TOKEN,
			AUTHORIZATION_CODE, CODE_VERIFIER, PASSWORD, SEALED_PLAINTEXT, PRIVATE_KEY_MEMBER, SYMMETRIC_KEY,
			HMAC_SECRET, JWT_KEY_ID, JWT_CLAIM, JWT_SIGNATURE);

	/**
	 * The {@code iss} of the sentinel tokens ({@link #compactJwt(String, Integer)},
	 * {@link #sentinelClaimsJson(Integer)}).
	 */
	public static final String COMPACT_JWT_ISSUER = "https://issuer.example";

	/**
	 * The {@code aud} of {@link #compactJwt(String, Integer)}.
	 */
	public static final String COMPACT_JWT_AUDIENCE = "https://audience.example";

	/**
	 * The {@code iat} of {@link #compactJwt(String, Integer)}: 2026-01-01T00:00:00Z.
	 */
	public static final Long COMPACT_JWT_ISSUED_AT = 1_767_225_600L;

	/**
	 * The {@code exp} of {@link #compactJwt(String, Integer)}: 2100-01-01T00:00:00Z.
	 */
	public static final Long COMPACT_JWT_EXPIRES_AT = 4_102_444_800L;

	/**
	 * The encoded forms of {@link #MARKER} that {@link #containsSentinel(CharSequence)} looks for besides the marker
	 * itself: the base64url and standard-base64 cores for byte offsets 0, 1 and 2 mod 3 (the two alphabets agree for
	 * this marker, so each core appears once), then its lowercase hex.
	 */
	static final List<String> ENCODED_MARKERS = encodedMarkers();

	/**
	 * The base64 cores alone, in alignment order: index i is the core for a marker at byte offset i mod 3.
	 */
	static final List<String> BASE64_MARKER_CORES = ENCODED_MARKERS.subList(0, ENCODED_MARKERS.size() - 1);

	/**
	 * The fewest octets {@link #signatureSegment(Integer)} can fill: 11 octets are 15 characters, room for the
	 * 14-character {@link #MARKER}.
	 */
	public static final int MINIMUM_SIGNATURE_OCTETS = 11;

	/**
	 * The most octets {@link #signatureSegment(Integer)} fills.
	 */
	public static final int MAXIMUM_SIGNATURE_OCTETS = 65_536;

	private static final Pattern WHITESPACE = Pattern.compile("\\s+");

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
	public static @NonNull String secret(@NonNull String label) {
		requireNonNull(label);
		if (label.length() > MAXIMUM_LABEL_LENGTH || !LABEL.matcher(label).matches())
			throw new IllegalArgumentException("A sentinel label is 1 to " + MAXIMUM_LABEL_LENGTH
					+ " lowercase ASCII letters, digits and single inner hyphens");
		return MARKER + "-" + label + "-" + MARKER;
	}

	/**
	 * Whether {@code text} contains {@link #MARKER}, compared case-insensitively, or one of its encoded forms (see the
	 * class description).
	 *
	 * @param text the text to check, or {@code null}
	 * @return {@code true} if a sentinel (or either end of one), plain or encoded, appears in {@code text}
	 */
	public static @NonNull Boolean containsSentinel(@Nullable CharSequence text) {
		if (text == null)
			return false;
		String string = text.toString();
		String lowerCase = string.toLowerCase(Locale.ROOT);
		if (lowerCase.contains(MARKER) || lowerCase.contains(ENCODED_MARKERS.get(ENCODED_MARKERS.size() - 1)))
			return true;
		if (containsBase64Core(string))
			return true;
		String withoutWhitespace = WHITESPACE.matcher(string).replaceAll("");
		return withoutWhitespace.length() != string.length() && containsBase64Core(withoutWhitespace);
	}

	/**
	 * A JWT-shaped compact string that carries a sentinel in three places: its header is
	 * <code>{"alg":<i>algorithm</i>,"typ":"JWT","kid":</code>{@link #JWT_KEY_ID}<code>}</code>, its claims are
	 * {@link #COMPACT_JWT_ISSUER}, {@code sub} {@link #JWT_CLAIM}, {@link #COMPACT_JWT_AUDIENCE},
	 * {@link #COMPACT_JWT_ISSUED_AT} and {@link #COMPACT_JWT_EXPIRES_AT}, and its signature segment is
	 * {@link #signatureSegment(Integer)}. The signature is not valid for any key.
	 * <p>
	 * At an algorithm's own signature length the token reaches signature verification, and fails there, with one
	 * exception: at ES512's 132 octets, r's first octet is {@code 0xb1} (from the marker's {@code sen}), so r exceeds
	 * the P-521 group order and the token stops at the range check before key selection. ES256's and ES384's r lie
	 * in range.
	 *
	 * @param algorithm the {@code alg} header value, such as {@code RS256}
	 * @param signatureOctets how many octets the signature segment decodes to: the algorithm's length, for the
	 * signature-mismatch path, or another, for the wrong-length path
	 * @return the compact string
	 */
	public static @NonNull String compactJwt(@NonNull String algorithm, @NonNull Integer signatureOctets) {
		requireNonNull(algorithm);
		String header = JsonText.object(List.of(Map.entry("alg", JsonText.string(algorithm)),
				Map.entry("typ", JsonText.string("JWT")), Map.entry("kid", JsonText.string(JWT_KEY_ID))));
		String claims = JsonText.object(List.of(Map.entry("iss", JsonText.string(COMPACT_JWT_ISSUER)),
				Map.entry("sub", JsonText.string(JWT_CLAIM)), Map.entry("aud", JsonText.string(COMPACT_JWT_AUDIENCE)),
				Map.entry("iat", String.valueOf(COMPACT_JWT_ISSUED_AT)),
				Map.entry("exp", String.valueOf(COMPACT_JWT_EXPIRES_AT))));
		return TestJws.base64Url(header) + "." + TestJws.base64Url(claims) + "." + signatureSegment(signatureOctets);
	}

	/**
	 * A canonical base64url signature segment that decodes to exactly {@code signatureOctets} octets and whose text is
	 * {@link #JWT_SIGNATURE}, repeated and cut to length, with its last character's unused bits cleared. It starts with
	 * {@link #MARKER}, so the plain walker finds it in any rendering of the token.
	 *
	 * @param signatureOctets how many octets the segment decodes to, {@value #MINIMUM_SIGNATURE_OCTETS} to
	 * {@value #MAXIMUM_SIGNATURE_OCTETS}
	 * @return the segment
	 */
	public static @NonNull String signatureSegment(@NonNull Integer signatureOctets) {
		requireNonNull(signatureOctets);
		if (signatureOctets < MINIMUM_SIGNATURE_OCTETS || signatureOctets > MAXIMUM_SIGNATURE_OCTETS)
			throw new IllegalArgumentException("A sentinel signature is " + MINIMUM_SIGNATURE_OCTETS + " to "
					+ MAXIMUM_SIGNATURE_OCTETS + " octets, not " + signatureOctets);
		int characters = (8 * signatureOctets + 5) / 6;
		StringBuilder segment = new StringBuilder(characters + JWT_SIGNATURE.length());
		while (segment.length() < characters)
			segment.append(JWT_SIGNATURE);
		segment.setLength(characters);
		int unusedBits = 6 * characters - 8 * signatureOctets;
		int last = TestJws.BASE64_URL_ALPHABET.indexOf(segment.charAt(characters - 1));
		segment.setCharAt(characters - 1, TestJws.BASE64_URL_ALPHABET.charAt(last & ~((1 << unusedBits) - 1)));
		return segment.toString();
	}

	/**
	 * A JWT claims set, as UTF-8 JSON text, that carries {@link #MARKER} exactly once, as the whole value of one claim,
	 * starting at a UTF-8 byte offset of {@code alignment} mod 3:
	 * {@code {"iss":"https://issuer.example","claim":"sentinel7f3a9c"}}, with the claim's name lengthened to shift the
	 * offset. The value is the bare marker rather than a full sentinel,
	 * whose second marker would sit at another alignment and blur which base64 core a test exercised.
	 *
	 * @param alignment 0, 1 or 2
	 * @return the claims text
	 */
	public static @NonNull String sentinelClaimsJson(@NonNull Integer alignment) {
		requireNonNull(alignment);
		if (alignment < 0 || alignment > 2)
			throw new IllegalArgumentException("An alignment is 0, 1 or 2, not " + alignment);
		for (int extra = 0; ; ++extra) {
			String prefix = "{\"iss\":" + JsonText.string(COMPACT_JWT_ISSUER) + ",\"claim" + "x".repeat(extra)
					+ "\":\"";
			if (prefix.getBytes(StandardCharsets.UTF_8).length % 3 == alignment)
				return prefix + MARKER + "\"}";
		}
	}

	/**
	 * A compact JWT whose only sentinel is {@link #sentinelClaimsJson(Integer)}'s claim, so the marker appears only
	 * base64url-encoded, at a known alignment: the positive control for base64url matching (M2 exit criterion 20). Its
	 * header is {@code {"alg":"RS256","typ":"JWT"}} and its signature 256 zero octets.
	 *
	 * @param alignment the marker's payload byte offset mod 3: 0, 1 or 2
	 * @return the compact string
	 */
	public static @NonNull String compactJwtWithSentinelClaim(@NonNull Integer alignment) {
		String header = JsonText.object(List.of(Map.entry("alg", JsonText.string("RS256")),
				Map.entry("typ", JsonText.string("JWT"))));
		return TestJws.base64Url(header) + "." + TestJws.base64Url(sentinelClaimsJson(alignment)) + "."
				+ TestJws.base64Url(new byte[256]);
	}

	private static boolean containsBase64Core(@NonNull String text) {
		for (String core : BASE64_MARKER_CORES)
			if (text.contains(core))
				return true;
		return false;
	}

	/**
	 * For each alignment r of the marker's first byte within a 3-byte base64 group, the characters of its encoding
	 * that depend on the marker's bits alone: character i covers bits [6i, 6i + 6), and the marker covers
	 * [8r, 8r + 8·length), whatever the bytes around it.
	 */
	private static @NonNull List<@NonNull String> encodedMarkers() {
		byte[] marker = MARKER.getBytes(StandardCharsets.US_ASCII);
		LinkedHashSet<String> forms = new LinkedHashSet<>();
		for (Base64.Encoder encoder : List.of(Base64.getUrlEncoder(), Base64.getEncoder())) {
			for (int alignment = 0; alignment < 3; ++alignment) {
				byte[] padded = new byte[alignment + marker.length + 3];
				System.arraycopy(marker, 0, padded, alignment, marker.length);
				String encoded = encoder.withoutPadding().encodeToString(padded);
				int first = (8 * alignment + 5) / 6;
				int last = (8 * (alignment + marker.length) - 6) / 6;
				forms.add(encoded.substring(first, last + 1));
			}
		}
		forms.add(HexFormat.of().formatHex(marker));
		return List.copyOf(forms);
	}

	/**
	 * Every rendering of {@code root}, and of what it reaches, that contains a sentinel (see the class
	 * documentation for what the walker reads).
	 *
	 * @param root what to walk, or {@code null}
	 * @return where each sentinel was found, such as {@code $.getCause().getSuppressed()[0].getMessage()}, in walk
	 * order; empty if none was
	 */
	public static @NonNull List<@NonNull String> findIn(@Nullable Object root) {
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
	static @NonNull List<@NonNull String> findIn(@Nullable Object root, @NonNull Set<@NonNull String> jsonPackages) {
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

		private Walker(@NonNull Set<@NonNull String> jsonPackages) {
			this.jsonPackages = Set.copyOf(jsonPackages);
		}

		private @NonNull List<@NonNull String> walk(@Nullable Object root) {
			enqueue(root, "$");
			while (!this.pending.isEmpty()) {
				Pending next = this.pending.removeFirst();
				visit(next.value, next.path);
			}
			return List.copyOf(this.locations);
		}

		private void enqueue(@Nullable Object value, @NonNull String path) {
			if (value == null)
				return;
			if (!(value instanceof CharSequence) && !this.visited.add(value))
				return;
			if (this.visited.size() > MAXIMUM_VISITS)
				throw new IllegalStateException("The sentinel walk visited more than " + MAXIMUM_VISITS + " objects");
			this.pending.addLast(new Pending(value, path));
		}

		private void check(@Nullable CharSequence text, @NonNull String path) {
			if (containsSentinel(text))
				this.locations.add(path);
		}

		private void visit(@NonNull Object value, @NonNull String path) {
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

		private void visitThrowable(@NonNull Throwable throwable, @NonNull String path) {
			check(throwable.getMessage(), path + ".getMessage()");
			check(throwable.getLocalizedMessage(), path + ".getLocalizedMessage()");
			check(throwable.toString(), path + ".toString()");
			check(printedStackTrace(throwable), path + " (printed stack trace)");
			Throwable[] suppressed = throwable.getSuppressed();
			for (int index = 0; index < suppressed.length; ++index)
				enqueue(suppressed[index], path + ".getSuppressed()[" + index + "]");
			enqueue(throwable.getCause(), path + ".getCause()");
		}

		private void visitLogRecord(@NonNull LogRecord logRecord, @NonNull String path) {
			check(logRecord.getMessage(), path + ".getMessage()");
			SimpleFormatter formatter = new SimpleFormatter();
			check(formatter.formatMessage(logRecord), path + " (formatted message)");
			check(formatter.format(logRecord), path + " (formatted line)");
			Object @Nullable [] parameters = logRecord.getParameters();
			if (parameters != null)
				enqueue(parameters, path + ".getParameters()");
			enqueue(logRecord.getThrown(), path + ".getThrown()");
		}

		private boolean isJsonValue(@NonNull Object value) {
			return this.jsonPackages.contains(value.getClass().getPackageName());
		}

		private void visitJsonValue(@NonNull Object value, @NonNull String path) {
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
	private static @Nullable Method publicNoArgumentMethod(@NonNull Class<?> type, @NonNull String name) {
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

	private static @NonNull String printedStackTrace(@NonNull Throwable throwable) {
		StringWriter stringWriter = new StringWriter();
		try (PrintWriter printWriter = new PrintWriter(stringWriter)) {
			throwable.printStackTrace(printWriter);
		}
		return stringWriter.toString();
	}

	private static final class Pending {
		private final Object value;
		private final String path;

		private Pending(@NonNull Object value, @NonNull String path) {
			this.value = value;
			this.path = path;
		}
	}
}
