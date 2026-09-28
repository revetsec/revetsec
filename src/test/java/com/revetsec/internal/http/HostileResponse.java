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

package com.revetsec.internal.http;

import com.revetsec.internal.Limits;
import com.revetsec.internal.http.HttpExchangeException.Kind;
import com.revetsec.testing.RawTlsServer;
import com.revetsec.testing.TestHttpsServer;
import org.jspecify.annotations.Nullable;

import javax.annotation.concurrent.Immutable;
import javax.annotation.concurrent.NotThreadSafe;
import java.io.ByteArrayOutputStream;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.Optional;

import static java.util.Objects.requireNonNull;

/**
 * The catalog of hostile HTTP responses that Revetsec's outbound HTTP must reject or contain (M1 plan, "Test helpers",
 * G6-7, exit criteria 10 to 12). It is public so the protocol milestones (M2 JWKS, M3 OIDC) can run the same cases
 * against their public types and map each {@link Kind} to their own exception.
 * <p>
 * Each case records:
 * <ul>
 *   <li>its {@link Transport}: {@link Transport#TEST_HTTPS_SERVER} when the JDK {@code HttpsServer} can send it, and
 *   {@link Transport#RAW_TLS_SERVER} when only exact bytes can (framing anomalies, close-delimited bodies, HTTP/1.0,
 *   oversized headers, pacing). Every case can also run on {@link RawTlsServer} ({@link #installOn(RawTlsServer,
 *   String)}), which is how exit criterion 12 shows the client closing the connection after each rejection;</li>
 *   <li>its expectation: an {@link HttpExchangeException} of {@link #getExpectedKind()}, or, when that is empty, a
 *   {@link RawResponse} with {@link #getExpectedDroppedStatus()} and {@code errorBodyDropped} (an oversized or
 *   encoded error body). Revetsec's checks run before the JDK parses {@code Content-Length} on every status but 204,
 *   so every framing case is {@link Kind#FRAMING} on every JDK. The JDK refuses some responses before any Revetsec
 *   check, and those are {@link Kind#IO}: a response head it cannot parse (a header section over
 *   {@code jdk.http.maxHeaderSize}, an invalid status line, an invalid header name), and a 204 that carries a
 *   nonzero or unparseable {@code Content-Length} or any {@code Transfer-Encoding};</li>
 *   <li>the {@link ResponseProfile} to request it with, whether the server can observe the client abort a body that
 *   is larger than the socket buffers ({@link #isServerAbortObservable()}), and whether the client closes the
 *   connection at all on the running JDK ({@link #isClientCloseObservable()}).</li>
 * </ul>
 * {@link #rejections()} are decided without timing. {@link #timeouts()} are paced or stalled responses that end in
 * {@link Kind#TIMEOUT} only when the caller's deadline or request timeout is short (a second or two); each keeps its
 * server busy for minutes otherwise. {@link #jwks()} is the catalog a JSON Web Key Set fetch runs (M2 exit criterion
 * 14): every case under {@link ResponseProfile#JWKS}, plus 300 KiB bodies and bodies one byte over the JWKS body
 * limit, a 304 without a {@code Location}, and more {@code Content-Type} fields a key set must not carry.
 * <p>
 * Bodies default to the limits of {@link HttpExchangeRequest#fromDefaults}: 256 KiB for a 2xx (the
 * {@link ResponseProfile#getBodySizeLimit()} row's default) and 16 KiB for an error body. The oversized bodies are
 * {@value #OVERSIZED_BODY_BYTES} bytes, far above every socket buffer.
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 */
@Immutable
public final class HostileResponse {
	/**
	 * The size of the oversized bodies: 12 MiB (exit criterion 10).
	 */
	public static final int OVERSIZED_BODY_BYTES = 12 * 1024 * 1024;

	/**
	 * The suffix of the path every redirect's {@code Location} names; its hit count must stay zero.
	 */
	public static final String REDIRECT_TARGET_SUFFIX = "-redirect-target";

	/**
	 * The suffix {@link #jwks()} appends to the name of a case it takes from {@link #all()} and requests under
	 * {@link ResponseProfile#JWKS}, so {@code "an invalid status line" + JWKS_NAME_SUFFIX} names that case there.
	 */
	public static final String JWKS_NAME_SUFFIX = " (JWKS)";

	/**
	 * The size of the JWKS bodies that stream past the default JWKS body limit without a {@code Content-Length}:
	 * 300 KiB (M2 exit criterion 15).
	 */
	public static final int JWKS_OVERSIZED_BODY_BYTES = 300 * 1024;

	private static final int DEFAULT_BODY_LIMIT = Limits.HTTP_RESPONSE_BODY_SIZE.getDefaultIntValue();
	private static final int DEFAULT_JWKS_BODY_LIMIT = Limits.JWKS_RESPONSE_BODY_SIZE.getDefaultIntValue();
	private static final String JWK_SET = "application/jwk-set+json";
	private static final int DEFAULT_ERROR_BODY_LIMIT = Limits.HTTP_ERROR_BODY_SIZE.getDefaultIntValue();
	private static final String JSON = "application/json";
	private static final byte[] SMALL_JSON = "{\"a\":1}".getBytes(StandardCharsets.US_ASCII);
	private static final int RAW_CHUNK_BYTES = 64 * 1024;

	/**
	 * Which test server sends a case.
	 */
	@Immutable
	public enum Transport {
		/**
		 * The JDK {@code HttpsServer} ({@link TestHttpsServer}), which frames bodies itself.
		 */
		TEST_HTTPS_SERVER,
		/**
		 * {@link RawTlsServer}, which writes exact bytes.
		 */
		RAW_TLS_SERVER
	}

	/**
	 * How a case's body is framed.
	 */
	@Immutable
	private enum Framing {
		/**
		 * A {@code Content-Length} for the body, written by the server.
		 */
		CONTENT_LENGTH,
		/**
		 * {@code Transfer-Encoding: chunked}, written by the server.
		 */
		CHUNKED,
		/**
		 * No framing header: the body ends when the server closes its side (raw only).
		 */
		CLOSE_DELIMITED,
		/**
		 * The case's own headers frame the body, exactly as given (raw only).
		 */
		VERBATIM
	}

	private final String name;
	private final Transport transport;
	private final ResponseProfile profile;
	private final @Nullable Kind expectedKind;
	private final @Nullable Integer expectedDroppedStatus;
	private final String statusLine;
	private final Integer status;
	private final List<List<String>> headers;
	private final Integer bodyBytes;
	private final boolean jsonBody;
	private final Framing framing;
	private final boolean redirect;
	private final boolean serverAbortObservable;
	private final int clientCloseObservableFrom;
	private final boolean bodyNeverSent;
	private final @Nullable Pacing pacing;

	private HostileResponse(Builder builder) {
		this.name = requireNonNull(builder.name);
		this.transport = requireNonNull(builder.transport);
		this.profile = requireNonNull(builder.profile);
		this.expectedKind = builder.expectedKind;
		this.expectedDroppedStatus = builder.expectedDroppedStatus;
		this.statusLine = requireNonNull(builder.statusLine);
		this.status = requireNonNull(builder.status);
		this.headers = List.copyOf(builder.headers);
		this.bodyBytes = builder.bodyBytes;
		this.jsonBody = builder.jsonBody;
		this.framing = requireNonNull(builder.framing);
		this.redirect = builder.redirect;
		this.serverAbortObservable = this.bodyBytes >= OVERSIZED_BODY_BYTES;
		this.clientCloseObservableFrom = builder.clientCloseObservableFrom;
		this.bodyNeverSent = builder.bodyNeverSent;
		this.pacing = builder.pacing;
		if ((this.expectedKind == null) == (this.expectedDroppedStatus == null))
			throw new IllegalStateException(this.name + ": exactly one of a kind and a dropped status is expected");
		if (this.transport == Transport.TEST_HTTPS_SERVER && (this.framing == Framing.CLOSE_DELIMITED
				|| this.framing == Framing.VERBATIM || this.pacing != null || this.bodyNeverSent))
			throw new IllegalStateException(this.name + ": the JDK server cannot send this case");
	}

	/**
	 * A copy of {@code source} under another name and profile; every byte the server sends stays the same.
	 */
	private HostileResponse(HostileResponse source, String name, ResponseProfile profile) {
		this.name = requireNonNull(name);
		this.transport = source.transport;
		this.profile = requireNonNull(profile);
		this.expectedKind = source.expectedKind;
		this.expectedDroppedStatus = source.expectedDroppedStatus;
		this.statusLine = source.statusLine;
		this.status = source.status;
		this.headers = source.headers;
		this.bodyBytes = source.bodyBytes;
		this.jsonBody = source.jsonBody;
		this.framing = source.framing;
		this.redirect = source.redirect;
		this.serverAbortObservable = source.serverAbortObservable;
		this.clientCloseObservableFrom = source.clientCloseObservableFrom;
		this.bodyNeverSent = source.bodyNeverSent;
		this.pacing = source.pacing;
	}

	/**
	 * Every case decided without timing: redirects, framing, content encoding, size and media type.
	 *
	 * @return the cases, in a fixed order
	 */
	public static List<HostileResponse> rejections() {
		List<HostileResponse> cases = new ArrayList<>();

		// G6-7: every 3xx is refused and never followed.
		for (int status : new int[]{300, 301, 302, 303, 304, 305, 307, 308, 399})
			cases.add(onJdkServer("redirect " + status, Kind.REDIRECT)
					.status(status, "Redirect")
					.redirect()
					.build());

		// G6-7 and exit criterion 12: framing the JDK itself accepts (RFC 9112 section 6.3).
		cases.add(raw("framing: two equal Content-Length fields", Kind.FRAMING)
				.header("Content-Type", JSON).header("Content-Length", "7").header("Content-Length", "7").json().build());
		cases.add(raw("framing: two different Content-Length fields", Kind.FRAMING)
				.header("Content-Type", JSON).header("Content-Length", "7").header("Content-Length", "3").json().build());
		cases.add(raw("framing: a Content-Length list", Kind.FRAMING)
				.header("Content-Type", JSON).header("Content-Length", "7, 7").json().build());
		cases.add(raw("framing: a negative Content-Length", Kind.FRAMING)
				.header("Content-Type", JSON).header("Content-Length", "-1").json().build());
		cases.add(raw("framing: a signed Content-Length", Kind.FRAMING)
				.header("Content-Type", JSON).header("Content-Length", "+7").json().build());
		cases.add(raw("framing: a hexadecimal Content-Length", Kind.FRAMING)
				.header("Content-Type", JSON).header("Content-Length", "0x7").json().build());
		cases.add(raw("framing: Content-Length with Transfer-Encoding chunked", Kind.FRAMING)
				.header("Content-Type", JSON).header("Content-Length", "7").header("Transfer-Encoding", "chunked")
				.json().build());
		cases.add(raw("framing: Transfer-Encoding gzip, chunked", Kind.FRAMING)
				.header("Content-Type", JSON).header("Transfer-Encoding", "gzip, chunked").json().build());
		cases.add(raw("framing: Transfer-Encoding identity", Kind.FRAMING)
				.header("Content-Type", JSON).header("Transfer-Encoding", "identity").json().build());
		cases.add(raw("framing: two Transfer-Encoding fields", Kind.FRAMING)
				.header("Content-Type", JSON).header("Transfer-Encoding", "chunked").header("Transfer-Encoding", "chunked")
				.json().build());
		cases.add(raw("framing: a 500 with Content-Length and Transfer-Encoding", Kind.FRAMING)
				.status(500, "Internal Server Error")
				.header("Content-Type", JSON).header("Content-Length", "7").header("Transfer-Encoding", "chunked")
				.json().build());

		// RFC 9110 section 15.3.5: a 204 has no content. The JDK checks a 204's framing itself, before it calls
		// Revetsec's body handler, and fails it as IO. It closes the connection, except for a first Content-Length it
		// cannot parse, which JDK 17 to 26 leave open until the server closes it; JDK 27 closes that too. Each is sent
		// as its head alone, then a stall, so only the client can end the connection.
		cases.add(raw("204 with two Content-Length: 7 fields", Kind.IO)
				.status(204, "No Content")
				.header("Content-Length", "7").header("Content-Length", "7").bodyNeverSent().build());
		cases.add(raw("204 with Content-Length and Transfer-Encoding chunked", Kind.IO)
				.status(204, "No Content")
				.header("Content-Length", "7").header("Transfer-Encoding", "chunked").bodyNeverSent().build());
		cases.add(raw("204 with a hexadecimal Content-Length", Kind.IO)
				.status(204, "No Content")
				.header("Content-Length", "0x7").bodyNeverSent().clientCloseObservableFrom(27).build());
		cases.add(raw("204 with a Content-Length list", Kind.IO)
				.status(204, "No Content")
				.header("Content-Length", "7, 7").bodyNeverSent().clientCloseObservableFrom(27).build());
		cases.add(raw("204 with a Content-Length too large for a long", Kind.IO)
				.status(204, "No Content")
				.header("Content-Length", "99999999999999999999").bodyNeverSent().clientCloseObservableFrom(27).build());
		// A zero first Content-Length is no body to the JDK, so the 204 reaches the body handler, which sees the
		// duplicate.
		cases.add(raw("204 with two Content-Length: 0 fields", Kind.FRAMING)
				.status(204, "No Content")
				.header("Content-Length", "0").header("Content-Length", "0").bodyNeverSent().build());

		// G6-7: a 2xx must not be content-encoded; Revetsec sends Accept-Encoding: identity.
		for (String contentEncoding : List.of("gzip", "identity, gzip", "GZIP", "br", "deflate", "x-gzip",
				"identity;q=1"))
			cases.add(onJdkServer("2xx with Content-Encoding " + contentEncoding, Kind.CONTENT_ENCODING)
					.header("Content-Type", JSON).header("Content-Encoding", contentEncoding).json().build());
		cases.add(onJdkServer("2xx with Content-Encoding identity then gzip in two fields", Kind.CONTENT_ENCODING)
				.header("Content-Type", JSON).header("Content-Encoding", "identity").header("Content-Encoding", "gzip")
				.json().build());

		// G5-5 and exit criterion 10: an encoded error body keeps its status and is dropped unread.
		cases.add(onJdkServer("gzip-encoded 503", null)
				.status(503, "Service Unavailable").dropped(503)
				.header("Content-Type", JSON).header("Content-Encoding", "gzip").json().build());
		cases.add(onJdkServer("br-encoded 401", null)
				.status(401, "Unauthorized").dropped(401)
				.header("Content-Type", JSON).header("Content-Encoding", "br").json().build());

		// Exit criterion 10: 12 MiB 2xx bodies fail at 256 KiB, however they are framed.
		cases.add(onJdkServer("12 MiB fixed-length 2xx", Kind.TOO_LARGE)
				.header("Content-Type", JSON).body(OVERSIZED_BODY_BYTES).build());
		cases.add(onJdkServer("12 MiB chunked 2xx", Kind.TOO_LARGE)
				.header("Content-Type", JSON).body(OVERSIZED_BODY_BYTES).framing(Framing.CHUNKED).build());
		cases.add(raw("12 MiB close-delimited 2xx", Kind.TOO_LARGE)
				.header("Content-Type", JSON).body(OVERSIZED_BODY_BYTES).framing(Framing.CLOSE_DELIMITED).build());
		cases.add(raw("12 MiB close-delimited HTTP/1.0 2xx", Kind.TOO_LARGE)
				.statusLine("HTTP/1.0 200 OK")
				.header("Content-Type", JSON).body(OVERSIZED_BODY_BYTES).framing(Framing.CLOSE_DELIMITED).build());
		cases.add(onJdkServer("chunked 2xx one byte over the body limit", Kind.TOO_LARGE)
				.header("Content-Type", JSON).body(DEFAULT_BODY_LIMIT + 1).framing(Framing.CHUNKED).build());
		cases.add(onJdkServer("fixed-length 2xx one byte over the body limit", Kind.TOO_LARGE)
				.header("Content-Type", JSON).body(DEFAULT_BODY_LIMIT + 1).build());
		// M1 plan, "Checks in apply()", step 4: a declared Content-Length over the limit is refused from the headers
		// alone, so a server that never sends the body cannot hold the caller until its deadline.
		cases.add(raw("2xx declaring 12 MiB that never sends its body", Kind.TOO_LARGE)
				.header("Content-Type", JSON).header("Content-Length", String.valueOf(OVERSIZED_BODY_BYTES))
				.bodyNeverSent().build());

		// Exit criterion 10: 12 MiB error bodies keep their status and are dropped.
		cases.add(onJdkServer("500 with a 12 MiB Content-Length", null)
				.status(500, "Internal Server Error").dropped(500)
				.header("Content-Type", JSON).body(OVERSIZED_BODY_BYTES).build());
		cases.add(onJdkServer("500 with a 12 MiB chunked body", null)
				.status(500, "Internal Server Error").dropped(500)
				.header("Content-Type", JSON).body(OVERSIZED_BODY_BYTES).framing(Framing.CHUNKED).build());
		cases.add(raw("500 with a 12 MiB close-delimited body", null)
				.status(500, "Internal Server Error").dropped(500)
				.header("Content-Type", JSON).body(OVERSIZED_BODY_BYTES).framing(Framing.CLOSE_DELIMITED).build());
		cases.add(onJdkServer("chunked 400 one byte over the error-body limit", null)
				.status(400, "Bad Request").dropped(400)
				.header("Content-Type", JSON).body(DEFAULT_ERROR_BODY_LIMIT + 1).framing(Framing.CHUNKED).build());
		cases.add(raw("500 declaring 12 MiB that never sends its body", null)
				.status(500, "Internal Server Error").dropped(500)
				.header("Content-Type", JSON).header("Content-Length", String.valueOf(OVERSIZED_BODY_BYTES))
				.bodyNeverSent().build());
		// A Content-Length of twenty digits is 1*DIGIT, so it is not a framing anomaly, but it is over every limit. The
		// JDK cannot parse it into a long and fails the exchange itself without closing the connection (JDK 17), so
		// Revetsec must cancel the exchange from the body handler.
		cases.add(raw("2xx with a Content-Length too large for a long", Kind.TOO_LARGE)
				.header("Content-Type", JSON).header("Content-Length", "99999999999999999999").json().build());
		cases.add(raw("500 with a Content-Length too large for a long", null)
				.status(500, "Internal Server Error").dropped(500)
				.header("Content-Type", JSON).header("Content-Length", "99999999999999999999").json().build());

		// G6-7: a 2xx needs exactly one Content-Type from its profile's list, with charset absent or utf-8.
		for (String contentType : List.of("text/html", "text/plain; charset=utf-8", "application/jwk-set+json",
				"application/jwt", "application/json; charset=iso-8859-1", "application/json; charset=utf-16",
				"application/json; charset=\"utf-16\"", "application/json; charset=utf-8; charset=utf-8",
				"application/json;charset", "application/json, text/plain", "application /json", "application/jsonp",
				"application/json+x", "*/*", "application/*", "json", ""))
			cases.add(onJdkServer("METADATA with Content-Type \"" + contentType + "\"", Kind.MEDIA_TYPE)
					.profile(ResponseProfile.METADATA).header("Content-Type", contentType).json().build());
		cases.add(onJdkServer("METADATA with no Content-Type", Kind.MEDIA_TYPE)
				.profile(ResponseProfile.METADATA).json().build());
		cases.add(onJdkServer("METADATA with two application/json Content-Type fields", Kind.MEDIA_TYPE)
				.profile(ResponseProfile.METADATA).header("Content-Type", JSON).header("Content-Type", JSON).json()
				.build());
		cases.add(onJdkServer("TOKEN with Content-Type text/plain", Kind.MEDIA_TYPE)
				.profile(ResponseProfile.TOKEN).header("Content-Type", "text/plain").json().build());
		cases.add(onJdkServer("INTROSPECTION with Content-Type application/token-introspection+jwt", Kind.MEDIA_TYPE)
				.profile(ResponseProfile.INTROSPECTION).header("Content-Type", "application/token-introspection+jwt")
				.json().build());
		for (String contentType : List.of("application/jwt", "application/jwk+json", "text/plain",
				"application/jwk-set+json; charset=iso-8859-1"))
			cases.add(onJdkServer("JWKS with Content-Type \"" + contentType + "\"", Kind.MEDIA_TYPE)
					.profile(ResponseProfile.JWKS).header("Content-Type", contentType).json().build());
		for (String contentType : List.of("application/jwk-set+json", "text/plain", "application/jose"))
			cases.add(onJdkServer("USERINFO with Content-Type \"" + contentType + "\"", Kind.MEDIA_TYPE)
					.profile(ResponseProfile.USERINFO).header("Content-Type", contentType).json().build());

		// The JDK refuses a response head it cannot parse with a ProtocolException before any Revetsec check, and
		// leaves the connection open: one connection per call, held for as long as the server keeps it, although IO is
		// a transient failure a caller may retry (RawTlsServer's class documentation). So the client close cannot be
		// shown. A few bytes are enough: a header section over jdk.http.maxHeaderSize (384 KiB by default), a status
		// line the JDK cannot parse, or a header name that is not a token.
		cases.add(raw("a 512 KiB header section", Kind.IO)
				.header("Content-Type", JSON).header("X-Filler", "a".repeat(512 * 1024)).header("Content-Length", "7")
				.json().clientCloseNotObservable().build());
		cases.add(raw("an invalid status line", Kind.IO)
				.statusLine("HTTP/1.1 099 X")
				.header("Content-Type", JSON).header("Content-Length", "7").json().clientCloseNotObservable().build());
		cases.add(raw("an invalid header name", Kind.IO)
				.header("Content-Type", JSON).header("Bad Name", "x").header("Content-Length", "7").json()
				.clientCloseNotObservable().build());

		return List.copyOf(cases);
	}

	/**
	 * Paced or stalled responses that end in {@link Kind#TIMEOUT} under a short deadline or request timeout (exit
	 * criterion 11). Each is sent by {@link RawTlsServer} and keeps it busy for minutes unless the client gives up.
	 *
	 * @return the cases, in a fixed order
	 */
	public static List<HostileResponse> timeouts() {
		return List.of(
				raw("a trickled body", Kind.TIMEOUT)
						.header("Content-Type", JSON).header("Content-Length", "100000")
						.pacing(new Pacing(PacingKind.TRICKLE_BODY, 100_000))
						.build(),
				raw("a chunked body that stalls after its first chunk", Kind.TIMEOUT)
						.header("Content-Type", JSON).header("Transfer-Encoding", "chunked")
						.pacing(new Pacing(PacingKind.STALL_AFTER_FIRST_CHUNK, 0))
						.build(),
				raw("a response that stalls after its headers", Kind.TIMEOUT)
						.header("Content-Type", JSON).header("Content-Length", "100")
						.pacing(new Pacing(PacingKind.STALL_AFTER_HEAD, 0))
						.build(),
				raw("headers that trickle in", Kind.TIMEOUT)
						.header("Content-Type", JSON).header("X-Filler", "a".repeat(20_000))
						.pacing(new Pacing(PacingKind.TRICKLE_HEAD, 0))
						.build(),
				raw("a server that never answers", Kind.TIMEOUT)
						.pacing(new Pacing(PacingKind.SILENT, 0))
						.build());
	}

	/**
	 * {@link #rejections()} followed by {@link #timeouts()}.
	 *
	 * @return every case
	 */
	public static List<HostileResponse> all() {
		List<HostileResponse> cases = new ArrayList<>(rejections());
		cases.addAll(timeouts());
		return List.copyOf(cases);
	}

	/**
	 * The catalog a JSON Web Key Set fetch runs (M2 plan, "Exceptions, transience and observers"; exit criterion 14),
	 * every case requested under {@link ResponseProfile#JWKS} with the default limits: 256 KiB for a 2xx body
	 * ({@link Limits#JWKS_RESPONSE_BODY_SIZE}) and 16 KiB for an error body. In order:
	 * <ol>
	 *   <li>every {@link #rejections()} case that {@link #appliesTo(ResponseProfile) applies} to JWKS: the JWKS
	 *   media-type cases as they are, and every other one under JWKS, named with {@link #JWKS_NAME_SUFFIX}. Among them
	 *   are {@code "an invalid status line (JWKS)"}, which the JDK refuses as {@link Kind#IO}, and the 304, which is
	 *   {@link Kind#REDIRECT} because there are no conditional requests;</li>
	 *   <li>JWKS-only cases, named from {@code "JWKS: "}: a 300 KiB body without a {@code Content-Length}, chunked and
	 *   close-delimited (exit criterion 15), a body one byte over the JWKS body limit in three forms, a 304 without
	 *   a {@code Location}, and more {@code Content-Type} fields a key set must not carry;</li>
	 *   <li>every {@link #timeouts()} case under JWKS, last, so callers can split the list with {@link #isPaced()}.</li>
	 * </ol>
	 * Each case keeps its expected {@link Kind}, or its dropped error status. A JWKS source maps them through its own
	 * table: the kind's category and transience, and for a dropped status, {@code REMOTE_ERROR}, transient on 429 and
	 * 5xx.
	 *
	 * @return the cases, in a fixed order, with unique names
	 */
	public static List<HostileResponse> jwks() {
		List<HostileResponse> cases = new ArrayList<>();

		for (HostileResponse hostileResponse : rejections())
			if (hostileResponse.appliesTo(ResponseProfile.JWKS))
				cases.add(hostileResponse.underJwks());

		// Exit criterion 15: a key set that streams past the 256 KiB JWKS limit without a Content-Length is aborted,
		// chunked or close-delimited; and one byte over the limit is enough, chunked, with a Content-Length, or declared
		// by a Content-Length whose body never comes.
		cases.add(onJdkServer("JWKS: 300 KiB chunked 2xx", Kind.TOO_LARGE)
				.profile(ResponseProfile.JWKS).header("Content-Type", JWK_SET).body(JWKS_OVERSIZED_BODY_BYTES)
				.framing(Framing.CHUNKED).build());
		cases.add(raw("JWKS: 300 KiB close-delimited 2xx", Kind.TOO_LARGE)
				.profile(ResponseProfile.JWKS).header("Content-Type", JWK_SET).body(JWKS_OVERSIZED_BODY_BYTES)
				.framing(Framing.CLOSE_DELIMITED).build());
		cases.add(onJdkServer("JWKS: chunked 2xx one byte over the JWKS body limit", Kind.TOO_LARGE)
				.profile(ResponseProfile.JWKS).header("Content-Type", JWK_SET).body(DEFAULT_JWKS_BODY_LIMIT + 1)
				.framing(Framing.CHUNKED).build());
		cases.add(onJdkServer("JWKS: fixed-length 2xx one byte over the JWKS body limit", Kind.TOO_LARGE)
				.profile(ResponseProfile.JWKS).header("Content-Type", JWK_SET).body(DEFAULT_JWKS_BODY_LIMIT + 1).build());
		cases.add(raw("JWKS: 2xx declaring one byte over the JWKS body limit that never sends its body", Kind.TOO_LARGE)
				.profile(ResponseProfile.JWKS).header("Content-Type", JWK_SET)
				.header("Content-Length", String.valueOf(DEFAULT_JWKS_BODY_LIMIT + 1)).bodyNeverSent().build());

		// M2-8: there are no conditional requests, so a 304 is a redirect like any 3xx, with or without a Location.
		cases.add(raw("JWKS: 304 Not Modified without a Location", Kind.REDIRECT)
				.profile(ResponseProfile.JWKS).status(304, "Not Modified").header("Content-Length", "0").build());

		// G6-7: a key set needs exactly one Content-Type, application/jwk-set+json or application/json, with no
		// charset but utf-8.
		cases.add(onJdkServer("JWKS: no Content-Type", Kind.MEDIA_TYPE)
				.profile(ResponseProfile.JWKS).json().build());
		cases.add(onJdkServer("JWKS: two Content-Type fields", Kind.MEDIA_TYPE)
				.profile(ResponseProfile.JWKS).header("Content-Type", JWK_SET).header("Content-Type", JSON).json()
				.build());
		for (String contentType : List.of("application/jwk-set+json, application/json",
				"application/jwk-set+json; charset=utf-16", "application/jwks+json", "application/jwk-set",
				"text/json"))
			cases.add(onJdkServer("JWKS: Content-Type \"" + contentType + "\"", Kind.MEDIA_TYPE)
					.profile(ResponseProfile.JWKS).header("Content-Type", contentType).json().build());

		for (HostileResponse hostileResponse : timeouts())
			cases.add(hostileResponse.underJwks());

		return List.copyOf(cases);
	}

	/**
	 * Scripts this case on {@code server} at {@code path}.
	 *
	 * @param server the server
	 * @param path the path, starting with {@code /}
	 * @throws IllegalStateException if the case's transport is {@link Transport#RAW_TLS_SERVER}
	 */
	public void installOn(TestHttpsServer server, String path) {
		requireNonNull(server);
		requireNonNull(path);
		if (this.transport != Transport.TEST_HTTPS_SERVER)
			throw new IllegalStateException(this.name + " needs RawTlsServer");
		TestHttpsServer.Response.Builder response = TestHttpsServer.Response.withStatus(this.status);
		for (List<String> header : headersFor(path))
			response.header(header.get(0), header.get(1));
		response.body(body());
		response.framing(this.framing == Framing.CHUNKED ? TestHttpsServer.Framing.CHUNKED
				: TestHttpsServer.Framing.FIXED_LENGTH);
		server.script(path, TestHttpsServer.Script.fromResponse(response.build()));
	}

	/**
	 * Scripts this case on {@code server} at {@code path}, as exact bytes. Every case can run here.
	 *
	 * @param server the server
	 * @param path the path, starting with {@code /}
	 */
	public void installOn(RawTlsServer server, String path) {
		requireNonNull(server);
		requireNonNull(path);
		server.script(path, rawScript(path));
	}

	/**
	 * The path a redirect's {@code Location} names when the case is installed at {@code path}.
	 *
	 * @param path the installed path
	 * @return the redirect target's path
	 */
	public static String redirectTargetPath(String path) {
		return requireNonNull(path) + REDIRECT_TARGET_SUFFIX;
	}

	/**
	 * A request for this case with the default limits and timeout, as the protocols send it.
	 *
	 * @param uri the installed case's URI
	 * @return the request
	 */
	public HttpExchangeRequest requestFor(URI uri) {
		return HttpExchangeRequest.fromDefaults(uri, this.profile);
	}

	/**
	 * The case's name, used as the test's display name.
	 *
	 * @return the name
	 */
	public String getName() {
		return this.name;
	}

	/**
	 * Which server the case is defined for.
	 *
	 * @return the transport
	 */
	public Transport getTransport() {
		return this.transport;
	}

	/**
	 * The profile to request the case with.
	 *
	 * @return the profile
	 */
	public ResponseProfile getProfile() {
		return this.profile;
	}

	/**
	 * Whether the case's expectation holds when it is requested under {@code profile}: a media-type case only under
	 * its own profile, and every other case under any profile, because its body is small JSON or larger than every
	 * default body limit and its {@code Content-Type}, if any, is {@code application/json}. The protocol milestones use
	 * it to pick the cases for their endpoint.
	 *
	 * @param profile the profile the caller's endpoint uses
	 * @return whether the expectation holds under {@code profile}
	 */
	public Boolean appliesTo(ResponseProfile profile) {
		requireNonNull(profile);
		return this.expectedKind != Kind.MEDIA_TYPE || this.profile == profile;
	}

	/**
	 * The kind the exchange must fail with, or empty when it must return a dropped error body.
	 *
	 * @return the expected kind
	 */
	public Optional<Kind> getExpectedKind() {
		return Optional.ofNullable(this.expectedKind);
	}

	/**
	 * The status a dropped error body keeps, or empty when the exchange must fail.
	 *
	 * @return the expected status
	 */
	public Optional<Integer> getExpectedDroppedStatus() {
		return Optional.ofNullable(this.expectedDroppedStatus);
	}

	/**
	 * Whether the response is a redirect whose {@link #redirectTargetPath(String)} must never be requested.
	 *
	 * @return {@code true} for the 3xx cases
	 */
	public Boolean isRedirect() {
		return this.redirect;
	}

	/**
	 * Whether the body is larger than any socket buffer, so the server sees the client abort it.
	 *
	 * @return {@code true} for the 12 MiB bodies
	 */
	public Boolean isServerAbortObservable() {
		return this.serverAbortObservable;
	}

	/**
	 * Whether the client closes the connection after the exchange on the running JDK, which {@link RawTlsServer} can
	 * show. It is {@code false} only where the JDK refuses the response itself and leaves the connection open: a
	 * response head it cannot parse, on every JDK, and a 204 with a {@code Content-Length} it cannot parse, before JDK
	 * 27.
	 *
	 * @return whether the client close is observable
	 */
	public Boolean isClientCloseObservable() {
		return Runtime.version().feature() >= this.clientCloseObservableFrom;
	}

	/**
	 * Whether the case is paced or stalled, so only a short deadline ends it.
	 *
	 * @return {@code true} for {@link #timeouts()}
	 */
	public Boolean isPaced() {
		return this.pacing != null;
	}

	@Override
	public String toString() {
		return this.name;
	}

	/**
	 * This case under {@link ResponseProfile#JWKS}: itself if it already is, otherwise a copy named with
	 * {@link #JWKS_NAME_SUFFIX}.
	 */
	private HostileResponse underJwks() {
		if (this.profile == ResponseProfile.JWKS)
			return this;
		return new HostileResponse(this, this.name + JWKS_NAME_SUFFIX, ResponseProfile.JWKS);
	}

	private List<List<String>> headersFor(String path) {
		List<List<String>> headersForPath = new ArrayList<>(this.headers);
		if (this.redirect) {
			headersForPath.add(List.of("Location", redirectTargetPath(path)));
			headersForPath.add(List.of("Content-Type", JSON));
		}
		return headersForPath;
	}

	private byte[] body() {
		if (this.jsonBody)
			return SMALL_JSON.clone();
		byte[] body = new byte[this.bodyBytes];
		Arrays.fill(body, (byte) 'a');
		return body;
	}

	private RawTlsServer.Script rawScript(String path) {
		StringBuilder head = new StringBuilder(this.statusLine).append("\r\n");
		for (List<String> header : headersFor(path))
			head.append(header.get(0)).append(": ").append(header.get(1)).append("\r\n");
		byte[] body = this.pacing == null ? body() : new byte[0];
		switch (this.framing) {
			case CONTENT_LENGTH -> head.append("Content-Length: ").append(body.length).append("\r\n");
			case CHUNKED -> head.append("Transfer-Encoding: chunked\r\n");
			case CLOSE_DELIMITED, VERBATIM -> {
				// The case's own headers, or none, frame the body.
			}
		}
		head.append("\r\n");
		byte[] headBytes = head.toString().getBytes(StandardCharsets.ISO_8859_1);

		RawTlsServer.Script.Builder script = RawTlsServer.Script.builder();
		if (this.pacing != null)
			return this.pacing.script(script, headBytes);
		if (this.bodyNeverSent)
			return script.write(headBytes).stall().build();
		script.write(headBytes);
		script.write(this.framing == Framing.CHUNKED ? chunked(body) : body);
		if (this.framing == Framing.CLOSE_DELIMITED)
			script.endOfStream();
		return script.build();
	}

	private static byte[] chunked(byte[] body) {
		ByteArrayOutputStream chunked = new ByteArrayOutputStream(body.length + body.length / 1024 + 16);
		for (int offset = 0; offset < body.length; offset += RAW_CHUNK_BYTES) {
			int length = Math.min(RAW_CHUNK_BYTES, body.length - offset);
			chunked.writeBytes((Integer.toHexString(length) + "\r\n").getBytes(StandardCharsets.US_ASCII));
			chunked.write(body, offset, length);
			chunked.writeBytes("\r\n".getBytes(StandardCharsets.US_ASCII));
		}
		chunked.writeBytes("0\r\n\r\n".getBytes(StandardCharsets.US_ASCII));
		return chunked.toByteArray();
	}

	private static Builder onJdkServer(String name, @Nullable Kind expectedKind) {
		return new Builder(name, Transport.TEST_HTTPS_SERVER, expectedKind);
	}

	private static Builder raw(String name, @Nullable Kind expectedKind) {
		return new Builder(name, Transport.RAW_TLS_SERVER, expectedKind).framing(Framing.VERBATIM);
	}

	/**
	 * How a paced case is sent.
	 */
	@Immutable
	private enum PacingKind {
		TRICKLE_BODY,
		STALL_AFTER_FIRST_CHUNK,
		STALL_AFTER_HEAD,
		TRICKLE_HEAD,
		SILENT
	}

	/**
	 * The pacing of a {@link #timeouts()} case. The server's own scheduler paces trickled writes (A-2).
	 */
	@Immutable
	private static final class Pacing {
		private static final Duration INTERVAL = Duration.ofMillis(50);

		private final PacingKind kind;
		private final int bodyBytes;

		private Pacing(PacingKind kind, int bodyBytes) {
			this.kind = kind;
			this.bodyBytes = bodyBytes;
		}

		private RawTlsServer.Script script(RawTlsServer.Script.Builder script, byte[] head) {
			switch (this.kind) {
				case TRICKLE_BODY -> {
					byte[] body = new byte[this.bodyBytes];
					Arrays.fill(body, (byte) ' ');
					return script.write(head).trickle(body, 10, INTERVAL).build();
				}
				case STALL_AFTER_FIRST_CHUNK -> {
					return script.write(head).write("1\r\n{\r\n").stall().build();
				}
				case STALL_AFTER_HEAD -> {
					return script.write(head).stall().build();
				}
				case TRICKLE_HEAD -> {
					return script.trickle(head, 10, INTERVAL).stall().build();
				}
				case SILENT -> {
					return script.stall().build();
				}
			}
			throw new IllegalStateException("Unknown pacing " + this.kind);
		}
	}

	/**
	 * Builds one case; the defaults are a 200 with a small JSON body and the {@link ResponseProfile#TOKEN} profile.
	 */
	@NotThreadSafe
	private static final class Builder {
		private final String name;
		private final Transport transport;
		private final @Nullable Kind expectedKind;
		private @Nullable Integer expectedDroppedStatus;
		private String statusLine = "HTTP/1.1 200 OK";
		private Integer status = 200;
		private ResponseProfile profile = ResponseProfile.TOKEN;
		private final List<List<String>> headers = new ArrayList<>();
		private Integer bodyBytes = 0;
		private boolean jsonBody;
		private Framing framing = Framing.CONTENT_LENGTH;
		private boolean redirect;
		/**
		 * The first JDK feature release on which the client closes the connection: 0 for every JDK.
		 */
		private int clientCloseObservableFrom;
		private boolean bodyNeverSent;
		private @Nullable Pacing pacing;

		private Builder(String name, Transport transport, @Nullable Kind expectedKind) {
			this.name = name;
			this.transport = transport;
			this.expectedKind = expectedKind;
		}

		private Builder status(int status, String reason) {
			this.status = status;
			this.statusLine = "HTTP/1.1 " + status + " " + reason;
			return this;
		}

		private Builder statusLine(String statusLine) {
			this.statusLine = statusLine;
			this.status = Integer.parseInt(statusLine.split(" ", 3)[1]);
			return this;
		}

		private Builder profile(ResponseProfile profile) {
			this.profile = profile;
			return this;
		}

		private Builder dropped(int status) {
			this.expectedDroppedStatus = status;
			return this;
		}

		private Builder header(String name, String value) {
			this.headers.add(List.of(name, value));
			return this;
		}

		private Builder json() {
			this.jsonBody = true;
			this.bodyBytes = SMALL_JSON.length;
			return this;
		}

		private Builder body(int bodyBytes) {
			this.jsonBody = false;
			this.bodyBytes = bodyBytes;
			return this;
		}

		private Builder framing(Framing framing) {
			this.framing = framing;
			return this;
		}

		private Builder redirect() {
			this.redirect = true;
			return this;
		}

		private Builder bodyNeverSent() {
			this.bodyNeverSent = true;
			return this;
		}

		private Builder clientCloseNotObservable() {
			this.clientCloseObservableFrom = Integer.MAX_VALUE;
			return this;
		}

		private Builder clientCloseObservableFrom(int feature) {
			this.clientCloseObservableFrom = feature;
			return this;
		}

		private Builder pacing(Pacing pacing) {
			this.pacing = pacing;
			return this;
		}

		private HostileResponse build() {
			if (this.framing == Framing.VERBATIM && this.pacing == null && this.transport == Transport.RAW_TLS_SERVER
					&& this.headers.stream().noneMatch(header -> isFramingHeader(header.get(0))))
				throw new IllegalStateException(this.name + ": a verbatim case names its own framing");
			return new HostileResponse(this);
		}

		private static boolean isFramingHeader(String name) {
			String lowerCase = name.toLowerCase(Locale.ROOT);
			return lowerCase.equals("content-length") || lowerCase.equals("transfer-encoding");
		}
	}
}
