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

package com.revetsec.internal.jose;

import com.revetsec.internal.encoding.EncodingException;
import com.revetsec.internal.encoding.StrictUtf8;
import com.revetsec.internal.json.JsonCodec;
import com.revetsec.internal.json.JsonLimits;
import com.revetsec.internal.json.JsonParseException;
import com.revetsec.jose.JoseException;
import com.revetsec.json.JsonArray;
import com.revetsec.json.JsonObject;
import com.revetsec.json.JsonValue;
import org.jspecify.annotations.NonNull;

import javax.annotation.concurrent.ThreadSafe;
import java.util.ArrayList;
import java.util.List;

import static java.util.Objects.requireNonNull;

/**
 * Parses a JSON Web Key Set document (RFC 7517 section 5) into a {@link ParsedKeySet}, for both the static and the
 * remote key source, so a document is accepted the same way on either path.
 * <p>
 * <strong>Document failures</strong> reject the whole document with {@link JoseException.Reason#KEY_SET}:
 * <ul>
 *   <li>more bytes than the size limit;</li>
 *   <li>not strict UTF-8 JSON under the protocol-document profile ({@link JsonLimits#protocolDocument(Integer)}), which
 *   rejects duplicate member names, a byte-order mark and anything past the structural limits;</li>
 *   <li>not a JSON object, or its {@code keys} member absent or not an array;</li>
 *   <li>more elements in {@code keys} than the key limit, which counts every element, usable or not;</li>
 *   <li>an element of {@code keys} that is not a JSON object.</li>
 * </ul>
 * Other members of the document are ignored. <strong>Each key</strong> then goes through {@link JwkParser}: a key
 * that breaks a rule is skipped with its reason and position, and never fails the set.
 * <p>
 * The parser does no I/O and keeps no state.
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 */
@ThreadSafe
public final class JwkSetParser {
	private static final String KEYS = "keys";

	private JwkSetParser() {
		// Static helpers only.
	}

	/**
	 * Parses a key set document from its UTF-8 bytes, such as a response body.
	 *
	 * @param document     the UTF-8 JSON text; not modified
	 * @param maximumBytes the size limit, from 1 byte to 4 MiB (the protocol-document profile's range)
	 * @param maximumKeys  the key limit, at least 1
	 * @return the usable keys and the skipped ones
	 * @throws NullPointerException     if {@code document} is {@code null}
	 * @throws IllegalArgumentException if a limit is out of range
	 * @throws JoseFailure              with {@link JoseException.Reason#KEY_SET} on a document failure
	 */
	@NonNull
	public static ParsedKeySet parse(byte @NonNull [] document,
																	 int maximumBytes,
																	 int maximumKeys) throws JoseFailure {
		requireNonNull(document);
		return parseDocument(document, limits(maximumBytes, maximumKeys), maximumKeys);
	}

	/**
	 * Parses a key set document given as text. It is encoded as UTF-8 first; text with an unpaired surrogate has no
	 * UTF-8 encoding and is a document failure.
	 *
	 * @param document     the JSON text
	 * @param maximumBytes the size limit of the UTF-8 encoding, from 1 byte to 4 MiB
	 * @param maximumKeys  the key limit, at least 1
	 * @return the usable keys and the skipped ones
	 * @throws NullPointerException     if {@code document} is {@code null}
	 * @throws IllegalArgumentException if a limit is out of range
	 * @throws JoseFailure              with {@link JoseException.Reason#KEY_SET} on a document failure
	 */
	@NonNull
	public static ParsedKeySet parse(@NonNull String document,
																	 int maximumBytes,
																	 int maximumKeys) throws JoseFailure {
		requireNonNull(document);
		JsonLimits limits = limits(maximumBytes, maximumKeys);

		// UTF-8 never has fewer bytes than UTF-16 has code units, so an oversized text is refused before it is encoded.
		if (document.length() > maximumBytes)
			throw keySetFailure();

		byte[] bytes;

		try {
			bytes = StrictUtf8.encode(document);
		} catch (EncodingException e) {
			throw keySetFailure();
		}

		return parseDocument(bytes, limits, maximumKeys);
	}

	/**
	 * The profile for {@code maximumBytes}, once both limits are checked.
	 */
	@NonNull
	private static JsonLimits limits(int maximumBytes,
																	 int maximumKeys) {
		if (maximumKeys < 1)
			throw new IllegalArgumentException("The key limit must be at least 1.");
		return JsonLimits.protocolDocument(maximumBytes);
	}

	@NonNull
	private static ParsedKeySet parseDocument(byte @NonNull [] document,
																						@NonNull JsonLimits limits,
																						int maximumKeys) throws JoseFailure {
		if (document.length > limits.getMaxInputBytes())
			throw keySetFailure();

		JsonValue root;

		try {
			root = JsonCodec.parse(document, limits);
		} catch (JsonParseException e) {
			throw keySetFailure();
		}

		if (!(root instanceof JsonObject object) || !(object.getMembers().get(KEYS) instanceof JsonArray keys))
			throw keySetFailure();

		List<@NonNull JsonValue> elements = keys.getElements();
		if (elements.size() > maximumKeys)
			throw keySetFailure();

		// Every element is checked before any key is parsed, so a document failure costs no key parsing.
		for (JsonValue element : elements)
			if (!(element instanceof JsonObject))
				throw keySetFailure();

		List<VerificationKey> usable = new ArrayList<>(elements.size());
		List<ParsedKeySet.Skip> skipped = new ArrayList<>();

		for (int index = 0; index < elements.size(); ++index) {
			try {
				usable.add(JwkParser.parse((JsonObject) elements.get(index)));
			} catch (SkippedKeyException e) {
				skipped.add(new ParsedKeySet.Skip(index, e.getReason()));
			}
		}

		return new ParsedKeySet(usable, skipped);
	}

	@NonNull
	private static JoseFailure keySetFailure() {
		return new JoseFailure(JoseException.Reason.KEY_SET);
	}
}
