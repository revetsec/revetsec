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

package com.revetsec.jose;

import org.jspecify.annotations.NonNull;

import com.revetsec.ErrorCategory;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;

import java.io.IOException;
import java.util.EnumSet;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Stream;

/**
 * The JOSE exceptions (plan M2-2, G6-1 to G6-3): the {@link JoseException.Reason} partition over the three leaves and
 * categories, with fixed messages, no cause and no transience; and {@link JsonWebKeySetUnavailableException}'s four
 * categories, one fixed message each, and a cause only for {@link ErrorCategory#TRANSPORT}.
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 */
final class JoseExceptionTests {
	/**
	 * Plan "Exceptions, transience and observers": each reason's leaf, transcribed.
	 */
	private static final Map<Class<? extends JoseException>, Set<JoseException.Reason>> PARTITION = Map.of(
			MalformedJoseInputException.class, EnumSet.of(JoseException.Reason.TOKEN_TOO_LARGE,
					JoseException.Reason.TOKEN_SYNTAX, JoseException.Reason.HEADER, JoseException.Reason.CLAIMS,
					JoseException.Reason.KEY_SET),
			UnsupportedJoseFeatureException.class, EnumSet.of(JoseException.Reason.ENCRYPTED_TOKEN,
					JoseException.Reason.JSON_SERIALIZATION, JoseException.Reason.CRITICAL_HEADER,
					JoseException.Reason.UNENCODED_PAYLOAD, JoseException.Reason.COMPRESSED_PAYLOAD,
					JoseException.Reason.NESTED_TOKEN),
			JwtValidationException.class, EnumSet.of(JoseException.Reason.ALGORITHM_NOT_ALLOWED,
					JoseException.Reason.UNTRUSTED_KEY_REFERENCE, JoseException.Reason.SIGNATURE_MALFORMED,
					JoseException.Reason.UNKNOWN_KEY, JoseException.Reason.AMBIGUOUS_KEY,
					JoseException.Reason.KEY_ALGORITHM_MISMATCH, JoseException.Reason.KEY_ISSUER_MISMATCH,
					JoseException.Reason.SIGNATURE_MISMATCH, JoseException.Reason.INVALID_TYPE,
					JoseException.Reason.ISSUER_MISMATCH, JoseException.Reason.AUDIENCE_MISMATCH,
					JoseException.Reason.MISSING_CLAIM, JoseException.Reason.EXPIRED, JoseException.Reason.NOT_YET_VALID,
					JoseException.Reason.ISSUED_IN_FUTURE, JoseException.Reason.CONFIRMATION_NOT_VERIFIED));

	private static final Map<Class<? extends JoseException>, ErrorCategory> CATEGORIES = Map.of(
			MalformedJoseInputException.class, ErrorCategory.MALFORMED_INPUT,
			UnsupportedJoseFeatureException.class, ErrorCategory.UNSUPPORTED,
			JwtValidationException.class, ErrorCategory.VALIDATION_FAILURE);

	// M2-2: every reason belongs to exactly one leaf, and the leaves cover every reason (27 in all).
	@Test
	void theReasonsArePartitionedOverTheThreeLeaves() {
		Set<JoseException.Reason> seen = new HashSet<>();
		for (Set<JoseException.Reason> reasons : PARTITION.values())
			for (JoseException.Reason reason : reasons)
				Assertions.assertTrue(seen.add(reason), reason::name);
		Assertions.assertEquals(EnumSet.allOf(JoseException.Reason.class), seen);
		Assertions.assertEquals(27, seen.size());
	}

	// Each reason builds its own leaf, with the leaf's category, a fixed one-sentence message, no cause, not transient
	// and nothing suppressed; a leaf refuses another leaf's reasons.
	@TestFactory
	@NonNull Stream<@NonNull DynamicTest> eachReasonBuildsItsLeafWithAFixedMessage() {
		Set<String> messages = new HashSet<>();
		return Stream.of(JoseException.Reason.values()).map(reason -> DynamicTest.dynamicTest(reason.name(), () -> {
			Class<? extends JoseException> leaf = PARTITION.entrySet().stream().filter(entry -> entry.getValue()
					.contains(reason)).findFirst().orElseThrow().getKey();
			JoseException exception = JoseException.fromReason(reason);

			Assertions.assertSame(leaf, exception.getClass());
			Assertions.assertSame(reason, exception.getReason());
			Assertions.assertEquals(CATEGORIES.get(leaf), exception.getCategory());
			Assertions.assertFalse(exception.isTransient());
			Assertions.assertNull(exception.getCause());
			exception.addSuppressed(new IllegalStateException());
			Assertions.assertEquals(0, exception.getSuppressed().length);
			String message = exception.getMessage();
			Assertions.assertNotNull(message);
			Assertions.assertTrue(message.endsWith("."), message);
			Assertions.assertTrue(messages.add(message), "one message per reason: " + message);
			Assertions.assertEquals(message, JoseException.fromReason(reason).getMessage());

			JoseException direct = leaf == MalformedJoseInputException.class ? MalformedJoseInputException.fromReason(reason)
					: leaf == UnsupportedJoseFeatureException.class ? UnsupportedJoseFeatureException.fromReason(reason)
					: JwtValidationException.fromReason(reason);
			Assertions.assertSame(leaf, direct.getClass());
			if (leaf != MalformedJoseInputException.class)
				Assertions.assertThrows(IllegalArgumentException.class, () -> MalformedJoseInputException.fromReason(reason));
			if (leaf != UnsupportedJoseFeatureException.class)
				Assertions.assertThrows(IllegalArgumentException.class,
						() -> UnsupportedJoseFeatureException.fromReason(reason));
			if (leaf != JwtValidationException.class)
				Assertions.assertThrows(IllegalArgumentException.class, () -> JwtValidationException.fromReason(reason));
		}));
	}

	// G6-2 and G6-3: a key set failure has TRANSPORT, REMOTE_ERROR, MALFORMED_INPUT or CONFIGURATION, one fixed message
	// per category, and is transient only where the category allows it.
	@Test
	void keySetFailuresHaveFourCategoriesWithFixedMessages() {
		Map<ErrorCategory, String> messages = Map.of(
				ErrorCategory.TRANSPORT, "The JSON Web Key Set could not be fetched.",
				ErrorCategory.REMOTE_ERROR, "The JSON Web Key Set endpoint answered with an error.",
				ErrorCategory.MALFORMED_INPUT, "The JSON Web Key Set response is malformed.",
				ErrorCategory.CONFIGURATION, "The JSON Web Key Set cannot be fetched in this configuration.");

		for (ErrorCategory category : ErrorCategory.values()) {
			if (!messages.containsKey(category)) {
				Assertions.assertThrows(IllegalArgumentException.class,
						() -> JsonWebKeySetUnavailableException.fromCategory(category, false), category::name);
				continue;
			}
			JsonWebKeySetUnavailableException exception = JsonWebKeySetUnavailableException.fromCategory(category, false);
			Assertions.assertEquals(category, exception.getCategory());
			Assertions.assertFalse(exception.isTransient());
			Assertions.assertNull(exception.getCause());
			Assertions.assertEquals(messages.get(category), exception.getMessage());

			boolean mayBeTransient = category == ErrorCategory.TRANSPORT || category == ErrorCategory.REMOTE_ERROR;
			if (mayBeTransient)
				Assertions.assertTrue(JsonWebKeySetUnavailableException.fromCategory(category, true).isTransient());
			else
				Assertions.assertThrows(IllegalArgumentException.class,
						() -> JsonWebKeySetUnavailableException.fromCategory(category, true), category::name);
		}
	}

	// Only the caller whose own request failed with an I/O error keeps the JDK's IOException, and only for TRANSPORT.
	@Test
	void onlyATransportFailureKeepsItsIoExceptionAsTheCause() {
		IOException cause = new IOException("connection reset");
		JsonWebKeySetUnavailableException withCause = JsonWebKeySetUnavailableException.fromCategory(
				ErrorCategory.TRANSPORT, true, cause);

		Assertions.assertSame(cause, withCause.getCause());
		Assertions.assertEquals("The JSON Web Key Set could not be fetched.", withCause.getMessage());
		Assertions.assertNull(JsonWebKeySetUnavailableException.fromCategory(ErrorCategory.TRANSPORT, false, null)
				.getCause());
		for (ErrorCategory category : List.of(ErrorCategory.REMOTE_ERROR, ErrorCategory.MALFORMED_INPUT,
				ErrorCategory.CONFIGURATION))
			Assertions.assertThrows(IllegalArgumentException.class,
					() -> JsonWebKeySetUnavailableException.fromCategory(category, false, cause), category::name);
	}
}
