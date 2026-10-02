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

import org.jspecify.annotations.NonNull;

import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.stream.Stream;

/**
 * The runtime floor for networked builders (plan section 9.6 and D2; CVE-2022-21449; exit criterion 13): 17.0.3 on
 * 17 and 18.0.1 on 18, compared with {@code compareToIgnoreOptional}, failing closed on pre-releases and unusual
 * version strings, with an explicit acknowledgment as the only way past it.
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 */
final class RuntimeFloorTests {
	// M1 plan, the RuntimeFloor parse table [verified], plus the neighbours that pin each comparison.
	@TestFactory
	@NonNull Stream<@NonNull DynamicTest> classifiesThePlansVersionTable() {
		Map<String, Boolean> belowFloor = new LinkedHashMap<>();
		// The plan's table.
		belowFloor.put("17.0.2", true);
		belowFloor.put("17.0.3", false);
		belowFloor.put("17.0.3+7-LTS", false);
		belowFloor.put("17-ea", true);
		belowFloor.put("17.0.2.0.1", true);
		belowFloor.put("18", true);
		belowFloor.put("18.0.1", false);
		// Neighbours.
		belowFloor.put("17", true);
		belowFloor.put("17.0.1", true);
		belowFloor.put("17.0.2+8", true);
		belowFloor.put("17.0.3-ea", true);
		belowFloor.put("17.0.3.0.1", false);
		belowFloor.put("17.0.20.1", false);
		belowFloor.put("17.1", false);
		belowFloor.put("18.0.0.1", true);
		belowFloor.put("18.0.1-ea", true);
		belowFloor.put("18.0.2", false);
		belowFloor.put("19", false);
		belowFloor.put("19-ea", false);
		belowFloor.put("21.0.11", false);
		belowFloor.put("27", false);
		belowFloor.put("16.0.2", true);
		belowFloor.put("11.0.25", true);

		return belowFloor.entrySet().stream().map(entry -> DynamicTest.dynamicTest(entry.getKey(), () -> {
			Runtime.Version version = Runtime.Version.parse(entry.getKey());
			Assertions.assertEquals(entry.getValue(), RuntimeFloor.isBelowFloor(version));
			if (entry.getValue())
				Assertions.assertThrows(IllegalStateException.class, () -> RuntimeFloor.require(version, false));
			else
				Assertions.assertDoesNotThrow(() -> RuntimeFloor.require(version, false));
			// The acknowledgment (acknowledgeUnpatchedRuntime(true)) lets every version through.
			Assertions.assertDoesNotThrow(() -> RuntimeFloor.require(version, true));
		}));
	}

	// Plan section 9.6: the refusal says what to do, and names the version and the floor.
	@Test
	void theRefusalNamesTheVersionTheFloorAndTheEscapeHatch() {
		IllegalStateException exception = Assertions.assertThrows(IllegalStateException.class,
				() -> RuntimeFloor.require(Runtime.Version.parse("17.0.2"), false));
		String message = String.valueOf(exception.getMessage());
		Assertions.assertTrue(message.contains("17.0.2"), message);
		Assertions.assertTrue(message.contains("17.0.3"), message);
		Assertions.assertTrue(message.contains("18.0.1"), message);
		Assertions.assertTrue(message.contains("acknowledgeUnpatchedRuntime(true)"), message);
	}

	// The JDKs Revetsec is built and tested on are all above the floor, so builders pass without an acknowledgment.
	@Test
	void theRunningJvmPasses() {
		Assertions.assertFalse(RuntimeFloor.isBelowFloor(Runtime.version()));
		Assertions.assertDoesNotThrow(() -> RuntimeFloor.require(false));
	}

	@Test
	void nullArgumentsThrowNullPointerException() {
		Assertions.assertThrows(NullPointerException.class, () -> RuntimeFloor.require(nullValue(), false));
		Assertions.assertThrows(NullPointerException.class,
				() -> RuntimeFloor.require(Runtime.version(), nullValue()));
		Assertions.assertThrows(NullPointerException.class, () -> RuntimeFloor.require(nullBoolean()));
		Assertions.assertThrows(NullPointerException.class, () -> RuntimeFloor.isBelowFloor(nullValue()));
	}

	@SuppressWarnings("NullAway")
	private static @NonNull Boolean nullBoolean() {
		return nullValue();
	}

	@SuppressWarnings({"NullAway", "TypeParameterUnusedInFormals"})
	private static <T> @NonNull T nullValue() {
		@Nullable T value = null;
		return value;
	}
}
