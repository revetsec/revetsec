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

import org.junit.jupiter.api.Test;

import java.util.Base64;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

final class BindingTypesTests {
    @Test void freshBindingsUseTheUnchangedCanonical43CharacterFormat() {
        BrowserBinding browser = BrowserBinding.fresh();
        OperationBinding operation = OperationBinding.fresh();

        for (String value : new String[]{browser.toSecretString(), operation.toSecretString()}) {
            assertEquals(43, value.length());
            assertTrue(value.matches("[A-Za-z0-9_-]{43}"));
            assertEquals(32, Base64.getUrlDecoder().decode(value).length);
        }
    }

    @Test void browserRestorationCountsJavaCodeUnitsAndPreservesExactSpelling() {
        String exactBoundary = "\uD83D\uDE00".repeat(BrowserBinding.MAXIMUM_CODE_UNITS / 2);
        BrowserBinding restored = BrowserBinding.fromTrustedPersistence(exactBoundary);
        assertSame(exactBoundary, restored.toSecretString());
        assertEquals(BrowserBinding.MAXIMUM_CODE_UNITS, restored.toSecretString().length());

        assertThrows(IllegalArgumentException.class,
                () -> BrowserBinding.fromTrustedPersistence(exactBoundary + "x"));

        String unmatchedSurrogate = "saml-\uD800-binding";
        assertSame(unmatchedSurrogate,
                BrowserBinding.fromTrustedPersistence(unmatchedSurrogate).toSecretString());
    }

    @Test void operationRestorationRetainsTheExistingTotpBoundaryAndWellFormedness() {
        String exactBoundary = "a".repeat(OperationBinding.MAXIMUM_CODE_UNITS);
        assertSame(exactBoundary,
                OperationBinding.fromTrustedPersistence(exactBoundary).toSecretString());
        assertThrows(IllegalArgumentException.class,
                () -> OperationBinding.fromTrustedPersistence(exactBoundary + "a"));
        assertThrows(IllegalArgumentException.class,
                () -> OperationBinding.fromTrustedPersistence("operation-\uD800"));
    }

    @SuppressWarnings("NullAway") // Required-argument and empty-value boundary checks.
    @Test void emptyAndNullRestorationFailBeforeAProtocolOrStoreIsEntered() {
        assertThrows(NullPointerException.class,
                () -> BrowserBinding.fromTrustedPersistence(null));
        assertThrows(IllegalArgumentException.class,
                () -> BrowserBinding.fromTrustedPersistence(""));
        assertThrows(NullPointerException.class,
                () -> OperationBinding.fromTrustedPersistence(null));
        assertThrows(IllegalArgumentException.class,
                () -> OperationBinding.fromTrustedPersistence(""));
    }

    @Test void stringDescriptionsAreFixedAndRedacted() {
        String browserSecret = "TEST-ONLY-browser-secret";
        String operationSecret = "TEST-ONLY-operation-secret";
        String browserDescription = BrowserBinding.fromTrustedPersistence(browserSecret).toString();
        String operationDescription = OperationBinding.fromTrustedPersistence(operationSecret).toString();

        assertEquals("BrowserBinding{<redacted>}", browserDescription);
        assertEquals("OperationBinding{<redacted>}", operationDescription);
        assertFalse(browserDescription.contains(browserSecret));
        assertFalse(operationDescription.contains(operationSecret));
    }
}
