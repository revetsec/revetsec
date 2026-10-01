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

package com.revetsec.oauth;

import org.junit.jupiter.api.Test;
import java.util.List;
import static org.junit.jupiter.api.Assertions.*;

final class BearerTokenResultTests {
    @Test
    void absentIsDistinctFromMalformedAndPresentRemainsUnverified() {
        assertInstanceOf(BearerTokenResult.Absent.class, BearerToken.fromAuthorizationHeaderValuesResult(List.of()));
        String credential = "TEST-ONLY-secret._~+/==";
        BearerTokenResult.Present present = assertInstanceOf(BearerTokenResult.Present.class,
                BearerToken.fromAuthorizationHeaderValuesResult(List.of("bEaReR   " + credential)));
        assertEquals(credential, present.getToken().value());
        assertFalse(present.toString().contains(credential));
        assertFalse(present.getToken().toString().contains(credential));
    }

    @Test
    void invalidGrammarAndDuplicatesYieldMalformedWithTheSameLegacyVerdict() {
        for (List<String> fields : List.of(List.of(""), List.of("Bearer"), List.of("Basic secret"),
                List.of("Bearer\tsecret"), List.of(" Bearer secret"), List.of("Bearer secret "),
                List.of("Bearer x,y"), List.of("Bearer x\r\n"), List.of("Bearer é"),
                List.of("Bearer ="), List.of("Bearer x=y"), List.of("Bearer a", "Bearer a"))) {
            BearerTokenResult malformed = BearerToken.fromAuthorizationHeaderValuesResult(fields);
            assertInstanceOf(BearerTokenResult.Malformed.class, malformed);
            assertEquals(AccessTokenValidationException.Reason.MALFORMED_REQUEST,
                    assertThrows(AccessTokenValidationException.class,
                            () -> BearerToken.fromAuthorizationHeaderValues(fields)).getReason());
            assertFalse(malformed.toString().contains("secret"));
        }
    }

    @Test
    void configuredCredentialAndPrefixBoundsAreCheckedBeforeCopying() {
        assertInstanceOf(BearerTokenResult.Present.class,
                BearerToken.fromAuthorizationHeaderValuesResult(List.of("Bearer " + "a".repeat(8192)), 8192));
        assertInstanceOf(BearerTokenResult.Malformed.class,
                BearerToken.fromAuthorizationHeaderValuesResult(List.of("Bearer " + "a".repeat(8193)), 8192));
        assertInstanceOf(BearerTokenResult.Present.class,
                BearerToken.fromAuthorizationHeaderValuesResult(List.of("Bearer" + " ".repeat(58) + "a"), 8192));
        assertInstanceOf(BearerTokenResult.Malformed.class,
                BearerToken.fromAuthorizationHeaderValuesResult(List.of("Bearer" + " ".repeat(59) + "a"), 8192));
        assertThrows(IllegalArgumentException.class,
                () -> BearerToken.fromAuthorizationHeaderValuesResult(List.of(), 8191));
    }

    @SuppressWarnings("NullAway") // Deliberate required-argument misuse.
    @Test
    void nullArgumentsRemainMisuseAndDuplicateCardinalityPrecedesElementAccess() {
        assertThrows(NullPointerException.class, () -> BearerToken.fromAuthorizationHeaderValuesResult(null));
        assertThrows(NullPointerException.class, () -> BearerToken.fromAuthorizationHeaderValuesResult(List.of(), null));
        assertThrows(NullPointerException.class, () -> BearerToken.fromAuthorizationHeaderValuesResult(java.util.Arrays.asList((String) null)));
        assertInstanceOf(BearerTokenResult.Malformed.class,
                BearerToken.fromAuthorizationHeaderValuesResult(java.util.Arrays.asList(null, "Bearer x")));
    }
}
