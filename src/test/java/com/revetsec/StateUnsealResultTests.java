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

import com.revetsec.testing.TestClock;
import com.revetsec.testing.TestSealers;
import org.junit.jupiter.api.Test;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import static org.junit.jupiter.api.Assertions.*;

final class StateUnsealResultTests {
    @Test
    void successIsAuthenticatedForItsContextAndDiagnosticTextIsRedacted() {
        StateSealer sealer = TestSealers.fromFixedKey();
        String secret = "TEST-ONLY-private-plaintext";
        String sealed = sealer.seal(secret, "context", Duration.ofMinutes(1));
        StateUnsealResult.Succeeded success = assertInstanceOf(StateUnsealResult.Succeeded.class,
                sealer.unsealResult(sealed, "context"));
        assertEquals(secret, success.getValue());
        assertFalse(success.toString().contains(secret));
        assertFalse(success.toString().contains(sealed));
        assertInstanceOf(StateUnsealResult.Rejected.class, sealer.unsealResult(sealed, "other-context"));
    }

    @Test
    void malformedTamperedWrongKeyAndExactExpiryShareOneOpaqueOutcome() {
        TestClock clock = TestClock.fromInstant(Instant.parse("2026-10-01T12:00:00Z"));
        StateSealer sealer = StateSealer.withActiveKey(TestSealers.fixedKey("result-key")).clock(clock).build();
        String sealed = sealer.seal("TEST-ONLY-private", "context", Duration.ofSeconds(1));
        StateSealer other = TestSealers.fromFixedKeys("other-key", List.of());
        StateUnsealResult wrongKey = other.unsealResult(sealed, "context");
        StateUnsealResult malformed = sealer.unsealResult("%%%", "context");
        StateUnsealResult tampered = sealer.unsealResult(sealed.substring(0, sealed.length() - 1), "context");
        clock.advance(Duration.ofSeconds(1));
        StateUnsealResult expired = sealer.unsealResult(sealed, "context");
        for (StateUnsealResult result : List.of(wrongKey, malformed, tampered, expired)) {
            assertInstanceOf(StateUnsealResult.Rejected.class, result);
            assertEquals(malformed.toString(), result.toString());
            assertEquals(0, result.getClass().getDeclaredFields().length);
        }
        assertThrows(InvalidSealedStateException.class, () -> sealer.unseal(sealed, "context"));
    }

    @SuppressWarnings("NullAway") // Deliberate required-argument misuse.
    @Test
    void badContextAndNullStillThrow() {
        StateSealer sealer = TestSealers.fromFixedKey();
        assertThrows(NullPointerException.class, () -> sealer.unsealResult(null, "context"));
        assertThrows(NullPointerException.class, () -> sealer.unsealResult("bad", null));
        assertThrows(IllegalArgumentException.class, () -> sealer.unsealResult("bad", ""));
    }
}
