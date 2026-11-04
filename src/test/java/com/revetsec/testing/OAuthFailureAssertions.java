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

import com.revetsec.oauth.*;
import org.jspecify.annotations.NonNull;
import static org.junit.jupiter.api.Assertions.*;

/** Fixed failure data may be shared; mutable throwable state belongs to one caller. */
public final class OAuthFailureAssertions {
    private OAuthFailureAssertions() { }
    public static void assertIndependentFailure(@NonNull OAuthException expected, @NonNull OAuthException actual) {
        assertNotSame(expected, actual);
        assertEquals(expected.getClass(), actual.getClass());
        assertEquals(expected.getReason(), actual.getReason());
        assertEquals(expected.getCategory(), actual.getCategory());
        assertEquals(expected.isTransient(), actual.isTransient());
        assertEquals(0, actual.getSuppressed().length);
        assertNull(actual.getCause());
        if (expected instanceof OAuthErrorResponseException error) {
            OAuthErrorResponseException copy = assertInstanceOf(OAuthErrorResponseException.class, actual);
            assertEquals(error.getStatus(), copy.getStatus());
            assertEquals(error.getErrorCode(), copy.getErrorCode());
            assertEquals(error.getRetryAfter(), copy.getRetryAfter());
        }
    }
}
