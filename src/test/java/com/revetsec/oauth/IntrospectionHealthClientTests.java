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

import com.revetsec.testing.TestHttpsServer;
import org.jspecify.annotations.NonNull;
import org.junit.jupiter.api.*;
import java.util.stream.Stream;
import static com.revetsec.oauth.Phase2Fixtures.*;
import static org.junit.jupiter.api.Assertions.*;

final class IntrospectionHealthClientTests {
    @TestFactory @NonNull Stream<@NonNull DynamicTest> tokenSpecificWafResponsesCannotDisableOtherCredentials() {
        return Stream.of(400,403,404,405,413,415,422,431).map(code -> DynamicTest.dynamicTest("status" + code, () -> {
            try (TestHttpsServer server = TestHttpsServer.start()) {
                response(server, "/inspect", code, "application/json", "{\"error\":\"invalid_request\"}");
                TokenIntrospectionClient client = inspect(server).build();
                assertEquals(code, assertInstanceOf(AccessTokenValidationResult.RejectedEndpoint.class,
                        client.validateResult(bearer("attacker-token"))).getStatus());
                response(server, "/inspect", 200, "application/json", active());
                assertInstanceOf(AccessTokenValidationResult.Succeeded.class, assertDoesNotThrow(() -> client.validateResult(bearer("legitimate-token"))));
                assertEquals(2, server.getHitCount("/inspect"));
            }
        }));
    }
    @TestFactory @NonNull Stream<@NonNull DynamicTest> aSingleServerErrorDoesNotDisableOtherCredentials() {
        return Stream.of(500,503).map(code -> DynamicTest.dynamicTest("status" + code, () -> {
            try (TestHttpsServer server = TestHttpsServer.start()) {
                response(server, "/inspect", code, "application/json", "{}");
                TokenIntrospectionClient client = inspect(server).build();
                assertThrows(OAuthErrorResponseException.class, () -> client.validateResult(bearer("attacker-token")));
                response(server, "/inspect", 200, "application/json", active());
                assertInstanceOf(AccessTokenValidationResult.Succeeded.class, assertDoesNotThrow(() -> client.validateResult(bearer("legitimate-token"))));
                assertEquals(2, server.getHitCount("/inspect"));
            }
        }));
    }
    @Test void repeatedServerErrorsOpenOnlyAnInfrastructureGuard() throws Exception {
        try (TestHttpsServer server = TestHttpsServer.start()) {
            response(server, "/inspect", 503, "application/json", "{}");
            TokenIntrospectionClient client = inspect(server).build();
            for (int n = 0; n < 3; n++) {
                int token = n;
                assertThrows(OAuthErrorResponseException.class, () -> client.validateResult(bearer("token-" + token)));
            }
            assertThrows(OAuthTransportException.class, () -> client.validateResult(bearer("other-token")));
            assertEquals(3, server.getHitCount("/inspect"));
        }
    }
}
