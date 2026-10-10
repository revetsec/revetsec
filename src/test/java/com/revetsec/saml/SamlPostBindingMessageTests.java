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

package com.revetsec.saml;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertTrue;

final class SamlPostBindingMessageTests {
    @Test void publicParseResultCarriesOnlyOpaqueUntrustedInput() {
        SamlPostBindingParseResult.Parsed parsed = assertInstanceOf(SamlPostBindingParseResult.Parsed.class,
                SamlPostBindingMessage.fromFormBodyResult("SAMLResponse=PHgvPg%3D%3D&RelayState=opaque"
                        .getBytes(StandardCharsets.UTF_8), List.of("application/x-www-form-urlencoded"), null));
        SamlPostBindingMessage message = parsed.getMessage();
        assertEquals("opaque", message.getRelayState().orElseThrow());
        assertTrue(message.toString().contains("<untrusted>"));
        assertTrue(SamlInboundResponse.parse(message) instanceof SamlInboundResponse.Rejected);
        assertEquals(SamlPostBindingParseResult.Reason.PARAMETERS,
                assertInstanceOf(SamlPostBindingParseResult.Rejected.class,
                        SamlPostBindingMessage.fromFormBodyResult(
                                "SAMLResponse=AA%3D%3D&SAMLResponse=AA%3D%3D".getBytes(StandardCharsets.UTF_8),
                                List.of("application/x-www-form-urlencoded"), null)).getReason());
    }
}
