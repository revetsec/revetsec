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
package com.revetsec.scim;

import org.jspecify.annotations.NonNull;
import org.junit.jupiter.api.Test;
import java.net.URI;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;

final class ScimCanonicalPathTests {
    private static @NonNull ScimAttributePath parsed(@NonNull String expression) {
        return assertInstanceOf(ScimAttributePathParseResult.Succeeded.class,
                ScimAttributePath.fromExpressionResult(expression)).getAttributePath();
    }

    @Test void publishedCanonicalizerUsesPolicyPathSpelling() {
        ScimResourceType user = ScimResourceType.userInstance();
        assertEquals("userName", user.canonicalAttributePath(parsed(
                user.getSchema().getId() + ":USERNAME")).orElseThrow().toScimString());
        String enterprise = ScimSchema.enterpriseUserInstance().getId();
        assertEquals(enterprise + ":manager.value", user.canonicalAttributePath(parsed(
                enterprise.toUpperCase(java.util.Locale.ROOT) + ":MANAGER.VALUE"))
                .orElseThrow().toScimString());
        assertTrue(user.canonicalAttributePath(parsed("unknownAttribute")).isEmpty());
    }

    @Test void authoritativeDotSegmentsCannotBecomeLocations() {
        ScimResourceType user = ScimResourceType.userInstance();
        ScimServiceProvider provider = ScimServiceProvider.builder()
                .baseUri(URI.create("https://example.test/scim/"))
                .resourceTypes(List.of(user)).build();
        org.junit.jupiter.api.Assertions.assertThrows(IllegalArgumentException.class,
                () -> provider.resourceLocationFor(user, "."));
        org.junit.jupiter.api.Assertions.assertThrows(IllegalArgumentException.class,
                () -> provider.resourceLocationFor(user, ".."));
    }
}
