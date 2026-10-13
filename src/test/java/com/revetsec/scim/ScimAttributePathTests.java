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

import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

final class ScimAttributePathTests {
    @Test void pathPartsAreStructuralAndOriginalSpellingsAreRetained() {
        assertParts("userName", Optional.empty(), "userName", Optional.empty());
        assertParts("name.familyName", Optional.empty(), "name", Optional.of("familyName"));
        assertParts("members.$ref", Optional.empty(), "members", Optional.of("$ref"));
        assertParts("members.$REF", Optional.empty(), "members", Optional.of("$REF"));
        assertEquals(path("members.$ref"), path("MEMBERS.$REF"));
        assertParts("$ref", Optional.empty(), "$ref", Optional.empty());
        assertParts("$REF", Optional.empty(), "$REF", Optional.empty());
        assertEquals(path("$ref"), path("$REF"));
        String schema = "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User";
        assertParts(schema + ":manager.value", Optional.of(schema), "manager", Optional.of("value"));
        assertParts("https://schemas.example.test/v2/User:Name.FamilyName",
                Optional.of("https://schemas.example.test/v2/User"), "Name", Optional.of("FamilyName"));
        assertParts("https://[2001:db8::1]:8443/schema:manager.$ref",
                Optional.of("https://[2001:db8::1]:8443/schema"), "manager", Optional.of("$ref"));
        assertParts("urn:example:many:colons:name", Optional.of("urn:example:many:colons"), "name", Optional.empty());
        assertParts("a-B_c9", Optional.empty(), "a-B_c9", Optional.empty());
    }

    @Test void schemaUrisAreIdentifiersAndAreNeverSubjectToOutboundHttpsRules() {
        assertParts("http://schemas.example.test/User:name", Optional.of("http://schemas.example.test/User"),
                "name", Optional.empty());
        assertParts("https://user@schemas.example.test/schema#part:name",
                Optional.of("https://user@schemas.example.test/schema#part"), "name", Optional.empty());
        assertParts("urn:example:User:name", Optional.of("urn:example:User"), "name", Optional.empty());
        assertParts("urn::name", Optional.of("urn:"), "name", Optional.empty());
    }

    @Test void namesAndSchemaIdsUseAsciiCaseEqualityWithMatchingHashes() {
        ScimAttributePath first = path("URN:EXAMPLE:User:Manager.Value");
        ScimAttributePath second = path("urn:example:user:manager.value");
        assertEquals(first, second);
        assertEquals(first.hashCode(), second.hashCode());
        assertEquals("URN:EXAMPLE:User:Manager.Value", first.toScimString());
        assertNotEquals(first, path("urn:example:other:manager.value"));
        assertNotEquals(first, path("urn:example:user:manager.displayName"));
        assertNotEquals(path("a.b"), path("a"));
    }

    @Test void invalidPathsRejectWithoutTrimmingOrInventingAdditionalLevels() {
        for (String expression : List.of("", " ", " userName", "userName ", "user\tName", ".value",
                "name.", "a.b.c", "a..b", "1name", "_name", "-name", "na mé", "namé", "İname",
                "members.$foo", "$foo", "$other", "a[foo]", "a/name", "a eq 1", ":name",
                "relative/schema:name", "https://[bad-ip]/schema:name", "urn:ex%zz:name")) {
            ScimError error = assertInstanceOf(ScimAttributePathParseResult.Rejected.class,
                    ScimAttributePath.fromExpressionResult(expression), expression).getError();
            assertEquals(400, error.getStatusCode());
            assertEquals(ScimErrorType.INVALID_PATH, error.getErrorType().orElseThrow());
            int offset = error.getExpressionOffset().orElseThrow();
            assertTrue(offset >= 0 && offset <= expression.length());
        }
    }

    @Test void pathNameAndSchemaIdentifierCapsHaveExactBoundaries() {
        path("a".repeat(128));
        rejected("a".repeat(129));
        path("a." + "b".repeat(128));
        rejected("a." + "b".repeat(129));
        String schema = "urn:" + "a".repeat(2_044);
        assertEquals(2_048, schema.length());
        path(schema + ":name");
        rejected(schema + "a:name");
    }

    @Test void standaloneDiagnosticsDoNotContainSchemaOrAttributeInput() {
        String secret = "scim-path-private-93ed3701";
        ScimAttributePath parsed = path("urn:" + secret + ":" + secret);
        assertFalse(parsed.toString().contains(secret));
        ScimError error = assertInstanceOf(ScimAttributePathParseResult.Rejected.class,
                ScimAttributePath.fromExpressionResult("urn:" + secret + ":a..b")).getError();
        assertFalse(error.toString().contains(secret));
        assertFalse(error.getDetail().contains(secret));
    }

    private static void assertParts(@NonNull String expression, @NonNull Optional<@NonNull String> schema,
                                    @NonNull String attribute, @NonNull Optional<@NonNull String> subattribute) {
        ScimAttributePath result = path(expression);
        assertEquals(schema, result.getSchemaId());
        assertEquals(attribute, result.getAttributeName());
        assertEquals(subattribute, result.getSubAttributeName());
        assertEquals(expression, result.toScimString());
    }

    private static @NonNull ScimAttributePath path(@NonNull String expression) {
        return assertInstanceOf(ScimAttributePathParseResult.Succeeded.class,
                ScimAttributePath.fromExpressionResult(expression), expression).getAttributePath();
    }

    private static void rejected(@NonNull String expression) {
        assertInstanceOf(ScimAttributePathParseResult.Rejected.class,
                ScimAttributePath.fromExpressionResult(expression), expression);
    }
}
