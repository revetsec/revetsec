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

import com.revetsec.json.JsonObject;
import com.revetsec.json.JsonArray;
import com.revetsec.json.JsonString;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/** Independent media-type and conditional-header grammar matrices. */
final class ScimM10WireTests {
    private static final @NonNull ScimLimits DEFAULTS = ScimLimits.fromDefaults();

    @Test void acceptsExactlyOneSupportedMediaTypeAndSyntacticCharsetRegardlessOfItsLabel() {
        for (String value : List.of("application/scim+json", "APPLICATION/JSON", "\tapplication/json \t",
                "application/scim+json; charset=utf-8", "application/json; charset=abc12-!~^", "application/json; CHARSET=\"ISO-8859-1\"",
                "application/json; charset=\"ut\\f-8\""))
            assertInstanceOf(ScimContentTypeResult.Accepted.class, ScimHeaders.contentType(List.of(value)), value);
    }

    @Test void rejectsAbsentRepeatedCombinedUnsupportedAndMalformedMediaTypeFields() {
        assertMediaRejected(List.of());
        assertMediaRejected(List.of("application/json", "application/json"));
        for (String value : List.of("", "application/json,application/json", "text/json", "application/xml", "application/",
                "application /json", "application", "application/json;", "application/json; =utf-8", "application/json; charset", "application/json; charset=\t", "application/json; charset=", "application/json; charset=\"\"",
                "application/json; charset=\"utf 8\"", "application/json; charset=utf-8; charset=utf-8", "application/json; q=1",
                "application/json\r\nX: injected", "application/json; charset=\"utf-8", "application/json; charset=\"utf-8\\\"",
                "application/json; charset=\u00e9", "application/json; charset=\"utf-8\\", "application/json\u0000")) assertMediaRejected(List.of(value));
    }

    @Test void contentTypeAcceptsItsInclusiveByteCeilingAndRejectsTheNextByte() {
        String prefix = "application/json; charset=";
        String exactly = prefix + "a".repeat(8_192 - prefix.length());
        assertInstanceOf(ScimContentTypeResult.Accepted.class, ScimHeaders.contentType(List.of(exactly)));
        assertMediaRejected(List.of(exactly + "a"));
    }

    @Test void missingConditionalsProceedAndWildcardsTestTheExistingResourceEvenWithoutVersion() {
        ScimResource versionless = resource(null);
        assertInstanceOf(ScimIfMatchResult.Satisfied.class, ScimHeaders.ifMatch(List.of(), versionless, DEFAULTS));
        assertInstanceOf(ScimIfNoneMatchResult.Proceed.class, ScimHeaders.ifNoneMatch(List.of(), versionless, DEFAULTS));
        assertInstanceOf(ScimIfMatchResult.Satisfied.class, ScimHeaders.ifMatch(List.of(" \t*\t "), versionless, DEFAULTS));
        assertInstanceOf(ScimIfNoneMatchResult.NotModified.class, ScimHeaders.ifNoneMatch(List.of("*"), versionless, DEFAULTS));
        assertMatchRejected(412, List.of("\"v\""), versionless, DEFAULTS);
        assertInstanceOf(ScimIfNoneMatchResult.Proceed.class, ScimHeaders.ifNoneMatch(List.of("\"v\""), versionless, DEFAULTS));
    }

    @Test void approvedWeakComparisonIgnoresOnlyTheExactWeakPrefixForBothConditionals() {
        for (String version : List.of("\"v\"", "W/\"v\"")) for (String value : List.of("\"v\"", "W/\"v\"")) {
            assertInstanceOf(ScimIfMatchResult.Satisfied.class, ScimHeaders.ifMatch(List.of(value), resource(version), DEFAULTS));
            assertInstanceOf(ScimIfNoneMatchResult.NotModified.class, ScimHeaders.ifNoneMatch(List.of(value), resource(version), DEFAULTS));
        }
        assertMatchRejected(412, List.of("\"V\""), resource("W/\"v\""), DEFAULTS);
        assertMatchRejected(412, List.of("\"different\""), resource("\"v\""), DEFAULTS);
    }

    @Test void validTagListsSpanPhysicalOccurrencesAndPreserveOpaqueCommasBackslashesAndObsText() {
        ScimResource current = resource("W/\"rev,\\\u00e9\"");
        List<String> values = List.of("\"other\",", " ,W/\"rev,\\\u00e9\",, ");
        assertInstanceOf(ScimIfMatchResult.Satisfied.class, ScimHeaders.ifMatch(values, current, DEFAULTS));
        assertInstanceOf(ScimIfNoneMatchResult.NotModified.class, ScimHeaders.ifNoneMatch(values, current, DEFAULTS));
        assertInstanceOf(ScimIfMatchResult.Satisfied.class, ScimHeaders.ifMatch(List.of("\"\""), resource("\"\""), DEFAULTS));
        assertInstanceOf(ScimIfMatchResult.Satisfied.class, ScimHeaders.ifMatch(List.of("\"*\""), resource("\"*\""), DEFAULTS));
    }

    @Test void malformedConditionalGrammarRejectsInsteadOfBeingTreatedAsAMiss() {
        for (List<String> values : List.of(List.of(""), List.of(",,"), List.of("*,\"v\""), List.of("*", "\"v\""),
                List.of("*", "*"), List.of("w/\"v\""), List.of("W/ \"v\""), List.of("W/"), List.of("\"a b\""), List.of("\"v\" \"other\""),
                List.of("\"v"), List.of("v"), List.of("\"v\t\""), List.of("\"v\u007f\""), List.of("\"v\u0100\""),
                List.of("\"v\"\r\nX: injected"))) {
            assertMatchRejected(400, values, resource("\"v\""), DEFAULTS);
            ScimIfNoneMatchResult.Rejected result = assertInstanceOf(ScimIfNoneMatchResult.Rejected.class,
                    ScimHeaders.ifNoneMatch(values, resource("\"v\""), DEFAULTS));
            assertSame(ScimError.invalidSyntaxInstance(), result.getError());
        }
    }

    @Test void boundsAreInclusiveAndCountAllPhysicalOccurrencesAndActualTags() {
        ScimLimits bytes = ScimLimits.builder().maximumConditionalHeaderBytes(256).build();
        String exactly = "\"" + "a".repeat(254) + "\"";
        assertInstanceOf(ScimIfNoneMatchResult.Proceed.class, ScimHeaders.ifNoneMatch(List.of(exactly), resource("\"v\""), bytes));
        assertMatchRejected(413, List.of(exactly + " "), resource("\"v\""), bytes);
        String encoded = "\"" + "\u00e9".repeat(126) + "aa\"";
        assertInstanceOf(ScimIfNoneMatchResult.Proceed.class, ScimHeaders.ifNoneMatch(List.of(encoded), resource("\"v\""), bytes));
        assertMatchRejected(413, List.of(encoded + " "), resource("\"v\""), bytes);
        ScimLimits tags = ScimLimits.builder().maximumConditionalTags(1).build();
        assertInstanceOf(ScimIfMatchResult.Satisfied.class, ScimHeaders.ifMatch(List.of("\"v\""), resource("\"v\""), tags));
        assertMatchRejected(413, List.of("\"v\",\"v\""), resource("\"v\""), tags);
        assertMatchRejected(413, List.of("", "\"v\""), resource("\"v\""), tags);
    }

    private static @NonNull ScimResource resource(@Nullable String version) {
        JsonObject.Builder document = JsonObject.builder().put("userName", "fixture")
                .put("schemas", JsonArray.fromElements(List.of(JsonString.fromValue("urn:ietf:params:scim:schemas:core:2.0:User"))));
        if (version != null) document.put("meta", JsonObject.builder().put("version", version).build());
        return ScimResource.withResourceType(ScimResourceType.userInstance()).document(document.build()).build();
    }
    private static void assertMediaRejected(@NonNull List<@NonNull String> values) {
        assertSame(ScimError.unsupportedMediaTypeInstance(), assertInstanceOf(ScimContentTypeResult.Rejected.class,
                ScimHeaders.contentType(values)).getError());
    }
    private static void assertMatchRejected(int status, @NonNull List<@NonNull String> values,
            @NonNull ScimResource resource, @NonNull ScimLimits limits) {
        assertEquals(status, assertInstanceOf(ScimIfMatchResult.Rejected.class, ScimHeaders.ifMatch(values, resource, limits)).getError().getStatusCode());
    }
}
