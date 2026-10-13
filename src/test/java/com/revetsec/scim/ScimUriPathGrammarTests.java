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

/**
 * Independent RFC 3986 sections 3.1–3.5 and Appendix A URI fixtures. SCIM paths require a scheme,
 * preserve spelling and use the reviewed ASCII structural matching profile. As approved, a schema
 * identifier can contain a fragment; no network/HTTP authority restrictions are applied here.
 * Fixture choices follow the URI grammar, rather than Java URI or production recognition as an oracle.
 * Source: https://www.rfc-editor.org/rfc/rfc3986.txt (read 2026-10-13).
 */
final class ScimUriPathGrammarTests {
    @Test void schemeAndEveryHierarchicalShapePreserveTheirKnownComponents() {
        for (@NonNull String schema : List.of("x:", "X:", "a0+.-:opaque", "a:/", "a:/one/two", "a:one/two",
                "a://", "a:///", "a:////two", "a://host", "a://host/", "a://host//one/./../two",
                "urn:example:one:two", "mailto:alice@example.test", "dav:", "about:")) {
            assertSchemaPath(schema, "Name", Optional.of("Value"));
        }
    }

    @Test void userInfoAndRegisteredNamesUseUriCharactersWithoutDnsOrHttpPolicy() {
        for (@NonNull String schema : List.of("x://@host", "x://alice@host", "x://alice:password@host",
                "x://user%40name:p%3Ass@host", "x://!$&'()*+,;=:@host", "x://user@", "x://@",
                "x://host:0", "x://host:", "x://:123", "x://:999999999999999999999",
                "x://host:00080/schema", "x://%65xample.test/schema", "x://%41%4a%4A/schema",
                "x://host_name.~!$&'()*+,;=/schema", "x://999.999.999.999/schema")) {
            assertSchemaPath(schema, "Emails", Optional.empty());
        }
    }

    @Test void pathsQueriesAndFragmentsRetainPercentEscapesAndTheirOwnDelimiters() {
        for (@NonNull String schema : List.of("x:!$&'()*+,;=:@-._~AZaz09", "x:/a%20b/%2F/%FF/%00",
                "x:/schema?", "x:/schema#", "x:/schema?#", "x:/schema?one/two?three:@!$&'()*+,;=",
                "x:/schema#one/two?three:@!$&'()*+,;=", "x:/schema?x=%7B%7D#f=%5B%5D",
                "x:/schema#fragment?is-not-a-query", "x:/schema?question?again#fragment",
                "x:/schema%23data?%3Fdata#%25data", "x:/schema(a)?q=(b)#f=(c)")) {
            assertSchemaPath(schema, "manager", Optional.of("$ref"));
        }
    }

    @Test void ipv6AndFutureLiteralsHaveKnownUriComponentsAndDoNotBeginValuePaths() {
        for (@NonNull String literal : List.of("[::]", "[::1]", "[2001:db8::2:1]", "[1:2:3:4:5:6:7:8]",
                "[::ffff:192.0.2.128]", "[v1.a]", "[VF.a]", "[v123.AZaz09-._~]",
                "[vF.!$&'()*+,;=:]")) {
            for (@NonNull String suffix : List.of("", ":", ":8443/schema")) {
                assertSchemaPath("x://" + literal + suffix, "members", Optional.of("$REF"));
            }
        }
        assertSchemaPath("x://user:secret@[2001:db8::1]:8443/schema", "emails", Optional.empty());
        assertSchemaPath("x://user@[v1.future]", "emails", Optional.empty());
    }

    @Test void malformedSchemesAndUriComponentsRejectWithoutInputEcho() {
        for (@NonNull String schema : List.of("", ":", "1x:part", "+x:part", "-x:part", ".x:part",
                "x_:part", "x%20:part", "x!:part", "é:part", "x:has space", "x:has\tcontrol",
                "x:back\\slash", "x:quoted\"data", "x:curly{data}", "x:pipe|data", "x:caret^data",
                "x:grave`data", "x:rawé", "x:/a[b]", "x:/a?b[c]", "x:/a#b[c]", "x:/a#one#two",
                "x:/%", "x:/%0", "x:/%GG", "x:/%G0", "x:/%0G", "x:/a?%", "x:/a?%GG",
                "x:/a#%", "x:/a#%GG")) {
            rejectedSchema(schema);
        }
    }

    @Test void malformedUserInfoHostsAndPortsRejectAtSyntaxBoundary() {
        for (@NonNull String schema : List.of("x://a@b@host", "x://@@host", "x://user^name@host",
                "x://user%@host", "x://user%0@host", "x://user%GG@host", "x://ho^st", "x://ho|st",
                "x://ho%st", "x://ho%0", "x://ho%GG", "x://ho%G0", "x://ho%0G",
                "x://host:abc", "x://host:+80", "x://host:-80", "x://host:80.0", "x://host:80:90",
                "x://[::1]extra", "x://[::1]:abc", "x://[::1]:1:2", "x://::1")) {
            rejectedSchema(schema);
        }
    }

    @Test void malformedIpLiteralBoundariesAreNotAcceptedAsRegisteredNames() {
        for (@NonNull String literal : List.of("[", "[]", "[a]", "[::1", "[::1]]", "[127.0.0.1]",
                "[1:2:3:4:5:6:7]", "[1:2:3:4:5:6:7:8:9]", "[1::2::3]", "[gggg::1]",
                "[::ffff:256.1.1.1]", "[v.a]", "[vG.a]", "[v1]", "[v1.]", "[v1.a%20]",
                "[v1.a?b]", "[v1.a/b]", "[v1.a@b]", "[v1.a^b]", "[v1.a[b]]")) {
            rejectedSchema("x://" + literal + "/schema");
        }
    }

    @Test void uriAndValuePathBracketsStayDistinctWithAuthoritiesAndUriSubDelimiters() {
        for (@NonNull String schema : List.of("x://example.test", "x://example.test:8080", "x://[::1]",
                "x://[::1]:8080", "x://user@[v1.a]", "x://host(a)", "x:/path(a)?q=(b)#f=(c)")) {
            @NonNull String expression = schema + ":emails[$ref pr]";
            ScimFilter.@NonNull ValuePath filter = assertInstanceOf(ScimFilter.ValuePath.class,
                    parseFilter(expression));
            assertEquals(Optional.of(schema), filter.getAttributePath().getSchemaId());
            assertEquals("emails", filter.getAttributePath().getAttributeName());
            ScimFilter.@NonNull Present inner = assertInstanceOf(ScimFilter.Present.class, filter.getFilter());
            assertEquals("$ref", inner.getAttributePath().getAttributeName());
            assertEquals(Optional.empty(), inner.getAttributePath().getSchemaId());
            assertEquals(expression, filter.toScimString());
        }
    }

    @Test void narrowRefNameAndAsciiNameBoundsDoNotGrantBroaderDollarSyntax() {
        for (@NonNull String name : List.of("$ref", "$REF", "$rEf", "A", "a0-B_c", "a".repeat(128))) {
            assertSchemaPath("x:identifier", name, Optional.of("$rEF"));
        }
        for (@NonNull String name : List.of("$", "$r", "$re", "$refs", "$foo", "r$ef", "$refx",
                "$rxf", "$rex", "$REFé", "_a", "-a", "1a", "a".repeat(129))) {
            rejected("x:identifier:" + name);
            rejected("x:identifier:valid." + name);
        }
        @NonNull String schema = "x:" + "a".repeat(2046);
        assertSchemaPath(schema, "n".repeat(128), Optional.of("s".repeat(128)));
        rejectedSchema(schema + "a");
        rejected(schema + ":" + "n".repeat(129) + "." + "s".repeat(128));
        rejected(schema + ":" + "n".repeat(128) + "." + "s".repeat(129));
    }

    @Test void offsetsAndDiagnosticsRemainBoundedForEveryUriComponent() {
        for (@NonNull String schema : List.of("x_bad:private-URI", "x://private-URI%GG", "x://private-URI:port",
                "x://private-URI@one@two", "x://[private-URI]", "x:/private-URI?%GG", "x:/a#private-URI#x")) {
            @NonNull ScimError error = rejected(schema + ":name");
            assertFalse(error.getDetail().contains("private-URI"));
            assertFalse(error.toString().contains("private-URI"));
        }
    }

    private static void assertSchemaPath(@NonNull String schema, @NonNull String attribute,
            @NonNull Optional<@NonNull String> subattribute) {
        @NonNull String expression = schema + ":" + attribute + subattribute.map(value -> "." + value).orElse("");
        @NonNull ScimAttributePath path = assertInstanceOf(ScimAttributePathParseResult.Succeeded.class,
                ScimAttributePath.fromExpressionResult(expression), expression).getAttributePath();
        assertEquals(Optional.of(schema), path.getSchemaId(), expression);
        assertEquals(attribute, path.getAttributeName(), expression);
        assertEquals(subattribute, path.getSubAttributeName(), expression);
        assertEquals(expression, path.toScimString());
        ScimFilter.@NonNull Present filter = assertInstanceOf(ScimFilter.Present.class, parseFilter(expression + " pr"));
        assertEquals(Optional.of(schema), filter.getAttributePath().getSchemaId(), expression);
        assertEquals(attribute, filter.getAttributePath().getAttributeName(), expression);
        assertEquals(subattribute, filter.getAttributePath().getSubAttributeName(), expression);
    }

    private static void rejectedSchema(@NonNull String schema) { rejected(schema + ":name"); }

    private static @NonNull ScimError rejected(@NonNull String expression) {
        @NonNull ScimError error = assertInstanceOf(ScimAttributePathParseResult.Rejected.class,
                ScimAttributePath.fromExpressionResult(expression), expression).getError();
        assertEquals(400, error.getStatusCode());
        assertEquals(Optional.of(ScimErrorType.INVALID_PATH), error.getErrorType());
        int offset = error.getExpressionOffset().orElseThrow();
        assertTrue(offset >= 0 && offset <= expression.length(), expression);
        return error;
    }

    private static @NonNull ScimFilter parseFilter(@NonNull String expression) {
        return assertInstanceOf(ScimFilterParseResult.Succeeded.class,
                ScimFilter.fromExpressionResult(expression), expression).getFilter();
    }
}
