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

import org.jspecify.annotations.NonNull;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;

final class BrowserRequestOriginPolicyTests {
    private static final URI APP = URI.create("https://app.example.com");
    private static final BrowserRequestOriginPolicy POLICY =
            BrowserRequestOriginPolicy.withAllowedOrigins(Set.of(APP)).build();

    @Test
    void safeMethodsAdmitBeforeMetadataInspection() {
        for (String method : List.of("GET", "HEAD", "OPTIONS"))
            assertAllowed(POLICY.checkResult(method, List.of("bad value", "duplicate"),
                    List.of("bad origin", "duplicate")), BrowserRequestOriginResult.Basis.SAFE_METHOD);
    }

    @Test
    void sameOriginAndUserInitiatedMetadataAdmitNullAbsentAndConfiguredOrigins() {
        for (String fetchSite : List.of("same-origin", "none")) {
            BrowserRequestOriginResult.Basis basis = fetchSite.equals("same-origin")
                    ? BrowserRequestOriginResult.Basis.SAME_ORIGIN
                    : BrowserRequestOriginResult.Basis.USER_INITIATED;
            for (List<String> origins : List.of(List.<String>of(), List.of("null"),
                    List.of(APP.toString())))
                assertAllowed(POLICY.checkResult("POST", List.of(fetchSite), origins), basis);
            assertRejected(POLICY.checkResult("POST", List.of(fetchSite),
                    List.of("https://other.example.com")), BrowserRequestOriginResult.Reason.UNTRUSTED_ORIGIN);
        }
    }

    @Test
    void sameSiteCrossSiteAbsentAndFutureFetchSiteRequireAnExactOrigin() {
        for (List<String> fetchSite : List.of(List.<String>of(), List.of("same-site"),
                List.of("cross-site"), List.of("future-site"), List.of(" Future-Site\t")))
            assertAllowed(POLICY.checkResult("POST", fetchSite, List.of(APP.toString())),
                    BrowserRequestOriginResult.Basis.CONFIGURED_ORIGIN);

        assertRejected(POLICY.checkResult("POST", List.of("same-site"), List.of()),
                BrowserRequestOriginResult.Reason.SAME_SITE);
        assertRejected(POLICY.checkResult("POST", List.of("cross-site"), List.of()),
                BrowserRequestOriginResult.Reason.CROSS_SITE);
        for (String unrecognized : List.of("future-site", " Future-Site\t", "Same-Origin", "NONE"))
            assertRejected(POLICY.checkResult("POST", List.of(unrecognized), List.of()),
                    BrowserRequestOriginResult.Reason.UNRECOGNIZED_FETCH_SITE);
        assertRejected(POLICY.checkResult("POST", List.of("future-site"), List.of("https://other.example.com")),
                BrowserRequestOriginResult.Reason.UNTRUSTED_ORIGIN);
        assertRejected(POLICY.checkResult("POST", List.of(), List.of("https://other.example.com")),
                BrowserRequestOriginResult.Reason.UNTRUSTED_ORIGIN);
    }

    @Test
    void opaqueOriginsRejectUnlessTrustedFetchMetadataAlreadyAdmittedTheRequest() {
        for (List<String> fetchSite : List.of(List.<String>of(), List.of("same-site"),
                List.of("cross-site"), List.of("future-site")))
            assertRejected(POLICY.checkResult("POST", fetchSite, List.of("null")),
                    BrowserRequestOriginResult.Reason.NULL_ORIGIN);
    }

    @Test
    void missingMetadataRejectsByDefaultAndCompatibilityAdmissionIsObservable() {
        assertRejected(POLICY.checkResult("POST", List.of(), List.of()),
                BrowserRequestOriginResult.Reason.MISSING_METADATA);
        BrowserRequestOriginPolicy compatible = BrowserRequestOriginPolicy.withAllowedOrigins(Set.of(APP))
                .allowMissingMetadata(true).build();
        assertAllowed(compatible.checkResult("POST", List.of(), List.of()),
                BrowserRequestOriginResult.Basis.MISSING_METADATA_COMPATIBILITY);
        assertRejected(compatible.checkResult("POST", List.of("cross-site"), List.of()),
                BrowserRequestOriginResult.Reason.CROSS_SITE);
    }

    @Test
    void duplicateAndMalformedFieldsRejectWithoutEchoingInputs() {
        for (BrowserRequestOriginResult result : List.of(
                POLICY.checkResult("POST", List.of("same-origin", "same-origin"), List.of()),
                POLICY.checkResult("POST", List.of("same-origin"), List.of(APP.toString(), APP.toString())),
                POLICY.checkResult("POST", List.of("same origin"), List.of()),
                POLICY.checkResult("POST", List.of("same-origin"), List.of(" https://app.example.com")),
                POLICY.checkResult("POST", List.of("same-origin"), List.of("https://app.example.com/")),
                POLICY.checkResult("POST", List.of("same-origin"), List.of("https://APP.example.com")),
                POLICY.checkResult("POST", List.of("same-origin"), List.of("not an origin")))) {
            assertRejected(result, BrowserRequestOriginResult.Reason.MALFORMED);
            assertEquals("BrowserRequestOriginResult{<redacted>}", result.toString());
        }
    }

    @Test
    void fetchSiteAndOriginGrammarBoundariesFailClosed() {
        for (String fetchSite : List.of("", " \t", "1site", "-site", "same@origin", "x".repeat(65)))
            assertRejected(POLICY.checkResult("POST", List.of(fetchSite), List.of(APP.toString())),
                    BrowserRequestOriginResult.Reason.MALFORMED);
        for (String fetchSite : List.of("*", "a1:/!#$%&'*+-.^_`|~", "x".repeat(64)))
            assertAllowed(POLICY.checkResult("POST", List.of(fetchSite), List.of(APP.toString())),
                    BrowserRequestOriginResult.Basis.CONFIGURED_ORIGIN);

        for (String origin : List.of("https://" + "a".repeat(2_048), "HTTPS://app.example.com",
                "ftp://app.example.com", "//app.example.com", "https:app.example.com", "https://my_app.example.com",
                "https://app.example.com?x", "https://app.example.com#x", "https://user@app.example.com",
                "https://app.example.com:0", "https://app.example.com:70000", "https://[fe80::1%25eth0]"))
            assertRejected(POLICY.checkResult("POST", List.of("same-origin"), List.of(origin)),
                    BrowserRequestOriginResult.Reason.MALFORMED);
    }

    @Test
    void methodsAreCaseSensitiveTokensAndBuilderNullsRestoreDefaults() {
        assertRejected(POLICY.checkResult("get", List.of(), List.of()),
                BrowserRequestOriginResult.Reason.MISSING_METADATA);
        assertAllowed(POLICY.checkResult("M-SEARCH", List.of("same-origin"), List.of()),
                BrowserRequestOriginResult.Basis.SAME_ORIGIN);
        assertAllowed(POLICY.checkResult("X!#$%&'*+.^_`|~9", List.of("same-origin"), List.of()),
                BrowserRequestOriginResult.Basis.SAME_ORIGIN);

        BrowserRequestOriginPolicy restored = BrowserRequestOriginPolicy.withAllowedOrigins(Set.of(APP))
                .allowMissingMetadata(true).allowMissingMetadata(null)
                .allowInsecureLoopback(true).allowInsecureLoopback(null).build();
        assertRejected(restored.checkResult("POST", List.of(), List.of()),
                BrowserRequestOriginResult.Reason.MISSING_METADATA);
        assertThrows(IllegalArgumentException.class, () -> BrowserRequestOriginPolicy
                .withAllowedOrigins(Set.of(URI.create("http://localhost:8080"))).allowInsecureLoopback(null).build());

        BrowserRequestOriginPolicy localhost = BrowserRequestOriginPolicy
                .withAllowedOrigins(Set.of(URI.create("http://localhost:8080"))).allowInsecureLoopback(true).build();
        assertAllowed(localhost.checkResult("POST", List.of("cross-site"), List.of("http://localhost:8080")),
                BrowserRequestOriginResult.Basis.CONFIGURED_ORIGIN);
        assertThrows(IllegalArgumentException.class, () -> BrowserRequestOriginPolicy
                .withAllowedOrigins(Set.of(URI.create("http://127.0.0.1:80"))).allowInsecureLoopback(true).build());
    }

    @Test
    void configuredOriginsMustBeCanonicalHttpsOrExplicitLoopbackHttp() {
        for (String origin : List.of("https://APP.example.com", "https://app.example.com/",
                "https://app.example.com:443", "https://user@app.example.com", "http://app.example.com"))
            assertThrows(IllegalArgumentException.class,
                    () -> BrowserRequestOriginPolicy.withAllowedOrigins(Set.of(URI.create(origin))).build());
        assertThrows(IllegalArgumentException.class,
                () -> BrowserRequestOriginPolicy.withAllowedOrigins(Set.of()).build());

        BrowserRequestOriginPolicy loopback = BrowserRequestOriginPolicy
                .withAllowedOrigins(Set.of(URI.create("http://127.0.0.1:8080")))
                .allowInsecureLoopback(true).build();
        assertAllowed(loopback.checkResult("POST", List.of(), List.of("http://127.0.0.1:8080")),
                BrowserRequestOriginResult.Basis.CONFIGURED_ORIGIN);
        assertThrows(IllegalArgumentException.class, () -> BrowserRequestOriginPolicy
                .withAllowedOrigins(Set.of(URI.create("http://example.com"))).allowInsecureLoopback(true).build());
    }

    @Test
    void ipv6LiteralOriginsUseTheBrowserSerialization() {
        BrowserRequestOriginPolicy literal = BrowserRequestOriginPolicy.withAllowedOrigins(Set.of(
                URI.create("https://[2001:db8::1]"), URI.create("https://[2001:db8::2]:8443"),
                URI.create("https://[1:0:1::1:0:0]"), URI.create("https://[::ffff:102:304]"))).build();
        for (String origin : List.of("https://[2001:db8::1]", "https://[2001:db8::2]:8443",
                "https://[1:0:1::1:0:0]", "https://[::ffff:102:304]"))
            assertAllowed(literal.checkResult("POST", List.of("cross-site"), List.of(origin)),
                    BrowserRequestOriginResult.Basis.CONFIGURED_ORIGIN);
        assertRejected(literal.checkResult("POST", List.of(), List.of("https://[2001:db8::2]")),
                BrowserRequestOriginResult.Reason.UNTRUSTED_ORIGIN);
        assertRejected(literal.checkResult("POST", List.of("same-origin"), List.of("https://[2001:db8::3]")),
                BrowserRequestOriginResult.Reason.UNTRUSTED_ORIGIN);
        for (String origin : List.of("https://[2001:0db8::1]", "https://[2001:DB8::1]",
                "https://[2001:db8:0:0:0:0:0:1]", "https://[::ffff:1.2.3.4]"))
            assertRejected(literal.checkResult("POST", List.of(), List.of(origin)),
                    BrowserRequestOriginResult.Reason.MALFORMED);

        // Browsers compress the first longest zero run and never use a dotted IPv4 tail.
        for (String origin : List.of("https://[2001:0db8::1]", "https://[2001:DB8::1]",
                "https://[2001:db8:0:0:0:0:0:1]", "https://[1:0:1:0:0:1::]", "https://[::ffff:1.2.3.4]"))
            assertThrows(IllegalArgumentException.class,
                    () -> BrowserRequestOriginPolicy.withAllowedOrigins(Set.of(URI.create(origin))).build());

        BrowserRequestOriginPolicy loopback = BrowserRequestOriginPolicy
                .withAllowedOrigins(Set.of(URI.create("http://[::1]:8080"))).allowInsecureLoopback(true).build();
        assertAllowed(loopback.checkResult("POST", List.of(), List.of("http://[::1]:8080")),
                BrowserRequestOriginResult.Basis.CONFIGURED_ORIGIN);
        assertThrows(IllegalArgumentException.class, () -> BrowserRequestOriginPolicy
                .withAllowedOrigins(Set.of(URI.create("http://[::1]:8080"))).build());
        assertThrows(IllegalArgumentException.class, () -> BrowserRequestOriginPolicy
                .withAllowedOrigins(Set.of(URI.create("http://[2001:db8::1]"))).allowInsecureLoopback(true).build());
    }

    @Test
    @SuppressWarnings("NullAway") // Deliberate required-null misuse verifies the public rejection contract.
    void inputsAreRequiredAndMethodMustBeAnHttpToken() {
        assertThrows(NullPointerException.class, () -> POLICY.checkResult(null, List.of(), List.of()));
        assertThrows(NullPointerException.class, () -> POLICY.checkResult("POST", null, List.of()));
        assertThrows(NullPointerException.class, () -> POLICY.checkResult("POST", List.of(), null));
        assertThrows(IllegalArgumentException.class, () -> POLICY.checkResult("", List.of(), List.of()));
        assertThrows(IllegalArgumentException.class, () -> POLICY.checkResult("BAD METHOD", List.of(), List.of()));
        assertEquals("BrowserRequestOriginPolicy{configuration=<redacted>}", POLICY.toString());
    }

    private static void assertAllowed(@NonNull BrowserRequestOriginResult result,
            BrowserRequestOriginResult.@NonNull Basis basis) {
        assertEquals(basis, assertInstanceOf(BrowserRequestOriginResult.Allowed.class, result).getBasis());
    }

    private static void assertRejected(@NonNull BrowserRequestOriginResult result,
            BrowserRequestOriginResult.@NonNull Reason reason) {
        assertEquals(reason, assertInstanceOf(BrowserRequestOriginResult.Rejected.class, result).getReason());
    }
}
