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
import java.time.Duration;
import java.util.ArrayList;
import java.util.EnumSet;
import java.util.List;
import java.util.Set;
import static org.junit.jupiter.api.Assertions.*;

/** Independent exact capability defaults, presets and trusted-configuration bounds. */
class ScimM10ConfigurationTests {
    @Test void paginationDefaultsAreExplicitAndResettable() {
        ScimPaginationConfig value = ScimPaginationConfig.builder().indexSupported(false).indexSupported(null)
                .cursorSupported(true).cursorSupported(null).defaultMethod(ScimPaginationMethod.CURSOR).defaultMethod(null)
                .defaultPageSize(10).defaultPageSize(null).maximumPageSize(20).maximumPageSize(null)
                .cursorTimeout(Duration.ofMinutes(2)).cursorTimeout(null).build();
        assertTrue(value.isIndexSupported()); assertFalse(value.isCursorSupported());
        assertEquals(ScimPaginationMethod.INDEX, value.getDefaultMethod());
        assertEquals(100, value.getDefaultPageSize()); assertEquals(1000, value.getMaximumPageSize());
        assertTrue(value.getCursorTimeout().isEmpty());
        assertEquals(ScimPaginationConfig.builder().build(), value);
        assertEquals(ScimPaginationConfig.builder().build().hashCode(), value.hashCode());
    }

    @Test void cursorSupportRequiresRealCommitmentAndSupportedDefault() {
        assertThrows(IllegalStateException.class, () -> ScimPaginationConfig.builder().cursorSupported(true).build());
        assertThrows(IllegalArgumentException.class, () -> ScimPaginationConfig.builder().indexSupported(false).build());
        assertThrows(IllegalArgumentException.class, () -> ScimPaginationConfig.builder().defaultMethod(ScimPaginationMethod.CURSOR).build());
        assertThrows(IllegalArgumentException.class, () -> ScimPaginationConfig.builder().indexSupported(false)
                .cursorSupported(true).cursorTimeout(Duration.ofSeconds(1)).build());
        ScimPaginationConfig cursor = ScimPaginationConfig.builder().indexSupported(false).cursorSupported(true)
                .defaultMethod(ScimPaginationMethod.CURSOR).cursorTimeout(Duration.ofHours(24)).build();
        assertFalse(cursor.isIndexSupported()); assertTrue(cursor.isCursorSupported());
        assertEquals(ScimPaginationMethod.CURSOR, cursor.getDefaultMethod());
        assertEquals(Duration.ofHours(24), cursor.getCursorTimeout().orElseThrow());
        assertDoesNotThrow(() -> ScimPaginationConfig.builder().cursorSupported(true).cursorTimeout(Duration.ofSeconds(1)).build());
        assertThrows(IllegalArgumentException.class, () -> ScimPaginationConfig.builder().cursorSupported(true).cursorTimeout(Duration.ofSeconds(1).minusNanos(1)).build());
        assertThrows(IllegalArgumentException.class, () -> ScimPaginationConfig.builder().cursorSupported(true).cursorTimeout(Duration.ofHours(24).plusNanos(1)).build());
    }

    @Test void pageBoundsAndConsistencyAreChecked() {
        for (int size : List.of(0, -1, 10001)) {
            assertThrows(IllegalArgumentException.class, () -> ScimPaginationConfig.builder().defaultPageSize(size).build());
            assertThrows(IllegalArgumentException.class, () -> ScimPaginationConfig.builder().maximumPageSize(size).build());
            assertThrows(IllegalArgumentException.class, () -> ScimServiceProviderConfig.builder().filterMaximumResults(size).build());
        }
        assertThrows(IllegalArgumentException.class, () -> ScimPaginationConfig.builder().defaultPageSize(101).maximumPageSize(100).build());
        assertDoesNotThrow(() -> ScimPaginationConfig.builder().defaultPageSize(1).maximumPageSize(1).build());
        assertDoesNotThrow(() -> ScimPaginationConfig.builder().defaultPageSize(10000).maximumPageSize(10000).build());
        assertDoesNotThrow(() -> ScimServiceProviderConfig.builder().filterMaximumResults(1).build());
        assertDoesNotThrow(() -> ScimServiceProviderConfig.builder().filterMaximumResults(10000).build());
    }

    @Test void capabilityDefaultsAndNullResetsCoverEveryProperty() {
        ScimServiceProviderConfig value = ScimServiceProviderConfig.builder().patchSupported(true).patchSupported(null)
                .filterSupported(true).filterSupported(null).sortSupported(true).sortSupported(null)
                .changePasswordSupported(true).changePasswordSupported(null).etagSupported(false).etagSupported(null)
                .filterMaximumResults(50).filterMaximumResults(null)
                .pagination(ScimPaginationConfig.builder().defaultPageSize(1).build()).pagination(null)
                .authenticationSchemes(List.of(scheme("httpbasic", false))).authenticationSchemes(null)
                .documentationUri(URI.create("https://example.com/docs")).documentationUri(null).build();
        assertFalse(value.isPatchSupported()); assertFalse(value.isFilterSupported()); assertFalse(value.isSortSupported());
        assertFalse(value.isChangePasswordSupported()); assertTrue(value.isEtagSupported());
        assertEquals(1000, value.getFilterMaximumResults());
        assertEquals(ScimPaginationConfig.builder().build(), value.getPagination());
        assertTrue(value.getAuthenticationSchemes().isEmpty()); assertTrue(value.getDocumentationUri().isEmpty());
        assertEquals(value, ScimServiceProviderConfig.builder().build());
        assertEquals(value.hashCode(), ScimServiceProviderConfig.builder().build().hashCode());
        ScimServiceProviderConfig enabled = ScimServiceProviderConfig.builder().patchSupported(true).filterSupported(true)
                .sortSupported(true).changePasswordSupported(true).etagSupported(false).filterMaximumResults(2).build();
        assertTrue(enabled.isPatchSupported()); assertTrue(enabled.isFilterSupported()); assertTrue(enabled.isSortSupported());
        assertTrue(enabled.isChangePasswordSupported()); assertFalse(enabled.isEtagSupported());
        assertEquals(2, enabled.getFilterMaximumResults()); assertNotEquals(value, enabled);
    }

    @SuppressWarnings("NullAway") // Intentionally exercise programmer misuse of a required factory input.
    @Test void authenticationDescriptionsHaveRequiredFieldsAndNoImplicitDefaultName() {
        assertThrows(IllegalStateException.class, () -> ScimAuthenticationScheme.withType("oauthbearertoken").build());
        assertThrows(IllegalStateException.class, () -> ScimAuthenticationScheme.withType("oauthbearertoken").name("Bearer").build());
        assertThrows(IllegalStateException.class, () -> ScimAuthenticationScheme.withType("oauthbearertoken").name("Bearer").name(null).description("Description").build());
        assertThrows(IllegalStateException.class, () -> ScimAuthenticationScheme.withType("oauthbearertoken").name("Bearer").description("Description").description(null).build());
        for (String type : List.of("oauth", "oauth2", "oauthbearertoken", "httpbasic", "httpdigest")) {
            ScimAuthenticationScheme value = scheme(type, false);
            assertEquals(type, value.getType()); assertEquals("Name", value.getName()); assertEquals("Description", value.getDescription());
            assertFalse(value.isPrimary()); assertTrue(value.getSpecUri().isEmpty()); assertTrue(value.getDocumentationUri().isEmpty());
        }
        for (String type : List.of("OAuth", "HTTPBasic", "", "unknown", "x".repeat(10000)))
            assertThrows(IllegalArgumentException.class, () -> ScimAuthenticationScheme.withType(type));
        assertThrows(NullPointerException.class, () -> ScimAuthenticationScheme.withType(null));
    }

    @Test void authenticationSnapshotsAndPrimaryUniquenessAreChecked() {
        ScimAuthenticationScheme.Builder builder = ScimAuthenticationScheme.withType("httpbasic").name("Name").description("Description")
                .primary(true).primary(null).specUri(URI.create("https://example.com/spec")).specUri(null)
                .documentationUri(URI.create("https://example.com/help")).documentationUri(null);
        assertEquals(scheme("httpbasic", false), builder.build());
        assertEquals(scheme("httpbasic", false).hashCode(), builder.build().hashCode());
        List<@NonNull ScimAuthenticationScheme> values = new ArrayList<>(List.of(scheme("oauth", true)));
        ScimServiceProviderConfig.Builder config = ScimServiceProviderConfig.builder().authenticationSchemes(values);
        values.clear();
        assertEquals(1, config.build().getAuthenticationSchemes().size());
        assertThrows(UnsupportedOperationException.class, () -> config.build().getAuthenticationSchemes().clear());
        assertEquals("httpbasic", config.authenticationSchemes(List.of(scheme("httpbasic", false))).build()
                .getAuthenticationSchemes().get(0).getType());
        assertThrows(IllegalArgumentException.class, () -> ScimServiceProviderConfig.builder()
                .authenticationSchemes(List.of(scheme("httpbasic", true), scheme("oauthbearertoken", true))).build());
        assertThrows(IllegalArgumentException.class, () -> ScimServiceProviderConfig.builder()
                .authenticationSchemes(java.util.Collections.nCopies(1025, scheme("httpbasic", false))));
    }

    @Test void trustedTextAndDocumentationLinksAreBoundedAndUnicodeValid() {
        assertThrows(IllegalArgumentException.class, () -> ScimAuthenticationScheme.withType("httpbasic").name("x".repeat(129)));
        assertThrows(IllegalArgumentException.class, () -> ScimAuthenticationScheme.withType("httpbasic").description("x".repeat(1025)));
        for (String invalid : List.of("", " ", "private\u0000text", "private\u007ftext", "\ud800", "\udc00"))
            assertThrows(IllegalArgumentException.class, () -> ScimAuthenticationScheme.withType("httpbasic").name(invalid));
        assertEquals("Unicode 😀", ScimAuthenticationScheme.withType("httpbasic").name("Unicode 😀").description("Description\ncontinued").build().getName());
        for (String invalid : List.of("urn:example:docs", "/relative", "ftp://example.com/docs", "https://user@example.com/docs")) {
            URI uri = URI.create(invalid);
            assertThrows(IllegalArgumentException.class, () -> ScimAuthenticationScheme.withType("httpbasic").specUri(uri));
            assertThrows(IllegalArgumentException.class, () -> ScimServiceProviderConfig.builder().documentationUri(uri));
        }
        URI large = URI.create("https://example.com/" + "x".repeat(2048));
        assertThrows(IllegalArgumentException.class, () -> ScimServiceProviderConfig.builder().documentationUri(large));
        URI docs = URI.create("HTTPS://example.com/help");
        assertEquals(docs, ScimAuthenticationScheme.withType("httpbasic").name("Name").description("Description").specUri(docs).build().getSpecUri().orElseThrow());
        assertEquals(docs, ScimServiceProviderConfig.builder().documentationUri(docs).build().getDocumentationUri().orElseThrow());
    }

    @Test void compatibilityPresetsAreExactAndDoNotEnableDeferredModes() {
        assertEquals(Set.of(), ScimCompatibility.strictInstance().getFeatures());
        assertEquals(Set.of(ScimCompatibilityFeature.PATCH_OPERATION_NAME_CASE_INSENSITIVE,
                ScimCompatibilityFeature.BOOLEAN_STRINGS, ScimCompatibilityFeature.PATCH_REMOVE_WITH_VALUE,
                ScimCompatibilityFeature.PATCH_VALUE_PATH_UPSERT, ScimCompatibilityFeature.PATCH_VALUE_OBJECT_ATTRIBUTE_PATHS,
                ScimCompatibilityFeature.FILTER_VALUE_PATH_SUB_ATTRIBUTE_COMPARISON,
                ScimCompatibilityFeature.INFER_MISSING_EXTENSION_SCHEMAS, ScimCompatibilityFeature.IGNORE_UNDECLARED_SCHEMA_URIS),
                ScimCompatibility.microsoftEntraIdInstance().getFeatures());
        assertEquals(Set.of(ScimCompatibilityFeature.PATCH_OPERATION_NAME_CASE_INSENSITIVE, ScimCompatibilityFeature.PATCH_READ_ONLY_ID_ECHO),
                ScimCompatibility.oktaInstance().getFeatures());
        assertFalse(ScimCompatibility.microsoftEntraIdInstance().getFeatures().contains(ScimCompatibilityFeature.COMPLEX_VALUE_AS_SCALAR));
        assertFalse(ScimCompatibility.microsoftEntraIdInstance().getFeatures().contains(ScimCompatibilityFeature.IGNORE_UNKNOWN_ATTRIBUTES));
        assertSame(ScimCompatibility.strictInstance(), ScimCompatibility.strictInstance());
        assertSame(ScimCompatibility.microsoftEntraIdInstance(), ScimCompatibility.microsoftEntraIdInstance());
        assertSame(ScimCompatibility.oktaInstance(), ScimCompatibility.oktaInstance());
    }

    @Test void compatibilitySetSnapshotsReplaceAndReset() {
        Set<@NonNull ScimCompatibilityFeature> input = EnumSet.of(ScimCompatibilityFeature.BOOLEAN_STRINGS);
        ScimCompatibility.Builder builder = ScimCompatibility.builder().features(input);
        input.add(ScimCompatibilityFeature.COMPLEX_VALUE_AS_SCALAR);
        ScimCompatibility first = builder.build();
        assertEquals(Set.of(ScimCompatibilityFeature.BOOLEAN_STRINGS), first.getFeatures());
        assertThrows(UnsupportedOperationException.class, () -> first.getFeatures().clear());
        assertEquals(Set.of(ScimCompatibilityFeature.IGNORE_UNKNOWN_ATTRIBUTES), builder.features(Set.of(ScimCompatibilityFeature.IGNORE_UNKNOWN_ATTRIBUTES)).build().getFeatures());
        assertEquals(ScimCompatibility.strictInstance(), builder.features(null).build());
        assertEquals(ScimCompatibility.strictInstance().hashCode(), builder.features(Set.of()).build().hashCode());
        assertNotEquals(first, ScimCompatibility.strictInstance());
    }

    @Test void disabledObserverProvidesEveryFixedHookWithoutData() {
        ScimObserver observer = ScimObserver.disabledInstance();
        assertSame(observer, ScimObserver.disabledInstance());
        for (ScimObserver.Operation operation : ScimObserver.Operation.values()) {
            observer.willProcess(operation);
            for (ScimObserver.Outcome outcome : ScimObserver.Outcome.values()) observer.didProcess(operation, outcome);
            observer.didFailToProcess(operation);
        }
        for (ScimCompatibilityFeature feature : ScimCompatibilityFeature.values()) observer.didUseCompatibilityFeature(feature);
    }

    @Test void configurationDiagnosticsDoNotExposeTrustedMetadata() {
        for (Object value : List.of(ScimPaginationConfig.builder().build(), ScimCompatibility.oktaInstance(),
                ScimAuthenticationScheme.withType("httpbasic").name("PRIVATE_AUTH_NAME").description("PRIVATE_AUTH_DESCRIPTION").build(),
                ScimServiceProviderConfig.builder().documentationUri(URI.create("https://PRIVATE-HOST.example/help")).build()))
            assertFalse(value.toString().contains("PRIVATE"));
    }

    @Test void configurationEqualityIncludesEachAdvertisedPromiseAndTrustedUri() {
        ScimPaginationConfig paging = ScimPaginationConfig.builder().build();
        for (ScimPaginationConfig changed : List.of(
                ScimPaginationConfig.builder().cursorSupported(true).cursorTimeout(Duration.ofSeconds(1)).build(),
                ScimPaginationConfig.builder().defaultPageSize(1).build(),
                ScimPaginationConfig.builder().maximumPageSize(1001).build(),
                ScimPaginationConfig.builder().cursorTimeout(Duration.ofSeconds(1)).build())) assertNotEquals(paging, changed);
        assertNotEquals(paging, null); assertNotEquals(paging, "paging");
        ScimAuthenticationScheme authentication = scheme("httpbasic", false);
        for (ScimAuthenticationScheme changed : List.of(scheme("oauth", false), scheme("httpbasic", true),
                ScimAuthenticationScheme.withType("httpbasic").name("Other").description("Description").build(),
                ScimAuthenticationScheme.withType("httpbasic").name("Name").description("Other").build(),
                ScimAuthenticationScheme.withType("httpbasic").name("Name").description("Description").specUri(URI.create("http://example.com/spec")).build(),
                ScimAuthenticationScheme.withType("httpbasic").name("Name").description("Description").documentationUri(URI.create("https://example.com/docs")).build()))
            assertNotEquals(authentication, changed);
        assertNotEquals(authentication, null); assertNotEquals(authentication, "auth");
        ScimServiceProviderConfig capabilities = ScimServiceProviderConfig.builder().build();
        for (ScimServiceProviderConfig changed : List.of(ScimServiceProviderConfig.builder().patchSupported(true).build(),
                ScimServiceProviderConfig.builder().filterSupported(true).build(), ScimServiceProviderConfig.builder().sortSupported(true).build(),
                ScimServiceProviderConfig.builder().changePasswordSupported(true).build(), ScimServiceProviderConfig.builder().etagSupported(false).build(),
                ScimServiceProviderConfig.builder().filterMaximumResults(1).build(), ScimServiceProviderConfig.builder().pagination(ScimPaginationConfig.builder().defaultPageSize(1).build()).build(),
                ScimServiceProviderConfig.builder().authenticationSchemes(List.of(authentication)).build(),
                ScimServiceProviderConfig.builder().documentationUri(URI.create("https://example.com/docs")).build())) assertNotEquals(capabilities, changed);
        assertNotEquals(capabilities, null); assertNotEquals(capabilities, "capabilities");
        assertNotEquals(ScimCompatibility.strictInstance(), null); assertNotEquals(ScimCompatibility.strictInstance(), "strict");
    }

    private static @NonNull ScimAuthenticationScheme scheme(@NonNull String type, boolean primary) {
        return ScimAuthenticationScheme.withType(type).name("Name").description("Description").primary(primary).build();
    }
}
