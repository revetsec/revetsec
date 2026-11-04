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

import com.revetsec.json.JsonArray;
import com.revetsec.json.JsonObject;
import com.revetsec.json.JsonString;
import org.jspecify.annotations.NonNull;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

/** The core User preset must neither advertise nor infer optional Enterprise support. */
final class ScimEnterpriseOptInTests {
    private static final @NonNull String ENTERPRISE = ScimSchema.enterpriseUserInstance().getId();

    @Test void sharedCoreUserHasNoExtensionsAndRetainsItsResponsePreference() {
        ScimResourceType core = ScimResourceType.userInstance();
        assertSame(core, ScimResourceType.userInstance());
        assertSame(ScimSchema.userInstance(), core.getSchema());
        assertEquals("User", core.getName());
        assertEquals("User", core.getId().orElseThrow());
        assertEquals("/Users", core.getEndpoint());
        assertTrue(core.getSchemaExtensions().isEmpty());
        assertFalse(core.hasStandardEnterpriseUserSchema());
        assertFalse(core.isPatchResponseNoContent());
        assertThrows(UnsupportedOperationException.class, () -> core.getSchemaExtensions().add(
                ScimSchemaExtension.fromSchema(ScimSchema.enterpriseUserInstance(), false)));
    }

    @Test void discoveryPublishesOnlyTheSelectedSchemaRegistrations() {
        ScimResourceType core = ScimResourceType.userInstance();
        ScimServiceProvider coreProvider = provider(core);
        String coreType = text(coreProvider.resourceTypeResponseResult("User", ""));
        assertTrue(coreType.contains("\"schemaExtensions\":[]"));
        assertFalse(coreType.contains(ENTERPRISE));
        assertFalse(text(coreProvider.schemasResponseResult("")).contains(ENTERPRISE));
        assertSame(ScimError.notFoundInstance(), assertInstanceOf(ScimResponseResult.Rejected.class,
                coreProvider.schemaResponseResult(ENTERPRISE, "")).getError());
        assertFalse(coreProvider.getServiceProviderConfig().isPatchSupported());

        ScimResourceType explicit = ScimTestResourceTypes.userWithEnterpriseInstance();
        ScimServiceProvider enterpriseProvider = provider(explicit);
        assertTrue(text(enterpriseProvider.resourceTypeResponseResult("User", "")).contains(ENTERPRISE));
        assertTrue(text(enterpriseProvider.schemasResponseResult("")).contains(ENTERPRISE));
        assertTrue(text(enterpriseProvider.schemaResponseResult(ENTERPRISE, "")).contains(ENTERPRISE));
        assertTrue(core.getSchemaExtensions().isEmpty());
    }

    @Test void coreOnlyRejectsEnterpriseInputPathsAndFilterConfiguration() {
        ScimResourceType core = ScimResourceType.userInstance();
        ScimServiceProvider provider = provider(core);
        assertInstanceOf(ScimResourceParseResult.Succeeded.class,
                provider.parseResourceResult(core, body(false)));
        assertEquals(ScimErrorType.INVALID_VALUE,
                assertInstanceOf(ScimResourceParseResult.Rejected.class,
                        provider.parseResourceResult(core, body(true))).getError().getErrorType().orElseThrow());
        assertInstanceOf(ScimAttributeSelectionResult.Rejected.class,
                provider.parseAttributeSelectionResult(core, "attributes=" + ENTERPRISE + ":department"));
        assertTrue(core.canonicalAttributePath(path(ENTERPRISE + ":manager.value")).isEmpty());
        assertThrows(IllegalArgumentException.class, () -> ScimServiceProvider.builder()
                .baseUri(URI.create("https://example.test/scim/"))
                .resourceTypes(List.of(core))
                .serviceProviderConfig(ScimServiceProviderConfig.builder().filterSupported(true).build())
                .filterPolicies(Map.of(core, ScimFilterPolicy.builder().allowedComparisons(
                        Map.of(ENTERPRISE + ":department", Set.of(ScimComparisonOperator.EQ))).build()))
                .build());
        ScimServiceProvider infer = ScimServiceProvider.builder()
                .baseUri(URI.create("https://example.test/scim/"))
                .resourceTypes(List.of(core))
                .compatibility(ScimCompatibility.builder().features(
                        Set.of(ScimCompatibilityFeature.INFER_MISSING_EXTENSION_SCHEMAS)).build()).build();
        String undeclared = "{\"schemas\":[\"" + core.getSchema().getId()
                + "\"],\"userName\":\"Ada\",\"" + ENTERPRISE + "\":{\"department\":\"Engineering\"}}";
        assertInstanceOf(ScimResourceParseResult.Rejected.class,
                infer.parseResourceResult(core, undeclared.getBytes(StandardCharsets.UTF_8)));
    }

    @Test void explicitOptionalAndRequiredExtensionsRetainTheirDifferentContracts() {
        ScimResourceType optional = ScimTestResourceTypes.userWithEnterpriseInstance();
        ScimServiceProvider provider = provider(optional);
        assertFalse(optional.getSchemaExtensions().get(0).isRequired());
        assertInstanceOf(ScimResourceParseResult.Succeeded.class,
                provider.parseResourceResult(optional, body(false)));
        ScimResource resource = assertInstanceOf(ScimResourceParseResult.Succeeded.class,
                provider.parseResourceResult(optional, body(true))).getResource();
        assertEquals("Engineering", ScimEnterpriseUser.fromResource(resource).getDepartment().orElseThrow());
        assertEquals(ENTERPRISE + ":department", optional.canonicalAttributePath(
                path(ENTERPRISE.toUpperCase(java.util.Locale.ROOT) + ":DEPARTMENT")).orElseThrow().toScimString());
        assertInstanceOf(ScimAttributeSelectionResult.Succeeded.class,
                provider.parseAttributeSelectionResult(optional, "attributes=" + ENTERPRISE + ":department"));

        ScimResourceType required = ScimResourceType.withName("User").id("User").endpoint("/Users")
                .schema(ScimSchema.userInstance()).schemaExtensions(List.of(
                        ScimSchemaExtension.fromSchema(ScimSchema.enterpriseUserInstance(), true))).build();
        ScimServiceProvider requiredProvider = provider(required);
        assertInstanceOf(ScimResourceParseResult.Rejected.class,
                requiredProvider.parseResourceResult(required, body(false)));
        assertInstanceOf(ScimResourceParseResult.Succeeded.class,
                requiredProvider.parseResourceResult(required, body(true)));
        assertTrue(text(requiredProvider.resourceTypeResponseResult("User", "")).contains("\"required\":true"));
    }

    private static @NonNull ScimServiceProvider provider(@NonNull ScimResourceType type) {
        return ScimServiceProvider.builder().baseUri(URI.create("https://example.test/scim/"))
                .resourceTypes(List.of(type)).build();
    }

    private static byte @NonNull [] body(boolean enterprise) {
        JsonObject.Builder body = JsonObject.builder().put("userName", "Ada");
        if (enterprise) body.put("schemas", JsonArray.fromElements(List.of(
                        JsonString.fromValue(ScimSchema.userInstance().getId()), JsonString.fromValue(ENTERPRISE))))
                .put(ENTERPRISE, JsonObject.builder().put("department", "Engineering").build());
        else body.put("schemas", JsonArray.fromElements(List.of(
                JsonString.fromValue(ScimSchema.userInstance().getId()))));
        return body.build().toJson().getBytes(StandardCharsets.UTF_8);
    }

    private static @NonNull String text(@NonNull ScimResponseResult result) {
        return new String(assertInstanceOf(ScimResponseResult.Prepared.class, result)
                .getResponse().toHttpBodyWithPersonalData(), StandardCharsets.UTF_8);
    }

    private static @NonNull ScimAttributePath path(@NonNull String expression) {
        return assertInstanceOf(ScimAttributePathParseResult.Succeeded.class,
                ScimAttributePath.fromExpressionResult(expression)).getAttributePath();
    }
}
