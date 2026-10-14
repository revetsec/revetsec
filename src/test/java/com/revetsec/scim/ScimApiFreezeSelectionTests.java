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

import static org.junit.jupiter.api.Assertions.*;

/** Public projection membership agrees with structural path equality without granting authorization. */
class ScimApiFreezeSelectionTests {
    private static final @NonNull ScimResourceType USER = ScimResourceType.userInstance();
    private static final @NonNull String ENTERPRISE = ScimSchema.enterpriseUserInstance().getId();
    private static final @NonNull String UPPER_ENTERPRISE = "URN:IETF:PARAMS:SCIM:SCHEMAS:EXTENSION:ENTERPRISE:2.0:USER";

    @Test void includedExtensionPathsAcceptEqualAsciiFoldedSchemaIdentifiers() {
        ScimAttributeSelection selection = selection(USER, "attributes=" + ENTERPRISE + ":department");
        ScimAttributePath canonical = selection.getIncludedAttributes().iterator().next();
        ScimAttributePath folded = path(UPPER_ENTERPRISE + ":DEPARTMENT");

        assertEquals(canonical, folded);
        assertEquals(canonical.hashCode(), folded.hashCode());
        assertTrue(selection.includes(canonical));
        assertTrue(selection.includes(folded));
        assertFalse(selection.includes(path(ENTERPRISE + ":division")));
        assertFalse(selection.includes(path("urn:example:other:department")));
    }

    @Test void excludedExtensionPathsRejectEqualAsciiFoldedSchemaIdentifiers() {
        ScimAttributeSelection selection = selection(USER, "excludedAttributes=" + ENTERPRISE + ":department");
        ScimAttributePath canonical = selection.getExcludedAttributes().iterator().next();
        ScimAttributePath folded = path(UPPER_ENTERPRISE + ":DEPARTMENT");

        assertEquals(canonical, folded);
        assertFalse(selection.includes(canonical));
        assertFalse(selection.includes(folded));
        assertTrue(selection.includes(path(ENTERPRISE + ":division")));
        assertTrue(selection.includes(path("displayName")));
    }

    @Test void includedExtensionChildExpandsItsParentWithoutIncludingSiblings() {
        ScimAttributeSelection selection = selection(USER, "attributes=" + ENTERPRISE + ":manager.value");

        assertTrue(selection.includes(path(UPPER_ENTERPRISE + ":MANAGER")));
        assertTrue(selection.includes(path(UPPER_ENTERPRISE + ":MANAGER.VALUE")));
        assertFalse(selection.includes(path(UPPER_ENTERPRISE + ":MANAGER.DISPLAYNAME")));
        assertFalse(selection.includes(path("manager.value")));
    }

    @Test void excludedExtensionParentExcludesFoldedChildrenWithoutExcludingCoreNames() {
        ScimAttributeSelection selection = selection(USER, "excludedAttributes=" + ENTERPRISE + ":manager");

        assertFalse(selection.includes(path(UPPER_ENTERPRISE + ":MANAGER")));
        assertFalse(selection.includes(path(UPPER_ENTERPRISE + ":MANAGER.VALUE")));
        assertFalse(selection.includes(path(UPPER_ENTERPRISE + ":MANAGER.DISPLAYNAME")));
        assertTrue(selection.includes(path("displayName")));
    }

    @Test void coreQualificationIsNormalizedDuringBinding() {
        ScimAttributeSelection selection = selection(USER,
                "attributes=" + USER.getSchema().getId() + ":USERNAME");

        assertEquals(path("userName"), selection.getIncludedAttributes().iterator().next());
        assertTrue(selection.getIncludedAttributes().iterator().next().getSchemaId().isEmpty());
        assertTrue(selection.includes(path("USERNAME")));
        assertFalse(selection.includes(path(ENTERPRISE + ":userName")));
    }

    @Test void implicitCoreAndRegisteredExtensionAttributesRemainDistinct() {
        String extensionId = "urn:example:api-freeze:extension";
        ScimSchema extension = ScimSchema.withId(extensionId).name("Extension")
                .attributes(List.of(ScimAttributeDefinition.withName("displayName").build())).build();
        ScimResourceType type = ScimResourceType.withName("User").endpoint("/Users")
                .schema(ScimSchema.userInstance())
                .schemaExtensions(List.of(ScimSchemaExtension.fromSchema(extension, false))).build();

        ScimAttributeSelection core = selection(type, "attributes=displayName");
        assertTrue(core.includes(path("DISPLAYNAME")));
        assertFalse(core.includes(path(extensionId + ":displayName")));

        ScimAttributeSelection selectedExtension = selection(type, "attributes=" + extensionId + ":displayName");
        assertTrue(selectedExtension.includes(path("URN:EXAMPLE:API-FREEZE:EXTENSION:DISPLAYNAME")));
        assertFalse(selectedExtension.includes(path("displayName")));

        ScimAttributeSelection excludedExtension = selection(type, "excludedAttributes=" + extensionId + ":displayName");
        assertFalse(excludedExtension.includes(path("URN:EXAMPLE:API-FREEZE:EXTENSION:DISPLAYNAME")));
        assertTrue(excludedExtension.includes(path("displayName")));
    }

    private static @NonNull ScimAttributeSelection selection(@NonNull ScimResourceType type, @NonNull String rawQuery) {
        ScimServiceProvider provider = ScimServiceProvider.builder()
                .baseUri(URI.create("https://example.invalid/scim/")).resourceTypes(List.of(type)).build();
        return assertInstanceOf(ScimAttributeSelectionResult.Succeeded.class,
                provider.parseAttributeSelectionResult(type, rawQuery)).getAttributeSelection();
    }

    private static @NonNull ScimAttributePath path(@NonNull String expression) {
        return assertInstanceOf(ScimAttributePathParseResult.Succeeded.class,
                ScimAttributePath.fromExpressionResult(expression)).getAttributePath();
    }
}
