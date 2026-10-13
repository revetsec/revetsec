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
import com.revetsec.json.JsonValue;
import org.jspecify.annotations.NonNull;

import javax.annotation.concurrent.ThreadSafe;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

/** Complete registered discovery descriptors, including unsupported Bulk and RFC 9865 pagination commitments. */
@ThreadSafe
final class ScimDiscovery {
    private static final @NonNull String CORE = "urn:ietf:params:scim:schemas:core:2.0:";
    private ScimDiscovery() { }

    static @NonNull JsonObject schema(@NonNull ScimSchema schema) {
        JsonObject.Builder body = JsonObject.builder().put("schemas", schemaNames("Schema"))
                .put("id", schema.getId()).put("name", schema.getName());
        schema.getDescription().ifPresent(description -> body.put("description", description));
        List<JsonValue> attributes = new ArrayList<>();
        for (ScimAttributeDefinition definition : schema.getAttributes()) attributes.add(attribute(definition));
        return body.put("attributes", JsonArray.fromElements(attributes)).build();
    }

    static @NonNull JsonObject resourceType(@NonNull ScimResourceType type) {
        JsonObject.Builder body = JsonObject.builder().put("schemas", schemaNames("ResourceType"))
                .put("name", type.getName()).put("endpoint", type.getEndpoint()).put("schema", type.getSchema().getId());
        type.getId().ifPresent(id -> body.put("id", id));
        type.getDescription().ifPresent(description -> body.put("description", description));
        List<JsonValue> extensions = new ArrayList<>();
        for (ScimSchemaExtension extension : type.getSchemaExtensions()) extensions.add(JsonObject.builder()
                .put("schema", extension.getSchema().getId()).put("required", extension.isRequired()).build());
        return body.put("schemaExtensions", JsonArray.fromElements(extensions)).build();
    }

    static @NonNull JsonObject configuration(@NonNull ScimServiceProviderConfig config) {
        JsonObject.Builder body = JsonObject.builder().put("schemas", schemaNames("ServiceProviderConfig"))
                .put("patch", supported(config.isPatchSupported()))
                .put("bulk", JsonObject.builder().put("supported", false).put("maxOperations", 0L).put("maxPayloadSize", 0L).build())
                .put("filter", JsonObject.builder().put("supported", config.isFilterSupported()).put("maxResults", config.getFilterMaximumResults().longValue()).build())
                .put("changePassword", supported(config.isChangePasswordSupported()))
                .put("sort", supported(config.isSortSupported())).put("etag", supported(config.isEtagSupported()));
        config.getDocumentationUri().ifPresent(uri -> body.put("documentationUri", uri.toASCIIString()));
        List<JsonValue> schemes = new ArrayList<>();
        for (ScimAuthenticationScheme scheme : config.getAuthenticationSchemes()) {
            JsonObject.Builder entry = JsonObject.builder().put("type", scheme.getType()).put("name", scheme.getName())
                    .put("description", scheme.getDescription()).put("primary", scheme.isPrimary());
            scheme.getSpecUri().ifPresent(uri -> entry.put("specUri", uri.toASCIIString()));
            scheme.getDocumentationUri().ifPresent(uri -> entry.put("documentationUri", uri.toASCIIString()));
            schemes.add(entry.build());
        }
        ScimPaginationConfig pagination = config.getPagination();
        JsonObject.Builder paging = JsonObject.builder().put("cursor", pagination.isCursorSupported()).put("index", pagination.isIndexSupported())
                .put("defaultPaginationMethod", pagination.getDefaultMethod() == ScimPaginationMethod.CURSOR ? "cursor" : "index")
                .put("defaultPageSize", pagination.getDefaultPageSize().longValue()).put("maxPageSize", pagination.getMaximumPageSize().longValue());
        pagination.getCursorTimeout().ifPresent(timeout -> paging.put("cursorTimeout", timeout.toSeconds()));
        return body.put("authenticationSchemes", JsonArray.fromElements(schemes)).put("pagination", paging.build()).build();
    }

    private static @NonNull JsonObject attribute(@NonNull ScimAttributeDefinition definition) {
        String type = switch (definition.getType()) {
            case STRING -> "string"; case BOOLEAN -> "boolean"; case DECIMAL -> "decimal"; case INTEGER -> "integer";
            case DATE_TIME -> "dateTime"; case BINARY -> "binary"; case REFERENCE -> "reference"; case COMPLEX -> "complex";
        };
        String mutability = switch (definition.getMutability()) {
            case READ_ONLY -> "readOnly"; case READ_WRITE -> "readWrite"; case IMMUTABLE -> "immutable"; case WRITE_ONLY -> "writeOnly";
        };
        String returned = switch (definition.getReturned()) {
            case ALWAYS -> "always"; case NEVER -> "never"; case DEFAULT -> "default"; case REQUEST -> "request";
        };
        String uniqueness = switch (definition.getUniqueness()) {
            case NONE -> "none"; case SERVER -> "server"; case GLOBAL -> "global";
        };
        JsonObject.Builder value = JsonObject.builder().put("name", definition.getName()).put("type", type)
                .put("multiValued", definition.isMultiValued()).put("required", definition.isRequired()).put("caseExact", definition.isCaseExact())
                .put("mutability", mutability).put("returned", returned);
        if (definition.getType() != ScimAttributeType.COMPLEX) value.put("uniqueness", uniqueness);
        definition.getDescription().ifPresent(description -> value.put("description", description));
        if (!definition.getCanonicalValues().isEmpty()) value.put("canonicalValues", strings(definition.getCanonicalValues()));
        if (!definition.getReferenceTypes().isEmpty()) value.put("referenceTypes", strings(definition.getReferenceTypes()));
        if (definition.getType() == ScimAttributeType.COMPLEX) {
            List<JsonValue> children = new ArrayList<>();
            for (ScimAttributeDefinition child : definition.getSubAttributes()) children.add(attribute(child));
            value.put("subAttributes", JsonArray.fromElements(children));
        }
        return value.build();
    }
    private static @NonNull JsonArray schemaNames(@NonNull String name) {
        return JsonArray.fromElements(List.of(JsonString.fromValue(CORE + name)));
    }
    private static @NonNull JsonArray strings(@NonNull Set<@NonNull String> values) {
        List<JsonValue> strings = new ArrayList<>();
        for (String value : values) strings.add(JsonString.fromValue(value));
        return JsonArray.fromElements(strings);
    }
    private static @NonNull JsonObject supported(@NonNull Boolean value) { return JsonObject.builder().put("supported", value).build(); }
}
