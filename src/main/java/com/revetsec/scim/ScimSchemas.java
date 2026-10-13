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

import com.revetsec.internal.Limits;
import com.revetsec.internal.json.AsciiCase;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import java.net.URI;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

/** SCIM-owned bounded registration validation, fixed schemas and schema lookup. */
final class ScimSchemas {
    private ScimSchemas() {}

    static @NonNull String requireAttributeName(@NonNull String value) {
        Objects.requireNonNull(value);
        if (value.length() > Limits.SCIM_ATTRIBUTE_NAME_LENGTH.getCap()
                || !(ScimAttributePath.fromExpressionResult(value) instanceof ScimAttributePathParseResult.Succeeded result)
                || result.getAttributePath().getSchemaId().isPresent()
                || result.getAttributePath().getSubAttributeName().isPresent())
            throw new IllegalArgumentException("Invalid bounded SCIM attribute name.");
        return value;
    }

    static @NonNull String requireName(@NonNull String value) {
        requireText(value, true);
        if (value.length() > Limits.SCIM_ATTRIBUTE_NAME_LENGTH.getCap()
                || value.chars().anyMatch(unit -> unit < 0x20))
            throw new IllegalArgumentException("SCIM configured name exceeds its limit.");
        return value;
    }

    static @NonNull String requireText(@NonNull String value, boolean nonempty) {
        Objects.requireNonNull(value);
        if (value.length() > Limits.SCIM_IDENTIFIER_LENGTH.getCap() || nonempty && value.isBlank())
            throw new IllegalArgumentException("Invalid bounded SCIM configured text.");
        for (int index = 0; index < value.length(); index++) {
            char unit = value.charAt(index);
            if (unit < 0x20 && unit != '\t' && unit != '\n' && unit != '\r' || unit == 0x7f)
                throw new IllegalArgumentException("Invalid SCIM configured text control character.");
            if (Character.isHighSurrogate(unit)) {
                if (++index >= value.length() || !Character.isLowSurrogate(value.charAt(index)))
                    throw new IllegalArgumentException("Invalid SCIM configured text Unicode.");
            } else if (Character.isLowSurrogate(unit))
                throw new IllegalArgumentException("Invalid SCIM configured text Unicode.");
        }
        return value;
    }

    static @NonNull String requireIdentifier(@NonNull String value) {
        requireText(value, true);
        for (int index = 0; index < value.length(); index++)
            if (value.charAt(index) <= 0x20 || value.charAt(index) == 0x7f)
                throw new IllegalArgumentException("Invalid SCIM identifier character.");
        if (AsciiCase.fold(value).contains("bulkid"))
            throw new IllegalArgumentException("SCIM identifiers cannot contain the reserved bulkId keyword.");
        return value;
    }

    static boolean absoluteUri(@NonNull String value) {
        Objects.requireNonNull(value);
        if (value.length() > Limits.SCIM_SCHEMA_ID_LENGTH.getCap()) return false;
        return ScimAttributePath.fromExpressionResult(value + ":x") instanceof ScimAttributePathParseResult.Succeeded;
    }

    static @NonNull String requireSchemaId(@NonNull String value) {
        if (!absoluteUri(value))
            throw new IllegalArgumentException("A SCIM schema identifier requires a bounded absolute URI.");
        return value;
    }

    static @NonNull String requireEndpoint(@NonNull String value) {
        Objects.requireNonNull(value);
        if (value.length() > Limits.SCIM_BASE_URI_LENGTH.getCap() || !value.startsWith("/")
                || value.startsWith("//") || value.endsWith("/"))
            throw new IllegalArgumentException("Invalid bounded SCIM resource endpoint.");
        for (int index = 0; index < value.length(); index++) {
            char unit = value.charAt(index);
            if (unit <= 0x20 || unit >= 0x7f || unit == '\\')
                throw new IllegalArgumentException("Invalid SCIM endpoint character.");
            if (unit == '%' && index + 2 < value.length()) {
                String encoded = value.substring(index + 1, index + 3);
                if (AsciiCase.fold(encoded).equals("2f") || AsciiCase.fold(encoded).equals("5c"))
                    throw new IllegalArgumentException("SCIM endpoints cannot contain encoded separators.");
            }
        }
        URI uri = URI.create(value);
        if (uri.isAbsolute() || uri.getRawAuthority() != null || uri.getRawQuery() != null
                || uri.getRawFragment() != null)
            throw new IllegalArgumentException("SCIM endpoints require authority-free paths.");
        String decoded = uri.getPath();
        if (decoded == null)
            throw new IllegalArgumentException("SCIM endpoints require paths.");
        for (String segment : decoded.substring(1).split("/", -1))
            if (segment.isEmpty() || segment.equals(".") || segment.equals(".."))
                throw new IllegalArgumentException("SCIM endpoints cannot contain traversal or empty segments.");
        return value;
    }

    static @NonNull URI requireDocumentationUri(@NonNull URI value) {
        Objects.requireNonNull(value);
        String text = value.toString();
        if (text.length() > Limits.SCIM_BASE_URI_LENGTH.getCap() || !value.isAbsolute()
                || value.getHost() == null || value.getRawUserInfo() != null
                || !("https".equals(AsciiCase.fold(value.getScheme())) || "http".equals(AsciiCase.fold(value.getScheme()))))
            throw new IllegalArgumentException("SCIM documentation requires a bounded HTTP(S) URI.");
        return value;
    }

    static void requireDefinitionCount(int count) {
        if (count > Limits.SCIM_ATTRIBUTE_DEFINITIONS.getCap())
            throw new IllegalArgumentException("SCIM definition count exceeds its limit.");
    }

    static int commonDefinitionCount() {
        int count = 0;
        for (ScimAttributeDefinition definition : commonAttributes()) count += definition.definitionCount();
        return count;
    }

    static @NonNull List<@NonNull ScimAttributeDefinition> attributes(
            @NonNull List<@NonNull ScimAttributeDefinition> values) {
        Objects.requireNonNull(values);
        requireDefinitionCount(values.size());
        int count = 0;
        for (ScimAttributeDefinition definition : values) {
            count += Objects.requireNonNull(definition).definitionCount();
            requireDefinitionCount(count);
        }
        return List.copyOf(values);
    }

    static @NonNull Set<@NonNull String> stringSet(@NonNull Set<@NonNull String> values) {
        Objects.requireNonNull(values);
        requireDefinitionCount(values.size());
        for (String value : values) requireText(Objects.requireNonNull(value), true);
        return Collections.unmodifiableSet(new LinkedHashSet<>(values));
    }

    static @NonNull List<@NonNull ScimSchemaExtension> extensions(
            @NonNull List<@NonNull ScimSchemaExtension> values) {
        Objects.requireNonNull(values);
        if (values.size() > Limits.SCIM_SCHEMA_EXTENSIONS.getCap())
            throw new IllegalArgumentException("SCIM extension count exceeds its limit.");
        for (ScimSchemaExtension value : values) Objects.requireNonNull(value);
        return List.copyOf(values);
    }

    static void requireDistinctAttributes(@NonNull List<@NonNull ScimAttributeDefinition> values) {
        Set<@NonNull String> names = new HashSet<>();
        for (ScimAttributeDefinition definition : values)
            if (!names.add(AsciiCase.fold(definition.getName())))
                throw new IllegalArgumentException("Duplicate SCIM attribute name.");
    }

    static boolean isCommonName(@NonNull String name) {
        String folded = AsciiCase.fold(name);
        return folded.equals("id") || folded.equals("externalid") || folded.equals("meta") || folded.equals("schemas");
    }

    static @NonNull Optional<@NonNull ScimAttributeDefinition> attribute(@NonNull ScimSchema schema,
            @NonNull String name) {
        return attribute(schema.getAttributes(), name);
    }

    static @NonNull Optional<@NonNull ScimAttributeDefinition> attribute(
            @NonNull List<@NonNull ScimAttributeDefinition> attributes, @NonNull String name) {
        String folded = AsciiCase.fold(name);
        for (ScimAttributeDefinition definition : attributes)
            if (AsciiCase.fold(definition.getName()).equals(folded)) return Optional.of(definition);
        return Optional.empty();
    }

    static @NonNull Optional<@NonNull ScimAttributeDefinition> find(@NonNull ScimResourceType type,
            @NonNull ScimAttributePath path) {
        Optional<ScimAttributeDefinition> top = topAttribute(type, path);
        if (top.isEmpty() || path.getSubAttributeName().isEmpty()) return top;
        return attribute(top.get().getSubAttributes(), path.getSubAttributeName().get());
    }

    private static @NonNull Optional<@NonNull ScimAttributeDefinition> topAttribute(@NonNull ScimResourceType type,
            @NonNull ScimAttributePath path) {
        if (path.getSchemaId().isEmpty() || AsciiCase.fold(path.getSchemaId().get())
                .equals(AsciiCase.fold(type.getSchema().getId()))) {
            if (type.getSchema().isDiscovery()) {
                Optional<ScimAttributeDefinition> declared = attribute(type.getSchema(), path.getAttributeName());
                if (declared.isPresent()) return declared;
                if (AsciiCase.fold(type.getSchema().getId()).equals("urn:ietf:params:scim:schemas:core:2.0:schema")
                        && !AsciiCase.fold(path.getAttributeName()).equals("schemas")) return Optional.empty();
            }
            Optional<ScimAttributeDefinition> common = attribute(commonAttributes(), path.getAttributeName());
            return common.isPresent() ? common : attribute(type.getSchema(), path.getAttributeName());
        }
        String folded = AsciiCase.fold(path.getSchemaId().get());
        for (ScimSchemaExtension extension : type.getSchemaExtensions())
            if (folded.equals(AsciiCase.fold(extension.getSchema().getId())))
                return attribute(extension.getSchema(), path.getAttributeName());
        return Optional.empty();
    }

    static @NonNull Optional<@NonNull ScimAttributePath> canonicalPath(@NonNull ScimResourceType type,
            @NonNull ScimAttributePath path) {
        Optional<ScimAttributeDefinition> top = topAttribute(type, path);
        if (top.isEmpty()) return Optional.empty();
        String expression = top.get().getName();
        if (path.getSubAttributeName().isPresent()) {
            Optional<ScimAttributeDefinition> child = attribute(top.get().getSubAttributes(), path.getSubAttributeName().get());
            if (child.isEmpty()) return Optional.empty();
            expression += "." + child.get().getName();
        }
        // Core paths normalize to unqualified spelling; extension paths retain their registered URI.
        if (path.getSchemaId().isPresent() && !AsciiCase.fold(path.getSchemaId().get())
                .equals(AsciiCase.fold(type.getSchema().getId()))) {
            for (ScimSchemaExtension extension : type.getSchemaExtensions())
                if (AsciiCase.fold(path.getSchemaId().get()).equals(AsciiCase.fold(extension.getSchema().getId()))) {
                    expression = extension.getSchema().getId() + ":" + expression; break;
                }
        }
        return Optional.of(((ScimAttributePathParseResult.Succeeded)
                ScimAttributePath.fromExpressionResult(expression)).getAttributePath());
    }

    static @NonNull List<@NonNull ScimSchema> allSchemas(@NonNull ScimResourceType type) {
        List<@NonNull ScimSchema> schemas = new ArrayList<>(1 + type.getSchemaExtensions().size());
        schemas.add(type.getSchema());
        for (ScimSchemaExtension extension : type.getSchemaExtensions()) schemas.add(extension.getSchema());
        return List.copyOf(schemas);
    }

    static @NonNull List<@NonNull ScimAttributeDefinition> commonAttributes() { return Common.ATTRIBUTES; }
    static @NonNull ScimSchema user() { return Standard.USER; }
    static @NonNull ScimSchema group() { return Standard.GROUP; }
    static @NonNull ScimSchema enterpriseUser() { return Standard.ENTERPRISE; }
    static @NonNull ScimSchema serviceProviderConfig() { return Standard.SERVICE; }
    static @NonNull ScimSchema resourceType() { return Standard.RESOURCE_TYPE; }
    static @NonNull ScimSchema schema() { return Standard.SCHEMA; }


    private static @NonNull ScimAttributeDefinition paginationDefinition() {
        return ScimAttributeDefinition.withName("pagination").type(ScimAttributeType.COMPLEX)
                .description("Pagination configuration options defined by RFC 9865 section 3.")
                .mutability(ScimMutability.READ_ONLY).subAttributes(List.of(
                        ScimAttributeDefinition.withName("cursor").type(ScimAttributeType.BOOLEAN)
                                .required(true).mutability(ScimMutability.READ_ONLY).build(),
                        ScimAttributeDefinition.withName("index").type(ScimAttributeType.BOOLEAN)
                                .required(true).mutability(ScimMutability.READ_ONLY).build(),
                        ScimAttributeDefinition.withName("defaultPaginationMethod")
                                .canonicalValues(Set.of("cursor", "index")).mutability(ScimMutability.READ_ONLY).build(),
                        ScimAttributeDefinition.withName("defaultPageSize").type(ScimAttributeType.INTEGER)
                                .mutability(ScimMutability.READ_ONLY).build(),
                        ScimAttributeDefinition.withName("maxPageSize").type(ScimAttributeType.INTEGER)
                                .mutability(ScimMutability.READ_ONLY).build(),
                        ScimAttributeDefinition.withName("cursorTimeout").type(ScimAttributeType.INTEGER)
                                .mutability(ScimMutability.READ_ONLY).build())).build();
    }

    private static final class Common {
        private static final @NonNull List<@NonNull ScimAttributeDefinition> ATTRIBUTES = List.of(
                ScimAttributeDefinition.withName("id").description("Service-provider assigned resource identifier.")
                        .caseExact(true).mutability(ScimMutability.READ_ONLY).returned(ScimReturned.ALWAYS)
                        .uniqueness(ScimUniqueness.SERVER).build(),
                ScimAttributeDefinition.withName("externalId").description("Client-assigned provisioning-domain identifier.")
                        .caseExact(true).build(),
                ScimAttributeDefinition.withName("meta").type(ScimAttributeType.COMPLEX)
                        .mutability(ScimMutability.READ_ONLY).subAttributes(List.of(
                                ScimAttributeDefinition.withName("resourceType").caseExact(true).mutability(ScimMutability.READ_ONLY).build(),
                                ScimAttributeDefinition.withName("created").type(ScimAttributeType.DATE_TIME)
                                        .mutability(ScimMutability.READ_ONLY).build(),
                                ScimAttributeDefinition.withName("lastModified").type(ScimAttributeType.DATE_TIME)
                                        .mutability(ScimMutability.READ_ONLY).build(),
                                ScimAttributeDefinition.withName("location").type(ScimAttributeType.REFERENCE)
                                        .referenceTypes(Set.of("uri")).caseExact(true)
                                        .mutability(ScimMutability.READ_ONLY).build(),
                                ScimAttributeDefinition.withName("version").caseExact(true).mutability(ScimMutability.READ_ONLY).build()))
                        .build(),
                ScimAttributeDefinition.withName("schemas").type(ScimAttributeType.STRING).multiValued(true)
                        .required(true).caseExact(true).returned(ScimReturned.ALWAYS).build());
        private Common() {}
    }

    private static final class Standard {
        private static final @NonNull ScimSchema USER = ScimSchema.withId("urn:ietf:params:scim:schemas:core:2.0:User").name("User")
                .description("User Account")
                .attributes(List.of(
                ScimAttributeDefinition.withName("userName")
                        .description("Unique identifier for the User, typically used by the user to directly authenticate to the service provider. Each User MUST include a non-empty userName value. This identifier MUST be unique across the service provider's entire set of Users. REQUIRED.")
                        .required(true)
                        .uniqueness(ScimUniqueness.SERVER)
                        .build(),
                ScimAttributeDefinition.withName("name")
                        .type(ScimAttributeType.COMPLEX)
                        .description("The components of the user's real name. Providers MAY return just the full name as a single string in the formatted sub-attribute, or they MAY return just the individual component attributes using the other sub-attributes, or they MAY return both. If both variants are returned, they SHOULD be describing the same name, with the formatted name indicating how the component attributes should be combined.")
                        .subAttributes(List.of(
                        ScimAttributeDefinition.withName("formatted")
                                .description("The full name, including all middle names, titles, and suffixes as appropriate, formatted for display (e.g., 'Ms. Barbara J Jensen, III').")
                                .build(),
                        ScimAttributeDefinition.withName("familyName")
                                .description("The family name of the User, or last name in most Western languages (e.g., 'Jensen' given the full name 'Ms. Barbara J Jensen, III').")
                                .build(),
                        ScimAttributeDefinition.withName("givenName")
                                .description("The given name of the User, or first name in most Western languages (e.g., 'Barbara' given the full name 'Ms. Barbara J Jensen, III').")
                                .build(),
                        ScimAttributeDefinition.withName("middleName")
                                .description("The middle name(s) of the User (e.g., 'Jane' given the full name 'Ms. Barbara J Jensen, III').")
                                .build(),
                        ScimAttributeDefinition.withName("honorificPrefix")
                                .description("The honorific prefix(es) of the User, or title in most Western languages (e.g., 'Ms.' given the full name 'Ms. Barbara J Jensen, III').")
                                .build(),
                        ScimAttributeDefinition.withName("honorificSuffix")
                                .description("The honorific suffix(es) of the User, or suffix in most Western languages (e.g., 'III' given the full name 'Ms. Barbara J Jensen, III').")
                                .build()
                ))
                        .build(),
                ScimAttributeDefinition.withName("displayName")
                        .description("The name of the User, suitable for display to end-users. The name SHOULD be the full name of the User being described, if known.")
                        .build(),
                ScimAttributeDefinition.withName("nickName")
                        .description("The casual way to address the user in real life, e.g., 'Bob' or 'Bobby' instead of 'Robert'. This attribute SHOULD NOT be used to represent a User's username (e.g., 'bjensen' or 'mpepperidge').")
                        .build(),
                ScimAttributeDefinition.withName("profileUrl")
                        .type(ScimAttributeType.REFERENCE)
                        .description("A fully qualified URL pointing to a page representing the User's online profile.")
                        .referenceTypes(Set.of("external"))
                        .build(),
                ScimAttributeDefinition.withName("title")
                        .description("The user's title, such as \"Vice President.\"")
                        .build(),
                ScimAttributeDefinition.withName("userType")
                        .description("Used to identify the relationship between the organization and the user. Typical values used might be 'Contractor', 'Employee', 'Intern', 'Temp', 'External', and 'Unknown', but any value may be used.")
                        .build(),
                ScimAttributeDefinition.withName("preferredLanguage")
                        .description("Indicates the User's preferred written or spoken language. Generally used for selecting a localized user interface; e.g., 'en_US' specifies the language English and country US.")
                        .build(),
                ScimAttributeDefinition.withName("locale")
                        .description("Used to indicate the User's default location for purposes of localizing items such as currency, date time format, or numerical representations.")
                        .build(),
                ScimAttributeDefinition.withName("timezone")
                        .description("The User's time zone in the 'Olson' time zone database format, e.g., 'America/Los_Angeles'.")
                        .build(),
                ScimAttributeDefinition.withName("active")
                        .type(ScimAttributeType.BOOLEAN)
                        .description("A Boolean value indicating the User's administrative status.")
                        .build(),
                ScimAttributeDefinition.withName("password")
                        .description("The User's cleartext password. This attribute is intended to be used as a means to specify an initial password when creating a new User or to reset an existing User's password.")
                        .mutability(ScimMutability.WRITE_ONLY)
                        .returned(ScimReturned.NEVER)
                        .build(),
                ScimAttributeDefinition.withName("emails")
                        .type(ScimAttributeType.COMPLEX)
                        .description("Email addresses for the user. The value SHOULD be canonicalized by the service provider, e.g., 'bjensen@example.com' instead of 'bjensen@EXAMPLE.COM'. Canonical type values of 'work', 'home', and 'other'.")
                        .multiValued(true)
                        .subAttributes(List.of(
                        ScimAttributeDefinition.withName("value")
                                .description("Email addresses for the user. The value SHOULD be canonicalized by the service provider, e.g., 'bjensen@example.com' instead of 'bjensen@EXAMPLE.COM'. Canonical type values of 'work', 'home', and 'other'.")
                                .build(),
                        ScimAttributeDefinition.withName("display")
                                .description("A human-readable name, primarily used for display purposes. READ-ONLY.")
                                .build(),
                        ScimAttributeDefinition.withName("type")
                                .description("A label indicating the attribute's function, e.g., 'work' or 'home'.")
                                .canonicalValues(Set.of("work", "home", "other"))
                                .build(),
                        ScimAttributeDefinition.withName("primary")
                                .type(ScimAttributeType.BOOLEAN)
                                .description("A Boolean value indicating the 'primary' or preferred attribute value for this attribute, e.g., the preferred mailing address or primary email address. The primary attribute value 'true' MUST appear no more than once.")
                                .build()
                ))
                        .build(),
                ScimAttributeDefinition.withName("phoneNumbers")
                        .type(ScimAttributeType.COMPLEX)
                        .description("Phone numbers for the User. The value SHOULD be canonicalized by the service provider according to the format specified in RFC 3966, e.g., 'tel:+1-201-555-0123'. Canonical type values of 'work', 'home', 'mobile', 'fax', 'pager', and 'other'.")
                        .multiValued(true)
                        .subAttributes(List.of(
                        ScimAttributeDefinition.withName("value")
                                .description("Phone number of the User.")
                                .build(),
                        ScimAttributeDefinition.withName("display")
                                .description("A human-readable name, primarily used for display purposes. READ-ONLY.")
                                .build(),
                        ScimAttributeDefinition.withName("type")
                                .description("A label indicating the attribute's function, e.g., 'work', 'home', 'mobile'.")
                                .canonicalValues(Set.of("work", "home", "mobile", "fax", "pager", "other"))
                                .build(),
                        ScimAttributeDefinition.withName("primary")
                                .type(ScimAttributeType.BOOLEAN)
                                .description("A Boolean value indicating the 'primary' or preferred attribute value for this attribute, e.g., the preferred phone number or primary phone number. The primary attribute value 'true' MUST appear no more than once.")
                                .build()
                ))
                        .build(),
                ScimAttributeDefinition.withName("ims")
                        .type(ScimAttributeType.COMPLEX)
                        .description("Instant messaging addresses for the User.")
                        .multiValued(true)
                        .subAttributes(List.of(
                        ScimAttributeDefinition.withName("value")
                                .description("Instant messaging address for the User.")
                                .build(),
                        ScimAttributeDefinition.withName("display")
                                .description("A human-readable name, primarily used for display purposes. READ-ONLY.")
                                .build(),
                        ScimAttributeDefinition.withName("type")
                                .description("A label indicating the attribute's function, e.g., 'aim', 'gtalk', 'xmpp'.")
                                .canonicalValues(Set.of("aim", "gtalk", "icq", "xmpp", "msn", "skype", "qq", "yahoo"))
                                .build(),
                        ScimAttributeDefinition.withName("primary")
                                .type(ScimAttributeType.BOOLEAN)
                                .description("A Boolean value indicating the 'primary' or preferred attribute value for this attribute, e.g., the preferred messenger or primary messenger. The primary attribute value 'true' MUST appear no more than once.")
                                .build()
                ))
                        .build(),
                ScimAttributeDefinition.withName("photos")
                        .type(ScimAttributeType.COMPLEX)
                        .description("URLs of photos of the User.")
                        .multiValued(true)
                        .subAttributes(List.of(
                        ScimAttributeDefinition.withName("value")
                                .type(ScimAttributeType.REFERENCE)
                                .description("URL of a photo of the User.")
                                .referenceTypes(Set.of("external"))
                                .build(),
                        ScimAttributeDefinition.withName("display")
                                .description("A human-readable name, primarily used for display purposes. READ-ONLY.")
                                .build(),
                        ScimAttributeDefinition.withName("type")
                                .description("A label indicating the attribute's function, i.e., 'photo' or 'thumbnail'.")
                                .canonicalValues(Set.of("photo", "thumbnail"))
                                .build(),
                        ScimAttributeDefinition.withName("primary")
                                .type(ScimAttributeType.BOOLEAN)
                                .description("A Boolean value indicating the 'primary' or preferred attribute value for this attribute, e.g., the preferred photo or thumbnail. The primary attribute value 'true' MUST appear no more than once.")
                                .build()
                ))
                        .build(),
                ScimAttributeDefinition.withName("addresses")
                        .type(ScimAttributeType.COMPLEX)
                        .description("A physical mailing address for this User. Canonical type values of 'work', 'home', and 'other'. This attribute is a complex type with the following sub-attributes.")
                        .multiValued(true)
                        .subAttributes(List.of(
                        ScimAttributeDefinition.withName("formatted")
                                .description("The full mailing address, formatted for display or use with a mailing label. This attribute MAY contain newlines.")
                                .build(),
                        ScimAttributeDefinition.withName("streetAddress")
                                .description("The full street address component, which may include house number, street name, P.O. box, and multi-line extended street address information. This attribute MAY contain newlines.")
                                .build(),
                        ScimAttributeDefinition.withName("locality")
                                .description("The city or locality component.")
                                .build(),
                        ScimAttributeDefinition.withName("region")
                                .description("The state or region component.")
                                .build(),
                        ScimAttributeDefinition.withName("postalCode")
                                .description("The zip code or postal code component.")
                                .build(),
                        ScimAttributeDefinition.withName("country")
                                .description("The country name component.")
                                .build(),
                        ScimAttributeDefinition.withName("type")
                                .description("A label indicating the attribute's function, e.g., 'work' or 'home'.")
                                .canonicalValues(Set.of("work", "home", "other"))
                                .build(),
                        ScimAttributeDefinition.withName("primary")
                                .type(ScimAttributeType.BOOLEAN)
                                .description("Whether this address is the preferred address. At most one is true.")
                                .build()
                ))
                        .build(),
                ScimAttributeDefinition.withName("groups")
                        .type(ScimAttributeType.COMPLEX)
                        .description("A list of groups to which the user belongs, either through direct membership, through nested groups, or dynamically calculated.")
                        .multiValued(true)
                        .mutability(ScimMutability.READ_ONLY)
                        .subAttributes(List.of(
                        ScimAttributeDefinition.withName("value")
                                .description("The identifier of the User's group.")
                                .mutability(ScimMutability.READ_ONLY)
                                .build(),
                        ScimAttributeDefinition.withName("$ref")
                                .type(ScimAttributeType.REFERENCE)
                                .description("The URI of the corresponding 'Group' resource to which the user belongs.")
                                .mutability(ScimMutability.READ_ONLY)
                                .referenceTypes(Set.of("Group"))
                                .build(),
                        ScimAttributeDefinition.withName("display")
                                .description("A human-readable name, primarily used for display purposes. READ-ONLY.")
                                .mutability(ScimMutability.READ_ONLY)
                                .build(),
                        ScimAttributeDefinition.withName("type")
                                .description("A label indicating the attribute's function, e.g., 'direct' or 'indirect'.")
                                .mutability(ScimMutability.READ_ONLY)
                                .canonicalValues(Set.of("direct", "indirect"))
                                .build()
                ))
                        .build(),
                ScimAttributeDefinition.withName("entitlements")
                        .type(ScimAttributeType.COMPLEX)
                        .description("A list of entitlements for the User that represent a thing the User has.")
                        .multiValued(true)
                        .subAttributes(List.of(
                        ScimAttributeDefinition.withName("value")
                                .description("The value of an entitlement.")
                                .build(),
                        ScimAttributeDefinition.withName("display")
                                .description("A human-readable name, primarily used for display purposes. READ-ONLY.")
                                .build(),
                        ScimAttributeDefinition.withName("type")
                                .description("A label indicating the attribute's function.")
                                .build(),
                        ScimAttributeDefinition.withName("primary")
                                .type(ScimAttributeType.BOOLEAN)
                                .description("A Boolean value indicating the 'primary' or preferred attribute value for this attribute. The primary attribute value 'true' MUST appear no more than once.")
                                .build()
                ))
                        .build(),
                ScimAttributeDefinition.withName("roles")
                        .type(ScimAttributeType.COMPLEX)
                        .description("A list of roles for the User that collectively represent who the User is, e.g., 'Student', 'Faculty'.")
                        .multiValued(true)
                        .subAttributes(List.of(
                        ScimAttributeDefinition.withName("value")
                                .description("The value of a role.")
                                .build(),
                        ScimAttributeDefinition.withName("display")
                                .description("A human-readable name, primarily used for display purposes. READ-ONLY.")
                                .build(),
                        ScimAttributeDefinition.withName("type")
                                .description("A label indicating the attribute's function.")
                                .build(),
                        ScimAttributeDefinition.withName("primary")
                                .type(ScimAttributeType.BOOLEAN)
                                .description("A Boolean value indicating the 'primary' or preferred attribute value for this attribute. The primary attribute value 'true' MUST appear no more than once.")
                                .build()
                ))
                        .build(),
                ScimAttributeDefinition.withName("x509Certificates")
                        .type(ScimAttributeType.COMPLEX)
                        .description("A list of certificates issued to the User.")
                        .multiValued(true)
                        .subAttributes(List.of(
                        ScimAttributeDefinition.withName("value")
                                .type(ScimAttributeType.BINARY)
                                .description("The value of an X.509 certificate.")
                                .build(),
                        ScimAttributeDefinition.withName("display")
                                .description("A human-readable name, primarily used for display purposes. READ-ONLY.")
                                .build(),
                        ScimAttributeDefinition.withName("type")
                                .description("A label indicating the attribute's function.")
                                .build(),
                        ScimAttributeDefinition.withName("primary")
                                .type(ScimAttributeType.BOOLEAN)
                                .description("A Boolean value indicating the 'primary' or preferred attribute value for this attribute. The primary attribute value 'true' MUST appear no more than once.")
                                .build()
                ))
                        .build()
                )).build();

        private static final @NonNull ScimSchema GROUP = ScimSchema.withId("urn:ietf:params:scim:schemas:core:2.0:Group").name("Group")
                .description("Group")
                .attributes(List.of(
                ScimAttributeDefinition.withName("displayName")
                        .description("A human-readable name for the Group. REQUIRED.")
                        .required(true)
                        .build(),
                ScimAttributeDefinition.withName("members")
                        .type(ScimAttributeType.COMPLEX)
                        .description("A list of members of the Group.")
                        .multiValued(true)
                        .subAttributes(List.of(
                        ScimAttributeDefinition.withName("value")
                                .description("Identifier of the member of this Group.")
                                .mutability(ScimMutability.IMMUTABLE)
                                .build(),
                        ScimAttributeDefinition.withName("$ref")
                                .type(ScimAttributeType.REFERENCE)
                                .description("The URI corresponding to a SCIM resource that is a member of this Group.")
                                .mutability(ScimMutability.IMMUTABLE)
                                .referenceTypes(Set.of("User", "Group"))
                                .build(),
                        ScimAttributeDefinition.withName("type")
                                .description("A label indicating the type of resource, e.g., 'User' or 'Group'.")
                                .mutability(ScimMutability.IMMUTABLE)
                                .canonicalValues(Set.of("User", "Group"))
                                .build(),
                        ScimAttributeDefinition.withName("display")
                                .description("Human-readable group-member display name.")
                                .mutability(ScimMutability.READ_ONLY)
                                .build()
                ))
                        .build()
                )).build();

        private static final @NonNull ScimSchema ENTERPRISE = ScimSchema.withId("urn:ietf:params:scim:schemas:extension:enterprise:2.0:User").name("EnterpriseUser")
                .description("Enterprise User")
                .attributes(List.of(
                ScimAttributeDefinition.withName("employeeNumber")
                        .description("Numeric or alphanumeric identifier assigned to a person, typically based on order of hire or association with an organization.")
                        .build(),
                ScimAttributeDefinition.withName("costCenter")
                        .description("Identifies the name of a cost center.")
                        .build(),
                ScimAttributeDefinition.withName("organization")
                        .description("Identifies the name of an organization.")
                        .build(),
                ScimAttributeDefinition.withName("division")
                        .description("Identifies the name of a division.")
                        .build(),
                ScimAttributeDefinition.withName("department")
                        .description("Identifies the name of a department.")
                        .build(),
                ScimAttributeDefinition.withName("manager")
                        .type(ScimAttributeType.COMPLEX)
                        .description("The User's manager. A complex type that optionally allows service providers to represent organizational hierarchy by referencing the 'id' attribute of another User.")
                        .subAttributes(List.of(
                        ScimAttributeDefinition.withName("value")
                                .description("The id of the SCIM resource representing the User's manager. REQUIRED.")
                                .caseExact(true)
                                .build(),
                        ScimAttributeDefinition.withName("$ref")
                                .type(ScimAttributeType.REFERENCE)
                                .description("The URI of the SCIM resource representing the User's manager. REQUIRED.")
                                .referenceTypes(Set.of("User"))
                                .build(),
                        ScimAttributeDefinition.withName("displayName")
                                .description("The displayName of the User's manager. OPTIONAL and READ-ONLY.")
                                .mutability(ScimMutability.READ_ONLY)
                                .build()
                ))
                        .build()
                )).build();

        private static final @NonNull ScimSchema SERVICE = ScimSchema.fromDiscovery(ScimSchema.withId("urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig").name("Service Provider Configuration")
                .description("Schema for representing the service provider's configuration")
                .attributes(List.of(
                ScimAttributeDefinition.withName("documentationUri")
                        .type(ScimAttributeType.REFERENCE)
                        .description("An HTTP-addressable URL pointing to the service provider's human-consumable help documentation.")
                        .mutability(ScimMutability.READ_ONLY)
                        .referenceTypes(Set.of("external"))
                        .build(),
                ScimAttributeDefinition.withName("patch")
                        .type(ScimAttributeType.COMPLEX)
                        .description("A complex type that specifies PATCH configuration options.")
                        .required(true)
                        .mutability(ScimMutability.READ_ONLY)
                        .subAttributes(List.of(
                        ScimAttributeDefinition.withName("supported")
                                .type(ScimAttributeType.BOOLEAN)
                                .description("A Boolean value specifying whether or not the operation is supported.")
                                .required(true)
                                .mutability(ScimMutability.READ_ONLY)
                                .build()
                ))
                        .build(),
                ScimAttributeDefinition.withName("bulk")
                        .type(ScimAttributeType.COMPLEX)
                        .description("A complex type that specifies bulk configuration options.")
                        .required(true)
                        .mutability(ScimMutability.READ_ONLY)
                        .subAttributes(List.of(
                        ScimAttributeDefinition.withName("supported")
                                .type(ScimAttributeType.BOOLEAN)
                                .description("A Boolean value specifying whether or not the operation is supported.")
                                .required(true)
                                .mutability(ScimMutability.READ_ONLY)
                                .build(),
                        ScimAttributeDefinition.withName("maxOperations")
                                .type(ScimAttributeType.INTEGER)
                                .description("An integer value specifying the maximum number of operations.")
                                .required(true)
                                .mutability(ScimMutability.READ_ONLY)
                                .build(),
                        ScimAttributeDefinition.withName("maxPayloadSize")
                                .type(ScimAttributeType.INTEGER)
                                .description("An integer value specifying the maximum payload size in bytes.")
                                .required(true)
                                .mutability(ScimMutability.READ_ONLY)
                                .build()
                ))
                        .build(),
                ScimAttributeDefinition.withName("filter")
                        .type(ScimAttributeType.COMPLEX)
                        .description("A complex type that specifies FILTER options.")
                        .required(true)
                        .mutability(ScimMutability.READ_ONLY)
                        .subAttributes(List.of(
                        ScimAttributeDefinition.withName("supported")
                                .type(ScimAttributeType.BOOLEAN)
                                .description("A Boolean value specifying whether or not the operation is supported.")
                                .required(true)
                                .mutability(ScimMutability.READ_ONLY)
                                .build(),
                        ScimAttributeDefinition.withName("maxResults")
                                .type(ScimAttributeType.INTEGER)
                                .description("An integer value specifying the maximum number of resources returned in a response.")
                                .required(true)
                                .mutability(ScimMutability.READ_ONLY)
                                .build()
                ))
                        .build(),
                ScimAttributeDefinition.withName("changePassword")
                        .type(ScimAttributeType.COMPLEX)
                        .description("A complex type that specifies configuration options related to changing a password.")
                        .required(true)
                        .mutability(ScimMutability.READ_ONLY)
                        .subAttributes(List.of(
                        ScimAttributeDefinition.withName("supported")
                                .type(ScimAttributeType.BOOLEAN)
                                .description("A Boolean value specifying whether or not the operation is supported.")
                                .required(true)
                                .mutability(ScimMutability.READ_ONLY)
                                .build()
                ))
                        .build(),
                ScimAttributeDefinition.withName("sort")
                        .type(ScimAttributeType.COMPLEX)
                        .description("A complex type that specifies sort result options.")
                        .required(true)
                        .mutability(ScimMutability.READ_ONLY)
                        .subAttributes(List.of(
                        ScimAttributeDefinition.withName("supported")
                                .type(ScimAttributeType.BOOLEAN)
                                .description("A Boolean value specifying whether or not the operation is supported.")
                                .required(true)
                                .mutability(ScimMutability.READ_ONLY)
                                .build()
                ))
                        .build(),
                ScimAttributeDefinition.withName("etag")
                        .type(ScimAttributeType.COMPLEX)
                        .description("ETag configuration.")
                        .required(true)
                        .mutability(ScimMutability.READ_ONLY)
                        .subAttributes(List.of(
                        ScimAttributeDefinition.withName("supported")
                                .type(ScimAttributeType.BOOLEAN)
                                .description("Whether entity tags are supported.")
                                .required(true)
                                .mutability(ScimMutability.READ_ONLY)
                                .build()
                ))
                        .build(),
                ScimAttributeDefinition.withName("authenticationSchemes")
                        .type(ScimAttributeType.COMPLEX)
                        .description("A complex type that specifies supported authentication scheme properties.")
                        .multiValued(true)
                        .required(true)
                        .mutability(ScimMutability.READ_ONLY)
                        .subAttributes(List.of(
                        ScimAttributeDefinition.withName("type")
                                .description("The authentication scheme.")
                                .required(true)
                                .mutability(ScimMutability.READ_ONLY)
                                .canonicalValues(Set.of("oauth", "oauth2", "oauthbearertoken", "httpbasic", "httpdigest"))
                                .build(),
                        ScimAttributeDefinition.withName("name")
                                .description("The common authentication scheme name, e.g., HTTP Basic.")
                                .required(true)
                                .mutability(ScimMutability.READ_ONLY)
                                .build(),
                        ScimAttributeDefinition.withName("description")
                                .description("A description of the authentication scheme.")
                                .required(true)
                                .mutability(ScimMutability.READ_ONLY)
                                .build(),
                        ScimAttributeDefinition.withName("specUri")
                                .type(ScimAttributeType.REFERENCE)
                                .description("An HTTP-addressable URL pointing to the authentication scheme's specification.")
                                .mutability(ScimMutability.READ_ONLY)
                                .referenceTypes(Set.of("external"))
                                .build(),
                        ScimAttributeDefinition.withName("documentationUri")
                                .type(ScimAttributeType.REFERENCE)
                                .description("An HTTP-addressable URL pointing to the authentication scheme's usage documentation.")
                                .mutability(ScimMutability.READ_ONLY)
                                .referenceTypes(Set.of("external"))
                                .build(),
                        ScimAttributeDefinition.withName("primary")
                                .type(ScimAttributeType.BOOLEAN)
                                .description("Whether this is the preferred authentication scheme.")
                                .mutability(ScimMutability.READ_ONLY)
                                .build()
                ))
                        .build(),
                paginationDefinition()
                )));

        private static final @NonNull ScimSchema RESOURCE_TYPE = ScimSchema.fromDiscovery(ScimSchema.withId("urn:ietf:params:scim:schemas:core:2.0:ResourceType").name("ResourceType")
                .description("Specifies the schema that describes a SCIM resource type")
                .attributes(List.of(
                ScimAttributeDefinition.withName("id").returned(ScimReturned.ALWAYS)
                        .description("The resource type's server unique id. May be the same as the 'name' attribute.")
                        .mutability(ScimMutability.READ_ONLY)
                        .build(),
                ScimAttributeDefinition.withName("name")
                        .description("The resource type name. When applicable, service providers MUST specify the name, e.g., 'User'.")
                        .required(true)
                        .caseExact(true)
                        .mutability(ScimMutability.READ_ONLY)
                        .uniqueness(ScimUniqueness.SERVER)
                        .build(),
                ScimAttributeDefinition.withName("description")
                        .description("The resource type's human-readable description. When applicable, service providers MUST specify the description.")
                        .mutability(ScimMutability.READ_ONLY)
                        .build(),
                ScimAttributeDefinition.withName("endpoint")
                        .type(ScimAttributeType.REFERENCE)
                        .description("The resource type's HTTP-addressable endpoint relative to the Base URL, e.g., '/Users'.")
                        .required(true)
                        .caseExact(true)
                        .mutability(ScimMutability.READ_ONLY)
                        .uniqueness(ScimUniqueness.SERVER)
                        .referenceTypes(Set.of("uri"))
                        .build(),
                ScimAttributeDefinition.withName("schema")
                        .type(ScimAttributeType.REFERENCE)
                        .description("The resource type's primary/base schema URI.")
                        .required(true)
                        .caseExact(true)
                        .mutability(ScimMutability.READ_ONLY)
                        .referenceTypes(Set.of("uri"))
                        .build(),
                ScimAttributeDefinition.withName("schemaExtensions")
                        .type(ScimAttributeType.COMPLEX)
                        .description("A list of URIs of the resource type's schema extensions.")
                        .multiValued(true)
                        .required(true)
                        .mutability(ScimMutability.READ_ONLY)
                        .subAttributes(List.of(
                        ScimAttributeDefinition.withName("schema")
                                .type(ScimAttributeType.REFERENCE)
                                .description("The URI of a schema extension.")
                                .required(true)
                                .caseExact(true)
                                .mutability(ScimMutability.READ_ONLY)
                                .referenceTypes(Set.of("uri"))
                                .build(),
                        ScimAttributeDefinition.withName("required")
                                .type(ScimAttributeType.BOOLEAN)
                                .description("A Boolean value that specifies whether or not the schema extension is required for the resource type. If true, a resource of this type MUST include this schema extension and also include any attributes declared as required in this schema extension. If false, a resource of this type MAY omit this schema extension.")
                                .required(true)
                                .mutability(ScimMutability.READ_ONLY)
                                .build()
                ))
                        .build()
                )));

        private static final @NonNull ScimSchema SCHEMA = ScimSchema.fromDiscovery(ScimSchema.withId("urn:ietf:params:scim:schemas:core:2.0:Schema").name("Schema")
                .description("Specifies the schema that describes a SCIM schema")
                .attributes(List.of(
                ScimAttributeDefinition.withName("id").returned(ScimReturned.ALWAYS)
                        .description("The unique URI of the schema. When applicable, service providers MUST specify the URI.")
                        .required(true)
                        .mutability(ScimMutability.READ_ONLY)
                        .build(),
                ScimAttributeDefinition.withName("name")
                        .description("The schema's human-readable name. When applicable, service providers MUST specify the name, e.g., 'User'.")
                        .required(true)
                        .mutability(ScimMutability.READ_ONLY)
                        .build(),
                ScimAttributeDefinition.withName("description")
                        .description("The schema's human-readable description. When applicable, service providers MUST specify the description.")
                        .mutability(ScimMutability.READ_ONLY)
                        .build(),
                ScimAttributeDefinition.withName("attributes")
                        .type(ScimAttributeType.COMPLEX)
                        .description("A complex attribute that includes the attributes of a schema.")
                        .multiValued(true)
                        .required(true)
                        .mutability(ScimMutability.READ_ONLY)
                        .subAttributes(List.of(
                        ScimAttributeDefinition.withName("name")
                                .description("The attribute's name.")
                                .required(true)
                                .caseExact(true)
                                .mutability(ScimMutability.READ_ONLY)
                                .build(),
                        ScimAttributeDefinition.withName("type")
                                .description("The attribute's data type. Valid values include 'string', 'complex', 'boolean', 'decimal', 'integer', 'dateTime', 'reference'. Binary values are also supported.")
                                .required(true)
                                .mutability(ScimMutability.READ_ONLY)
                                .canonicalValues(Set.of("string", "complex", "boolean", "decimal", "integer", "dateTime", "reference", "binary"))
                                .build(),
                        ScimAttributeDefinition.withName("multiValued")
                                .type(ScimAttributeType.BOOLEAN)
                                .description("A Boolean value indicating an attribute's plurality.")
                                .required(true)
                                .mutability(ScimMutability.READ_ONLY)
                                .build(),
                        ScimAttributeDefinition.withName("description")
                                .description("A human-readable description of the attribute.")
                                .caseExact(true)
                                .mutability(ScimMutability.READ_ONLY)
                                .build(),
                        ScimAttributeDefinition.withName("required")
                                .type(ScimAttributeType.BOOLEAN)
                                .description("A boolean value indicating whether or not the attribute is required.")
                                .mutability(ScimMutability.READ_ONLY)
                                .build(),
                        ScimAttributeDefinition.withName("canonicalValues")
                                .description("A collection of canonical values. When applicable, service providers MUST specify the canonical types, e.g., 'work', 'home'.")
                                .multiValued(true)
                                .caseExact(true)
                                .mutability(ScimMutability.READ_ONLY)
                                .build(),
                        ScimAttributeDefinition.withName("caseExact")
                                .type(ScimAttributeType.BOOLEAN)
                                .description("A Boolean value indicating whether or not a string attribute is case sensitive.")
                                .mutability(ScimMutability.READ_ONLY)
                                .build(),
                        ScimAttributeDefinition.withName("mutability")
                                .description("Indicates whether or not an attribute is modifiable.")
                                .caseExact(true)
                                .mutability(ScimMutability.READ_ONLY)
                                .canonicalValues(Set.of("readOnly", "readWrite", "immutable", "writeOnly"))
                                .build(),
                        ScimAttributeDefinition.withName("returned")
                                .description("Indicates when an attribute is returned in a response (e.g., to a query).")
                                .caseExact(true)
                                .mutability(ScimMutability.READ_ONLY)
                                .canonicalValues(Set.of("always", "never", "default", "request"))
                                .build(),
                        ScimAttributeDefinition.withName("uniqueness")
                                .description("Indicates how unique a value must be.")
                                .caseExact(true)
                                .mutability(ScimMutability.READ_ONLY)
                                .canonicalValues(Set.of("none", "server", "global"))
                                .build(),
                        ScimAttributeDefinition.withName("referenceTypes")
                                .description("Used only with an attribute of type 'reference'. Specifies a SCIM resourceType that a reference attribute MAY refer to, e.g., 'User'.")
                                .multiValued(true)
                                .caseExact(true)
                                .mutability(ScimMutability.READ_ONLY)
                                .build(),
                        ScimAttributeDefinition.withName("subAttributes")
                                .type(ScimAttributeType.COMPLEX)
                                .description("Used to define the sub-attributes of a complex attribute.")
                                .multiValued(true)
                                .mutability(ScimMutability.READ_ONLY)
                                .subAttributes(List.of(
                                ScimAttributeDefinition.withName("name")
                                        .description("The attribute's name.")
                                        .required(true)
                                        .caseExact(true)
                                        .mutability(ScimMutability.READ_ONLY)
                                        .build(),
                                ScimAttributeDefinition.withName("type")
                                        .description("The simple subattribute data type: string, boolean, decimal, integer, dateTime, reference or binary.")
                                        .required(true)
                                        .mutability(ScimMutability.READ_ONLY)
                                        .canonicalValues(Set.of("string", "boolean", "decimal", "integer", "dateTime", "reference", "binary"))
                                        .build(),
                                ScimAttributeDefinition.withName("multiValued")
                                        .type(ScimAttributeType.BOOLEAN)
                                        .description("A Boolean value indicating an attribute's plurality.")
                                        .required(true)
                                        .mutability(ScimMutability.READ_ONLY)
                                        .build(),
                                ScimAttributeDefinition.withName("description")
                                        .description("A human-readable description of the attribute.")
                                        .caseExact(true)
                                        .mutability(ScimMutability.READ_ONLY)
                                        .build(),
                                ScimAttributeDefinition.withName("required")
                                        .type(ScimAttributeType.BOOLEAN)
                                        .description("A boolean value indicating whether or not the attribute is required.")
                                        .mutability(ScimMutability.READ_ONLY)
                                        .build(),
                                ScimAttributeDefinition.withName("canonicalValues")
                                        .description("A collection of canonical values. When applicable, service providers MUST specify the canonical types, e.g., 'work', 'home'.")
                                        .multiValued(true)
                                        .caseExact(true)
                                        .mutability(ScimMutability.READ_ONLY)
                                        .build(),
                                ScimAttributeDefinition.withName("caseExact")
                                        .type(ScimAttributeType.BOOLEAN)
                                        .description("A Boolean value indicating whether or not a string attribute is case sensitive.")
                                        .mutability(ScimMutability.READ_ONLY)
                                        .build(),
                                ScimAttributeDefinition.withName("mutability")
                                        .description("Indicates whether or not an attribute is modifiable.")
                                        .caseExact(true)
                                        .mutability(ScimMutability.READ_ONLY)
                                        .canonicalValues(Set.of("readOnly", "readWrite", "immutable", "writeOnly"))
                                        .build(),
                                ScimAttributeDefinition.withName("returned")
                                        .description("Indicates when an attribute is returned in a response (e.g., to a query).")
                                        .caseExact(true)
                                        .mutability(ScimMutability.READ_ONLY)
                                        .canonicalValues(Set.of("always", "never", "default", "request"))
                                        .build(),
                                ScimAttributeDefinition.withName("uniqueness")
                                        .description("Indicates how unique a value must be.")
                                        .caseExact(true)
                                        .mutability(ScimMutability.READ_ONLY)
                                        .canonicalValues(Set.of("none", "server", "global"))
                                        .build(),
                                ScimAttributeDefinition.withName("referenceTypes")
                                        .description("Used only with an attribute of type 'reference'. Specifies a SCIM resourceType that a reference attribute MAY refer to, e.g., 'User'.")
                                        .multiValued(true)
                                        .caseExact(true)
                                        .mutability(ScimMutability.READ_ONLY)
                                        .build()
                        ))
                                .build()
                ))
                        .build()
                )));

        private Standard() {}
    }
}
