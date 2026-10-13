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

import com.google.errorprone.annotations.CheckReturnValue;
import com.revetsec.internal.json.AsciiCase;
import com.revetsec.internal.Limits;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import javax.annotation.concurrent.Immutable;
import javax.annotation.concurrent.NotThreadSafe;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

/**
 * Immutable SCIM attribute characteristics. Canonical values are suggested values, not an
 * enforced whitelist. Application-resource schemas permit only one complex attribute level.
 *
 * @since 1.0.0
 */
@Immutable
@CheckReturnValue
public final class ScimAttributeDefinition {
    private final @NonNull String name;
    private final @NonNull ScimAttributeType type;
    private final @Nullable String description;
    private final boolean multiValued;
    private final boolean required;
    private final boolean caseExact;
    private final @NonNull ScimMutability mutability;
    private final @NonNull ScimReturned returned;
    private final @NonNull ScimUniqueness uniqueness;
    private final @NonNull Set<@NonNull String> canonicalValues;
    private final @NonNull Set<@NonNull String> referenceTypes;
    private final @NonNull List<@NonNull ScimAttributeDefinition> subAttributes;
    private final int definitionCount;
    private final int definitionDepth;

    private ScimAttributeDefinition(@NonNull Builder builder) {
        name = builder.name;
        type = builder.type == null ? ScimAttributeType.STRING : builder.type;
        description = builder.description;
        multiValued = Boolean.TRUE.equals(builder.multiValued);
        required = Boolean.TRUE.equals(builder.required);
        caseExact = Boolean.TRUE.equals(builder.caseExact);
        mutability = builder.mutability == null ? ScimMutability.READ_WRITE : builder.mutability;
        returned = builder.returned == null ? ScimReturned.DEFAULT : builder.returned;
        uniqueness = builder.uniqueness == null ? ScimUniqueness.NONE : builder.uniqueness;
        canonicalValues = builder.canonicalValues;
        referenceTypes = builder.referenceTypes;
        subAttributes = builder.subAttributes;
        if (type != ScimAttributeType.COMPLEX && !subAttributes.isEmpty())
            throw new IllegalArgumentException("Only a complex SCIM attribute has subattributes.");
        if (type != ScimAttributeType.REFERENCE && !referenceTypes.isEmpty())
            throw new IllegalArgumentException("Only a reference SCIM attribute has reference types.");
        if (caseExact && type != ScimAttributeType.STRING && type != ScimAttributeType.REFERENCE
                && type != ScimAttributeType.BINARY)
            throw new IllegalArgumentException("SCIM caseExact applies only to string-like attributes.");
        if ((type == ScimAttributeType.COMPLEX || type == ScimAttributeType.BOOLEAN
                || type == ScimAttributeType.DATE_TIME || type == ScimAttributeType.BINARY)
                && uniqueness != ScimUniqueness.NONE)
            throw new IllegalArgumentException("This SCIM attribute type has no uniqueness characteristic.");
        if (mutability == ScimMutability.WRITE_ONLY && returned != ScimReturned.NEVER)
            throw new IllegalArgumentException("A write-only SCIM attribute must never be returned.");
        if (type != ScimAttributeType.STRING && !canonicalValues.isEmpty())
            throw new IllegalArgumentException("SCIM canonical values require a string attribute.");
        ScimSchemas.requireDistinctAttributes(subAttributes);
        int count = 1;
        int depth = 1;
        for (ScimAttributeDefinition child : subAttributes) {
            count += child.definitionCount;
            depth = Math.max(depth, 1 + child.definitionDepth);
        }
        ScimSchemas.requireDefinitionCount(count);
        if (depth > Limits.SCIM_FILTER_DEPTH.getCap())
            throw new IllegalArgumentException("SCIM attribute definition nesting exceeds its limit.");
        definitionCount = count;
        definitionDepth = depth;
    }

    /**
     * Starts a definition for a bounded attribute name. The special {@code $ref} is permitted
     * here for subattributes, while a schema rejects it as a top-level application attribute.
     * @param name the required name
     * @return a new builder
     * @since 1.0.0
     */
    public static @NonNull Builder withName(@NonNull String name) {
        return new Builder(ScimSchemas.requireAttributeName(name));
    }

    /**
     * Returns the canonical attribute name.
     * @return the canonical attribute name
     * @since 1.0.0
     */
    public @NonNull String getName() { return name; }

    /**
     * Returns the declared attribute type.
     * @return the declared attribute type
     * @since 1.0.0
     */
    public @NonNull ScimAttributeType getType() { return type; }

    /**
     * Returns the optional description.
     * @return the optional description
     * @since 1.0.0
     */
    public @NonNull Optional<@NonNull String> getDescription() { return Optional.ofNullable(description); }

    /**
     * Returns whether the attribute is multi-valued.
     * @return whether the attribute is multi-valued
     * @since 1.0.0
     */
    public @NonNull Boolean isMultiValued() { return multiValued; }

    /**
     * Returns whether assigned data is required.
     * @return whether assigned data is required
     * @since 1.0.0
     */
    public @NonNull Boolean isRequired() { return required; }

    /**
     * Returns whether string comparison is case exact.
     * @return whether string comparison is case exact
     * @since 1.0.0
     */
    public @NonNull Boolean isCaseExact() { return caseExact; }

    /**
     * Returns the write characteristic.
     * @return the write characteristic
     * @since 1.0.0
     */
    public @NonNull ScimMutability getMutability() { return mutability; }

    /**
     * Returns the response visibility characteristic.
     * @return the response visibility characteristic
     * @since 1.0.0
     */
    public @NonNull ScimReturned getReturned() { return returned; }

    /**
     * Returns the application-enforced uniqueness characteristic.
     * @return the application-enforced uniqueness characteristic
     * @since 1.0.0
     */
    public @NonNull ScimUniqueness getUniqueness() { return uniqueness; }

    /**
     * Returns the immutable suggested canonical values.
     * @return the immutable suggested canonical values
     * @since 1.0.0
     */
    public @NonNull Set<@NonNull String> getCanonicalValues() { return canonicalValues; }

    /**
     * Returns the immutable allowed reference-type descriptions.
     * @return the immutable allowed reference-type descriptions
     * @since 1.0.0
     */
    public @NonNull Set<@NonNull String> getReferenceTypes() { return referenceTypes; }

    /**
     * Returns the immutable subattribute definitions.
     * @return the immutable subattribute definitions
     * @since 1.0.0
     */
    public @NonNull List<@NonNull ScimAttributeDefinition> getSubAttributes() { return subAttributes; }

    /**
     * Compares semantic attribute characteristics, folding only the structural name.
     * @param other the comparison value
     * @return whether the definitions have equal characteristics
     * @since 1.0.0
     */
    @Override public boolean equals(@Nullable Object other) {
        return this == other || other instanceof ScimAttributeDefinition value
                && AsciiCase.fold(name).equals(AsciiCase.fold(value.name)) && type == value.type
                && Objects.equals(description, value.description) && multiValued == value.multiValued
                && required == value.required && caseExact == value.caseExact && mutability == value.mutability
                && returned == value.returned && uniqueness == value.uniqueness
                && canonicalValues.equals(value.canonicalValues) && referenceTypes.equals(value.referenceTypes)
                && subAttributes.equals(value.subAttributes);
    }

    /**
     * Returns the hash of semantic attribute characteristics.
     * @return the semantic hash
     * @since 1.0.0
     */
    @Override public int hashCode() {
        return Objects.hash(AsciiCase.fold(name), type, description, multiValued, required, caseExact,
                mutability, returned, uniqueness, canonicalValues, referenceTypes, subAttributes);
    }

    /**
     * Returns a fixed description without configured schema data.
     * @return a fixed redacted description
     * @since 1.0.0
     */
    @Override public @NonNull String toString() { return "ScimAttributeDefinition{<redacted>}"; }

    int definitionCount() { return definitionCount; }

    /**
     * Mutable, non-thread-safe definition configuration. Null restores the stated default.
     * Collections replace the complete value and are bounded before an immutable snapshot.
     * @since 1.0.0
     */
    @NotThreadSafe
    @CheckReturnValue
    public static final class Builder {
        private final @NonNull String name;
        private @Nullable ScimAttributeType type;
        private @Nullable String description;
        private @Nullable Boolean multiValued;
        private @Nullable Boolean required;
        private @Nullable Boolean caseExact;
        private @Nullable ScimMutability mutability;
        private @Nullable ScimReturned returned;
        private @Nullable ScimUniqueness uniqueness;
        private @NonNull Set<@NonNull String> canonicalValues = Set.of();
        private @NonNull Set<@NonNull String> referenceTypes = Set.of();
        private @NonNull List<@NonNull ScimAttributeDefinition> subAttributes = List.of();
        private Builder(@NonNull String name) { this.name = name; }

        /**
         * Sets type; null restores STRING.
         * @param value the replacement, or null to restore its default
         * @return this builder
         * @since 1.0.0
         */
        public @NonNull Builder type(@Nullable ScimAttributeType value) { type = value; return this; }

        /**
         * Sets description; null restores absent.
         * @param value the replacement, or null to restore its default
         * @return this builder
         * @since 1.0.0
         */
        public @NonNull Builder description(@Nullable String value) { description = value == null ? null : ScimSchemas.requireText(value, false); return this; }

        /**
         * Sets multiValued; null restores false.
         * @param value the replacement, or null to restore its default
         * @return this builder
         * @since 1.0.0
         */
        public @NonNull Builder multiValued(@Nullable Boolean value) { multiValued = value; return this; }

        /**
         * Sets required; null restores false.
         * @param value the replacement, or null to restore its default
         * @return this builder
         * @since 1.0.0
         */
        public @NonNull Builder required(@Nullable Boolean value) { required = value; return this; }

        /**
         * Sets caseExact; null restores false.
         * @param value the replacement, or null to restore its default
         * @return this builder
         * @since 1.0.0
         */
        public @NonNull Builder caseExact(@Nullable Boolean value) { caseExact = value; return this; }

        /**
         * Sets mutability; null restores READ_WRITE.
         * @param value the replacement, or null to restore its default
         * @return this builder
         * @since 1.0.0
         */
        public @NonNull Builder mutability(@Nullable ScimMutability value) { mutability = value; return this; }

        /**
         * Sets returned; null restores DEFAULT.
         * @param value the replacement, or null to restore its default
         * @return this builder
         * @since 1.0.0
         */
        public @NonNull Builder returned(@Nullable ScimReturned value) { returned = value; return this; }

        /**
         * Sets uniqueness; null restores NONE.
         * @param value the replacement, or null to restore its default
         * @return this builder
         * @since 1.0.0
         */
        public @NonNull Builder uniqueness(@Nullable ScimUniqueness value) { uniqueness = value; return this; }

        /**
         * Sets canonicalValues; null restores empty.
         * @param value the replacement, or null to restore its default
         * @return this builder
         * @since 1.0.0
         */
        public @NonNull Builder canonicalValues(@Nullable Set<@NonNull String> value) { canonicalValues = value == null ? Set.of() : ScimSchemas.stringSet(value); return this; }

        /**
         * Sets referenceTypes; null restores empty.
         * @param value the replacement, or null to restore its default
         * @return this builder
         * @since 1.0.0
         */
        public @NonNull Builder referenceTypes(@Nullable Set<@NonNull String> value) { referenceTypes = value == null ? Set.of() : ScimSchemas.stringSet(value); return this; }

        /**
         * Sets subAttributes; null restores empty.
         * @param value the replacement, or null to restore its default
         * @return this builder
         * @since 1.0.0
         */
        public @NonNull Builder subAttributes(@Nullable List<@NonNull ScimAttributeDefinition> value) { subAttributes = value == null ? List.of() : ScimSchemas.attributes(value); return this; }

        /**
         * Validates compatible characteristics and creates an immutable definition.
         * @return the definition
         * @since 1.0.0
         */
        public @NonNull ScimAttributeDefinition build() { return new ScimAttributeDefinition(this); }
    }
}
