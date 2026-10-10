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
package com.revetsec.saml;

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import javax.annotation.concurrent.Immutable;
import java.util.List;
import java.util.Optional;

/**
 * An attribute from the covered Assertion. Text values are exposed separately from complex
 * values so callers cannot mistake nested XML for a scalar identifier.
 *
 * @since 1.0.0
 */
@Immutable
public final class SamlAttribute {
    private final @NonNull String name;
    private final @Nullable String nameFormat;
    private final @Nullable String friendlyName;
    private final @NonNull List<@NonNull String> values;
    private final @NonNull List<@NonNull SamlAttributeValue> typedValues;

    SamlAttribute(@NonNull String name, @Nullable String nameFormat, @Nullable String friendlyName,
            @NonNull List<@NonNull SamlAttributeValue> typedValues) {
        this.name = name;
        this.nameFormat = nameFormat;
        this.friendlyName = friendlyName;
        this.typedValues = List.copyOf(typedValues);
        this.values = List.copyOf(typedValues.stream()
                .flatMap(value -> value.getText().stream()).toList());
    }

    /**
     * Returns the exact attribute Name.
     *
     * @return name
     * @since 1.0.0
     */
    public @NonNull String getName() { return name; }
    /**
     * Returns the optional NameFormat URI.
     *
     * @return optional format
     * @since 1.0.0
     */
    public @NonNull Optional<@NonNull String> getNameFormat() { return Optional.ofNullable(nameFormat); }
    /**
     * Returns the optional friendly name for display only.
     *
     * @return optional friendly name
     * @since 1.0.0
     */
    public @NonNull Optional<@NonNull String> getFriendlyName() { return Optional.ofNullable(friendlyName); }
    /**
     * Returns immutable text values in assertion order.
     *
     * @return text values
     * @since 1.0.0
     */
    public @NonNull List<@NonNull String> getValues() { return values; }
    /**
     * Returns all values in assertion order, including nested NameID and opaque complex values.
     *
     * @return immutable typed values
     * @since 1.0.0
     */
    public @NonNull List<@NonNull SamlAttributeValue> getTypedValues() { return typedValues; }
    /**
     * Redacts values and names.
     *
     * @return redacted description
     * @since 1.0.0
     */
    @Override public @NonNull String toString() { return "SamlAttribute{<redacted>}"; }
}
