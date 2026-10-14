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
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/** Separate configured spellings exercise the builtin semantic proof in live targets. */
final class ScimM12FuzzFixtures {
    private ScimM12FuzzFixtures() {}
    static @NonNull ScimSchema rebuiltGroup() { return rebuilt(ScimSchema.groupInstance()); }
    static @NonNull ScimSchema rebuiltUser() { return rebuilt(ScimSchema.userInstance()); }
    static @NonNull ScimSchema rebuiltEnterpriseUser() { return rebuilt(ScimSchema.enterpriseUserInstance()); }
    private static @NonNull ScimSchema rebuilt(@NonNull ScimSchema schema) {
        return ScimSchema.withId(schema.getId().toUpperCase(Locale.ROOT)).name(schema.getName())
                .description(schema.getDescription().orElse(null)).attributes(upperNames(schema.getAttributes())).build();
    }
    private static @NonNull List<@NonNull ScimAttributeDefinition> upperNames(@NonNull List<@NonNull ScimAttributeDefinition> input) {
        List<ScimAttributeDefinition> output=new ArrayList<>();
        for (ScimAttributeDefinition attribute:input) output.add(ScimAttributeDefinition.withName(attribute.getName().toUpperCase(Locale.ROOT))
                .type(attribute.getType()).description(attribute.getDescription().orElse(null)).multiValued(attribute.isMultiValued())
                .required(attribute.isRequired()).caseExact(attribute.isCaseExact()).mutability(attribute.getMutability())
                .returned(attribute.getReturned()).uniqueness(attribute.getUniqueness()).canonicalValues(attribute.getCanonicalValues())
                .referenceTypes(attribute.getReferenceTypes()).subAttributes(upperNames(attribute.getSubAttributes())).build());
        return output;
    }
}
