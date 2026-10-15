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
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

final class ScimTrustedConstructionLimitTests {
    @Test void configuredWorkLimitAppliesToBuilderAndCopyWithDistinctFailure() {
        ScimResourceType type = ScimResourceType.groupInstance();
        List<JsonValue> members = new ArrayList<>();
        for (int index = 0; index < 1000; index++)
            members.add(JsonObject.builder().put("value", "member-" + index).build());
        JsonObject large = JsonObject.builder()
                .put("schemas", JsonArray.fromElements(List.of(JsonString.fromValue(type.getSchema().getId()))))
                .put("displayName", "large-group")
                .put("members", JsonArray.fromElements(members)).build();
        ScimLimits low = ScimLimits.builder().maximumWorkUnits(10000).build();
        ScimLimits high = ScimLimits.builder().maximumWorkUnits(4000000).build();
        assertThrows(ScimResourceWorkLimitException.class,
                () -> ScimResource.withResourceType(type).limits(low).document(large).build());
        ScimResource resource = ScimResource.withResourceType(type).limits(high).document(large).build();
        assertEquals(1000, ((JsonArray) resource.getDocument().find("members").orElseThrow())
                .getElements().size());
        assertEquals(resource.getDocument(), resource.copy().finish().getDocument());
        assertThrows(ScimResourceWorkLimitException.class,
                () -> resource.copy().limits(low).finish());
    }
}
