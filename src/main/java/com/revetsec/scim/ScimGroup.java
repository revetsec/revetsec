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
import com.revetsec.json.*;
import org.jspecify.annotations.NonNull;
import javax.annotation.concurrent.Immutable;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import static java.util.Objects.requireNonNull;

/** Intentional typed provisioning view; diagnostics are redacted.
 * @since 1.0.0
 */
@Immutable public final class ScimGroup {
    private final @NonNull ScimResource resource;
    private ScimGroup(@NonNull ScimResource resource) { this.resource = resource; }
    /** Creates a typed view of a complete standard Group schema.
     * Equivalent rebuilt schemas are accepted; a foreign or altered schema is a programming error.
     * @param resource the resource
     * @return the view
     * @since 1.0.0
     */
    @CheckReturnValue public static @NonNull ScimGroup fromResource(@NonNull ScimResource resource) {
        requireNonNull(resource);
        if (!resource.getResourceType().hasStandardGroupSchema())
            throw new IllegalArgumentException("The resource does not have the required core schema.");
        return new ScimGroup(resource);
    }
    /** Returns the underlying resource.
     * @return the resource
     * @since 1.0.0
     */
    public @NonNull ScimResource getResource() { return resource; }
    /** Returns displayName.
     * @return the provisioning value
     * @since 1.0.0
     */
    public @NonNull String getDisplayName() { return resource.getDocument().find("displayName").filter(JsonString.class::isInstance).map(JsonString.class::cast).map(JsonString::getValue).orElseThrow(); }
    /** Returns members.
     * @return the provisioning value
     * @since 1.0.0
     */
    public @NonNull List<@NonNull JsonObject> getMembers() { return objects("members"); }
    private @NonNull List<@NonNull JsonObject> objects(@NonNull String name) {
        JsonValue raw = resource.getDocument().getMembers().get(name);
        if (!(raw instanceof JsonArray array)) return List.of();
        List<JsonObject> objects = new ArrayList<>();
        for (JsonValue value : array.getElements()) if (value instanceof JsonObject object) objects.add(object);
        return List.copyOf(objects);
    }
    /** Returns a fixed redacted description.
     * @return the description
     * @since 1.0.0
     */
    @Override public @NonNull String toString() { return "ScimGroup{resource=<redacted>}"; }
}
