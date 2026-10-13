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
@Immutable public final class ScimUser {
    private final @NonNull ScimResource resource;
    private ScimUser(@NonNull ScimResource resource) { this.resource = resource; }
    /** Creates a typed view; a foreign resource schema is a programming error.
     * @param resource the resource
     * @return the view
     * @since 1.0.0
     */
    @CheckReturnValue public static @NonNull ScimUser fromResource(@NonNull ScimResource resource) {
        requireNonNull(resource);
        if (!AsciiCase.fold(resource.getResourceType().getSchema().getId()).equals(AsciiCase.fold(ScimSchema.userInstance().getId())))
            throw new IllegalArgumentException("The resource does not have the required core schema.");
        return new ScimUser(resource);
    }
    /** Returns the underlying resource.
     * @return the resource
     * @since 1.0.0
     */
    public @NonNull ScimResource getResource() { return resource; }
    /** Returns userName.
     * @return the provisioning value
     * @since 1.0.0
     */
    public @NonNull String getUserName() { return resource.getDocument().findString("userName").orElseThrow(); }
    /** Returns displayName.
     * @return the provisioning value
     * @since 1.0.0
     */
    public @NonNull Optional<@NonNull String> getDisplayName() { return resource.getDocument().findString("displayName"); }
    /** Returns active.
     * @return the provisioning value
     * @since 1.0.0
     */
    public @NonNull Optional<@NonNull Boolean> isActive() { return resource.getDocument().findBoolean("active"); }
    /** Returns emails.
     * @return the provisioning value
     * @since 1.0.0
     */
    public @NonNull List<@NonNull JsonObject> getEmails() { return objects("emails"); }
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
    @Override public @NonNull String toString() { return "ScimUser{resource=<redacted>}"; }
}
