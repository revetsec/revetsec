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
import com.revetsec.internal.json.AsciiCase;
import org.jspecify.annotations.NonNull;
import javax.annotation.concurrent.Immutable;
import java.util.Optional;
import static java.util.Objects.requireNonNull;

/** Intentional Enterprise User extension view; diagnostics are redacted.
 * @since 1.0.0
 */
@Immutable public final class ScimEnterpriseUser {
    private final @NonNull ScimResource resource;
    private final @NonNull JsonObject extension;
    private ScimEnterpriseUser(@NonNull ScimResource resource, @NonNull JsonObject extension) { this.resource = resource; this.extension = extension; }
    /** Creates a view; an absent extension or foreign resource is a programming error.
     * @param resource the User resource with an Enterprise extension
     * @return the view
     * @since 1.0.0
     */
    @CheckReturnValue public static @NonNull ScimEnterpriseUser fromResource(@NonNull ScimResource resource) {
        requireNonNull(resource);
        if (!AsciiCase.fold(resource.getResourceType().getSchema().getId()).equals(AsciiCase.fold(ScimSchema.userInstance().getId())))
            throw new IllegalArgumentException("The resource does not have the required User schema.");
        JsonObject extension = resource.getExtension(ScimSchema.enterpriseUserInstance().getId()).orElseThrow(() -> new IllegalArgumentException("The resource has no Enterprise User extension."));
        return new ScimEnterpriseUser(resource,extension);
    }
    /** Returns the underlying resource.
     * @return the resource
     * @since 1.0.0
     */
    public @NonNull ScimResource getResource() { return resource; }
    /** Returns employeeNumber.
     * @return the provisioning value
     * @since 1.0.0
     */
    public @NonNull Optional<@NonNull String> getEmployeeNumber() { return extension.findString("employeeNumber"); }
    /** Returns department.
     * @return the provisioning value
     * @since 1.0.0
     */
    public @NonNull Optional<@NonNull String> getDepartment() { return extension.findString("department"); }
    /** Returns organization.
     * @return the provisioning value
     * @since 1.0.0
     */
    public @NonNull Optional<@NonNull String> getOrganization() { return extension.findString("organization"); }
    /** Returns division.
     * @return the provisioning value
     * @since 1.0.0
     */
    public @NonNull Optional<@NonNull String> getDivision() { return extension.findString("division"); }
    /** Returns the manager object without fetching its link.
     * @return the manager
     * @since 1.0.0
     */
    public @NonNull Optional<@NonNull JsonObject> getManager() {
        JsonValue raw = extension.getMembers().get("manager");
        return raw instanceof JsonObject object ? Optional.of(object) : Optional.empty();
    }
    /** Returns a fixed redacted description.
     * @return the description
     * @since 1.0.0
     */
    @Override public @NonNull String toString() { return "ScimEnterpriseUser{resource=<redacted>}"; }
}
