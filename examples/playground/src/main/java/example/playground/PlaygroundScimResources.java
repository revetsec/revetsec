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
package example.playground;

import com.revetsec.scim.*;
import com.revetsec.soklet.SokletScim;
import com.soklet.*;
import com.soklet.annotation.*;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import java.util.List;
import java.util.function.Supplier;

/** Explicit authenticated routes shared by the Playground and independent-client harness. */
public final class PlaygroundScimResources {
    private final PlaygroundScim app;
    @NonNull PlaygroundScimResources(@NonNull PlaygroundScim app) { this.app = app; }
    private @NonNull MarshaledResponse response(@NonNull Request request, @NonNull Supplier<@NonNull ScimResponse> operation) {
        if (!app.authenticated(request)) return SokletScim.responseFor(app.error(ScimError.unauthenticatedInstance()))
                .copy().headers(headers -> headers.put("WWW-Authenticate", List.of("Bearer realm=\"scim\""))).finish();
        if (request.isContentTooLarge()) return SokletScim.responseFor(app.error(ScimError.requestTooLargeInstance()));
        MarshaledResponse prepared = SokletScim.responseFor(operation.get());
        String allowed = allowedMethodsFor(request.getPath());
        if (prepared.getStatusCode() == 405 && allowed != null)
            return prepared.copy().headers(headers -> headers.put("Allow", List.of(allowed))).finish();
        return prepared;
    }
    private static @Nullable String allowedMethodsFor(@NonNull String path) {
        // Soklet supplies HEAD through GET fallback and handles OPTIONS for these known routes.
        if (java.util.Set.of("/scim/v2/ServiceProviderConfig", "/scim/v2/ResourceTypes", "/scim/v2/Schemas").contains(path)) return "GET, HEAD, OPTIONS";
        if (java.util.Set.of("/scim/v2/Users", "/scim/v2/Groups").contains(path)) return "GET, HEAD, POST, OPTIONS";
        return null;
    }
    @POST("/scim/v2/.search") public @NonNull MarshaledResponse aggregateSearch(@NonNull Request request) {
        return response(request, () -> app.error(ScimError.notImplementedInstance()));
    }
    @GET("/scim/v2/{unknown}") @POST("/scim/v2/{unknown}") @PUT("/scim/v2/{unknown}") @PATCH("/scim/v2/{unknown}") @DELETE("/scim/v2/{unknown}")
    public @NonNull MarshaledResponse unknown(@NonNull Request request) {
        return response(request, () -> app.error(allowedMethodsFor(request.getPath()) != null
                ? ScimError.methodNotAllowedInstance() : ScimError.notFoundInstance()));
    }
    @GET("/scim/v2/ServiceProviderConfig") public @NonNull MarshaledResponse config(@NonNull Request request) {
        return response(request, () -> app.prepared(app.provider.serviceProviderConfigResponseResult(request.getRawQuery().orElse(""))));
    }
    @GET("/scim/v2/ResourceTypes") public @NonNull MarshaledResponse types(@NonNull Request request) {
        return response(request, () -> app.prepared(app.provider.resourceTypesResponseResult(request.getRawQuery().orElse(""))));
    }
    @GET("/scim/v2/ResourceTypes/{name}") public @NonNull MarshaledResponse type(@NonNull Request request, @PathParameter(name="name") @NonNull String name) {
        return response(request, () -> app.prepared(app.provider.resourceTypeResponseResult(name, request.getRawQuery().orElse(""))));
    }
    @GET("/scim/v2/Schemas") public @NonNull MarshaledResponse schemas(@NonNull Request request) {
        return response(request, () -> app.prepared(app.provider.schemasResponseResult(request.getRawQuery().orElse(""))));
    }
    @GET("/scim/v2/Schemas/{id}") public @NonNull MarshaledResponse schema(@NonNull Request request, @PathParameter(name="id") @NonNull String id) {
        return response(request, () -> app.prepared(app.provider.schemaResponseResult(id, request.getRawQuery().orElse(""))));
    }
    @GET("/scim/v2/Users") public @NonNull MarshaledResponse listUsers(@NonNull Request request) {
        return response(request, () -> app.list(ScimResourceType.userInstance(), request, false));
    }
    @POST("/scim/v2/Users/.search") public @NonNull MarshaledResponse searchUsers(@NonNull Request request) {
        return response(request, () -> app.list(ScimResourceType.userInstance(), request, true));
    }
    @POST("/scim/v2/Users") public @NonNull MarshaledResponse createUser(@NonNull Request request) {
        return response(request, () -> app.create(ScimResourceType.userInstance(), request));
    }
    @GET("/scim/v2/Users/{id}") public @NonNull MarshaledResponse getUser(@NonNull Request request, @PathParameter(name="id") @NonNull String id) {
        return response(request, () -> app.get(ScimResourceType.userInstance(), id, request));
    }
    @PUT("/scim/v2/Users/{id}") public @NonNull MarshaledResponse putUser(@NonNull Request request, @PathParameter(name="id") @NonNull String id) {
        return response(request, () -> app.write(ScimResourceType.userInstance(), id, request, false));
    }
    @PATCH("/scim/v2/Users/{id}") public @NonNull MarshaledResponse patchUser(@NonNull Request request, @PathParameter(name="id") @NonNull String id) {
        return response(request, () -> app.write(ScimResourceType.userInstance(), id, request, true));
    }
    @DELETE("/scim/v2/Users/{id}") public @NonNull MarshaledResponse deleteUser(@NonNull Request request, @PathParameter(name="id") @NonNull String id) {
        return response(request, () -> app.delete(ScimResourceType.userInstance(), id, request));
    }
    @GET("/scim/v2/Groups") public @NonNull MarshaledResponse listGroups(@NonNull Request request) {
        return response(request, () -> app.list(ScimResourceType.groupInstance(), request, false));
    }
    @POST("/scim/v2/Groups/.search") public @NonNull MarshaledResponse searchGroups(@NonNull Request request) {
        return response(request, () -> app.list(ScimResourceType.groupInstance(), request, true));
    }
    @POST("/scim/v2/Groups") public @NonNull MarshaledResponse createGroup(@NonNull Request request) {
        return response(request, () -> app.create(ScimResourceType.groupInstance(), request));
    }
    @GET("/scim/v2/Groups/{id}") public @NonNull MarshaledResponse getGroup(@NonNull Request request, @PathParameter(name="id") @NonNull String id) {
        return response(request, () -> app.get(ScimResourceType.groupInstance(), id, request));
    }
    @PUT("/scim/v2/Groups/{id}") public @NonNull MarshaledResponse putGroup(@NonNull Request request, @PathParameter(name="id") @NonNull String id) {
        return response(request, () -> app.write(ScimResourceType.groupInstance(), id, request, false));
    }
    @PATCH("/scim/v2/Groups/{id}") public @NonNull MarshaledResponse patchGroup(@NonNull Request request, @PathParameter(name="id") @NonNull String id) {
        return response(request, () -> app.write(ScimResourceType.groupInstance(), id, request, true));
    }
    @DELETE("/scim/v2/Groups/{id}") public @NonNull MarshaledResponse deleteGroup(@NonNull Request request, @PathParameter(name="id") @NonNull String id) {
        return response(request, () -> app.delete(ScimResourceType.groupInstance(), id, request));
    }
}
