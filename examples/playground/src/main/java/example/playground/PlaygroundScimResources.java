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
    private final @Nullable PlaygroundScim app;
    private final @Nullable PlaygroundScimDirectory directory;
    PlaygroundScimResources(@NonNull PlaygroundScim app) { this.app = app; this.directory=null; }
    PlaygroundScimResources(@NonNull PlaygroundScimDirectory directory) { this.app=null;this.directory=directory; }
    private @NonNull PlaygroundScim legacy(){return java.util.Objects.requireNonNull(this.app);}
    private @NonNull MarshaledResponse response(@NonNull Request request, @NonNull Supplier<@NonNull ScimResponse> operation) {
        if(this.directory!=null)return this.directory.handle(request);
        if(!request.getRawPath().startsWith("/scim/v2/"))return SokletScim.responseFor(legacy().error(ScimError.notFoundInstance()));
        if (!legacy().authenticated(request)) return SokletScim.responseFor(legacy().error(ScimError.unauthenticatedInstance()))
                .copy().headers(headers -> headers.put("WWW-Authenticate", List.of("Bearer realm=\"scim\""))).finish();
        if (request.isContentTooLarge()) return SokletScim.responseFor(legacy().error(ScimError.requestTooLargeInstance()));
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
    @POST("/scim/v2/.search") @POST("/scim/{tenant}/v2/.search") public @NonNull MarshaledResponse aggregateSearch(@NonNull Request request) {
        return response(request, () -> legacy().error(ScimError.notImplementedInstance()));
    }
    @GET("/scim/v2/{unknown}") @GET("/scim/{tenant}/v2/{unknown}") @POST("/scim/v2/{unknown}") @POST("/scim/{tenant}/v2/{unknown}") @PUT("/scim/v2/{unknown}") @PUT("/scim/{tenant}/v2/{unknown}") @PATCH("/scim/v2/{unknown}") @PATCH("/scim/{tenant}/v2/{unknown}") @DELETE("/scim/v2/{unknown}") @DELETE("/scim/{tenant}/v2/{unknown}")
    public @NonNull MarshaledResponse unknown(@NonNull Request request) {
        return response(request, () -> legacy().error(allowedMethodsFor(request.getPath()) != null
                ? ScimError.methodNotAllowedInstance() : ScimError.notFoundInstance()));
    }
    @GET("/scim/v2/ServiceProviderConfig") @GET("/scim/{tenant}/v2/ServiceProviderConfig") public @NonNull MarshaledResponse config(@NonNull Request request) {
        return response(request, () -> legacy().prepared(legacy().provider.serviceProviderConfigResponseResult(request.getRawQuery().orElse(""))));
    }
    @GET("/scim/v2/ResourceTypes") @GET("/scim/{tenant}/v2/ResourceTypes") public @NonNull MarshaledResponse types(@NonNull Request request) {
        return response(request, () -> legacy().prepared(legacy().provider.resourceTypesResponseResult(request.getRawQuery().orElse(""))));
    }
    @GET("/scim/v2/ResourceTypes/{name}") @GET("/scim/{tenant}/v2/ResourceTypes/{name}") public @NonNull MarshaledResponse type(@NonNull Request request, @PathParameter(name="name") @NonNull String name) {
        return response(request, () -> legacy().prepared(legacy().provider.resourceTypeResponseResult(name, request.getRawQuery().orElse(""))));
    }
    @GET("/scim/v2/Schemas") @GET("/scim/{tenant}/v2/Schemas") public @NonNull MarshaledResponse schemas(@NonNull Request request) {
        return response(request, () -> legacy().prepared(legacy().provider.schemasResponseResult(request.getRawQuery().orElse(""))));
    }
    @GET("/scim/v2/Schemas/{id}") @GET("/scim/{tenant}/v2/Schemas/{id}") public @NonNull MarshaledResponse schema(@NonNull Request request, @PathParameter(name="id") @NonNull String id) {
        return response(request, () -> legacy().prepared(legacy().provider.schemaResponseResult(id, request.getRawQuery().orElse(""))));
    }
    @GET("/scim/v2/Users") @GET("/scim/{tenant}/v2/Users") public @NonNull MarshaledResponse listUsers(@NonNull Request request) {
        return response(request, () -> legacy().list(PlaygroundScim.USER_TYPE, request, false));
    }
    @POST("/scim/v2/Users/.search") @POST("/scim/{tenant}/v2/Users/.search") public @NonNull MarshaledResponse searchUsers(@NonNull Request request) {
        return response(request, () -> legacy().list(PlaygroundScim.USER_TYPE, request, true));
    }
    @POST("/scim/v2/Users") @POST("/scim/{tenant}/v2/Users") public @NonNull MarshaledResponse createUser(@NonNull Request request) {
        return response(request, () -> legacy().create(PlaygroundScim.USER_TYPE, request));
    }
    @GET("/scim/v2/Users/{id}") @GET("/scim/{tenant}/v2/Users/{id}") public @NonNull MarshaledResponse getUser(@NonNull Request request, @PathParameter(name="id") @NonNull String id) {
        return response(request, () -> legacy().get(PlaygroundScim.USER_TYPE, id, request));
    }
    @PUT("/scim/v2/Users/{id}") @PUT("/scim/{tenant}/v2/Users/{id}") public @NonNull MarshaledResponse putUser(@NonNull Request request, @PathParameter(name="id") @NonNull String id) {
        return response(request, () -> legacy().write(PlaygroundScim.USER_TYPE, id, request, false));
    }
    @PATCH("/scim/v2/Users/{id}") @PATCH("/scim/{tenant}/v2/Users/{id}") public @NonNull MarshaledResponse patchUser(@NonNull Request request, @PathParameter(name="id") @NonNull String id) {
        return response(request, () -> legacy().write(PlaygroundScim.USER_TYPE, id, request, true));
    }
    @DELETE("/scim/v2/Users/{id}") @DELETE("/scim/{tenant}/v2/Users/{id}") public @NonNull MarshaledResponse deleteUser(@NonNull Request request, @PathParameter(name="id") @NonNull String id) {
        return response(request, () -> legacy().delete(PlaygroundScim.USER_TYPE, id, request));
    }
    @GET("/scim/v2/Groups") @GET("/scim/{tenant}/v2/Groups") public @NonNull MarshaledResponse listGroups(@NonNull Request request) {
        return response(request, () -> legacy().list(ScimResourceType.groupInstance(), request, false));
    }
    @POST("/scim/v2/Groups/.search") @POST("/scim/{tenant}/v2/Groups/.search") public @NonNull MarshaledResponse searchGroups(@NonNull Request request) {
        return response(request, () -> legacy().list(ScimResourceType.groupInstance(), request, true));
    }
    @POST("/scim/v2/Groups") @POST("/scim/{tenant}/v2/Groups") public @NonNull MarshaledResponse createGroup(@NonNull Request request) {
        return response(request, () -> legacy().create(ScimResourceType.groupInstance(), request));
    }
    @GET("/scim/v2/Groups/{id}") @GET("/scim/{tenant}/v2/Groups/{id}") public @NonNull MarshaledResponse getGroup(@NonNull Request request, @PathParameter(name="id") @NonNull String id) {
        return response(request, () -> legacy().get(ScimResourceType.groupInstance(), id, request));
    }
    @PUT("/scim/v2/Groups/{id}") @PUT("/scim/{tenant}/v2/Groups/{id}") public @NonNull MarshaledResponse putGroup(@NonNull Request request, @PathParameter(name="id") @NonNull String id) {
        return response(request, () -> legacy().write(ScimResourceType.groupInstance(), id, request, false));
    }
    @PATCH("/scim/v2/Groups/{id}") @PATCH("/scim/{tenant}/v2/Groups/{id}") public @NonNull MarshaledResponse patchGroup(@NonNull Request request, @PathParameter(name="id") @NonNull String id) {
        return response(request, () -> legacy().write(ScimResourceType.groupInstance(), id, request, true));
    }
    @DELETE("/scim/v2/Groups/{id}") @DELETE("/scim/{tenant}/v2/Groups/{id}") public @NonNull MarshaledResponse deleteGroup(@NonNull Request request, @PathParameter(name="id") @NonNull String id) {
        return response(request, () -> legacy().delete(ScimResourceType.groupInstance(), id, request));
    }
}
