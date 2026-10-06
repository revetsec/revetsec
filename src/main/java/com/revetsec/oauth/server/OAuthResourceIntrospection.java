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

package com.revetsec.oauth.server;

import com.revetsec.internal.http.Deadline;
import com.revetsec.jose.StaticJsonWebKeySource;
import com.revetsec.json.JsonObject;
import org.jspecify.annotations.NonNull;
import java.util.Map;
import java.util.Set;
import static java.util.Objects.requireNonNull;

/** Registered confidential resource authority before checked access-token claim release; no cache. */
final class OAuthResourceIntrospection {
 private final @NonNull OAuthIssuerTokenStatus status;
 private final @NonNull OAuthServerIngressLimits limits;
 private final int bodyCap, headerCap;
 OAuthResourceIntrospection(@NonNull OAuthIssuerTokenStatus status, @NonNull OAuthServerIngressLimits limits, int bodyCap, int headerCap) {
  this.status = requireNonNull(status); this.limits = requireNonNull(limits);
  if (bodyCap < 4096 || bodyCap > 131072 || headerCap < 1024 || headerCap > 65536) throw OAuthStoreFormat.invalid();
  this.bodyCap = bodyCap; this.headerCap = headerCap;
 }
 /** Resource is trusted endpoint configuration, never token-controlled or inferred from Host. */
 @NonNull OAuthStatusResponse introspect(@NonNull OAuthServerRequest request, @NonNull OAuthServerClientRepository clients,
   @NonNull String resource, @NonNull StaticJsonWebKeySource keys, @NonNull Deadline deadline) {
  if (request.endpoint() != OAuthServerRequest.Endpoint.INTROSPECTION) throw OAuthServerRequest.invalid();
  OAuthServerConfiguration.resources(Map.of(resource, Set.of()), 1);
  OAuthServerClientRegistration client = OAuthServerClientAdmission.authenticate(request, clients, deadline, this.limits);
  if (client.isAuthorizationCodePermitted() || !client.getIntrospectionResources().contains(resource))
   throw OAuthServerClientAdmission.failure(OAuthServerAdmissionFailure.Reason.UNAUTHORIZED_CLIENT);
  String token = request.required("token");
  String selected = request.value("resource");
  if (selected != null && !resource.equals(selected)) return inactive();
  try {
   return this.status.validate(token, resource, keys, deadline, claims -> {
    var response = JsonObject.builder().put("active", true).put("token_type", "Bearer");
    for (var member : claims.getMembers().entrySet()) response.put(member.getKey(), member.getValue());
    return OAuthStatusResponse.prepare(response.build(), this.bodyCap, this.headerCap);
   });
  } catch (OAuthServerAdmissionFailure rejection) {
   if (rejection.reason() != OAuthServerAdmissionFailure.Reason.INVALID_TOKEN) throw rejection;
   OAuthServerClientAdmission.remaining(deadline); return inactive();
  }
 }
 private @NonNull OAuthStatusResponse inactive() { return OAuthStatusResponse.prepare(JsonObject.builder().put("active", false).build(), this.bodyCap, this.headerCap); }
 @Override public @NonNull String toString() { return "OAuthResourceIntrospection{<redacted>}"; }
}
