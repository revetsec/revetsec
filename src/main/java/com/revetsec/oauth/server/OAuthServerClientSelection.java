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
import com.revetsec.json.JsonObject;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import java.util.Map;
import java.util.Optional;
import java.util.function.BooleanSupplier;
import java.util.Set;
import static java.util.Objects.requireNonNull;
import static com.revetsec.oauth.server.OAuthServerAdmissionFailure.Reason.INVALID_CLIENT;

/** Engine-owned registry precedence and operation-local metadata retrieval. No caller supplies a fresh-fetch proof. */
final class OAuthServerClientSelection {
 private final @NonNull OAuthServerClientRepository repository;
 private final @NonNull OAuthServerIngressLimits limits;
 private final @Nullable OAuthClientMetadataFetcher metadata;
 private final boolean publicBoundary;
 OAuthServerClientSelection(@NonNull OAuthServerClientRepository repository, @NonNull OAuthServerIngressLimits limits,
   @Nullable OAuthClientMetadataFetcher metadata) {
  this(repository,limits,metadata,false);
 }
 OAuthServerClientSelection(@NonNull OAuthServerClientRepository repository,@NonNull OAuthServerIngressLimits limits,
   @Nullable OAuthClientMetadataFetcher metadata,boolean publicBoundary) {
  this.publicBoundary=publicBoundary;
  this.repository = requireNonNull(repository); this.limits = requireNonNull(limits); this.metadata = metadata;
 }
 boolean metadataEnabled() { return this.metadata != null; }
 @NonNull Selected authorization(@NonNull String id,
   @NonNull Map<@NonNull String, @NonNull Set<@NonNull String>> resources, @NonNull Deadline deadline) {
  return select(id, resources, deadline, false, () -> true).orElseThrow();
 }
 @NonNull Selected authenticate(@NonNull OAuthServerRequest request,
   @NonNull Map<@NonNull String, @NonNull Set<@NonNull String>> resources, @NonNull Deadline deadline) {
  return authenticate(request, resources, deadline, () -> true).orElseThrow();
 }
 @NonNull Optional<@NonNull Selected> authenticate(@NonNull OAuthServerRequest request,
   @NonNull Map<@NonNull String, @NonNull Set<@NonNull String>> resources, @NonNull Deadline deadline,
   @NonNull BooleanSupplier admission) {
  if (request.endpoint() == OAuthServerRequest.Endpoint.AUTHORIZATION) throw OAuthServerRequest.invalid();
  if (request.clientAssertion()) throw OAuthServerClientAdmission.failure(INVALID_CLIENT);
  // Basic is registry-only. A missing verifier/unknown registration never becomes public metadata authentication.
  if (request.authorization() != null) return Optional.of(registered(OAuthServerClientAdmission.authenticate(request, this.repository, deadline, this.limits)));
  String id = request.value("client_id");
  if (id == null || id.isEmpty() || request.endpoint() == OAuthServerRequest.Endpoint.INTROSPECTION)
   throw OAuthServerClientAdmission.failure(INVALID_CLIENT);
  Optional<Selected> selected = select(id, resources, deadline, true, admission);
  if (selected.isPresent() && selected.orElseThrow().client().getAuthentication().isConfidential()) throw OAuthServerClientAdmission.failure(INVALID_CLIENT);
  return selected;
 }
 private @NonNull Optional<@NonNull Selected> select(@NonNull String id,
   @NonNull Map<@NonNull String, @NonNull Set<@NonNull String>> resources, @NonNull Deadline deadline, boolean fresh, @NonNull BooleanSupplier admission) {
  Map<String, Set<String>> ceiling = OAuthServerAuthorizationAdmission.checkedServerResources(resources, this.limits);
  var registered = OAuthServerClientAdmission.findRegistered(id, this.repository, deadline, this.limits);
  if (registered.isPresent()) return Optional.of(registered(registered.orElseThrow()));
  OAuthClientMetadataFetcher fetcher = this.metadata;
  if (fetcher == null) throw OAuthServerClientAdmission.failure(INVALID_CLIENT);
  OAuthClientMetadataDocument document;
  try {
   Optional<OAuthClientMetadataDocument> found = fresh ? fetcher.freshIfEligible(id, deadline, admission)
     : Optional.of(fetcher.reusable(id, deadline));
   if (found.isEmpty()) return Optional.empty();
   document = found.orElseThrow();
  }
  catch(OAuthServerAdmissionFailure failure) {
   if(this.publicBoundary && failure.reason()==OAuthServerAdmissionFailure.Reason.INFRASTRUCTURE) throw OAuthServerTransportException.fromReason(OAuthServerException.Reason.CLIENT_METADATA_UNAVAILABLE,false);
   throw failure;
  }
  OAuthServerClientAdmission.remaining(deadline);
  // Remote scope/software/key declarations grant no permission. This is only a configured request ceiling.
  OAuthServerClientRegistration client = OAuthServerClientRegistration.withClientId(id)
   .configurationVersion(document.fingerprint()).clientName(document.clientName()).redirectUris(document.redirectUris())
   .allowedScopesByResource(ceiling).refreshTokenPermitted(document.refreshTokenPermitted()).build();
  String fingerprint = OAuthAuthorizationRecord.digest(JsonObject.builder().put("source", "CIMD")
   .put("security", document.fingerprint()).build().toJson());
  return Optional.of(new Selected(client, fingerprint));
 }
 static @NonNull Selected registered(@NonNull OAuthServerClientRegistration client) {
  return new Selected(requireNonNull(client), OAuthAuthorizationRecord.clientFingerprint(client));
 }
 /** Internal bounded snapshot; it carries no reusable fetch permission and cannot bypass authenticate(). */
 static final class Selected {
  private final @NonNull OAuthServerClientRegistration client;
  private final @NonNull String fingerprint;
  private Selected(@NonNull OAuthServerClientRegistration client, @NonNull String fingerprint) {
   this.client = client; this.fingerprint = fingerprint;
  }
  @NonNull OAuthServerClientRegistration client() { return this.client; }
  @NonNull String fingerprint() { return this.fingerprint; }
  @Override public @NonNull String toString() { return "Selected{<redacted>}"; }
 }
 @Override public @NonNull String toString() { return "OAuthServerClientSelection{<redacted>}"; }
}
