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
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Function;
import static java.util.Objects.requireNonNull;
import static com.revetsec.oauth.server.OAuthStoreFailure.Reason.*;

/** Monotonic whole-grant revocation. Unknown/wrong-owner credentials have one prepared ordinary response. */
final class OAuthGrantRevocation {
 private final @NonNull OAuthStoreCoordinator coordinator;
 private final @NonNull OAuthStoreRecordCodec codec;
 private final @NonNull OAuthIssuerTokenStatus status;
 private final @NonNull OAuthServerIngressLimits limits;
 private final int attempts, subjectLimit, bodyCap, headerCap;
 OAuthGrantRevocation(@NonNull OAuthStoreCoordinator coordinator, @NonNull OAuthStoreRecordCodec codec,
   @NonNull OAuthIssuerTokenStatus status, @NonNull OAuthServerIngressLimits limits, int attempts, int subjectLimit, int bodyCap, int headerCap) {
  this.coordinator = requireNonNull(coordinator); this.codec = requireNonNull(codec); this.status = requireNonNull(status); this.limits = requireNonNull(limits);
  if (attempts < 1 || attempts > 8 || subjectLimit < 16 || subjectLimit > 1024 || bodyCap < 4096 || bodyCap > 131072 || headerCap < 1024 || headerCap > 65536)
   throw OAuthStoreFormat.invalid();
  this.attempts = attempts; this.subjectLimit = subjectLimit; this.bodyCap = bodyCap; this.headerCap = headerCap;
 }
 @NonNull OAuthStatusResponse revoke(@NonNull OAuthServerRequest request, @NonNull OAuthServerClientRepository clients,
   @NonNull StaticJsonWebKeySource keys, @NonNull Deadline deadline) {
  return revokeSelected(request, d -> OAuthServerClientSelection.registered(OAuthServerClientAdmission.authenticate(request, clients, d, this.limits)), keys, deadline);
 }
 @NonNull OAuthStatusResponse revoke(@NonNull OAuthServerRequest request, @NonNull OAuthServerClientSelection clients,
   @NonNull Map<@NonNull String, @NonNull Set<@NonNull String>> resources,
   @NonNull StaticJsonWebKeySource keys, @NonNull Deadline deadline) {
  return revokeSelected(request, d -> clients.authenticate(request, resources, d), keys, deadline);
 }
 private @NonNull OAuthStatusResponse revokeSelected(@NonNull OAuthServerRequest request,
   @NonNull Function<@NonNull Deadline, OAuthServerClientSelection.@NonNull Selected> clients,
   @NonNull StaticJsonWebKeySource keys, @NonNull Deadline deadline) {
  if (request.endpoint() != OAuthServerRequest.Endpoint.REVOCATION) throw OAuthServerRequest.invalid();
  requireNonNull(keys);
  String token = request.required("token");
  OAuthStatusResponse response = OAuthStatusResponse.revocation(this.bodyCap, this.headerCap);
  // Hints never choose authority. Only the typed refresh prefix selects the raw credential parser;
  // every other token follows the compact JWT parser, including malformed leading-dot values.
  boolean refresh = OAuthServerCredential.isRefresh(token);
  for (int attempt = 0; attempt < this.attempts; attempt++) {
   OAuthServerClientSelection.Selected selectedClient = clients.apply(deadline);
   OAuthServerClientRegistration client = selectedClient.client();
   String id; JsonObject claims = null;
   try {
    if (refresh) id = OAuthServerCredential.refreshDigest(token);
    else { claims = this.status.retainedClaims(token, keys, deadline); id = claims.findString("jti").orElseThrow(OAuthServerRequest::invalid); }
   } catch (IllegalArgumentException invalid) { return response; }
   catch (OAuthServerAdmissionFailure invalid) {
    if (invalid.reason() != OAuthServerAdmissionFailure.Reason.INVALID_TOKEN) throw invalid;
    OAuthServerClientAdmission.remaining(deadline); return response;
   }
   OAuthStoreCoordinator.Session session = this.coordinator.begin(deadline);
   OAuthAuthorizationRecord credential = this.status.read(session, this.codec.key(refresh ? OAuthStoreKey.Kind.REFRESH_TOKEN : OAuthStoreKey.Kind.ACCESS_TOKEN, id));
   if (credential == null) { if (session.barrier() == OAuthStoreCommitStatus.COMMITTED) return response; else continue; }
   OAuthStoreKey grantKey = this.codec.key(OAuthStoreKey.Kind.GRANT, credential.text("grantId"));
   OAuthAuthorizationRecord grant = this.status.read(session, grantKey);
   if (grant == null) { if (session.barrier() == OAuthStoreCommitStatus.COMMITTED) return response; else continue; }
   if (refresh) checkRefresh(credential, grant, id); else this.status.checkAccessGrant(credential, grant);
   OAuthStoreFence subject = session.subject(grant.text("subject"));
   String resource = request.value("resource");
   boolean owned = grant.text("clientId").equals(client.getClientId())
    && OAuthAuthorizationRecord.equalDigest(grant.text("clientHash"), selectedClient.fingerprint())
    && (resource == null || resource.equals(grant.text("resource")))
    && credential.matchesIssuer(session.issuer()) && grant.matchesSubject(subject)
    && (claims == null || this.status.matches(claims, credential, grant.text("resource")));
   session.requireBefore(credential.retention()); session.requireBefore(grant.retention());
   OAuthStoreCommitStatus result = owned && grant.text("status").equals("ACTIVE") ? terminate(session, grantKey, grant) : session.barrier();
   if (result == OAuthStoreCommitStatus.COMMITTED) return response;
  }
  throw new OAuthStoreFailure(UNAVAILABLE);
 }
 /** Trusted app grant reference; repeating a reconciled revocation never increments an epoch or resurrects a grant. */
 void revokeGrant(@NonNull String grantId, @NonNull Deadline deadline) {
  OAuthStoreFormat.nonce(grantId);
  for (int attempt = 0; attempt < this.attempts; attempt++) {
   OAuthStoreCoordinator.Session session = this.coordinator.begin(deadline);
   OAuthStoreKey key = this.codec.key(OAuthStoreKey.Kind.GRANT, grantId);
   OAuthAuthorizationRecord grant = this.status.read(session, key);
   OAuthStoreCommitStatus result;
   if (grant == null) result = session.barrier();
   else {
    // Required permanent fences are not recreated, even for an already revoked grant.
    session.subject(grant.text("subject")); session.requireBefore(grant.retention());
    String state = grant.text("status");
    result = state.equals("REVOKED") || state.equals("DENIED") ? session.barrier() : terminate(session, key, grant);
   }
   if (result == OAuthStoreCommitStatus.COMMITTED) return;
  }
  throw new OAuthStoreFailure(UNAVAILABLE);
 }
 private void checkRefresh(@NonNull OAuthAuthorizationRecord refresh, @NonNull OAuthAuthorizationRecord grant, @NonNull String id) {
  String state = grant.text("status");
  if (!refresh.sameLineage(grant) || !grant.refresh() || !state.equals("ACTIVE") && !state.equals("REVOKED")
    || !refresh.horizon().equals(grant.horizon()) || refresh.expires().isAfter(grant.expires())
    || refresh.text("status").equals("USED") == grant.text("refreshId").equals(id)) throw new OAuthStoreFailure(CORRUPT_STATE);
 }
 private @NonNull OAuthStoreCommitStatus terminate(OAuthStoreCoordinator.@NonNull Session session, @NonNull OAuthStoreKey key,
   @NonNull OAuthAuthorizationRecord grant) {
  OAuthAuthorizationRecord terminated;
  OAuthStoreEntry entry;
  try { terminated = grant.terminated(this.limits, this.subjectLimit); entry = this.codec.seal(key, terminated.retention(), terminated.toPayload()); }
  catch (VirtualMachineError fatal) { throw fatal; }
  catch (Throwable failure) { if (failure instanceof InterruptedException) Thread.currentThread().interrupt(); throw new OAuthStoreFailure(CORRUPT_STATE); }
  return session.commit(List.of(OAuthStoreTransaction.Mutation.fromPut(entry)));
 }
 @Override public @NonNull String toString() { return "OAuthGrantRevocation{<redacted>}"; }
}
