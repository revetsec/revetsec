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
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Supplier;
import static java.util.Objects.requireNonNull;
import static com.revetsec.oauth.server.OAuthStoreFailure.Reason.*;
import static com.revetsec.oauth.server.OAuthServerAdmissionFailure.Reason.*;

/** Strict registered-client refresh rotation. Only a committed issuance releases prepared credentials. */
final class OAuthRefreshRotation {
 private final @NonNull OAuthStoreCoordinator coordinator;
 private final @NonNull OAuthStoreRecordCodec codec;
 private final @NonNull OAuthServerIngressLimits limits;
 private final @NonNull OAuthGrantRetention retention;
 private final OAuthTokenResponse.@NonNull Encoder encoder;
 private final @NonNull Duration accessLifetime, refreshIdle;
 private final boolean refreshEnabled;
 private final int attempts, subjectLimit;
 OAuthRefreshRotation(@NonNull OAuthStoreCoordinator coordinator, @NonNull OAuthStoreRecordCodec codec,
   @NonNull OAuthServerIngressLimits limits, @NonNull OAuthGrantRetention retention, OAuthTokenResponse.@NonNull Encoder encoder,
   @NonNull Duration accessLifetime, boolean refreshEnabled, @NonNull Duration refreshIdle, int attempts, int subjectLimit) {
  this.coordinator = requireNonNull(coordinator); this.codec = requireNonNull(codec); this.limits = requireNonNull(limits);
  this.retention = requireNonNull(retention); this.encoder = requireNonNull(encoder);
  this.accessLifetime = OAuthGrantRetention.duration(accessLifetime, Duration.ofSeconds(30), Duration.ofMinutes(15));
  retention.requireAccessLifetime(accessLifetime); this.refreshEnabled = refreshEnabled;
  this.refreshIdle = OAuthGrantRetention.duration(refreshIdle, Duration.ofMinutes(5), Duration.ofDays(7));
  if (!codec.issuer().equals(encoder.issuer()) || attempts < 1 || attempts > 8 || subjectLimit < 16 || subjectLimit > 1024
    || accessLifetime.compareTo(refreshIdle) > 0) throw OAuthStoreFormat.invalid();
  this.attempts = attempts; this.subjectLimit = subjectLimit;
 }
 @NonNull OAuthTokenResponse rotate(@NonNull OAuthServerRequest request, @NonNull OAuthServerClientRepository clients,
   @NonNull Map<@NonNull String, @NonNull Set<@NonNull String>> resources, @NonNull OAuthGrantPolicy policy, @NonNull Deadline deadline) {
  return rotate(request, new OAuthServerClientSelection(clients, this.limits, null), resources, policy, deadline);
 }
 @NonNull OAuthTokenResponse rotate(@NonNull OAuthServerRequest request, @NonNull OAuthServerClientSelection clients,
   @NonNull Map<@NonNull String, @NonNull Set<@NonNull String>> resources, @NonNull OAuthGrantPolicy policy, @NonNull Deadline deadline) {
  OAuthServerAuthorizationAdmission.requireTokenGrant(request); requireNonNull(policy);
  if (!request.required("grant_type").equals("refresh_token")) throw OAuthServerRequest.invalid();
  String refreshId;
  try { refreshId = OAuthServerCredential.refreshDigest(request.required("refresh_token")); }
  catch (IllegalArgumentException failure) { throw invalid(); }
  Map<String, Set<String>> server = OAuthServerConfiguration.resources(resources, this.limits.resources);
  for (int attempt = 0; attempt < this.attempts; attempt++) {
   OAuthServerClientSelection.Selected selectedClient = clients.authenticate(request, server, deadline);
   OAuthServerClientRegistration client = selectedClient.client();
   String fingerprint = selectedClient.fingerprint();
   OAuthStoreCoordinator.Session session = this.coordinator.begin(deadline);
   OAuthStoreKey refreshKey = this.codec.key(OAuthStoreKey.Kind.REFRESH_TOKEN, refreshId);
   OAuthAuthorizationRecord refresh = read(session, refreshKey, false);
   OAuthStoreKey grantKey = this.codec.key(OAuthStoreKey.Kind.GRANT, refresh.text("grantId"));
   OAuthAuthorizationRecord grant = read(session, grantKey, true);
   if (!refresh.sameLineage(grant) || !grant.refresh()
     || !grant.text("status").equals("ACTIVE") && !grant.text("status").equals("REVOKED")
     || !refresh.horizon().equals(grant.horizon()) || refresh.expires().isAfter(grant.expires())) throw new OAuthStoreFailure(CORRUPT_STATE);
   // No destructive reuse action precedes fresh authentication and exact owner/security/resource binding.
   if (!grant.text("clientId").equals(client.getClientId()) || !OAuthAuthorizationRecord.equalDigest(grant.text("clientHash"), fingerprint)
     || !grant.text("resource").equals(request.required("resource"))) throw invalid();
   if (!refresh.matchesIssuer(session.issuer()) || !grant.matchesSubject(session.subject(grant.text("subject")))) throw invalid();
   Set<String> approved = grant.scopes(this.limits);
   Set<String> selected = OAuthServerAuthorizationAdmission.selectScopes(grant.text("resource"), request.value("scope"), client,
    Map.of(grant.text("resource"), approved), this.limits);
   boolean used = refresh.text("status").equals("USED");
   if (used == grant.text("refreshId").equals(refreshId)) throw new OAuthStoreFailure(CORRUPT_STATE);
   session.requireBefore(refresh.retention()); session.requireBefore(grant.retention());
   if (used || grant.text("status").equals("REVOKED")) {
    if (grant.text("status").equals("REVOKED")) { if (session.barrier() == OAuthStoreCommitStatus.COMMITTED) throw invalid(); }
    else if (terminate(session, grantKey, grant)) throw invalid();
    continue;
   }
   if (!session.effectiveNow().isBefore(refresh.expires()) || !session.effectiveNow().isBefore(grant.expires())) throw invalid();
   session.requireBefore(refresh.expires()); session.requireBefore(grant.expires());
   Set<String> current = server.get(grant.text("resource"));
   Instant requiredHorizon = prepared(() -> this.retention.accessRetention(grant.expires().plus(grant.maximumAccessLifetime())));
   if (!this.refreshEnabled || !client.isRefreshTokenPermitted() || current == null || !current.containsAll(approved)
     || this.accessLifetime.compareTo(grant.maximumAccessLifetime()) > 0 || requiredHorizon.isAfter(grant.horizon())) {
    if (terminate(session, grantKey, grant)) throw invalid(); else continue;
   }
   OAuthAuthorizationDecision decision = authorize(policy, grant, deadline);
   if (decision.isDenied()) { if (terminate(session, grantKey, grant)) throw invalid(); else continue; }
   Map<String, Set<String>> choices = decision.getAuthorizedScopesByResource(); Set<String> continuing = choices.get(grant.text("resource"));
   if (!decision.getSubject().orElseThrow(() -> OAuthServerClientAdmission.failure(INFRASTRUCTURE)).equals(grant.text("subject"))
     || choices.size() != 1 || continuing == null || !approved.containsAll(continuing)) throw OAuthServerClientAdmission.failure(INFRASTRUCTURE);
   // A narrowed continuing decision ends this family; a narrowed request changes only this access token.
   if (!continuing.equals(approved) || !decision.isRefreshTokenPermitted()) {
    if (terminate(session, grantKey, grant)) throw invalid(); else continue;
   }
   Instant issued = session.effectiveNow();
   Instant expires = prepared(() -> OAuthGrantRetention.expiry(issued, this.accessLifetime));
   Instant accessRetention = prepared(() -> this.retention.accessRetention(expires));
   if (accessRetention.isAfter(grant.horizon())) throw new OAuthStoreFailure(CORRUPT_STATE);
   session.requireBefore(expires);
   String credential = prepared(() -> OAuthServerCredential.refresh(this.codec.freshVersion())), nextId = OAuthServerCredential.refreshDigest(credential);
   OAuthStoreKey nextKey = this.codec.key(OAuthStoreKey.Kind.REFRESH_TOKEN, nextId);
   String jti = prepared(this.codec::freshVersion); OAuthStoreKey accessKey = this.codec.key(OAuthStoreKey.Kind.ACCESS_TOKEN, jti);
   if (session.read(nextKey).isPresent() || session.read(accessKey).isPresent()) continue;
   OAuthAuthorizationRecord nextGrant = prepared(() -> grant.rotated(nextId, this.limits, this.subjectLimit));
   Instant idle = prepared(() -> OAuthGrantRetention.expiry(issued, this.refreshIdle));
   Instant refreshExpiry = idle.isAfter(grant.expires()) ? grant.expires() : idle;
   List<OAuthStoreTransaction.Mutation> mutations = List.of(
    put(refreshKey, prepared(() -> refresh.refreshUsed(this.limits, this.subjectLimit))), put(grantKey, nextGrant),
    put(nextKey, prepared(() -> OAuthAuthorizationRecord.refresh(nextId, nextGrant, refreshExpiry, this.limits, this.subjectLimit))),
    put(accessKey, prepared(() -> OAuthAuthorizationRecord.access(jti, nextGrant, issued, expires, accessRetention, selected, this.limits, this.subjectLimit))));
   OAuthTokenResponse response = prepareResponse(nextGrant, jti, issued, expires, selected, credential, deadline);
   if (session.commit(mutations) == OAuthStoreCommitStatus.COMMITTED) return response;
  }
  throw new OAuthStoreFailure(UNAVAILABLE);
 }
 private @NonNull OAuthAuthorizationDecision authorize(@NonNull OAuthGrantPolicy policy, @NonNull OAuthAuthorizationRecord grant, @NonNull Deadline deadline) {
  OAuthGrantContext context = prepared(() -> OAuthGrantContext.fromCheckedGrant(grant.text("subject"), grant.text("clientId"),
   "refresh_token", grant.text("id"), Map.of(grant.text("resource"), grant.scopes(this.limits)), true));
  OAuthAuthorizationDecision decision;
  try { decision = policy.authorizeGrant(context, OAuthServerClientAdmission.remaining(deadline)); }
  catch (VirtualMachineError fatal) { throw fatal; }
  catch (Throwable failure) { if (failure instanceof InterruptedException) Thread.currentThread().interrupt(); throw OAuthServerClientAdmission.failure(INFRASTRUCTURE); }
  OAuthServerClientAdmission.remaining(deadline); if (decision == null) throw OAuthServerClientAdmission.failure(INFRASTRUCTURE); return decision;
 }
 private @NonNull OAuthTokenResponse prepareResponse(@NonNull OAuthAuthorizationRecord grant, @NonNull String jti,
   @NonNull Instant issued, @NonNull Instant expires, @NonNull Set<@NonNull String> scopes, @Nullable String refresh, @NonNull Deadline deadline) {
  try { return this.encoder.prepare(grant, jti, issued, expires, scopes, refresh, deadline); }
  catch (VirtualMachineError fatal) { throw fatal; }
  catch (Throwable failure) { if (failure instanceof InterruptedException) Thread.currentThread().interrupt(); throw OAuthServerClientAdmission.failure(INFRASTRUCTURE); }
 }
 private boolean terminate(OAuthStoreCoordinator.@NonNull Session session, @NonNull OAuthStoreKey key,
   @NonNull OAuthAuthorizationRecord grant) {
  return session.commit(List.of(put(key, prepared(() -> grant.terminated(this.limits, this.subjectLimit))))) == OAuthStoreCommitStatus.COMMITTED;
 }
 private @NonNull OAuthAuthorizationRecord read(OAuthStoreCoordinator.@NonNull Session session, @NonNull OAuthStoreKey key, boolean required) {
  OAuthStoreEntry entry = session.read(key).orElseThrow(() -> required ? new OAuthStoreFailure(CORRUPT_STATE) : invalid());
  if (!session.effectiveNow().isBefore(entry.getRetainUntil())) { if (required) throw new OAuthStoreFailure(CORRUPT_STATE); else throw invalid(); }
  String raw = key.getStorageKey(), id = raw.substring(raw.lastIndexOf(':') + 1);
  OAuthAuthorizationRecord record = prepared(() -> OAuthAuthorizationRecord.decode(key.getKind(), id,
   this.codec.open(entry, Clock.fixed(session.effectiveNow(), ZoneOffset.UTC)), this.limits, this.subjectLimit));
  if (!record.retention().equals(entry.getRetainUntil())) throw new OAuthStoreFailure(CORRUPT_STATE); return record;
 }
 private OAuthStoreTransaction.@NonNull Mutation put(@NonNull OAuthStoreKey key, @NonNull OAuthAuthorizationRecord record) {
  return prepared(() -> OAuthStoreTransaction.Mutation.fromPut(this.codec.seal(key, record.retention(), record.toPayload())));
 }
 private static <T> @NonNull T prepared(@NonNull Supplier<@NonNull T> work) {
  try { return work.get(); } catch (VirtualMachineError fatal) { throw fatal; } catch (Throwable failure) { throw new OAuthStoreFailure(CORRUPT_STATE); }
 }
 private static @NonNull OAuthServerAdmissionFailure invalid() { return OAuthServerClientAdmission.failure(INVALID_GRANT); }
 @Override public @NonNull String toString() { return "OAuthRefreshRotation{<redacted>}"; }
}
