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
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Supplier;
import static java.util.Objects.requireNonNull;
import static com.revetsec.oauth.server.OAuthStoreFailure.Reason.*;
import static com.revetsec.oauth.server.OAuthServerAdmissionFailure.Reason.*;

/** Registered-client code exchange and bound replay. No callback or signing happens inside a store commit. */
final class OAuthCodeRedemption {
 private final @NonNull OAuthStoreCoordinator coordinator;
 private final @NonNull OAuthStoreRecordCodec codec;
 private final @NonNull OAuthServerIngressLimits limits;
 private final @NonNull OAuthGrantRetention retention;
 private final OAuthTokenResponse.@NonNull Encoder encoder;
 private final @NonNull Duration accessLifetime, refreshIdle, refreshAbsolute;
 private final boolean refreshEnabled;
 private final int attempts, subjectLimit;
 OAuthCodeRedemption(@NonNull OAuthStoreCoordinator coordinator, @NonNull OAuthStoreRecordCodec codec,
   @NonNull OAuthServerIngressLimits limits, @NonNull OAuthGrantRetention retention, OAuthTokenResponse.@NonNull Encoder encoder,
   @NonNull Duration accessLifetime, boolean refreshEnabled, @NonNull Duration refreshIdle, @NonNull Duration refreshAbsolute,
   int attempts, int subjectLimit) {
  this.coordinator = requireNonNull(coordinator); this.codec = requireNonNull(codec); this.limits = requireNonNull(limits);
  this.retention = requireNonNull(retention); this.encoder = requireNonNull(encoder);
  this.accessLifetime = OAuthGrantRetention.duration(accessLifetime, Duration.ofSeconds(30), Duration.ofMinutes(15));
  retention.requireAccessLifetime(accessLifetime); this.refreshEnabled = refreshEnabled;
  this.refreshIdle = OAuthGrantRetention.duration(refreshIdle, Duration.ofMinutes(5), Duration.ofDays(7));
  this.refreshAbsolute = OAuthGrantRetention.duration(refreshAbsolute, Duration.ofHours(1), Duration.ofDays(30));
  if (!codec.issuer().equals(encoder.issuer()) || attempts < 1 || attempts > 8 || subjectLimit < 16 || subjectLimit > 1024
    || refreshEnabled && (accessLifetime.compareTo(refreshIdle) > 0 || refreshIdle.compareTo(refreshAbsolute) > 0)) throw OAuthStoreFormat.invalid();
  this.attempts = attempts; this.subjectLimit = subjectLimit;
 }
 @NonNull OAuthTokenResponse redeem(@NonNull OAuthServerRequest request, @NonNull OAuthServerClientRepository clients,
   @NonNull Map<@NonNull String, @NonNull Set<@NonNull String>> resources, @NonNull OAuthGrantPolicy policy, @NonNull Deadline deadline) {
  return redeem(request, new OAuthServerClientSelection(clients, this.limits, null), resources, policy, deadline);
 }
 @NonNull OAuthTokenResponse redeem(@NonNull OAuthServerRequest request, @NonNull OAuthServerClientSelection clients,
   @NonNull Map<@NonNull String, @NonNull Set<@NonNull String>> resources, @NonNull OAuthGrantPolicy policy, @NonNull Deadline deadline) {
  OAuthServerAuthorizationAdmission.requireTokenGrant(request); requireNonNull(policy);
  if (!request.required("grant_type").equals("authorization_code") || request.value("scope") != null) throw OAuthServerRequest.invalid();
  String codeId, verifier;
  try { codeId = OAuthServerCredential.codeDigest(request.required("code")); verifier = OAuthAuthorizationRecord.verifierDigest(request.required("code_verifier")); }
  catch (IllegalArgumentException failure) { throw invalid(); }
  Map<String, Set<String>> server = OAuthServerConfiguration.resources(resources, this.limits.resources);
  for (int attempt = 0; attempt < this.attempts; attempt++) {
   // Resolve/authenticate again after every conflict; neither app decisions nor metadata are positive caches.
   OAuthServerClientSelection.Selected selectedClient = clients.authenticate(request, server, deadline);
   OAuthServerClientRegistration client = selectedClient.client();
   if (!client.isAuthorizationCodePermitted()) throw OAuthServerClientAdmission.failure(UNAUTHORIZED_CLIENT);
   String fingerprint = selectedClient.fingerprint();
   OAuthStoreCoordinator.Session session = this.coordinator.begin(deadline);
   OAuthStoreKey codeKey = this.codec.key(OAuthStoreKey.Kind.CODE, codeId);
   OAuthAuthorizationRecord code = read(session, codeKey, false);
   OAuthStoreKey grantKey = this.codec.key(OAuthStoreKey.Kind.GRANT, code.text("grantId"));
   OAuthAuthorizationRecord grant = read(session, grantKey, true);
   if (!grant.text("codeId").equals(codeId) || !code.sameLineage(grant)) throw new OAuthStoreFailure(CORRUPT_STATE);
   if (!grant.text("clientId").equals(client.getClientId()) || !OAuthAuthorizationRecord.equalDigest(grant.text("clientHash"), fingerprint)
     || !grant.text("resource").equals(request.required("resource")) || !OAuthAuthorizationRecord.equalDigest(code.text("challenge"), verifier)
     || request.value("redirect_uri") != null && !code.text("redirect").equals(request.value("redirect_uri"))) throw invalid();
   if (!code.matchesIssuer(session.issuer()) || !grant.matchesSubject(session.subject(grant.text("subject")))) throw invalid();
   String status = code.text("status");
   if (status.equals("USED")) {
    if (!grant.text("status").equals("ACTIVE") && !grant.text("status").equals("REVOKED")
      || code.horizon().isBefore(grant.horizon())) throw new OAuthStoreFailure(CORRUPT_STATE);
    session.requireBefore(code.retention()); session.requireBefore(grant.retention());
    if (grant.text("status").equals("REVOKED")) { if (session.barrier() == OAuthStoreCommitStatus.COMMITTED) throw invalid(); }
    else if (session.commit(List.of(put(grantKey, prepared(() -> grant.terminated(this.limits, this.subjectLimit))))) == OAuthStoreCommitStatus.COMMITTED) throw invalid();
    continue;
   }
   if (!status.equals("UNUSED") || !grant.text("status").equals("PENDING")) throw invalid();
   if (!code.expires().equals(grant.expires())) throw new OAuthStoreFailure(CORRUPT_STATE);
   if (!session.effectiveNow().isBefore(code.expires())) throw invalid();
   session.requireBefore(code.expires());
   Set<String> approved = grant.scopes(this.limits), current = server.get(grant.text("resource"));
   if (current == null || !current.containsAll(approved)) {
    if (terminate(session, codeKey, code, grantKey, grant)) throw invalid(); else continue;
   }
   OAuthAuthorizationDecision decision = authorize(policy, grant, deadline);
   if (decision.isDenied()) { if (terminate(session, codeKey, code, grantKey, grant)) throw invalid(); else continue; }
   Map<String, Set<String>> choices = decision.getAuthorizedScopesByResource(); Set<String> selected = choices.get(grant.text("resource"));
   if (!decision.getSubject().orElseThrow(() -> OAuthServerClientAdmission.failure(INFRASTRUCTURE)).equals(grant.text("subject"))
     || choices.size() != 1 || selected == null || !approved.containsAll(selected)
     || decision.isRefreshTokenPermitted() && !grant.refresh()) throw OAuthServerClientAdmission.failure(INFRASTRUCTURE);
   if (selected.isEmpty()) { if (terminate(session, codeKey, code, grantKey, grant)) throw invalid(); else continue; }
   Instant issued = session.effectiveNow();
   Instant expires = prepared(() -> OAuthGrantRetention.expiry(session.effectiveNow(), this.accessLifetime));
   session.requireBefore(expires);
   boolean refreshAllowed = this.refreshEnabled && client.isRefreshTokenPermitted() && grant.refresh() && decision.isRefreshTokenPermitted();
   String refreshCredential = refreshAllowed ? prepared(() -> OAuthServerCredential.refresh(this.codec.freshVersion())) : null;
   String refreshId = refreshCredential == null ? null : OAuthServerCredential.refreshDigest(refreshCredential);
   Instant grantExpiry = refreshAllowed ? prepared(() -> OAuthGrantRetention.expiry(session.effectiveNow(), this.refreshAbsolute)) : expires;
   Instant calculatedHorizon = prepared(() -> this.retention.horizon(grantExpiry));
   Instant horizon = calculatedHorizon.isBefore(code.expires()) ? code.expires() : calculatedHorizon;
   Instant codeHorizon = horizon;
   OAuthAuthorizationRecord active = prepared(() -> grant.activated(grantExpiry, horizon, this.retention.maximumAccessLifetime(), selected,
    refreshId, this.limits, this.subjectLimit));
   String jti = prepared(this.codec::freshVersion); OAuthStoreKey accessKey = this.codec.key(OAuthStoreKey.Kind.ACCESS_TOKEN, jti);
   if (session.read(accessKey).isPresent()) continue;
   List<OAuthStoreTransaction.Mutation> mutations = new ArrayList<>();
   mutations.add(put(codeKey, prepared(() -> code.consumed(codeHorizon, this.limits, this.subjectLimit)))); mutations.add(put(grantKey, active));
   OAuthAuthorizationRecord access = prepared(() -> OAuthAuthorizationRecord.access(jti, active, issued, expires,
    this.retention.accessRetention(expires), this.limits, this.subjectLimit)); mutations.add(put(accessKey, access));
   if (refreshId != null) {
    OAuthStoreKey refreshKey = this.codec.key(OAuthStoreKey.Kind.REFRESH_TOKEN, refreshId);
    if (session.read(refreshKey).isPresent()) continue;
    Instant idle = prepared(() -> OAuthGrantRetention.expiry(session.effectiveNow(), this.refreshIdle));
    Instant refreshExpiry = idle.isAfter(grantExpiry) ? grantExpiry : idle;
    mutations.add(put(refreshKey, prepared(() -> OAuthAuthorizationRecord.refresh(refreshId, active, refreshExpiry, this.limits, this.subjectLimit))));
   }
   OAuthTokenResponse response = prepareResponse(active, jti, issued, expires, selected, refreshCredential, deadline);
   if (session.commit(mutations) == OAuthStoreCommitStatus.COMMITTED) return response;
  }
  throw new OAuthStoreFailure(UNAVAILABLE);
 }
 private @NonNull OAuthAuthorizationDecision authorize(@NonNull OAuthGrantPolicy policy, @NonNull OAuthAuthorizationRecord grant, @NonNull Deadline deadline) {
  OAuthGrantContext context = prepared(() -> OAuthGrantContext.fromCheckedGrant(grant.text("subject"), grant.text("clientId"),
   "authorization_code", grant.text("id"), Map.of(grant.text("resource"), grant.scopes(this.limits)), grant.refresh()));
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
  catch (OAuthServerException failure) {throw failure;}
  catch (Throwable failure) { if (failure instanceof InterruptedException) Thread.currentThread().interrupt(); throw OAuthServerClientAdmission.failure(INFRASTRUCTURE); }
 }
 private boolean terminate(OAuthStoreCoordinator.@NonNull Session session, @NonNull OAuthStoreKey codeKey,
   @NonNull OAuthAuthorizationRecord code, @NonNull OAuthStoreKey grantKey, @NonNull OAuthAuthorizationRecord grant) {
  return session.commit(List.of(put(codeKey, prepared(() -> code.terminated(this.limits, this.subjectLimit))),
   put(grantKey, prepared(() -> grant.terminated(this.limits, this.subjectLimit))))) == OAuthStoreCommitStatus.COMMITTED;
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
 @Override public @NonNull String toString() { return "OAuthCodeRedemption{<redacted>}"; }
}
