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
import java.util.Optional;
import java.util.Set;
import java.util.function.Supplier;
import static java.util.Objects.requireNonNull;
import static com.revetsec.oauth.server.OAuthStoreFailure.Reason.*;

/**
 * Caller-thread consent ledger. Callers supply freshly resolved client snapshots and trusted app decisions.
 * Login/session fixation/CSRF belongs to the trusted app edge; policy callbacks precede commit.
 * Pending grants are not issued tokens; redemption must atomically add issuance/replay facts before token release.
 */
final class OAuthAuthorizationLedger {
 private final @NonNull OAuthStoreCoordinator coordinator;
 private final @NonNull OAuthStoreRecordCodec codec;
 private final @NonNull OAuthServerIngressLimits limits;
 private final @NonNull Duration interactionLifetime;
 private final @NonNull Duration codeLifetime;
 private final int maximumAttempts;
 private final int subjectLimit;
 private final boolean refreshEnabled;
 OAuthAuthorizationLedger(@NonNull OAuthStoreCoordinator coordinator, @NonNull OAuthStoreRecordCodec codec,
   @NonNull OAuthServerIngressLimits limits, @NonNull Duration interactionLifetime, @NonNull Duration codeLifetime,
   int maximumAttempts, int subjectLimit, boolean refreshEnabled) {
  this.coordinator = requireNonNull(coordinator); this.codec = requireNonNull(codec); this.limits = requireNonNull(limits);
  this.interactionLifetime = OAuthGrantRetention.duration(interactionLifetime, Duration.ofMinutes(1), Duration.ofHours(1));
  this.codeLifetime = OAuthGrantRetention.duration(codeLifetime, Duration.ofSeconds(30), Duration.ofMinutes(10));
  if (codeLifetime.compareTo(interactionLifetime) > 0 || maximumAttempts < 1 || maximumAttempts > 8
    || subjectLimit < 16 || subjectLimit > 1024) throw OAuthStoreFormat.invalid();
  this.maximumAttempts = maximumAttempts; this.subjectLimit = subjectLimit; this.refreshEnabled = refreshEnabled;
 }
 @NonNull String begin(@NonNull OAuthServerAuthorizationAdmission admission, @NonNull String browserBinding,
   @NonNull Deadline deadline) {
  String browserHash = OAuthAuthorizationRecord.credentialDigest(browserBinding);
  String clientHash = admission.fingerprint();
  for (int attempt = 0; attempt < this.maximumAttempts; attempt++) {
   OAuthStoreCoordinator.Session session = this.coordinator.begin(deadline);
   String credential = prepared(this.codec::freshVersion), id = OAuthAuthorizationRecord.credentialDigest(credential);
   OAuthStoreKey key = this.codec.key(OAuthStoreKey.Kind.INTERACTION, id);
   if (session.read(key).isPresent()) continue;
   Instant expires = prepared(() -> OAuthGrantRetention.expiry(session.effectiveNow(), this.interactionLifetime));
   OAuthAuthorizationRecord record = prepared(() -> OAuthAuthorizationRecord.interaction(id, browserHash, clientHash,
    admission, session.issuer(), expires, this.limits));
   session.requireBefore(expires);
   if (session.commit(List.of(put(key, expires, record))) == OAuthStoreCommitStatus.COMMITTED) return credential;
  }
  throw new OAuthStoreFailure(UNAVAILABLE);
 }
 /** Each resume is admitted by a complete condition-only barrier; completion re-reads instead of trusting this view. */
 @NonNull OAuthAuthorizationRecord resume(@NonNull String interaction, @NonNull String browserBinding,
   @NonNull OAuthServerClientRegistration currentClient, @NonNull Deadline deadline) {
  return resume(interaction, browserBinding, OAuthServerClientSelection.registered(currentClient), deadline);
 }
 @NonNull OAuthAuthorizationRecord resume(@NonNull String interaction, @NonNull String browserBinding,
   OAuthServerClientSelection.@NonNull Selected selectedClient, @NonNull Deadline deadline) {
  OAuthStoreKey key = interactionKey(interaction); String browserHash = OAuthAuthorizationRecord.credentialDigest(browserBinding);
  String fingerprint = selectedClient.fingerprint();
  for (int attempt = 0; attempt < this.maximumAttempts; attempt++) {
   OAuthStoreCoordinator.Session session = this.coordinator.begin(deadline);
   OAuthAuthorizationRecord record = checkedInteraction(session, key, browserHash, fingerprint);
   session.requireBefore(record.expires());
   if (session.barrier() == OAuthStoreCommitStatus.COMMITTED) return record;
  }
  throw new OAuthStoreFailure(UNAVAILABLE);
 }
 /** Returns a code only after COMMITTED; empty is a committed denial, never a success replay. */
 @NonNull Optional<@NonNull String> complete(@NonNull String interaction, @NonNull String browserBinding,
   @NonNull OAuthServerClientRegistration currentClient,
   @NonNull Map<@NonNull String, @NonNull Set<@NonNull String>> currentServerResources,
   @NonNull OAuthAuthorizationDecision decision, @NonNull Deadline deadline) {
  return complete(interaction, browserBinding, OAuthServerClientSelection.registered(currentClient), currentServerResources, decision, deadline);
 }
 @NonNull Optional<@NonNull String> complete(@NonNull String interaction, @NonNull String browserBinding,
   OAuthServerClientSelection.@NonNull Selected selectedClient,
   @NonNull Map<@NonNull String, @NonNull Set<@NonNull String>> currentServerResources,
   @NonNull OAuthAuthorizationDecision decision, @NonNull Deadline deadline) {
  return completePrepared(interaction, browserBinding, () -> selectedClient, currentServerResources, decision, null, null, deadline).code;
 }
 @NonNull OAuthServerResponse completeResponse(@NonNull String interaction, @NonNull String browserBinding,
   OAuthServerClientSelection.@NonNull Selected selectedClient,
   @NonNull Map<@NonNull String, @NonNull Set<@NonNull String>> currentServerResources,
   @NonNull OAuthAuthorizationDecision decision, @NonNull OAuthAuthorizationResponseEncoder encoder, @NonNull Deadline deadline) {
  return requireNonNull(completePrepared(interaction, browserBinding, () -> selectedClient, currentServerResources, decision, null, requireNonNull(encoder), deadline).response);
 }
 /** Resolve only the browser-bound client identity; a later resume/completion rechecks its current fingerprint. */
 @NonNull String clientId(@NonNull String interaction, @NonNull String browserBinding, @NonNull Deadline deadline) {
  OAuthStoreKey key = interactionKey(interaction); String browserHash = OAuthAuthorizationRecord.credentialDigest(browserBinding);
  for (int attempt = 0; attempt < this.maximumAttempts; attempt++) {
   OAuthStoreCoordinator.Session session = this.coordinator.begin(deadline);
   OAuthAuthorizationRecord record = checkedInteraction(session, key, browserHash, null);
   session.requireBefore(record.expires());
   if (session.barrier() == OAuthStoreCommitStatus.COMMITTED) return record.text("clientId");
  }
  throw new OAuthStoreFailure(UNAVAILABLE);
 }
 @NonNull OAuthAuthorizationResult completeResult(@NonNull String interaction, @NonNull String browserBinding,
   @NonNull Supplier<OAuthServerClientSelection.@NonNull Selected> selected,
   @NonNull Map<@NonNull String, @NonNull Set<@NonNull String>> resources,
   @NonNull OAuthAuthorizationDecision decision, @NonNull OAuthGrantPolicy policy,
   @NonNull OAuthAuthorizationResponseEncoder encoder, @NonNull Deadline deadline) {
  Completion completion = completePrepared(interaction, browserBinding, selected, resources, decision, requireNonNull(policy), requireNonNull(encoder), deadline);
  OAuthServerResponse response = requireNonNull(completion.response);
  return completion.code.isPresent() ? OAuthAuthorizationResult.fromCompleted(response) : OAuthAuthorizationResult.fromDenied(response);
 }
 private @NonNull Completion completePrepared(@NonNull String interaction, @NonNull String browserBinding,
   @NonNull Supplier<OAuthServerClientSelection.@NonNull Selected> selectClient,
   @NonNull Map<@NonNull String, @NonNull Set<@NonNull String>> currentServerResources,
   @NonNull OAuthAuthorizationDecision decision, @Nullable OAuthGrantPolicy policy, @Nullable OAuthAuthorizationResponseEncoder encoder, @NonNull Deadline deadline) {
  requireNonNull(decision);
  OAuthStoreKey key = interactionKey(interaction); String browserHash = OAuthAuthorizationRecord.credentialDigest(browserBinding);
  Map<String, Set<String>> resources = OAuthServerConfiguration.resources(currentServerResources, this.limits.resources);
  for (int attempt = 0; attempt < this.maximumAttempts; attempt++) {
   OAuthServerClientSelection.Selected selectedClient = selectClient.get();
   OAuthServerClientRegistration currentClient = selectedClient.client(); String fingerprint = selectedClient.fingerprint();
   OAuthStoreCoordinator.Session session = this.coordinator.begin(deadline);
   OAuthAuthorizationRecord record = checkedInteraction(session, key, browserHash, fingerprint);
   List<OAuthStoreTransaction.Mutation> changes = new ArrayList<>();
   changes.add(put(key, record.expires(), record.completed()));
   session.requireBefore(record.expires());
   Optional<String> code = Optional.empty();
   if (!decision.isDenied()) {
    String resource = record.text("resource"); Set<String> approved = decision.getAuthorizedScopesByResource().get(resource);
    if (decision.getAuthorizedScopesByResource().size() != 1 || approved == null) throw invalid();
    Set<String> requested = record.scopes(this.limits), server = resources.get(resource);
    if (server == null || !requested.containsAll(approved) || !server.containsAll(approved)) throw invalid();
    // An explicit empty scope decision consumes consent as denial; it cannot mint a zero-scope credential.
    if (!approved.isEmpty()) {
     String subject = decision.getSubject().orElseThrow(OAuthStoreFormat::invalid);
     OAuthServerConfiguration.text(subject, this.subjectLimit);
     OAuthStoreFence subjectFence = session.subject(subject);
     String credential = prepared(() -> OAuthServerCredential.code(this.codec.freshVersion())), codeId = OAuthServerCredential.codeDigest(credential);
     String grantId = prepared(this.codec::freshVersion);
     OAuthStoreKey codeKey = this.codec.key(OAuthStoreKey.Kind.CODE, codeId), grantKey = this.codec.key(OAuthStoreKey.Kind.GRANT, grantId);
     if (session.read(codeKey).isPresent() || session.read(grantKey).isPresent()) continue;
     Instant expires = prepared(() -> OAuthGrantRetention.expiry(session.effectiveNow(), this.codeLifetime));
     session.requireBefore(expires);
     boolean refresh = this.refreshEnabled && currentClient.isRefreshTokenPermitted() && decision.isRefreshTokenPermitted();
     if (policy != null) {
      OAuthGrantContext context = OAuthGrantContext.fromCheckedGrant(subject, record.text("clientId"), "authorization_code", grantId, Map.of(resource, approved), refresh);
      OAuthAuthorizationDecision current;
      try { current = policy.authorizeGrant(context, OAuthServerClientAdmission.remaining(deadline)); }
      catch (VirtualMachineError fatal) { throw fatal; }
      catch (Throwable failure) { if (failure instanceof InterruptedException) Thread.currentThread().interrupt(); throw OAuthServerClientAdmission.failure(OAuthServerAdmissionFailure.Reason.INFRASTRUCTURE); }
      OAuthServerClientAdmission.remaining(deadline);
      if (current == null) throw OAuthServerClientAdmission.failure(OAuthServerAdmissionFailure.Reason.INFRASTRUCTURE);
      if (current.isDenied()) approved = Set.of();
      else {
       Set<String> narrowed = current.getAuthorizedScopesByResource().get(resource);
       if (!current.getSubject().orElseThrow(OAuthStoreFormat::invalid).equals(subject)
         || current.getAuthorizedScopesByResource().size() != 1 || narrowed == null || !approved.containsAll(narrowed)
         || current.isRefreshTokenPermitted() && !refresh) throw OAuthServerClientAdmission.failure(OAuthServerAdmissionFailure.Reason.INFRASTRUCTURE);
       approved = narrowed; refresh = current.isRefreshTokenPermitted();
      }
     }
     if (approved.isEmpty()) {
      OAuthServerResponse denied = requireNonNull(encoder).prepare(record, null);
      if (session.commit(changes) == OAuthStoreCommitStatus.COMMITTED) return new Completion(Optional.empty(), denied);
      continue;
     }
     Set<String> finalApproved = approved; boolean finalRefresh = refresh;
     OAuthAuthorizationRecord codeRecord = prepared(() -> OAuthAuthorizationRecord.code(codeId, grantId, record,
       session.issuer(), subjectFence, expires, this.limits, this.subjectLimit));
     OAuthAuthorizationRecord grant = prepared(() -> OAuthAuthorizationRecord.grant(grantId, codeId, record, subject,
       finalApproved, finalRefresh, session.issuer(), subjectFence, expires, this.limits, this.subjectLimit));
     changes.add(put(codeKey, expires, codeRecord)); changes.add(put(grantKey, expires, grant)); code = Optional.of(credential);
    }
   }
   OAuthServerResponse response = encoder == null ? null : encoder.prepare(record, code.orElse(null));
   if (session.commit(changes) == OAuthStoreCommitStatus.COMMITTED) return new Completion(code, response);
  }
  throw new OAuthStoreFailure(UNAVAILABLE);
 }
 private static final class Completion {
  private final @NonNull Optional<@NonNull String> code;
  private final @Nullable OAuthServerResponse response;
  private Completion(@NonNull Optional<@NonNull String> code, @Nullable OAuthServerResponse response) { this.code = code; this.response = response; }
 }
 private @NonNull OAuthAuthorizationRecord checkedInteraction(OAuthStoreCoordinator.@NonNull Session session,
   @NonNull OAuthStoreKey key, @NonNull String browserHash, @Nullable String fingerprint) {
  OAuthStoreEntry entry = session.read(key).orElseThrow(OAuthAuthorizationLedger::invalid);
  if (!session.effectiveNow().isBefore(entry.getRetainUntil())) throw invalid();
  OAuthAuthorizationRecord record = prepared(() -> OAuthAuthorizationRecord.decode(key.getKind(), identifier(key),
   this.codec.open(entry, Clock.fixed(session.effectiveNow(), ZoneOffset.UTC)), this.limits, this.subjectLimit));
  if (!record.expires().equals(entry.getRetainUntil())) throw new OAuthStoreFailure(CORRUPT_STATE);
  if (!record.text("status").equals("PENDING") || !record.matchesIssuer(session.issuer())
    || !session.effectiveNow().isBefore(record.expires())
    || !OAuthAuthorizationRecord.equalDigest(record.text("browserHash"), browserHash)
    || fingerprint != null && !OAuthAuthorizationRecord.equalDigest(record.text("clientHash"), fingerprint)) throw invalid();
  return record;
 }
 private @NonNull OAuthStoreKey interactionKey(@NonNull String credential) {
  return this.codec.key(OAuthStoreKey.Kind.INTERACTION, OAuthAuthorizationRecord.credentialDigest(credential));
 }
 private static @NonNull String identifier(@NonNull OAuthStoreKey key) {
  String storage = key.getStorageKey(); return storage.substring(storage.lastIndexOf(':') + 1);
 }
 private OAuthStoreTransaction.@NonNull Mutation put(@NonNull OAuthStoreKey key, @NonNull Instant retention,
   @NonNull OAuthAuthorizationRecord record) {
  return prepared(() -> OAuthStoreTransaction.Mutation.fromPut(this.codec.seal(key, retention, record.toPayload())));
 }
 private static <T> @NonNull T prepared(@NonNull Supplier<@NonNull T> operation) {
  try { return operation.get(); }
  catch (VirtualMachineError fatal) { throw fatal; }
  catch (Throwable failure) { throw new OAuthStoreFailure(CORRUPT_STATE); }
 }
 private static @NonNull OAuthServerAdmissionFailure invalid() {
  return new OAuthServerAdmissionFailure(OAuthServerAdmissionFailure.Reason.INVALID_REQUEST);
 }
 @Override public @NonNull String toString() { return "OAuthAuthorizationLedger{<redacted>}"; }
}
