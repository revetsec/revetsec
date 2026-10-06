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
import com.revetsec.internal.jose.JwtValidationAccess;
import com.revetsec.jose.JoseException;
import com.revetsec.jose.JwsAlgorithm;
import com.revetsec.jose.Jwt;
import com.revetsec.jose.JwtValidator;
import com.revetsec.jose.StaticJsonWebKeySource;
import com.revetsec.json.JsonObject;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Optional;
import java.util.Set;
import java.util.function.Supplier;
import java.util.function.Function;
import static java.util.Objects.requireNonNull;
import static com.revetsec.oauth.server.OAuthStoreFailure.Reason.*;

/** Internal issuer status admission. Successful sequential reads never substitute for the atomic barrier. */
final class OAuthIssuerTokenStatus {
 private static final @NonNull Set<@NonNull String> CLAIMS = Set.of("iss", "sub", "aud", "client_id", "iat", "exp", "jti", "scope");
 private final @NonNull OAuthStoreCoordinator coordinator;
 private final @NonNull OAuthStoreRecordCodec codec;
 private final @NonNull OAuthServerIngressLimits limits;
 private final @NonNull Clock clock;
 private final @NonNull Duration skew;
 private final int attempts, subjectLimit, tokenLimit;
 OAuthIssuerTokenStatus(@NonNull OAuthStoreCoordinator coordinator, @NonNull OAuthStoreRecordCodec codec,
   @NonNull OAuthServerIngressLimits limits, @NonNull Clock clock, @NonNull Duration skew,
   int attempts, int subjectLimit, int tokenLimit) {
  this.coordinator = requireNonNull(coordinator); this.codec = requireNonNull(codec); this.limits = requireNonNull(limits);
  this.clock = requireNonNull(clock); this.skew = OAuthGrantRetention.duration(skew, Duration.ZERO, Duration.ofSeconds(60));
  if (attempts < 1 || attempts > 8 || subjectLimit < 16 || subjectLimit > 1024 || tokenLimit < 1024 || tokenLimit > 65536)
   throw OAuthStoreFormat.invalid();
  this.attempts = attempts; this.subjectLimit = subjectLimit; this.tokenLimit = tokenLimit;
 }
 /** Returns immutable checked claims only after COMMITTED; never returns/retains the received credential. */
 @NonNull JsonObject validate(@NonNull String compact, @NonNull String resource,
   @NonNull StaticJsonWebKeySource keys, @NonNull Deadline deadline) {
  return validate(compact, resource, keys, deadline, Function.identity());
 }
 /** Fresh checked public snapshot before the existing uncached atomic issuer-status admission. */
 @NonNull JsonObject validate(@NonNull String compact,@NonNull String resource,
   @NonNull OAuthIssuerKeyLifecycle keys,@NonNull Deadline deadline) {
  return validate(compact,resource,keys.verificationKeys(deadline),deadline);
 }
 /** Prepare the complete internal response before the authoritative status admission. */
 <T> @NonNull T validate(@NonNull String compact, @NonNull String resource,
   @NonNull StaticJsonWebKeySource keys, @NonNull Deadline deadline, @NonNull Function<@NonNull JsonObject, @NonNull T> prepare) {
  requireNonNull(prepare); requireNonNull(resource);
  JsonObject claims = verify(compact, resource, keys, deadline, false);
  String jti = claims.findString("jti").orElseThrow(OAuthIssuerTokenStatus::invalid);
  // Every conflict starts a new authoritative read set while preserving the original operation budget.
  for (int attempt = 0; attempt < this.attempts; attempt++) {
   OAuthStoreCoordinator.Session session = this.coordinator.begin(deadline);
   OAuthAuthorizationRecord access = read(session, this.codec.key(OAuthStoreKey.Kind.ACCESS_TOKEN, jti));
   if (access == null) { if (session.barrier() == OAuthStoreCommitStatus.COMMITTED) throw invalid(); else continue; }
   OAuthAuthorizationRecord grant = read(session, this.codec.key(OAuthStoreKey.Kind.GRANT, access.text("grantId")));
   if (grant == null) { if (session.barrier() == OAuthStoreCommitStatus.COMMITTED) throw invalid(); else continue; }
   OAuthStoreFence subject = session.subject(access.text("subject"));
   checkAccessGrant(access, grant);
   Instant lastAdmission = prepared(() -> access.expires().plus(this.skew));
   Instant earliestAdmission = prepared(() -> Instant.ofEpochSecond(access.number("issued")).minus(this.skew));
   String state = grant.text("status");
   boolean valid = state.equals("ACTIVE") && access.matchesIssuer(session.issuer()) && access.matchesSubject(subject)
     && session.effectiveNow().isBefore(lastAdmission) && !session.effectiveNow().isBefore(earliestAdmission)
     && matches(claims, access, resource);
   T response = valid ? requireNonNull(prepare.apply(claims)) : null;
   if (valid) session.requireBefore(lastAdmission);
   if (session.barrier() == OAuthStoreCommitStatus.COMMITTED) { if (!valid) throw invalid(); return requireNonNull(response); }
  }
  throw new OAuthStoreFailure(UNAVAILABLE);
 }
 /** Signature and exact profile recognition only; never an admission proof. */
 @NonNull JsonObject retainedClaims(@NonNull String compact, @NonNull StaticJsonWebKeySource keys, @NonNull Deadline deadline) {
  return verify(compact, null, keys, deadline, true);
 }
 private @NonNull JsonObject verify(@NonNull String compact, @Nullable String resource,
   @NonNull StaticJsonWebKeySource keys, @NonNull Deadline deadline, boolean retained) {
  requireNonNull(compact); requireNonNull(keys);
  if (resource != null) OAuthServerConfiguration.resources(java.util.Map.of(resource, Set.of()), 1);
  OAuthServerClientAdmission.remaining(deadline);
  // Fixed local key snapshot: no discovery, remote key source, positive token-status cache or caller claim override.
  JwtValidator.Builder builder = JwtValidator.withIssuer(this.codec.issuer()).jsonWebKeySource(keys);
  builder = resource == null ? builder.acceptAnyAudience(true) : builder.expectedAudiences(Set.of(resource));
  JwtValidator validator = builder
   .allowedAlgorithms(Set.of(JwsAlgorithm.RS256)).allowedTypes(Set.of("at+jwt")).typeRequired(true).requiredClaims(CLAIMS)
   .clockSkew(this.skew).clock(this.clock).maximumTokenLength(this.tokenLimit).build();
  Jwt jwt;
  try { jwt = retained ? JwtValidationAccess.get().validateIssuerRevocation(validator, compact, deadline::remainingNanos)
    : JwtValidationAccess.get().validate(validator, compact, deadline::remainingNanos); }
  catch (JoseException rejection) { OAuthServerClientAdmission.remaining(deadline); throw invalid(); }
  catch (VirtualMachineError fatal) { throw fatal; }
  catch (Throwable fault) { if (fault instanceof InterruptedException) Thread.currentThread().interrupt(); throw new OAuthStoreFailure(UNAVAILABLE); }
  OAuthServerClientAdmission.remaining(deadline);
  JsonObject claims = jwt.getClaims().toJsonObject();
  if (!claims.getMembers().keySet().equals(CLAIMS) || jwt.getKeyId().isEmpty()
    || claims.findString("aud").isEmpty() || resource != null && !resource.equals(claims.findString("aud").orElse(null))) throw invalid();
  String jti = claims.findString("jti").orElseThrow(OAuthIssuerTokenStatus::invalid);
  try { OAuthStoreFormat.nonce(jti); } catch (IllegalArgumentException rejection) { throw invalid(); }
  return claims;
 }
 /** Authenticated contradictory storage must never be translated into an ordinary inactive response. */
 void checkAccessGrant(@NonNull OAuthAuthorizationRecord access, @NonNull OAuthAuthorizationRecord grant) {
  if (!access.sameLineage(grant) || !access.text("subject").equals(grant.text("subject"))
    || !access.text("clientId").equals(grant.text("clientId")) || !access.text("resource").equals(grant.text("resource"))
    || !grant.scopes(this.limits).containsAll(access.scopes(this.limits))) throw new OAuthStoreFailure(CORRUPT_STATE);
  String state = grant.text("status");
  if (!state.equals("ACTIVE") && !state.equals("REVOKED")) throw new OAuthStoreFailure(CORRUPT_STATE);
  Instant issued = prepared(() -> Instant.ofEpochSecond(access.number("issued")));
  if (access.expires().isAfter(prepared(() -> issued.plus(grant.maximumAccessLifetime())))
    || access.expires().isAfter(prepared(() -> grant.expires().plus(grant.maximumAccessLifetime())))
    || access.retention().isAfter(grant.horizon())
    || access.retention().isBefore(prepared(() -> access.expires().plus(this.skew)))) throw new OAuthStoreFailure(CORRUPT_STATE);
 }
 boolean matches(@NonNull JsonObject claims, @NonNull OAuthAuthorizationRecord access, @NonNull String resource) {
  return resource.equals(access.text("resource")) && resource.equals(claims.findString("aud").orElse(null)) && this.codec.issuer().equals(claims.findString("iss").orElse(null))
   && access.text("subject").equals(claims.findString("sub").orElse(null))
   && access.text("clientId").equals(claims.findString("client_id").orElse(null))
   && claims.findLong("iat").orElse(Long.MIN_VALUE) == access.number("issued")
   && claims.findLong("exp").orElse(Long.MIN_VALUE) == access.expires().getEpochSecond()
   && String.join(" ", access.scopes(this.limits).stream().sorted().toList()).equals(claims.findString("scope").orElse(null));
 }
 @Nullable OAuthAuthorizationRecord read(OAuthStoreCoordinator.@NonNull Session session, @NonNull OAuthStoreKey key) {
  Optional<OAuthStoreEntry> observed = session.read(key);
  if (observed.isEmpty()) return null;
  OAuthStoreEntry entry = observed.orElseThrow();
  if (!session.effectiveNow().isBefore(entry.getRetainUntil())) return null;
  String raw = key.getStorageKey(), id = raw.substring(raw.lastIndexOf(':') + 1);
  OAuthAuthorizationRecord record = prepared(() -> OAuthAuthorizationRecord.decode(key.getKind(), id,
   this.codec.open(entry, Clock.fixed(session.effectiveNow(), ZoneOffset.UTC)), this.limits, this.subjectLimit));
  if (!record.retention().equals(entry.getRetainUntil())) throw new OAuthStoreFailure(CORRUPT_STATE);
  return record;
 }
 private static <T> @NonNull T prepared(@NonNull Supplier<@NonNull T> work) {
  try { return work.get(); } catch (VirtualMachineError fatal) { throw fatal; } catch (Throwable fault) { throw new OAuthStoreFailure(CORRUPT_STATE); }
 }
 private static @NonNull OAuthServerAdmissionFailure invalid() {
  return OAuthServerClientAdmission.failure(OAuthServerAdmissionFailure.Reason.INVALID_TOKEN);
 }
 @Override public @NonNull String toString() { return "OAuthIssuerTokenStatus{<redacted>}"; }
}
