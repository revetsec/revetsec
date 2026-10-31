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
import com.revetsec.oauth.AccessTokenValidationException;
import com.revetsec.internal.jose.JwtValidationAccess;
import com.revetsec.jose.JoseException;
import com.revetsec.jose.JwsAlgorithm;
import com.revetsec.jose.Jwt;
import com.revetsec.jose.JwtValidator;
import com.revetsec.jose.StaticJwksSource;
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
import java.util.function.BiFunction;
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
   @NonNull StaticJwksSource keys, @NonNull Deadline deadline) {
  return validate(compact, resource, keys, deadline, Function.identity());
 }
 /** Fresh checked public snapshot before the existing uncached atomic issuer-status admission. */
 @NonNull JsonObject validate(@NonNull String compact,@NonNull String resource,
   @NonNull OAuthIssuerKeyLifecycle keys,@NonNull Deadline deadline) {
  return validate(compact,resource,keys,deadline,Function.identity(),()->{});
 }
 /** Prepare the complete internal response before the authoritative status admission. */
 <T> @NonNull T validate(@NonNull String compact, @NonNull String resource,
   @NonNull StaticJwksSource keys, @NonNull Deadline deadline, @NonNull Function<@NonNull JsonObject, @NonNull T> prepare) {
  return validatePrepared(compact,resource,keys,deadline,(claims,authorityClock)->prepare.apply(claims));
 }
 <T> @NonNull T validatePrepared(@NonNull String compact,@NonNull String resource,
   @NonNull StaticJwksSource keys,@NonNull Deadline deadline,
   @NonNull BiFunction<@NonNull JsonObject,@NonNull Clock,@NonNull T> prepare){
  return validatePrepared(compact,resource,keys,deadline,prepare,null,()->{});
 }
 <T> @NonNull T validate(@NonNull String compact,@NonNull String resource,@NonNull OAuthIssuerKeyLifecycle keys,
   @NonNull Deadline deadline,@NonNull Function<@NonNull JsonObject,@NonNull T> prepare,@NonNull Runnable beforeAttempt){
  beforeAttempt.run();
  return validatePrepared(compact,resource,keys.recognitionKeys(deadline),deadline,(claims,authorityClock)->prepare.apply(claims),keys,beforeAttempt);
 }
 private <T> @NonNull T validatePrepared(@NonNull String compact,@NonNull String resource,
   @NonNull StaticJwksSource keys,@NonNull Deadline deadline,
   @NonNull BiFunction<@NonNull JsonObject,@NonNull Clock,@NonNull T> prepare,
   @Nullable OAuthIssuerKeyLifecycle lifecycle,@NonNull Runnable beforeAttempt){
  requireNonNull(prepare); requireNonNull(resource);
  JsonObject claims = verify(compact, resource, keys, deadline);
  String jti = claimString(claims, "jti").orElseThrow(OAuthIssuerTokenStatus::invalid);
  // Every conflict starts a new authoritative read set while preserving the original operation budget.
  for (int attempt = 0; attempt < this.attempts; attempt++) {
   if(attempt>0)beforeAttempt.run();
   OAuthStoreCoordinator.Session session = this.coordinator.begin(deadline);
   session.expiresAs(OAuthServerException.Reason.TOKEN_REVOKED);
   if(lifecycle!=null){JsonObject current=verify(compact,resource,lifecycle.verificationKeys(deadline,session::authorityNow),deadline);
    if(!current.toJson().equals(claims.toJson()))throw invalid();
   }
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
   T response = valid ? requireNonNull(prepare.apply(claims,Clock.fixed(session.effectiveNow(),ZoneOffset.UTC))) : null;
   if (valid) session.requireBefore(lastAdmission);
   if (session.barrier() == OAuthStoreCommitStatus.COMMITTED) { if (!valid) throw invalid(); return requireNonNull(response); }
  }
  throw new OAuthStoreFailure(UNAVAILABLE);
 }
 /** Signature/profile failures keep their fixed M5 diagnostics without constructing a worker-time proof. */
 @NonNull JsonObject recognizeForProof(@NonNull String compact,@NonNull String resource,
   @NonNull StaticJwksSource keys,@NonNull Deadline deadline){
  try{return verify(compact,resource,keys,deadline,true);}
  catch(OAuthServerAdmissionFailure failure){if(failure.reason()!=OAuthServerAdmissionFailure.Reason.INVALID_TOKEN)throw failure;
   throw new RecognitionFailure(null);
  }
 }
 /** Actual M5 proof preparation follows a healthy root observation and precedes the complete fact join. */
 @NonNull OAuthIssuerAccessTokenResult validateProof(@NonNull JsonObject claims,@NonNull String resource,
   @NonNull Deadline deadline,@NonNull Function<OAuthStoreCoordinator.@NonNull Session,@NonNull OAuthIssuerAccessTokenResult> prepare){
  String jti=claimString(claims,"jti").orElseThrow(OAuthIssuerTokenStatus::invalid);
  for(int attempt=0;attempt<this.attempts;attempt++){
   OAuthStoreCoordinator.Session session=this.coordinator.begin(deadline);session.expiresAs(OAuthServerException.Reason.TOKEN_REVOKED);
   OAuthIssuerAccessTokenResult proof=requireNonNull(prepare.apply(session));
   if(proof instanceof OAuthIssuerAccessTokenResult.Rejected)return proof;
   OAuthAuthorizationRecord access=read(session,this.codec.key(OAuthStoreKey.Kind.ACCESS_TOKEN,jti));
   if(access==null){if(session.barrier()==OAuthStoreCommitStatus.COMMITTED)return OAuthIssuerAccessTokenResult.fromRejection(OAuthServerException.Reason.TOKEN_REVOKED,null,null);continue;}
   OAuthAuthorizationRecord grant=read(session,this.codec.key(OAuthStoreKey.Kind.GRANT,access.text("grantId")));
   if(grant==null){if(session.barrier()==OAuthStoreCommitStatus.COMMITTED)return OAuthIssuerAccessTokenResult.fromRejection(OAuthServerException.Reason.TOKEN_REVOKED,null,null);continue;}
   OAuthStoreFence subject=session.subject(access.text("subject"));checkAccessGrant(access,grant);
   Instant upper=prepared(()->access.expires().plus(this.skew));
   boolean valid=grant.text("status").equals("ACTIVE") && access.matchesIssuer(session.issuer()) && access.matchesSubject(subject)
     && session.effectiveNow().isBefore(upper) && !session.effectiveNow().isBefore(prepared(()->Instant.ofEpochSecond(access.number("issued")).minus(this.skew)))
     && matches(claims,access,resource);
   if(valid)session.requireBefore(upper);
   if(session.barrier()==OAuthStoreCommitStatus.COMMITTED)return valid?proof:OAuthIssuerAccessTokenResult.fromRejection(OAuthServerException.Reason.TOKEN_REVOKED,null,null);
  }
  throw new OAuthStoreFailure(UNAVAILABLE);
 }
 /** Fixed diagnostic only, with no token, claims, external message or cause. */
 static final class RecognitionFailure extends RuntimeException {
  private static final long serialVersionUID=1L;
  private final JoseException.@Nullable Reason joseReason;
  private RecognitionFailure(JoseException.@Nullable Reason reason){super("The issuer access token was rejected.",null,false,false);this.joseReason=reason;}
  @NonNull OAuthIssuerAccessTokenResult result(){return OAuthIssuerAccessTokenResult.fromRejection(OAuthServerException.Reason.TOKEN_REVOKED,AccessTokenValidationException.Reason.JWT_REJECTED,this.joseReason);}
 }
 /** Signature and exact profile recognition only; never an admission proof. */
 @NonNull JsonObject retainedClaims(@NonNull String compact, @NonNull StaticJwksSource keys, @NonNull Deadline deadline) {
  return verify(compact, null, keys, deadline);
 }
 private @NonNull JsonObject verify(@NonNull String compact, @Nullable String resource,
   @NonNull StaticJwksSource keys, @NonNull Deadline deadline) {
  return verify(compact,resource,keys,deadline,false);
 }
 private @NonNull JsonObject verify(@NonNull String compact,@Nullable String resource,
   @NonNull StaticJwksSource keys,@NonNull Deadline deadline,boolean diagnostics){
  requireNonNull(compact); requireNonNull(keys);
  if(compact.length()>this.tokenLimit){if(diagnostics)throw new RecognitionFailure(JoseException.Reason.TOKEN_TOO_LARGE);throw invalid();}
  if (resource != null) OAuthServerConfiguration.resources(java.util.Map.of(resource, Set.of()), 1);
  OAuthServerClientAdmission.remaining(deadline);
  // Fixed local key snapshot: no discovery, remote key source, positive token-status cache or caller claim override.
  JwtValidator.Builder builder = JwtValidator.withIssuer(this.codec.issuer()).jwksSource(keys);
  builder = resource == null ? builder.acceptAnyAudience(true) : builder.expectedAudiences(Set.of(resource));
  JwtValidator validator = builder
   .allowedAlgorithms(Set.of(JwsAlgorithm.RS256)).allowedTypes(Set.of("at+jwt")).typeRequired(true).requiredClaims(CLAIMS)
   .clockSkew(this.skew).clock(this.clock).maximumTokenLength(Math.max(8192,this.tokenLimit)).build();
  Jwt jwt;
  try { jwt = JwtValidationAccess.get().validateIssuerRevocation(validator, compact, deadline::remainingNanos); }
  catch (JoseException rejection) { OAuthServerClientAdmission.remaining(deadline);if(diagnostics)throw new RecognitionFailure(rejection.getReason());throw invalid(); }
  catch(IllegalArgumentException rejection){OAuthServerClientAdmission.remaining(deadline);if(diagnostics)throw new RecognitionFailure(JoseException.Reason.TOKEN_SYNTAX);throw invalid();}
  catch (VirtualMachineError fatal) { throw fatal; }
  catch (Throwable fault) { if (fault instanceof InterruptedException) Thread.currentThread().interrupt(); throw new OAuthStoreFailure(UNAVAILABLE); }
  OAuthServerClientAdmission.remaining(deadline);
  JsonObject claims = jwt.getClaims().toJsonObject();
  if (!claims.getMembers().keySet().equals(CLAIMS) || jwt.getKeyId().isEmpty()
    || claimString(claims, "aud").isEmpty() || resource != null && !resource.equals(claimString(claims, "aud").orElse(null))) throw invalid();
  String jti = claimString(claims, "jti").orElseThrow(OAuthIssuerTokenStatus::invalid);
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
  return resource.equals(access.text("resource")) && resource.equals(claimString(claims, "aud").orElse(null)) && this.codec.issuer().equals(claimString(claims, "iss").orElse(null))
   && access.text("subject").equals(claimString(claims, "sub").orElse(null))
   && access.text("clientId").equals(claimString(claims, "client_id").orElse(null))
   && claimLong(claims, "iat").orElse(Long.MIN_VALUE) == access.number("issued")
   && claimLong(claims, "exp").orElse(Long.MIN_VALUE) == access.expires().getEpochSecond()
   && String.join(" ", access.scopes(this.limits).stream().sorted().toList()).equals(claimString(claims, "scope").orElse(null));
 }
 @Nullable OAuthAuthorizationRecord read(OAuthStoreCoordinator.@NonNull Session session, @NonNull OAuthStoreKey key) {
  Optional<OAuthStoreEntry> observed = session.read(key);
  if (observed.isEmpty()) return null;
  OAuthStoreEntry entry = observed.orElseThrow();
  if (!session.effectiveNow().isBefore(entry.getRetainUntil())) return null;
  String raw = key.getStorageKey(), id = raw.substring(raw.lastIndexOf(':') + 1);
  OAuthAuthorizationRecord record = prepared(() -> OAuthAuthorizationRecord.decode(key.getKind(), id,
   session.open(entry), this.limits, this.subjectLimit));
  if (!record.retention().equals(entry.getRetainUntil())) throw new OAuthStoreFailure(CORRUPT_STATE);
  return record;
 }
 private static <T> @NonNull T prepared(@NonNull Supplier<@NonNull T> work) {
  try { return work.get(); } catch (VirtualMachineError fatal) { throw fatal; } catch (Throwable fault) { OAuthStoreCoordinator.preserveInterrupt(fault);throw new OAuthStoreFailure(CORRUPT_STATE); }
 }
 private static @NonNull Optional<@NonNull String> claimString(@NonNull JsonObject claims, @NonNull String name) {
  return claims.find(name).map(value -> {
   if (!(value instanceof com.revetsec.json.JsonString text)) throw invalid();
   return text.getValue();
  });
 }
 private static @NonNull Optional<@NonNull Long> claimLong(@NonNull JsonObject claims, @NonNull String name) {
  return claims.find(name).flatMap(value -> {
   if (!(value instanceof com.revetsec.json.JsonNumber number)) throw invalid();
   return number.getLongValueExact();
  });
 }
 private static @NonNull OAuthServerAdmissionFailure invalid() {
  return OAuthServerClientAdmission.failure(OAuthServerAdmissionFailure.Reason.INVALID_TOKEN);
 }
 @Override public @NonNull String toString() { return "OAuthIssuerTokenStatus{<redacted>}"; }
}
