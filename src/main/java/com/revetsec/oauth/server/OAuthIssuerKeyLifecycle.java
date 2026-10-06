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
import com.revetsec.jose.JsonWebKeySet;
import com.revetsec.jose.StaticJsonWebKeySource;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.ReentrantLock;
import static java.util.Objects.requireNonNull;

/** Observed consistency guard, not a durable key history or proof of external publication. No positive token cache. */
final class OAuthIssuerKeyLifecycle {
 private final @NonNull OAuthIssuerKeyProvider provider;
 private final boolean publicBoundary;
 private final @NonNull Clock clock;
 private final @NonNull Duration freshness;
 private final @NonNull OAuthGrantRetention retention;
 private final @NonNull ReentrantLock lock=new ReentrantLock();
 private final @NonNull Map<@NonNull String,@NonNull Instant> reserved=new HashMap<>();
 private @Nullable OAuthIssuerKeySnapshot previous;
 private @Nullable Instant lastNow;
 OAuthIssuerKeyLifecycle(@NonNull OAuthIssuerKeyProvider provider,@NonNull Clock clock,@NonNull Duration freshness,
   @NonNull OAuthGrantRetention retention) {
  this(provider,clock,freshness,retention,false);
 }
 OAuthIssuerKeyLifecycle(@NonNull OAuthIssuerKeyProvider provider,@NonNull Clock clock,@NonNull Duration freshness,
   @NonNull OAuthGrantRetention retention,boolean publicBoundary) {
  this.publicBoundary=publicBoundary;
  this.provider=requireNonNull(provider);this.clock=requireNonNull(clock);
  this.freshness=OAuthGrantRetention.duration(freshness,Duration.ZERO,Duration.ofMinutes(5));this.retention=requireNonNull(retention);
 }
 @NonNull OAuthIssuerKeySnapshot snapshot(@NonNull Deadline deadline) { return checked(deadline,null); }
 private @NonNull OAuthIssuerKeySnapshot checked(@NonNull Deadline deadline,@Nullable Instant expiry) {
  // Trusted callback and clock execute outside the consistency lock, never inside a backend transaction.
  try {
   OAuthIssuerKeySnapshot next=requireNonNull(this.provider.getSnapshot(OAuthServerClientAdmission.remaining(deadline)));
   OAuthServerClientAdmission.remaining(deadline);Instant now=requireNonNull(this.clock.instant());
   if(!this.lock.tryLock(OAuthServerClientAdmission.remaining(deadline).toNanos(),TimeUnit.NANOSECONDS)) throw unavailable();
   try {
    OAuthServerClientAdmission.remaining(deadline);
    if(next.getPublishedAt().isAfter(now) || (this.lastNow!=null && now.isBefore(this.lastNow))) throw unavailable();
    OAuthIssuerKeySnapshot old=this.previous;
    if(old!=null) {
     boolean same=old.getGeneration().equals(next.getGeneration());
     if(same ? !facts(old).equals(facts(next)) : !next.getPublishedAt().isAfter(old.getPublishedAt())) throw unavailable();
     for(String id:old.getVerificationKeys().keySet()) {
      if(next.getVerificationKeys().containsKey(id)) {
       if(!OAuthIssuerPublicKeys.material(requireNonNull(old.getVerificationKeys().get(id))).equals(
         OAuthIssuerPublicKeys.material(requireNonNull(next.getVerificationKeys().get(id))))) throw unavailable();
       Instant boundary=old.getRetirementNotBefore().get(id), replacement=next.getRetirementNotBefore().get(id);
       if(boundary!=null && replacement!=null && replacement.isBefore(boundary)) throw unavailable();
      } else {
       Instant boundary=old.getRetirementNotBefore().get(id), required=this.reserved.get(id);
       if(boundary==null || now.isBefore(boundary) || (required!=null && now.isBefore(required))) throw unavailable();
      }
     }
    }
    for(Map.Entry<String,Instant> reservation:this.reserved.entrySet()) {
     Instant boundary=next.getRetirementNotBefore().get(reservation.getKey());
     if(next.getVerificationKeys().containsKey(reservation.getKey()) && boundary!=null && boundary.isBefore(reservation.getValue())) throw unavailable();
    }
    String active=next.getActiveKey().getKeyId();
    Instant retirement=next.getRetirementNotBefore().get(active);
    if(retirement!=null && !now.isBefore(retirement)) throw unavailable();
    if(expiry!=null) {
     if(now.isBefore(next.getPublishedAt().plus(this.freshness)) || !expiry.isAfter(now)) throw unavailable();
     Instant required=this.retention.accessRetention(expiry);
     if(retirement!=null && retirement.isBefore(required)) throw unavailable();
     this.reserved.merge(active,required,(a,b)->a.isAfter(b)?a:b);
    }
    this.reserved.keySet().retainAll(next.getVerificationKeys().keySet());
    this.previous=next;this.lastNow=now;return next;
   } finally { this.lock.unlock(); }
  } catch(VirtualMachineError fatal) { throw fatal; }
  catch(Throwable fault) { if(fault instanceof InterruptedException) Thread.currentThread().interrupt();throw unavailable(); }
 }
 private static @NonNull JsonObject facts(@NonNull OAuthIssuerKeySnapshot snapshot) {
  JsonObject.Builder retirement=JsonObject.builder();
  for(String id:snapshot.getRetirementNotBefore().keySet().stream().sorted().toList())
   retirement.put(id,requireNonNull(snapshot.getRetirementNotBefore().get(id)).toString());
  return JsonObject.builder().put("publishedAt",snapshot.getPublishedAt().toString())
   .put("active",snapshot.getActiveKey().getKeyId()).put("keys",OAuthIssuerPublicKeys.jwks(snapshot.getVerificationKeys()))
   .put("retirement",retirement.build()).build();
 }
 @NonNull String sign(byte @NonNull [] claims,@NonNull Instant expiry,@NonNull Deadline deadline) {
  OAuthIssuerKeySnapshot selected=checked(deadline,expiry);
  try {
   String result=selected.getActiveKey().signer().toCompactSerialization("at+jwt",selected.getActiveKey().getKeyId(),null,
    claims,OAuthServerClientAdmission.remaining(deadline));
   // Recheck rotation after provider signing and before a caller can prepare/commit an issuance response.
   OAuthIssuerKeySnapshot after=snapshot(deadline);String id=selected.getActiveKey().getKeyId();
   if(!after.getVerificationKeys().containsKey(id) || !OAuthIssuerPublicKeys.material(requireNonNull(after.getVerificationKeys().get(id)))
     .equals(OAuthIssuerPublicKeys.material(selected.getActiveKey().getPublicKey()))) throw unavailable();
   Instant boundary=after.getRetirementNotBefore().get(id);
   if(boundary!=null && boundary.isBefore(this.retention.accessRetention(expiry))) throw unavailable();
   OAuthServerClientAdmission.remaining(deadline);return result;
  } catch(VirtualMachineError fatal) { throw fatal; }
  catch(Throwable fault) { if(fault instanceof InterruptedException) Thread.currentThread().interrupt();throw signingFailure(); }
 }
 void warmUp(@NonNull Deadline deadline) {
  OAuthIssuerKeySnapshot selected=snapshot(deadline);
  try { selected.getActiveKey().signer().warmUp(OAuthServerClientAdmission.remaining(deadline));snapshot(deadline); }
  catch(VirtualMachineError fatal) { throw fatal; }
  catch(Throwable fault) { if(fault instanceof InterruptedException) Thread.currentThread().interrupt();throw signingFailure(); }
 }
 @NonNull StaticJsonWebKeySource verificationKeys(@NonNull Deadline deadline) {
  OAuthIssuerKeySnapshot keys=snapshot(deadline);
  StaticJsonWebKeySource result=StaticJsonWebKeySource.fromJsonWebKeySet(JsonWebKeySet.fromJson(OAuthIssuerPublicKeys.jwks(keys.getVerificationKeys()).toJson()));
  OAuthServerClientAdmission.remaining(deadline);return result;
 }
 private @NonNull RuntimeException signingFailure() {
  return this.publicBoundary ? OAuthServerSigningException.fromReason(OAuthServerException.Reason.SIGNING_FAILED) : unavailable();
 }
 private static @NonNull OAuthServerAdmissionFailure unavailable() {
  return new OAuthServerAdmissionFailure(OAuthServerAdmissionFailure.Reason.INFRASTRUCTURE);
 }
 @Override public @NonNull String toString() { return "OAuthIssuerKeyLifecycle{<redacted>}"; }
}
