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
import com.revetsec.jose.Jwks;
import com.revetsec.jose.JwksParseResult;
import com.revetsec.jose.StaticJwksSource;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Supplier;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.ReentrantLock;
import static java.util.Objects.requireNonNull;

/**
 * Observed consistency guard, not a durable key history or proof of external publication. New active keys must
 * already have been published for the public metadata HTTP cache max-age. No positive token cache.
 */
final class OAuthIssuerKeyLifecycle {
 private final @NonNull OAuthIssuerKeyProvider provider;
 private final boolean publicBoundary;
 private final @NonNull Clock clock;
 private final @NonNull Duration publicMetadataHttpCacheMaxAge;
 private final @NonNull OAuthGrantRetention retention;
 private final @NonNull ReentrantLock lock=new ReentrantLock();
 private final @NonNull History provisional=new History();
 private final @NonNull History admitted=new History();
 /** Provider facts are checked within one temporal domain; worker observations never mutate authority history. */
 private static final class History {
  private final @NonNull Map<@NonNull String,@NonNull Instant> reserved=new HashMap<>();
  private final @NonNull Map<@NonNull String,@NonNull Instant> firstPublished=new HashMap<>();
  private @Nullable OAuthIssuerKeySnapshot previous;
  private @Nullable Instant lastNow;
 }
 OAuthIssuerKeyLifecycle(@NonNull OAuthIssuerKeyProvider provider,@NonNull Clock clock,@NonNull Duration publicMetadataHttpCacheMaxAge,
   @NonNull OAuthGrantRetention retention) {
  this(provider,clock,publicMetadataHttpCacheMaxAge,retention,false);
 }
 OAuthIssuerKeyLifecycle(@NonNull OAuthIssuerKeyProvider provider,@NonNull Clock clock,@NonNull Duration publicMetadataHttpCacheMaxAge,
   @NonNull OAuthGrantRetention retention,boolean publicBoundary) {
  this.publicBoundary=publicBoundary;
  this.provider=requireNonNull(provider);this.clock=requireNonNull(clock);
  this.publicMetadataHttpCacheMaxAge=OAuthGrantRetention.duration(publicMetadataHttpCacheMaxAge,Duration.ZERO,Duration.ofMinutes(5));this.retention=requireNonNull(retention);
 }
 @NonNull OAuthIssuerKeySnapshot snapshot(@NonNull Deadline deadline) { return checked(deadline,null); }
 private @NonNull OAuthIssuerKeySnapshot checked(@NonNull Deadline deadline,@Nullable Instant expiry) {
  return checked(deadline,expiry,this.clock::instant,this.provisional);
 }
 private @NonNull OAuthIssuerKeySnapshot checked(@NonNull Deadline deadline,@Nullable Instant expiry,
   @NonNull Supplier<@NonNull Instant> authorityTime,@NonNull History history) {
  // The provider callback runs outside the consistency lock; sample the clock after acquiring it.
  try {
   OAuthIssuerKeySnapshot next=requireNonNull(this.provider.getSnapshot(OAuthServerClientAdmission.remaining(deadline)));
   OAuthServerClientAdmission.remaining(deadline);
   if(!this.lock.tryLock(OAuthServerClientAdmission.remaining(deadline).toNanos(),TimeUnit.NANOSECONDS)) throw unavailable();
   try {
    OAuthServerClientAdmission.remaining(deadline);
    Instant now=requireNonNull(authorityTime.get());
    if(next.getPublishedAt().isAfter(now) || (history.lastNow!=null && now.isBefore(history.lastNow))) throw unavailable();
    OAuthIssuerKeySnapshot old=history.previous;
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
       Instant boundary=old.getRetirementNotBefore().get(id), required=history.reserved.get(id);
       if(boundary==null || now.isBefore(boundary) || (required!=null && now.isBefore(required))) throw unavailable();
      }
     }
    }
    for(Map.Entry<String,Instant> reservation:history.reserved.entrySet()) {
     Instant boundary=next.getRetirementNotBefore().get(reservation.getKey());
     if(next.getVerificationKeys().containsKey(reservation.getKey()) && boundary!=null && boundary.isBefore(reservation.getValue())) throw unavailable();
    }
    String active=next.getActiveKey().getKeyId();
    Instant retirement=next.getRetirementNotBefore().get(active);
    if(retirement!=null && !now.isBefore(retirement)) throw unavailable();
    Map<String,Instant> publication=new HashMap<>();
    for(String id:next.getVerificationKeys().keySet()) {
     Instant first=old!=null && old.getVerificationKeys().containsKey(id)
      ? history.firstPublished.getOrDefault(id,old.getPublishedAt()) : next.getPublishedAt();
     publication.put(id,first);
    }
    if(expiry!=null) {
     if(now.isBefore(requireNonNull(publication.get(active)).plus(this.publicMetadataHttpCacheMaxAge)) || !expiry.isAfter(now)) throw unavailable();
     Instant required=this.retention.accessRetention(expiry);
     if(retirement!=null && retirement.isBefore(required)) throw unavailable();
     history.reserved.merge(active,required,(a,b)->a.isAfter(b)?a:b);
    }
    history.reserved.keySet().retainAll(next.getVerificationKeys().keySet());
    history.firstPublished.clear();history.firstPublished.putAll(publication);
    history.previous=next;history.lastNow=now;return next;
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
  return sign(claims,expiry,deadline,this.clock::instant,this.provisional);
 }
 @NonNull String sign(byte @NonNull [] claims,@NonNull Instant expiry,@NonNull Deadline deadline,
   @NonNull Supplier<@NonNull Instant> authorityTime) {
  return sign(claims,expiry,deadline,authorityTime,this.admitted);
 }
 private @NonNull String sign(byte @NonNull [] claims,@NonNull Instant expiry,@NonNull Deadline deadline,
   @NonNull Supplier<@NonNull Instant> authorityTime,@NonNull History history) {
  OAuthIssuerKeySnapshot selected=checked(deadline,expiry,authorityTime,history);
  try {
   String result=selected.getActiveKey().signer().toCompactSerialization("at+jwt",selected.getActiveKey().getKeyId(),null,
    claims,OAuthServerClientAdmission.remaining(deadline));
   // Recheck rotation after provider signing and before a caller can prepare/commit an issuance response.
   OAuthIssuerKeySnapshot after=checked(deadline,null,authorityTime,history);String id=selected.getActiveKey().getKeyId();
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
 void warmUp(@NonNull Deadline deadline,@NonNull Supplier<@NonNull Instant> authorityTime){
  OAuthIssuerKeySnapshot selected=checked(deadline,null,authorityTime,this.admitted);
  try{selected.getActiveKey().signer().warmUp(OAuthServerClientAdmission.remaining(deadline));checked(deadline,null,authorityTime,this.admitted);}
  catch(VirtualMachineError fatal){throw fatal;}catch(Throwable fault){OAuthStoreCoordinator.preserveInterrupt(fault);throw signingFailure();}
 }
 @NonNull StaticJwksSource verificationKeys(@NonNull Deadline deadline) {return publicKeys(snapshot(deadline),deadline);}
 @NonNull StaticJwksSource verificationKeys(@NonNull Deadline deadline,@NonNull Supplier<@NonNull Instant> authorityTime){
  return publicKeys(checked(deadline,null,authorityTime,this.admitted),deadline);
 }
 /** Provisional cryptographic recognition only: no temporal eligibility or remembered authority facts. */
 @NonNull StaticJwksSource recognitionKeys(@NonNull Deadline deadline){
  try{return publicKeys(requireNonNull(this.provider.getSnapshot(OAuthServerClientAdmission.remaining(deadline))),deadline);}
  catch(VirtualMachineError fatal){throw fatal;}catch(Throwable fault){OAuthStoreCoordinator.preserveInterrupt(fault);throw unavailable();}
 }
 private static @NonNull StaticJwksSource publicKeys(@NonNull OAuthIssuerKeySnapshot keys,@NonNull Deadline deadline){
  JwksParseResult parsed=Jwks.fromJsonResult(OAuthIssuerPublicKeys.jwks(keys.getVerificationKeys()).toJson());
  if(!(parsed instanceof JwksParseResult.Succeeded success))throw new IllegalStateException("Generated issuer keys are invalid.");
  StaticJwksSource result=StaticJwksSource.fromJwks(success.getJwks());OAuthServerClientAdmission.remaining(deadline);return result;
 }
 private @NonNull RuntimeException signingFailure() {
  return this.publicBoundary ? OAuthServerSigningException.fromReason(OAuthServerException.Reason.SIGNING_FAILED) : unavailable();
 }
 private static @NonNull OAuthServerAdmissionFailure unavailable() {
  return new OAuthServerAdmissionFailure(OAuthServerAdmissionFailure.Reason.INFRASTRUCTURE);
 }
 @Override public @NonNull String toString() { return "OAuthIssuerKeyLifecycle{<redacted>}"; }
}
