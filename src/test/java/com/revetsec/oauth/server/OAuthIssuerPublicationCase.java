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
import com.revetsec.internal.json.JsonCodec;
import com.revetsec.internal.json.JsonLimits;
import com.revetsec.json.JsonObject;
import com.revetsec.json.JsonString;
import org.jspecify.annotations.NonNull;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.Signature;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.Base64;
import static java.util.Objects.requireNonNull;

/** Owned child JVM with no history shared with other nodes or its successor process. */
final class OAuthIssuerPublicationCase {
 private OAuthIssuerPublicationCase(){}
 private static final class Time extends Clock {
  @NonNull Instant now=Instant.EPOCH;
  @Override public @NonNull ZoneId getZone(){return ZoneOffset.UTC;}
  @Override public @NonNull Clock withZone(@NonNull ZoneId zone){return this;}
  @Override public @NonNull Instant instant(){return this.now;}
 }
 public static void main(@NonNull String @NonNull [] args) throws Exception {
  var provider=new OAuthIssuerPublicationFixture(Path.of(args[0]));Time time=new Time();boolean admitted=Boolean.parseBoolean(args[1]);
  var retention=new OAuthGrantRetention(Duration.ofMinutes(5),Duration.ofSeconds(30),Duration.ofSeconds(10),Duration.ofSeconds(60));
  var lifecycle=new OAuthIssuerKeyLifecycle(provider,time,Duration.ofSeconds(60),retention);
  try(var input=new BufferedReader(new InputStreamReader(System.in,StandardCharsets.UTF_8))){
   String command;while((command=input.readLine())!=null){if(command.equals("EXIT"))return;String[] fields=command.split(" ",-1);time.now=Instant.parse(fields[1]);Deadline budget=Deadline.fromNow(Duration.ofSeconds(10));
    try{
     if(fields[0].equals("SNAP")){
      if(admitted){var ignored=lifecycle.verificationKeys(budget,time::instant);}else{var ignored=lifecycle.snapshot(budget);}
      var snapshot=provider.getSnapshot(budget.remaining());System.out.println("KEYS "+String.join(",",snapshot.getVerificationKeys().keySet().stream().sorted().toList()));
     }else{
      Instant expiry=Instant.parse(fields[2]);byte[] claims=("{\"iss\":\"https://issuer.example/tenant\",\"exp\":"+expiry.getEpochSecond()+"}").getBytes(StandardCharsets.UTF_8);
      String signed=admitted?lifecycle.sign(claims,expiry,budget,time::instant):lifecycle.sign(claims,expiry,budget);
      String[] pieces=signed.split("\\.",-1);JsonObject header=(JsonObject)JsonCodec.parse(Base64.getUrlDecoder().decode(pieces[0]),JsonLimits.jose(1024));String id=((JsonString)header.find("kid").orElseThrow()).getValue();
      Signature oracle=Signature.getInstance("SHA256withRSA");oracle.initVerify(OAuthIssuerPublicationFixture.key(id).getPublicKey());oracle.update((pieces[0]+"."+pieces[1]).getBytes(StandardCharsets.US_ASCII));
      if(!oracle.verify(Base64.getUrlDecoder().decode(pieces[2])))throw new AssertionError("Fixture signature failed JCA verification.");System.out.println("SIGNED "+id+" verified");
     }
    }catch(OAuthServerAdmissionFailure failure){System.out.println("UNAVAILABLE "+failure.reason());}
    System.out.flush();
   }
  }
 }
}
