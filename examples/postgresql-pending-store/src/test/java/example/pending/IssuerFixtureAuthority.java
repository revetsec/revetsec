/* Copyright 2026 Revetware LLC. Licensed under Apache-2.0. */
package example.pending;

import com.revetsec.StoreAdmission;
import com.revetsec.StoreTimeObservation;
import org.jspecify.annotations.NonNull;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;

/** Independent scripted authority channel; never a production UTC or witness implementation. */
public final class IssuerFixtureAuthority {
 private IssuerFixtureAuthority() { }
 public static @NonNull String identity(@NonNull String value){try{return Base64.getUrlEncoder().withoutPadding().encodeToString(MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8)));}catch(Exception failure){throw new IllegalStateException("Fixture identity unavailable",failure);}}
 public static @NonNull String physical(@NonNull String namespace){return identity("issuer-physical/"+namespace);}
 public static @NonNull StoreAdmission admission(@NonNull String namespace){return StoreAdmission.fromIdentifiers(identity("issuer-authority/"+namespace),identity("issuer-recovery/"+namespace));}
 public static @NonNull String clock(@NonNull String namespace){return identity("issuer-clock/"+namespace);}
 public static PostgresqlIssuerStore.@NonNull Authority fromEnvironment(@NonNull String namespace){
  // Explicit separate input. Never consult REVETSEC_TEST_ISSUER_TIME or the worker Clock.
  Instant now=Instant.parse(System.getenv().getOrDefault("REVETSEC_TEST_ISSUER_AUTHORITY_NOW","2026-10-06T12:00:00Z"));
  boolean available=!"unavailable".equals(System.getenv("REVETSEC_TEST_ISSUER_AUTHORITY_MODE"));
  return (scope,budget)->{
   if(!physical(namespace).equals(scope) || budget.isZero() || budget.isNegative())throw new IllegalStateException("Fixture authority unavailable");
   return available?StoreTimeObservation.Healthy.fromObservation(admission(namespace),clock(namespace),now,Duration.ZERO):StoreTimeObservation.Unavailable.fromAdmission(admission(namespace));
  };
 }
 public static @NonNull PostgresqlIssuerStore store(@NonNull String namespace,PostgresqlIssuerStore.@NonNull ConnectionSource source,int cap){return new PostgresqlIssuerStore(namespace,physical(namespace),source,cap,fromEnvironment(namespace));}
}
