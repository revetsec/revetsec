/* Copyright 2026 Revetware LLC. Licensed under Apache-2.0. */
package verification.store;

import com.revetsec.StoreAdmission;
import com.revetsec.StoreTimeObservation;
import com.revetsec.oauth.server.*;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.time.Duration;
import java.time.Instant;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;
import java.util.Properties;

/** Unpublished wrapper over the same admitted issuer adapter, with private SQL fault controls. */
final class PostgresStore implements OAuthAuthorizationServerStore {
 final int capacity;
 volatile @Nullable OAuthStoreTransaction last;
 volatile @Nullable Probe probe;
 private final @NonNull FixtureIssuerStore backend;
 interface Probe {void at(@NonNull String stage,@NonNull OAuthStoreTransaction transaction)throws SQLException;}
 static @NonNull String identity(@NonNull String value){try{return Base64.getUrlEncoder().withoutPadding().encodeToString(MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8)));}catch(Exception failure){throw new IllegalStateException("Fixture hash unavailable",failure);}}
 PostgresStore(@NonNull String url,@NonNull Properties properties,int capacity){
  this.capacity=capacity;Properties copy=new Properties();copy.putAll(properties);
  String namespace="fixture_verification",physical=identity("issuer-physical/"+namespace);
  StoreAdmission admission=StoreAdmission.fromIdentifiers(identity("issuer-authority/"+namespace),identity("issuer-recovery/"+namespace));
  // Authority is an independent explicit fixture input. Never read the worker's `now` property.
  Instant authorityNow=Instant.parse(properties.getProperty("authorityNow","2026-10-06T12:00:00Z"));
  boolean healthy=!properties.getProperty("authorityMode","healthy").equals("unavailable");
  this.backend=new FixtureIssuerStore(namespace,physical,remaining->{
   return new BudgetDataSource(url,copy,System.nanoTime()+remaining.toNanos()).getConnection();
  },capacity,(scope,budget)->{if(!physical.equals(scope))throw new IllegalStateException("Fixture physical scope changed");return healthy?StoreTimeObservation.Healthy.fromObservation(admission,identity("issuer-clock/"+namespace),authorityNow,Duration.ZERO):StoreTimeObservation.Unavailable.fromAdmission(admission);});
 }
 static int millis(long deadline){long remaining=deadline-System.nanoTime();if(remaining<=0 || Thread.currentThread().isInterrupted())throw new IllegalStateException("Issuer fixture budget expired");return (int)Math.max(1,Math.min(60000,(remaining+999999)/1000000));}
 @Override public @NonNull OAuthStoreReadResult read(@NonNull OAuthStoreKey key,@NonNull Duration budget){return this.backend.read(key,budget);}
 @Override public @NonNull OAuthStoreCommitReceipt commit(@NonNull OAuthStoreTransaction transaction,@NonNull Duration budget){this.last=transaction;this.backend.probe=this.probe;return this.backend.commit(transaction,budget);}
}
