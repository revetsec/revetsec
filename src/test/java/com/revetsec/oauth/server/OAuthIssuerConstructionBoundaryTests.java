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

import com.revetsec.SealingKey;
import com.revetsec.StateSealer;
import com.revetsec.internal.http.Deadline;
import com.revetsec.jose.JwsAlgorithm;
import com.revetsec.jose.JwsSigner;
import com.revetsec.json.JsonObject;
import com.revetsec.testing.TestJsonWebKeys;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAPublicKeySpec;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicReference;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Exact accepted limits for issuer components that enforce store and wire safety. */
final class OAuthIssuerConstructionBoundaryTests {
 private static final @NonNull Instant NOW = Instant.parse("2026-10-04T00:00:00Z");
 private static final @NonNull String ISSUER = "https://issuer.example/tenant";
 private static final @NonNull Clock CLOCK = Clock.fixed(NOW, ZoneOffset.UTC);
 private static final @NonNull OAuthServerIngressLimits LIMITS = OAuthServerIngressLimits.fromDefaults();

 private static @NonNull OAuthStoreRecordCodec codec() {
  byte[] key = new byte[32];
  for (int index = 0; index < key.length; index++) key[index] = (byte) (index + 1);
  StateSealer sealer = StateSealer.withActiveKey(
   SealingKey.fromBase64("key", Base64.getEncoder().encodeToString(key)))
   .clock(CLOCK).build();
  return new OAuthStoreRecordCodec(ISSUER, sealer, 3800);
 }

 private static @NonNull JwsSigner signer() {
  TestJsonWebKeys.Fixture key = TestJsonWebKeys.Fixture.IDP_SIGNING_RSA_2048;
  return JwsSigner.fromRsaKeyPair(key.getPrivateKey(), key.getPublicKey(), JwsAlgorithm.RS256);
 }

 private static @NonNull OAuthGrantRetention retention() {
  return new OAuthGrantRetention(Duration.ofMinutes(5), Duration.ofSeconds(30),
   Duration.ofSeconds(10), Duration.ofSeconds(60));
 }

 private static @NonNull OAuthIssuerKeyLifecycle lifecycle() {
  TestJsonWebKeys.Fixture key = TestJsonWebKeys.Fixture.IDP_SIGNING_RSA_2048;
  OAuthIssuerSigningKey active = OAuthIssuerSigningKey.fromKeyPair("key", key.getPrivateKey(), key.getPublicKey());
  OAuthIssuerKeySnapshot snapshot = OAuthIssuerKeySnapshot.withActiveKey(active)
   .generation("generation").publishedAt(NOW.minusSeconds(600)).build();
  return new OAuthIssuerKeyLifecycle(OAuthIssuerKeyProvider.fromSnapshot(snapshot), CLOCK,
   Duration.ZERO, retention());
 }

 private static @NonNull OAuthStoreCoordinator coordinator(@NonNull OAuthStoreRecordCodec codec) {
  return new OAuthStoreCoordinator(new OAuthAtomicStoreFixture(), codec, CLOCK, 3, 255);
 }

 @Test void consentLedgerAdmitsExactCodeAndRetryAndSubjectBounds() {
  OAuthStoreRecordCodec codec = codec();
  OAuthStoreCoordinator coordinator = coordinator(codec);
  for (int attempts : new int[] {1, 8}) {
   for (int subjects : new int[] {16, 1024}) {
    assertDoesNotThrow(() -> new OAuthAuthorizationLedger(coordinator, codec, LIMITS,
     Duration.ofMinutes(10), Duration.ofMinutes(10), attempts, subjects, true));
   }
  }
 }

 @Test void grantRetentionAdmitsSkewAtExactlyHalfTheAccessLifetime() {
  assertDoesNotThrow(() -> new OAuthGrantRetention(Duration.ofSeconds(30),
   Duration.ofSeconds(15), Duration.ofSeconds(1), Duration.ZERO));
 }

 @Test void codeRedemptionAdmitsExactRetrySubjectAndRefreshLifetimeBounds() {
  OAuthStoreRecordCodec codec = codec();
  OAuthStoreCoordinator coordinator = coordinator(codec);
  OAuthGrantRetention retention = retention();
  OAuthTokenResponse.Encoder encoder = new OAuthTokenResponse.Encoder(ISSUER, "key", signer(), 4096, 1024);
  for (int attempts : new int[] {1, 8}) {
   for (int subjects : new int[] {16, 1024}) {
    assertDoesNotThrow(() -> new OAuthCodeRedemption(coordinator, codec, LIMITS, retention,
     encoder, Duration.ofMinutes(5), true, Duration.ofMinutes(5), Duration.ofHours(1), attempts, subjects));
   }
  }
  assertDoesNotThrow(() -> new OAuthCodeRedemption(coordinator, codec, LIMITS, retention,
   encoder, Duration.ofMinutes(5), true, Duration.ofDays(1), Duration.ofDays(1), 1, 16));
 }

 @Test void refreshRotationAdmitsExactRetrySubjectAndIdleLifetimeBounds() {
  OAuthStoreRecordCodec codec = codec();
  OAuthStoreCoordinator coordinator = coordinator(codec);
  OAuthGrantRetention retention = retention();
  OAuthTokenResponse.Encoder encoder = new OAuthTokenResponse.Encoder(ISSUER, "key", signer(), 4096, 1024);
  for (int attempts : new int[] {1, 8}) {
   for (int subjects : new int[] {16, 1024}) {
    assertDoesNotThrow(() -> new OAuthRefreshRotation(coordinator, codec, LIMITS, retention,
     encoder, Duration.ofMinutes(5), true, Duration.ofMinutes(5), attempts, subjects));
   }
  }
 }

 @Test void refreshRotationRejectsAccessLifetimeBeyondRetentionMaximum() {
  OAuthStoreRecordCodec codec = codec();
  OAuthStoreCoordinator coordinator = coordinator(codec);
  OAuthGrantRetention shortRetention = new OAuthGrantRetention(Duration.ofSeconds(30),
   Duration.ZERO, Duration.ofSeconds(1), Duration.ZERO);
  OAuthTokenResponse.Encoder encoder = new OAuthTokenResponse.Encoder(ISSUER, "key", signer(), 4096, 1024);
  assertThrows(IllegalArgumentException.class, () -> new OAuthRefreshRotation(coordinator, codec,
   LIMITS, shortRetention, encoder, Duration.ofMinutes(5), false, Duration.ofMinutes(5), 1, 16));
 }

 @Test void revocationAdmitsEveryExactRetrySubjectAndWireBound() {
  OAuthStoreRecordCodec codec = codec();
  OAuthStoreCoordinator coordinator = coordinator(codec);
  OAuthIssuerTokenStatus status = new OAuthIssuerTokenStatus(coordinator, codec, LIMITS, CLOCK,
   Duration.ZERO, 3, 255, 16384);
  for (int attempts : new int[] {1, 8}) {
   for (int subjects : new int[] {16, 1024}) {
    for (int body : new int[] {4096, 131072}) {
     for (int header : new int[] {1024, 65536}) {
      assertDoesNotThrow(() -> new OAuthGrantRevocation(coordinator, codec, status, LIMITS,
       attempts, subjects, body, header));
     }
    }
   }
  }
 }

 @Test void tokenStatusAdmitsEveryExactRetrySubjectAndTokenBound() {
  OAuthStoreRecordCodec codec = codec();
  OAuthStoreCoordinator coordinator = coordinator(codec);
  for (int attempts : new int[] {1, 8}) {
   for (int subjects : new int[] {16, 1024}) {
    for (int token : new int[] {1024, 65536}) {
     assertDoesNotThrow(() -> new OAuthIssuerTokenStatus(coordinator, codec, LIMITS, CLOCK,
      Duration.ZERO, attempts, subjects, token));
    }
   }
  }
 }

 @Test void resourceIntrospectionAdmitsExactWireBounds() {
  OAuthStoreRecordCodec codec = codec();
  OAuthStoreCoordinator coordinator = coordinator(codec);
  OAuthIssuerTokenStatus status = new OAuthIssuerTokenStatus(coordinator, codec, LIMITS, CLOCK,
   Duration.ZERO, 3, 255, 16384);
  for (int body : new int[] {4096, 131072}) {
   for (int header : new int[] {1024, 65536}) {
    assertDoesNotThrow(() -> new OAuthResourceIntrospection(status, LIMITS, body, header));
   }
  }
 }

 @Test void coordinatorAdmitsExactRetryAndSubjectBounds() {
  OAuthStoreRecordCodec codec = codec();
  for (int attempts : new int[] {1, 8}) {
   for (int subjects : new int[] {16, 1024}) {
    assertDoesNotThrow(() -> new OAuthStoreCoordinator(new OAuthAtomicStoreFixture(), codec,
     CLOCK, attempts, subjects));
   }
  }
 }

 @Test void fixedSignerEncoderAdmitsExactWireBounds() {
  JwsSigner signer = signer();
  for (int body : new int[] {4096, 131072}) {
   for (int header : new int[] {1024, 65536}) {
    assertDoesNotThrow(() -> new OAuthTokenResponse.Encoder(ISSUER, "key", signer, body, header));
   }
  }
 }

 @Test void managedSignerEncoderAdmitsExactWireBounds() {
  OAuthIssuerKeyLifecycle lifecycle = lifecycle();
  for (int body : new int[] {4096, 131072}) {
   for (int header : new int[] {1024, 65536}) {
    assertDoesNotThrow(() -> new OAuthTokenResponse.Encoder(ISSUER, lifecycle, body, header));
   }
  }
 }

 @Test void publicMetadataAdmitsExactWireAndRepresentationBounds() {
  JsonObject empty = JsonObject.builder().build();
  for (int body : new int[] {4096, 131072}) {
   for (int header : new int[] {1024, 65536}) {
    assertDoesNotThrow(() -> OAuthPublicMetadataResponse.prepare(empty, "GET", Duration.ZERO,
     body, header));
   }
  }
  String payload = "a".repeat(4088);
  JsonObject exact = JsonObject.builder().put("x", payload).build();
  assertEquals(4096, exact.toJson().getBytes(java.nio.charset.StandardCharsets.UTF_8).length);
  assertEquals(4096, OAuthPublicMetadataResponse.prepare(exact, "GET", Duration.ZERO,
   4096, 1024).body().length);
 }

 @Test void issuerMetadataAdmitsExactWireBounds() {
  URI issuer = URI.create(ISSUER);
  URI authorization = URI.create(ISSUER + "/authorize");
  URI token = URI.create(ISSUER + "/token");
  URI jwks = URI.create(ISSUER + "/jwks");
  for (int body : new int[] {4096, 131072}) {
   for (int header : new int[] {1024, 65536}) {
    assertDoesNotThrow(() -> new OAuthIssuerMetadata(issuer, authorization, token, jwks,
     null, null, true, false, Set.of("read"), Duration.ZERO, body, header));
   }
  }
 }

 @Test void issuerMetadataRejectsInvalidRequiredAndOptionalRoutes() {
  URI issuer = URI.create(ISSUER);
  URI authorization = URI.create(ISSUER + "/authorize");
  URI token = URI.create(ISSUER + "/token");
  URI jwks = URI.create(ISSUER + "/jwks");
  URI invalid = URI.create("http://remote.example/endpoint");
  assertThrows(IllegalArgumentException.class, () -> new OAuthIssuerMetadata(invalid,
   authorization, token, jwks, null, null, false, false, Set.of(), Duration.ZERO, 4096, 1024));
  assertThrows(IllegalArgumentException.class, () -> new OAuthIssuerMetadata(issuer,
   invalid, token, jwks, null, null, false, false, Set.of(), Duration.ZERO, 4096, 1024));
  assertThrows(IllegalArgumentException.class, () -> new OAuthIssuerMetadata(issuer,
   authorization, invalid, jwks, null, null, false, false, Set.of(), Duration.ZERO, 4096, 1024));
  assertThrows(IllegalArgumentException.class, () -> new OAuthIssuerMetadata(issuer,
   authorization, token, invalid, null, null, false, false, Set.of(), Duration.ZERO, 4096, 1024));
  assertThrows(IllegalArgumentException.class, () -> new OAuthIssuerMetadata(issuer,
   authorization, token, jwks, invalid, null, false, false, Set.of(), Duration.ZERO, 4096, 1024));
  assertThrows(IllegalArgumentException.class, () -> new OAuthIssuerMetadata(issuer,
   authorization, token, jwks, null, invalid, false, false, Set.of(), Duration.ZERO, 4096, 1024));
 }

 @Test void issuerMetadataAdmitsPortAtTheExactUriBoundary() {
  URI issuer = URI.create("https://issuer.example:65535/tenant");
  assertDoesNotThrow(() -> new OAuthIssuerMetadata(issuer, URI.create(ISSUER + "/authorize"),
   URI.create(ISSUER + "/token"), URI.create(ISSUER + "/jwks"), null, null,
   false, false, Set.of(), Duration.ZERO, 4096, 1024));
 }

 @Test void issuerBuilderAdmitsPortAtTheExactUriBoundary() {
  assertDoesNotThrow(() -> OAuthAuthorizationServer.withIssuer("https://issuer.example:65535/tenant"));
 }

 @Test void keySnapshotBuilderAcceptsExactMapCapacity() {
  TestJsonWebKeys.Fixture key = TestJsonWebKeys.Fixture.IDP_SIGNING_RSA_2048;
  OAuthIssuerSigningKey active = OAuthIssuerSigningKey.fromKeyPair("key", key.getPrivateKey(), key.getPublicKey());
  Map<String, java.security.PublicKey> keys = new LinkedHashMap<>();
  Map<String, Instant> retirements = new LinkedHashMap<>();
  for (int index = 0; index < 100; index++) {
   keys.put("key-" + index, key.getPublicKey());
   retirements.put("key-" + index, NOW.plusSeconds(600));
  }
  assertDoesNotThrow(() -> OAuthIssuerKeySnapshot.withActiveKey(active).verificationKeys(keys));
  assertDoesNotThrow(() -> OAuthIssuerKeySnapshot.withActiveKey(active).retirementNotBefore(retirements));
 }

 @Test void publicKeyProjectionAcceptsExactRsaIntegerWidths() throws Exception {
  RSAPublicKey ordinary = (RSAPublicKey) TestJsonWebKeys.Fixture.IDP_SIGNING_RSA_2048.getPublicKey();
  BigInteger exponent32 = BigInteger.ONE.shiftLeft(31).add(BigInteger.ONE);
  RSAPublicKey exactExponent = (RSAPublicKey) KeyFactory.getInstance("RSA")
   .generatePublic(new RSAPublicKeySpec(ordinary.getModulus(), exponent32));
  assertEquals(exponent32, ((RSAPublicKey) OAuthIssuerPublicKeys.snapshot(exactExponent)).getPublicExponent());
  BigInteger modulus16384 = BigInteger.ONE.shiftLeft(16383).add(BigInteger.valueOf(65537));
  RSAPublicKey exactModulus = (RSAPublicKey) KeyFactory.getInstance("RSA")
   .generatePublic(new RSAPublicKeySpec(modulus16384, BigInteger.valueOf(65537)));
  assertEquals(modulus16384.bitLength(), ((RSAPublicKey) OAuthIssuerPublicKeys.snapshot(exactModulus))
   .getModulus().bitLength());
 }

 @Test void serverSettingsAdmitCodeLifetimeEqualToInteractionLifetime() {
  OAuthServerSettings settings = OAuthServerSettings.builder()
   .authorizationInteractionLifetime(Duration.ofMinutes(5))
   .authorizationCodeLifetime(Duration.ofMinutes(5))
   .build(false, 16384);
  assertEquals(Duration.ofMinutes(5), settings.authorizationCodeLifetime);
 }

 @Test void serverSettingsAdmitRefreshAndSkewEqualityBoundaries() {
  assertDoesNotThrow(() -> OAuthServerSettings.builder()
   .accessTokenLifetime(Duration.ofMinutes(5))
   .refreshTokenIdleLifetime(Duration.ofMinutes(5))
   .build(true, 16384));
  assertDoesNotThrow(() -> OAuthServerSettings.builder()
   .refreshTokenIdleLifetime(Duration.ofHours(1))
   .refreshTokenAbsoluteLifetime(Duration.ofHours(1))
   .build(true, 16384));
  assertDoesNotThrow(() -> OAuthServerSettings.builder()
   .accessTokenLifetime(Duration.ofSeconds(30))
   .clockSkew(Duration.ofSeconds(15))
   .build(false, 16384));
 }

 @Test void rejectionResultsRefuseInfrastructureReasons() {
  OAuthServerResponse response = OAuthServerResponse.prepare(400,
   Map.of("Referrer-Policy", List.of("no-referrer")), null, new byte[0], 4096, 1024);
  assertThrows(IllegalArgumentException.class, () -> OAuthAuthorizationResult.fromRejection(
   OAuthServerException.Reason.STORE_UNAVAILABLE, response));
  assertThrows(IllegalArgumentException.class, () -> OAuthIntrospectionResult.fromRejection(
   OAuthServerException.Reason.STORE_UNAVAILABLE, response));
  assertThrows(IllegalArgumentException.class, () -> OAuthRevocationResult.fromRejection(
   OAuthServerException.Reason.STORE_UNAVAILABLE, response));
 }

 @Test void clientDisplayNameSurvivesImmutableRegistration() {
  OAuthServerClientRegistration client = OAuthServerClientRegistration.withClientId("client")
   .authorizationCodePermitted(false).configurationVersion("v1").clientName("Display name").build();
  assertEquals("Display name", client.getClientName().orElseThrow());
 }

 @Test void observationAdmitsExactHttpStatusRangeAndMeasuresShortElapsedTime() {
  AtomicReference<@Nullable Duration> elapsed = new AtomicReference<>();
  OAuthServerObserver observer = new OAuthServerObserver() {
   @Override public void didHandleEndpoint(OAuthServerObserver.@NonNull Endpoint endpoint, @Nullable Integer statusCode,
     @NonNull Duration measured) { elapsed.set(measured); }
  };
  for (int status : new int[] {100, 599}) {
   new OAuthServerObservation(observer, OAuthServerObserver.Endpoint.METADATA).succeeded(status);
   @Nullable Duration measured = elapsed.get();
   assertTrue(measured != null && !measured.isNegative() && measured.compareTo(Duration.ofMinutes(1)) < 0);
  }
 }

 @Test void keySnapshotReleasesTheConsistencyLockForAnotherCaller() throws Exception {
  OAuthIssuerKeyLifecycle lifecycle = lifecycle();
  lifecycle.snapshot(Deadline.fromNow(Duration.ofSeconds(1)));
  ExecutorService executor = Executors.newSingleThreadExecutor();
  try {
   Future<OAuthIssuerKeySnapshot> second = executor.submit(() -> lifecycle.snapshot(
    Deadline.fromNow(Duration.ofMillis(250))));
   assertEquals("generation", second.get(2, TimeUnit.SECONDS).getGeneration());
  } finally {
   executor.shutdownNow();
  }
 }

 @Test void subjectRegistrationAndRevocationStopAtTheConfiguredRetryCount() {
  OAuthStoreRecordCodec codec = codec();
  OAuthAtomicStoreFixture store = new OAuthAtomicStoreFixture();
  OAuthStoreCoordinator coordinator = new OAuthStoreCoordinator(store, codec, CLOCK, 1, 255);
  assertEquals(OAuthStoreCommitStatus.COMMITTED,
   coordinator.initializeFreshIssuer(Deadline.fromNow(Duration.ofSeconds(1))));
  store.conflicts = 1;
  OAuthStoreFailure registration = assertThrows(OAuthStoreFailure.class,
   () -> coordinator.establishNewSubject("subject", Deadline.fromNow(Duration.ofSeconds(1))));
  assertEquals(OAuthStoreFailure.Reason.UNAVAILABLE, registration.reason());
  assertEquals(2, store.commits);

  coordinator.establishNewSubject("subject", Deadline.fromNow(Duration.ofSeconds(1)));
  int before = store.commits;
  store.conflicts = 1;
  OAuthStoreFailure revocation = assertThrows(OAuthStoreFailure.class,
   () -> coordinator.revokeSubject("subject", Deadline.fromNow(Duration.ofSeconds(1))));
  assertEquals(OAuthStoreFailure.Reason.UNAVAILABLE, revocation.reason());
  assertEquals(before + 1, store.commits);
 }

 @Test void closedStoreSessionRejectsBeforeInspectingAnotherMutationList() {
  OAuthStoreRecordCodec codec = codec();
  OAuthStoreCoordinator coordinator = coordinator(codec);
  assertEquals(OAuthStoreCommitStatus.COMMITTED,
   coordinator.initializeFreshIssuer(Deadline.fromNow(Duration.ofSeconds(1))));
  OAuthStoreCoordinator.Session session = coordinator.begin(Deadline.fromNow(Duration.ofSeconds(1)));
  assertEquals(OAuthStoreCommitStatus.COMMITTED, session.barrier());
  OAuthStoreTransaction.Mutation mutation = OAuthStoreTransaction.Mutation.fromRemove(
   codec.key(OAuthStoreKey.Kind.GRANT, "A".repeat(43)));
  assertThrows(IllegalStateException.class, () -> session.commit(List.of(mutation, mutation,
   mutation, mutation, mutation, mutation, mutation, mutation)));
 }

 @Test void malformedTrustedGrantReferenceIsRejectedBeforeBackendAccess() {
  OAuthStoreRecordCodec codec = codec();
  OAuthAtomicStoreFixture store = new OAuthAtomicStoreFixture();
  OAuthStoreCoordinator coordinator = new OAuthStoreCoordinator(store, codec, CLOCK, 1, 255);
  assertEquals(OAuthStoreCommitStatus.COMMITTED,
   coordinator.initializeFreshIssuer(Deadline.fromNow(Duration.ofSeconds(1))));
  OAuthIssuerTokenStatus status = new OAuthIssuerTokenStatus(coordinator, codec, LIMITS, CLOCK,
   Duration.ZERO, 1, 255, 16384);
  OAuthGrantRevocation revocation = new OAuthGrantRevocation(coordinator, codec, status, LIMITS,
   1, 255, 4096, 1024);
  int reads = store.reads;
  assertThrows(IllegalArgumentException.class,
   () -> revocation.revokeGrant("bad", Deadline.fromNow(Duration.ofSeconds(1))));
  assertEquals(reads, store.reads);
 }
}
