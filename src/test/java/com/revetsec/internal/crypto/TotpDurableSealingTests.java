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

package com.revetsec.internal.crypto;

import com.revetsec.SealingKey;
import com.revetsec.StateSealer;
import com.revetsec.StateUnsealResult;
import com.revetsec.internal.encoding.Base64Url;
import org.jspecify.annotations.NonNull;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

final class TotpDurableSealingTests {
 private static final @NonNull Instant NOW = Instant.parse("2026-10-15T12:00:00Z");
 private static final @NonNull String CONTEXT = "revetsec/totp/durable/v1:account-one";
 private static final @NonNull String PAYLOAD = "permanent authenticated TOTP state";

 @Test void permanentRecordsSurviveFarFutureOpeningWithoutConsultingApplicationClock() throws Exception {
  @NonNull StateSealer original = sealer("old", 1, Clock.fixed(NOW, ZoneOffset.UTC));
  @NonNull String permanent = SealedStateAccess.get().sealDurable(original, PAYLOAD, CONTEXT);
  @NonNull String expiring = original.seal(PAYLOAD, CONTEXT, Duration.ofDays(1));
  @NonNull StateSealer future = sealer("old", 1,
    Clock.fixed(Instant.parse("9999-12-31T23:59:59Z"), ZoneOffset.UTC));
  assertEquals(PAYLOAD, SealedStateAccess.get().unsealDurable(future, permanent, CONTEXT));
  assertInstanceOf(StateUnsealResult.Rejected.class, future.unsealResult(expiring, CONTEXT));
  @NonNull Clock forbiddenClock = new Clock() {
   @Override public @NonNull ZoneId getZone() { return ZoneOffset.UTC; }
   @Override public @NonNull Clock withZone(@NonNull ZoneId zone) { return this; }
   @Override public @NonNull Instant instant() { throw new AssertionError("Durable sealing must not consult the application clock"); }
  };
  @NonNull StateSealer clockIndependent = sealer("old", 1, forbiddenClock);
  assertEquals(PAYLOAD, SealedStateAccess.get().unsealDurable(clockIndependent, permanent, CONTEXT));
  @NonNull String another = SealedStateAccess.get().sealDurable(clockIndependent, PAYLOAD, CONTEXT);
  assertEquals(PAYLOAD, SealedStateAccess.get().unsealDurable(original, another, CONTEXT));
 }

 @Test void authenticFiniteLifetimeUnderTotpTypeIsRejectedAsInvalid() throws Exception {
  @NonNull StateSealer sealer = sealer("active", 1, Clock.fixed(NOW, ZoneOffset.UTC));
  @NonNull String finite = SealedStateAccess.get().seal(sealer, SealedStateType.TOTP_RECORD, PAYLOAD, CONTEXT,
    NOW.plusSeconds(3600));
  assertEquals(PAYLOAD, SealedStateAccess.get().unseal(sealer, SealedStateType.TOTP_RECORD,
    finite, CONTEXT, Clock.fixed(NOW, ZoneOffset.UTC)));
  assertEquals(UnsealException.Kind.INVALID, assertThrows(UnsealException.class,
    () -> SealedStateAccess.get().unsealDurable(sealer, finite, CONTEXT)).getKind());
 }

 @Test void applicationAndEveryOtherProtocolTypeCannotOpenAsDurableTotpEvenWithPermanentLifetime() throws Exception {
  byte @NonNull [] master = master(1);
  SealerV1.@NonNull Key key;
  try { key = SealerV1.Key.fromMasterKey("active", master); }
  finally { Arrays.fill(master, (byte) 0); }
  @NonNull StateSealer sealer = sealer("active", 1, Clock.fixed(NOW, ZoneOffset.UTC));
  for (@NonNull SealedStateType type : SealedStateType.values()) {
   if (type == SealedStateType.TOTP_RECORD) continue;
   @NonNull String other = SealerV1.seal(key, type, CONTEXT, Long.MAX_VALUE,
     PAYLOAD.getBytes(StandardCharsets.UTF_8), new byte[16], new byte[12]);
   assertEquals(UnsealException.Kind.INVALID, assertThrows(UnsealException.class,
     () -> SealedStateAccess.get().unsealDurable(sealer, other, CONTEXT)).getKind(), type.name());
  }
  @NonNull String permanent = SealedStateAccess.get().sealDurable(sealer, PAYLOAD, CONTEXT);
  for (@NonNull SealedStateType type : List.of(SealedStateType.APP, SealedStateType.WEBAUTHN_RECORD))
   assertEquals(UnsealException.Kind.INVALID, assertThrows(UnsealException.class,
     () -> SealedStateAccess.get().unseal(sealer, type, permanent, CONTEXT,
       Clock.fixed(NOW, ZoneOffset.UTC))).getKind(), type.name());
 }

 @Test void authenticatedContextIsolatesEveryAddressAndTamperingNeverOpens() throws Exception {
  @NonNull StateSealer sealer = sealer("active", 1, Clock.fixed(NOW, ZoneOffset.UTC));
  @NonNull String permanent = SealedStateAccess.get().sealDurable(sealer, PAYLOAD, CONTEXT);
  for (@NonNull String otherContext : List.of("revetsec/totp/durable/v1:account-two", "different-namespace",
    "different-recovery-epoch", "different-record-kind"))
   assertEquals(UnsealException.Kind.INVALID, assertThrows(UnsealException.class,
     () -> SealedStateAccess.get().unsealDurable(sealer, permanent, otherContext)).getKind());
  byte @NonNull [] wire = Base64Url.decode(permanent);
  try {
   wire[wire.length - 1] ^= 1;
   @NonNull String tampered = Base64Url.encode(wire);
   assertEquals(UnsealException.Kind.INVALID, assertThrows(UnsealException.class,
     () -> SealedStateAccess.get().unsealDurable(sealer, tampered, CONTEXT)).getKind());
  } finally { Arrays.fill(wire, (byte) 0); }
  assertEquals(PAYLOAD, SealedStateAccess.get().unsealDurable(sealer, permanent, CONTEXT));
 }

 @Test void durableFramingHasSeparateBoundFromBrowserStateAndRejectsOversizeBeforeOpening() throws Exception {
  @NonNull StateSealer sealer = sealer("active", 1, Clock.fixed(NOW, ZoneOffset.UTC));
  @NonNull String large = "x".repeat(10_000);
  @NonNull String permanent = SealedStateAccess.get().sealDurable(sealer, large, CONTEXT);
  assertTrue(permanent.length() > SealedStateAccess.get().getMaximumSealedLength(sealer));
  assertEquals(large, SealedStateAccess.get().unsealDurable(sealer, permanent, CONTEXT));
  assertThrows(IllegalArgumentException.class, () -> SealedStateAccess.get().sealDurable(sealer,
    "x".repeat(48_001), CONTEXT));
  assertThrows(IllegalArgumentException.class, () -> SealedStateAccess.get().sealDurable(sealer,
    "é".repeat(30_000), CONTEXT));
  assertEquals(UnsealException.Kind.INVALID, assertThrows(UnsealException.class,
    () -> SealedStateAccess.get().unsealDurable(sealer, "A".repeat(65_537), CONTEXT)).getKind());
  for (@NonNull String malformed : List.of("", "A", permanent + "=", " " + permanent))
   assertEquals(UnsealException.Kind.INVALID, assertThrows(UnsealException.class,
     () -> SealedStateAccess.get().unsealDurable(sealer, malformed, CONTEXT)).getKind());
 }

 @Test void keyIdentifiersAreImmutableExactSnapshotsAndRetainedKeysOpenPermanentRecords() throws Exception {
  @NonNull StateSealer old = sealer("old", 1, Clock.fixed(NOW, ZoneOffset.UTC));
  @NonNull StateSealer promoted = StateSealer.withActiveKey(key("new", 2)).verificationKeys(List.of(key("old", 1)))
    .clock(Clock.fixed(NOW.plusSeconds(86_400), ZoneOffset.UTC)).build();
  @NonNull String original = SealedStateAccess.get().sealDurable(old, PAYLOAD, CONTEXT);
  assertEquals("new", SealedStateAccess.get().getActiveKeyId(promoted));
  @NonNull Set<@NonNull String> ids = SealedStateAccess.get().getOpeningKeyIds(promoted);
  assertEquals(Set.of("new", "old"), ids);
  assertThrows(UnsupportedOperationException.class, () -> ids.clear());
  assertEquals(Set.of("old"), SealedStateAccess.get().getOpeningKeyIds(old));
  assertEquals(PAYLOAD, SealedStateAccess.get().unsealDurable(promoted, original, CONTEXT));
  @NonNull String migrated = SealedStateAccess.get().sealDurable(promoted, PAYLOAD, CONTEXT);
  assertNotEquals(original, migrated);
  @NonNull StateSealer retired = sealer("new", 2, Clock.fixed(NOW, ZoneOffset.UTC));
  assertEquals(PAYLOAD, SealedStateAccess.get().unsealDurable(retired, migrated, CONTEXT));
  assertEquals(UnsealException.Kind.INVALID, assertThrows(UnsealException.class,
    () -> SealedStateAccess.get().unsealDurable(retired, original, CONTEXT)).getKind());
  assertEquals(Set.of("new", "old"), ids);
 }

 @Test void keyIdCannotSubstituteForOpeningKeyMaterial() {
  @NonNull StateSealer original = sealer("same-id", 1, Clock.fixed(NOW, ZoneOffset.UTC));
  @NonNull StateSealer changedMaterial = sealer("same-id", 2, Clock.fixed(NOW, ZoneOffset.UTC));
  @NonNull String permanent = SealedStateAccess.get().sealDurable(original, PAYLOAD, CONTEXT);
  assertEquals(UnsealException.Kind.INVALID, assertThrows(UnsealException.class,
    () -> SealedStateAccess.get().unsealDurable(changedMaterial, permanent, CONTEXT)).getKind());
 }

 private static @NonNull StateSealer sealer(@NonNull String id, int seed, @NonNull Clock clock) {
  return StateSealer.withActiveKey(key(id, seed)).clock(clock).build();
 }
 private static @NonNull SealingKey key(@NonNull String id, int seed) {
  byte @NonNull [] material = master(seed);
  try { return SealingKey.fromBase64(id, Base64.getEncoder().encodeToString(material)); }
  finally { Arrays.fill(material, (byte) 0); }
 }
 private static byte @NonNull [] master(int seed) {
  byte @NonNull [] bytes = new byte[32];
  for (int index = 0; index < bytes.length; index++) bytes[index] = (byte) (seed + index);
  return bytes;
 }
}
