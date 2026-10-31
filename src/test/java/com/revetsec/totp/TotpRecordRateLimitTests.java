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

package com.revetsec.totp;

import com.revetsec.SealingKey;
import com.revetsec.internal.crypto.ClosedMigrationIntent;
import com.revetsec.StateSealer;
import com.revetsec.internal.crypto.SealedStateAccess;
import com.revetsec.internal.crypto.TotpPrimitives;
import com.revetsec.internal.encoding.Base64Url;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.Test;

import javax.annotation.concurrent.NotThreadSafe;
import javax.annotation.concurrent.ThreadSafe;
import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

/** Durable format migration and bounds for the six-digit attempt ledger. */
@NotThreadSafe
final class TotpRecordRateLimitTests {
    @Test void legacyNamespaceRequiresClosedMigrationBeforeNormalTtr3Read() throws IOException {
        StateSealer sealer = sealer();
        TotpRecords legacy = new TotpRecords(sealer);
        TotpRecordsV3 records = new TotpRecordsV3(sealer);
        TotpStoreKey key = TotpStoreKey.forNamespace("example", "epoch-one");
        Instant now = Instant.ofEpochSecond(1_700_000_010L, 123);
        ScriptedTotpStore store = new ScriptedTotpStore("example", "epoch-one", now);
        String version = legacy.freshId();
        TotpStoreRecord oldRecord = sealLegacy(sealer, key, version, legacyNamespace(key, version, now));
        assertThrows(IOException.class, () -> records.open(oldRecord));
        TotpStoreRecord migrated = new TotpMigrationV3(sealer).migrateNamespace(oldRecord, intent(legacy, store));
        try (TotpRecordsV3.Decoded reopened = records.open(migrated)) {
            assertNull(reopened.account);
            TotpRecordsV3.Namespace root = java.util.Objects.requireNonNull(reopened.namespace);
            assertEquals(now, root.getMinimum());
            assertEquals(store.admission().getAuthorityId(), root.getAuthorityId());
        }
    }

    @Test void closedMigrationPromotesLegacyChargesAndPreservesThemOnTtr3Reseal() throws IOException {
        StateSealer sealer = sealer();
        TotpRecords legacy = new TotpRecords(sealer);
        TotpRecordsV3 records = new TotpRecordsV3(sealer);
        TotpStoreKey key = TotpStoreKey.forAccount("example", "epoch-one", "account-1");
        TotpStoreKey rootKey = TotpStoreKey.forNamespace("example", "epoch-one");
        Instant now = Instant.ofEpochSecond(1_700_000_010L);
        ScriptedTotpStore store = new ScriptedTotpStore("example", "epoch-one", now);
        String version = legacy.freshId(), rootVersion = legacy.freshId(), chargeId = legacy.freshId();
        TotpStoreRecord oldRoot = sealLegacy(sealer, rootKey, rootVersion, legacyNamespace(rootKey, rootVersion, now));
        TotpStoreRecord oldRecord = sealLegacy(sealer, key, version,
                legacyAccount(key, version, legacy.freshId(), List.of(chargeId), now));
        TotpStoreRecord migrated = new TotpMigrationV3(sealer).migrateAccount(oldRecord, oldRoot, intent(legacy, store));
        assertThrows(IOException.class, () -> records.open(oldRecord));
        try (TotpRecordsV3.Decoded decoded = records.open(migrated)) {
            TotpRecords.Account account = java.util.Objects.requireNonNull(decoded.account);
            assertEquals(1, account.charges.size());
            assertEquals(1, account.totpCharges.size());
            assertEquals(chargeId, account.totpCharges.get(0).id);
            TotpStoreRecord resealed = records.sealAccount(key, account);
            try (TotpRecordsV3.Decoded reopened = records.open(resealed)) {
                assertEquals(1, java.util.Objects.requireNonNull(reopened.account).totpCharges.size());
            }
        }
    }

    @Test void migratedFiveChargesAndFiveLaterFailuresReachTheDailyLimit() throws IOException {
        StateSealer sealer = sealer();
        TotpRecords legacy = new TotpRecords(sealer);
        Instant now = Instant.ofEpochSecond(1_700_000_010L);
        ScriptedTotpStore store = new ScriptedTotpStore("example", "epoch-one", now);
        MigrationGate gate = new MigrationGate();
        TotpStoreKey namespaceKey = TotpStoreKey.forNamespace("example", "epoch-one");
        TotpStoreKey accountKey = TotpStoreKey.forAccount("example", "epoch-one", "account-1");
        List<String> charges = List.of(legacy.freshId(), legacy.freshId(), legacy.freshId(), legacy.freshId(), legacy.freshId());
        String rootVersion = legacy.freshId(), version = legacy.freshId();
        TotpStoreRecord oldRoot = sealLegacy(sealer, namespaceKey, rootVersion, legacyNamespace(namespaceKey, rootVersion, now));
        TotpStoreRecord oldAccount = sealLegacy(sealer, accountKey, version,
                legacyAccount(accountKey, version, legacy.freshId(), charges, now));
        TotpMigrationV3 migration = new TotpMigrationV3(sealer);
        ClosedMigrationIntent intent = intent(legacy, store);
        store.seedClosedMigration(List.of(migration.migrateNamespace(oldRoot, intent), migration.migrateAccount(oldAccount, oldRoot, intent)));
        store.setTime(now.plusSeconds(301));
        TotpAuthenticator later = authenticator(store, sealer, gate, now.plusSeconds(301));
        for (int attempt = 0; attempt < 5; attempt++)
            assertInstanceOf(TotpVerificationResult.Rejected.class,
                    later.verifyResult("account-1", "bad", "login-binding"));
        store.setTime(now.plusSeconds(602));
        TotpAuthenticator afterCooldown = authenticator(store, sealer, gate, now.plusSeconds(602));
        TotpVerificationResult.Throttled blocked = assertInstanceOf(TotpVerificationResult.Throttled.class,
                afterCooldown.verifyResult("account-1", "bad", "login-binding"));
        assertEquals(Duration.ofDays(1).minusSeconds(602), blocked.getRetryAfter());
    }

    private static @NonNull ClosedMigrationIntent intent(@NonNull TotpRecords legacy, @NonNull ScriptedTotpStore store) {
        return ClosedMigrationIntent.fromExternalIntent(legacy.freshId(), store.admission(), Set.of(ClosedMigrationIntent.Format.TOTP_TTR3));
    }

    @Test void dailyLedgerDecoderRejectsMoreThanTenCharges() throws IOException {
        StateSealer sealer = sealer();
        TotpRecords records = new TotpRecords(sealer);
        TotpStoreKey key = TotpStoreKey.forAccount("example", "epoch-one", "account-1");
        Instant now = Instant.ofEpochSecond(1_700_000_010L);
        TotpRecords.Namespace namespace = new TotpRecords.Namespace(now);
        TotpRecords.Account account = new TotpRecords.Account("account-1", records.freshId(), now);
        for (int attempt = 0; attempt < 11; attempt++)
            account.totpCharges.add(new TotpRecords.Charge(records.freshId(), now));
        TotpStoreRecord malformed = records.seal(key, namespace, account);
        assertThrows(IOException.class, () -> records.open(malformed));
    }

    private static @NonNull StateSealer sealer() {
        byte[] keyBytes = new byte[32];
        for (int index = 0; index < keyBytes.length; index++) keyBytes[index] = (byte) (index + 23);
        return StateSealer.withActiveKey(SealingKey.fromBase64("test", Base64.getEncoder().encodeToString(keyBytes)))
                .build();
    }

    private static byte @NonNull [] legacyAccount(@NonNull TotpStoreKey key, @NonNull String version,
            @NonNull String fence, @NonNull List<@NonNull String> chargeIds, @NonNull Instant now) throws IOException {
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        try (DataOutputStream out = new DataOutputStream(buffer)) {
            out.writeInt(0x54545231);
            text(out, key.getStorageKey()); text(out, version);
            text(out, "account-1"); text(out, fence); instant(out, now);
            out.writeBoolean(false); out.writeBoolean(false);
            text(out, ""); out.writeInt(0);
            out.writeInt(chargeIds.size());
            for (String chargeId : chargeIds) { text(out, chargeId); instant(out, now); }
        }
        return buffer.toByteArray();
    }

    private static @NonNull TotpStoreRecord sealLegacy(@NonNull StateSealer sealer,
            @NonNull TotpStoreKey key, @NonNull String version, byte @NonNull [] plaintext) {
        try {
            String sealed = SealedStateAccess.get().sealDurable(sealer, Base64Url.encode(plaintext), context(key));
            return TotpStoreRecord.fromStoredForm(key, version, sealed.getBytes(StandardCharsets.US_ASCII));
        } finally { Arrays.fill(plaintext, (byte) 0); }
    }

    private static @NonNull TotpAuthenticator authenticator(@NonNull TotpStore store,
            @NonNull StateSealer sealer, @NonNull TotpRecoveryGate gate, @NonNull Instant now) {
        return TotpAuthenticator.withIssuer("Example").credentialNamespace("example")
                .recoveryEpoch("epoch-one").store(store).stateSealer(sealer).recoveryGate(gate)
                .clock(Clock.fixed(now, ZoneOffset.UTC)).build();
    }

    @ThreadSafe
    private static final class MigrationGate implements TotpRecoveryGate {
        @Override public TotpRecoveryGate.@Nullable Permit acquire(@NonNull TotpRecoveryContext context,
                @NonNull Duration remainingBudget) {
            if (!"epoch-one".equals(context.getRecoveryEpoch()) || !"example".equals(context.getCredentialNamespace())
                    || remainingBudget.isNegative() || remainingBudget.isZero()) return null;
            return new MigrationPermit();
        }
    }

    @NotThreadSafe
    private static final class MigrationPermit implements TotpRecoveryGate.Permit {
        private boolean closed;
        @Override public @NonNull Boolean isCurrent() { return !this.closed; }
        @Override public void close() { this.closed = true; }
    }

    private static byte @NonNull [] legacyNamespace(@NonNull TotpStoreKey key, @NonNull String version,
            @NonNull Instant now) throws IOException {
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        try (DataOutputStream out = new DataOutputStream(buffer)) {
            out.writeInt(0x54545231);
            text(out, key.getStorageKey()); text(out, version); instant(out, now);
        }
        return buffer.toByteArray();
    }

    private static void text(@NonNull DataOutputStream out, @NonNull String value) throws IOException {
        byte[] bytes = value.getBytes(StandardCharsets.UTF_8);
        out.writeInt(bytes.length); out.write(bytes);
    }

    private static void instant(@NonNull DataOutputStream out, @NonNull Instant value) throws IOException {
        out.writeLong(value.getEpochSecond()); out.writeInt(value.getNano());
    }

    private static @NonNull String context(@NonNull TotpStoreKey key) {
        byte[] hash = TotpPrimitives.digest("revetsec/totp/address/v1", key.getStorageKey());
        try { return "revetsec/totp/durable/v1:" + Base64Url.encode(hash); }
        finally { Arrays.fill(hash, (byte) 0); }
    }
}
