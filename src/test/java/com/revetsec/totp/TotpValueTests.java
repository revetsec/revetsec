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

import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Boundary checks for enrollment options and secret-bearing library-created values. */
final class TotpValueTests {
    @Test void enrollmentOptionsRequireAnExplicitDisplayNameAndExactReplacementGeneration() {
        assertThrows(NullPointerException.class,
                () -> TotpEnrollmentOptions.withAccountId("account").build());
        assertThrows(IllegalArgumentException.class,
                () -> TotpEnrollmentOptions.withAccountId(""));
        assertThrows(IllegalArgumentException.class,
                () -> TotpEnrollmentOptions.withAccountId("account").accountName("line\nbreak"));
        assertThrows(IllegalArgumentException.class,
                () -> TotpEnrollmentOptions.withAccountId("account").accountName("bad\ud800"));
        assertThrows(IllegalArgumentException.class,
                () -> TotpEnrollmentOptions.withAccountId("account").accountName("person:account"));
        assertThrows(IllegalArgumentException.class,
                () -> TotpEnrollmentOptions.withAccountId("é".repeat(513)));
        assertThrows(IllegalArgumentException.class,
                () -> TotpEnrollmentOptions.withAccountId("bad\ud800"));
        assertEquals("tenant:account", TotpEnrollmentOptions.withAccountId("tenant:account")
                .accountName("Name").build().getAccountId());
        assertEquals("é".repeat(512), TotpEnrollmentOptions.withAccountId("é".repeat(512))
                .accountName("Name").build().getAccountId());
        TotpEnrollmentOptions.Builder builder = TotpEnrollmentOptions.withAccountId("account")
                .accountName("person@example.com").replacingFactorId("factor-1");
        TotpEnrollmentOptions replacement = builder.build();
        builder = builder.replacingFactorId(null).accountName("Updated name");
        assertEquals("factor-1", replacement.getReplacingFactorId().orElseThrow());
        assertEquals("person@example.com", replacement.getAccountName());
        assertTrue(builder.build().getReplacingFactorId().isEmpty());
        assertFalse(replacement.toString().contains("person@example.com"));
    }

    @Test void nullableBuilderPropertiesClearRequiredValuesOrRestoreDefaults() {
        TotpEnrollmentOptions.Builder options = TotpEnrollmentOptions.withAccountId("account")
                .accountName("Name").accountName(null);
        assertThrows(NullPointerException.class, options::build);
        assertThrows(NullPointerException.class, () -> TotpAuthenticator.withIssuer("Example")
                .credentialNamespace("namespace").credentialNamespace(null).build());
        InMemoryTotpStore store = InMemoryTotpStore.withNamespace("namespace", "epoch")
                .maximumEntries(1).maximumEntries(null)
                .maximumSealedBytes(1L).maximumSealedBytes(null).build();
        assertTrue(store.read(java.util.Set.of(TotpStoreKey.forNamespace("namespace", "epoch")),
                Duration.ofSeconds(1)) instanceof TotpStoreReadResult.Available);
    }

    @Test void recoveryPlaintextIsDefensivelyHeldAndDiagnosticsAreRedacted() {
        List<String> source = new ArrayList<>(List.of("SECRET-RECOVERY-CODE"));
        RecoveryCodes codes = new RecoveryCodes("namespace", "epoch", "account", "factor",
                "batch", Instant.EPOCH, source);
        source.clear();
        assertEquals(List.of("SECRET-RECOVERY-CODE"), codes.getCodes());
        assertThrows(UnsupportedOperationException.class, () -> codes.getCodes().clear());
        TotpEnrollment enrollment = new TotpEnrollment("enrollment", "factor", Instant.EPOCH,
                "otpauth://totp/secret", "BASE32SECRET", "epoch");
        assertFalse(codes.toString().contains("SECRET-RECOVERY-CODE"));
        assertFalse(enrollment.toString().contains("BASE32SECRET"));
        assertFalse(TotpEnrollmentRequestResult.prepared(enrollment).toString().contains("secret"));
        assertFalse(RecoveryCodeRotationResult.succeeded(codes).toString().contains("SECRET"));
    }

    @Test void proofTypesCarryDistinctMethodProvenanceAndRecoveryEpoch() {
        TotpVerification verification = new TotpVerification("namespace", "epoch", "account",
                "factor", Instant.EPOCH, "pending-login");
        RecoveryCodeUse recovery = new RecoveryCodeUse("namespace", "epoch", "account", "factor",
                Instant.EPOCH, "pending-login", 9);
        assertEquals(TotpAuthenticationMethod.TOTP, verification.getMethod());
        assertEquals(TotpAuthenticationMethod.RECOVERY_CODE, recovery.getMethod());
        assertEquals("epoch", verification.getRecoveryEpoch());
        assertEquals("epoch", recovery.getRecoveryEpoch());
        assertEquals(9, recovery.getRemainingRecoveryCodeCount());
        assertFalse(verification.toString().contains("pending-login"));
        assertFalse(recovery.toString().contains("pending-login"));
    }

    @Test void throttleDurationsCannotBeNegative() {
        assertThrows(IllegalArgumentException.class,
                () -> TotpVerificationResult.throttled(Duration.ofSeconds(-1)));
        assertThrows(IllegalArgumentException.class,
                () -> RecoveryCodeUseResult.throttled(Duration.ofSeconds(-1)));
    }
}
