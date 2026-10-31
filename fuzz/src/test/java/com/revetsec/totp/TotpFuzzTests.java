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

import com.code_intelligence.jazzer.junit.FuzzTest;
import com.revetsec.SealingKey;
import com.revetsec.StateSealer;
import com.revetsec.internal.crypto.TotpPrimitives;
import org.jspecify.annotations.NonNull;
import org.junit.jupiter.api.Assertions;

import javax.annotation.concurrent.ThreadSafe;
import java.security.GeneralSecurityException;
import java.time.Clock;
import java.util.Arrays;
import java.util.Base64;

/** Public-flow mutation checks that keep one valid credential as a control after each bad input.
 * @since 1.0.0
 */
@ThreadSafe
public final class TotpFuzzTests {
    private static final @NonNull String ACCOUNT = "fuzz-account";
    private static final @NonNull String NAMESPACE = "fuzz-namespace";
    private static final @NonNull String EPOCH = "fuzz-epoch";
    private static final @NonNull String BROWSER = "fuzz-browser-binding";
    private static final @NonNull String LOGIN = "fuzz-pending-login";
    private static final @NonNull Clock CLOCK = Clock.systemUTC();
    private static final @NonNull StateSealer SEALER = StateSealer.withActiveKey(key()).build();
    private static final @NonNull TotpRecoveryGate GATE = (context, budget) -> new TotpRecoveryGate.Permit() {
        @Override public @NonNull Boolean isCurrent() { return !budget.isNegative() && !budget.isZero(); }
        @Override public void close() { }
    };

    private TotpFuzzTests() { }

    /** A changed recovery carrier cannot consume an authentic verifier or release recovery proof. */
    @FuzzTest(maxDuration = "2m")
    public void changedRecoveryCodeNeverConsumesTheValidCode(byte @NonNull [] input)
            throws GeneralSecurityException {
        TotpAuthenticator totp = newAuthenticator();
        RecoveryCodes codes = enroll(totp);
        String valid = codes.getCodes().get(0);
        int choice = selected(input, 7);
        String changed = changedRecoveryCode(valid, choice, selectedTail(input, valid.length()));
        Assertions.assertFalse(valid.equals(changed));
        Assertions.assertInstanceOf(RecoveryCodeUseResult.Rejected.class,
                totp.consumeRecoveryCodeResult(ACCOUNT, changed, LOGIN));
        RecoveryCodeUse proof = Assertions.assertInstanceOf(RecoveryCodeUseResult.Succeeded.class,
                totp.consumeRecoveryCodeResult(ACCOUNT, valid, LOGIN)).getUse();
        Assertions.assertEquals(TotpAuthenticationMethod.RECOVERY_CODE, proof.getMethod());
        Assertions.assertEquals(EPOCH, proof.getRecoveryEpoch());
        Assertions.assertEquals(9, proof.getRemainingRecoveryCodeCount());
        Assertions.assertInstanceOf(RecoveryCodeUseResult.Rejected.class,
                totp.consumeRecoveryCodeResult(ACCOUNT, valid, LOGIN));
    }

    /** A malformed TOTP carrier cannot release proof or spend the valid step. */
    @FuzzTest(maxDuration = "2m")
    public void malformedTotpCodeNeverConsumesTheValidStep(byte @NonNull [] input)
            throws GeneralSecurityException {
        TotpAuthenticator totp = newAuthenticator();
        TotpEnrollment pending = begin(totp);
        String valid = code(pending);
        Assertions.assertInstanceOf(TotpEnrollmentResult.Succeeded.class,
                totp.confirmEnrollmentResult(ACCOUNT, pending.getEnrollmentId(), valid, BROWSER));
        // Confirmation consumed this step. The next step is still inside the allowed window.
        String next = nextCode(pending);
        if (next.equals(valid) || next.equals(codeForStep(pending, CLOCK.instant().getEpochSecond() / 30 - 1)))
            return; // A 6-digit collision is ambiguous by design, and cannot be used as a control.
        String changed = changedTotpCode(next, selected(input, 6), selectedTail(input, next.length()));
        Assertions.assertInstanceOf(TotpVerificationResult.Rejected.class,
                totp.verifyResult(ACCOUNT, changed, LOGIN));
        Assertions.assertInstanceOf(TotpVerificationResult.Succeeded.class,
                totp.verifyResult(ACCOUNT, next, LOGIN));
        Assertions.assertInstanceOf(TotpVerificationResult.Rejected.class,
                totp.verifyResult(ACCOUNT, next, LOGIN));
    }

    private static @NonNull TotpAuthenticator newAuthenticator() {
        InMemoryTotpStore store = InMemoryTotpStore.withNamespace(NAMESPACE, EPOCH).build();
        TotpAuthenticator totp = TotpAuthenticator.withIssuer("Fuzz Example")
                .credentialNamespace(NAMESPACE).recoveryEpoch(EPOCH).store(store)
                .stateSealer(SEALER).recoveryGate(GATE).clock(CLOCK).build();
        Assertions.assertInstanceOf(TotpNamespaceInitializationResult.Initialized.class,
                totp.initializeNamespaceResult());
        return totp;
    }

    private static @NonNull TotpEnrollment begin(@NonNull TotpAuthenticator totp) {
        TotpEnrollmentOptions options = TotpEnrollmentOptions.withAccountId(ACCOUNT)
                .accountName("fuzz@example.com").build();
        return Assertions.assertInstanceOf(TotpEnrollmentRequestResult.Prepared.class,
                totp.beginEnrollmentResult(options, BROWSER)).getEnrollment();
    }

    private static @NonNull RecoveryCodes enroll(@NonNull TotpAuthenticator totp)
            throws GeneralSecurityException {
        TotpEnrollment pending = begin(totp);
        return Assertions.assertInstanceOf(TotpEnrollmentResult.Succeeded.class,
                totp.confirmEnrollmentResult(ACCOUNT, pending.getEnrollmentId(), code(pending), BROWSER))
                .getRecoveryCodes();
    }

    private static @NonNull String code(@NonNull TotpEnrollment pending) throws GeneralSecurityException {
        return codeForStep(pending, CLOCK.instant().getEpochSecond() / 30);
    }

    private static @NonNull String nextCode(@NonNull TotpEnrollment pending) throws GeneralSecurityException {
        return codeForStep(pending, CLOCK.instant().getEpochSecond() / 30 + 1);
    }

    private static @NonNull String codeForStep(@NonNull TotpEnrollment pending, long step)
            throws GeneralSecurityException {
        byte[] secret = decodeBase32(pending.getManualEntryKey());
        try { return TotpPrimitives.hotp(secret, step, "HmacSHA1", 6); }
        finally { Arrays.fill(secret, (byte) 0); }
    }

    private static byte @NonNull [] decodeBase32(@NonNull String encoded) {
        byte[] bytes = new byte[encoded.length() * 5 / 8];
        int bits = 0;
        int buffer = 0;
        int output = 0;
        for (int index = 0; index < encoded.length(); index++) {
            int symbol = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567".indexOf(encoded.charAt(index));
            Assertions.assertTrue(symbol >= 0);
            buffer = (buffer << 5) | symbol;
            bits += 5;
            if (bits >= 8) {
                bits -= 8;
                bytes[output++] = (byte) (buffer >>> bits);
            }
        }
        return bytes;
    }

    private static @NonNull SealingKey key() {
        byte[] material = new byte[32];
        for (int index = 0; index < material.length; index++) material[index] = (byte) (index + 17);
        return SealingKey.fromBase64("fuzz-key", Base64.getEncoder().encodeToString(material));
    }

    private static int selected(byte @NonNull [] input, int choices) {
        return input.length == 0 ? 0 : Byte.toUnsignedInt(input[0]) % choices;
    }

    private static int selectedTail(byte @NonNull [] input, int length) {
        return input.length < 2 ? 0 : Byte.toUnsignedInt(input[1]) % length;
    }

    private static @NonNull String changedRecoveryCode(@NonNull String valid, int choice, int position) {
        int at = position;
        while (valid.charAt(at) == '-') at = (at + 1) % valid.length();
        return switch (choice) {
            case 0 -> replace(valid, at, '!');
            case 1 -> replace(valid, at, valid.charAt(at) == '0' ? '1' : '0');
            case 2 -> valid.substring(0, at) + valid.substring(at + 1);
            case 3 -> valid + '0';
            case 4 -> replace(valid, at, '\uFF10');
            case 5 -> valid.replace('-', '_');
            default -> valid.repeat(5);
        };
    }

    private static @NonNull String changedTotpCode(@NonNull String valid, int choice, int position) {
        return switch (choice) {
            case 0 -> replace(valid, position, 'x');
            case 1 -> valid.substring(0, position) + valid.substring(position + 1);
            case 2 -> valid + '0';
            case 3 -> replace(valid, position, '\uFF10');
            case 4 -> " " + valid;
            default -> valid.repeat(22);
        };
    }

    private static @NonNull String replace(@NonNull String source, int index, char replacement) {
        return source.substring(0, index) + replacement + source.substring(index + 1);
    }
}
