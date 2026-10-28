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
package com.revetsec.password;

import com.google.errorprone.annotations.CheckReturnValue;
import com.revetsec.internal.encoding.EncodingException;
import com.revetsec.internal.encoding.StrictUtf8;
import com.revetsec.internal.password.Argon2id;
import com.revetsec.internal.password.Argon2idInterruptedException;
import com.revetsec.internal.password.LegacyPasswordVerifier;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

import javax.annotation.concurrent.NotThreadSafe;
import javax.annotation.concurrent.ThreadSafe;
import java.nio.CharBuffer;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.text.Normalizer;
import java.util.Arrays;

import static java.util.Objects.requireNonNull;

/** Standalone, caller-thread password hashing. New hashes are Argon2id v19; legacy bcrypt and
 * PBKDF2 verification are separate, opt-in operations selected by trusted account provenance.
 * Applications own account lookup, per-account online admission, password policy, credential
 * persistence, credential-version checks, rehash compare-and-swap, and login sessions/MFA.
 * <p>Instances are safe to share across threads when their supplied work gate and pepper source
 * are shared and thread-safe. No operation starts a worker thread. A pepper-enabled instance
 * requires its peppered native stored form and never falls back to an unpeppered PHC value.
 * @since 1.0.0 */
@ThreadSafe
public final class PasswordHasher {
    private static final int SALT_BYTES = 16;
    private static final int TAG_BYTES = 32;

    private final @NonNull Argon2idParameters parameters;
    private final @NonNull PasswordWorkGate workGate;
    private final @NonNull PasswordVerificationLimits limits;
    private final @Nullable PasswordPepperSource pepperSource;
    private final @Nullable LegacyPasswordPreparation bcryptPreparation;
    private final int maximumBcryptLogRounds;
    private final @Nullable LegacyPasswordPreparation pbkdf2Preparation;
    private final int maximumPbkdf2Iterations;

    private PasswordHasher(@NonNull Builder builder) {
        this.parameters = builder.parameters;
        this.workGate = requireNonNull(builder.workGate);
        this.limits = builder.limits;
        this.pepperSource = builder.pepperSource;
        this.bcryptPreparation = builder.bcryptPreparation;
        this.maximumBcryptLogRounds = builder.maximumBcryptLogRounds;
        this.pbkdf2Preparation = builder.pbkdf2Preparation;
        this.maximumPbkdf2Iterations = builder.maximumPbkdf2Iterations;
    }

    /** Starts configuration with the required new-hash policy. Construction performs no crypto,
     * random-source, provider, storage, or network work.
     * @param parameters Argon2id v19 creation parameters
     * @return a builder
     * @since 1.0.0 */
    public static @NonNull Builder withArgon2id(@NonNull Argon2idParameters parameters) {
        return new Builder(requireNonNull(parameters));
    }

    /** Hashes a new password after bounded NFC/strict-UTF-8 preparation. The input array is
     * borrowed and never modified or retained; the caller must clear it when finished. No minimum
     * password-strength policy is implied by successful hashing.
     * @param password complete submitted password
     * @return a new stored verifier, rejection, or unavailability
     * @since 1.0.0 */
    @CheckReturnValue
    public @NonNull PasswordHashResult hashResult(char @NonNull [] password) {
        requireNonNull(password);
        if (Thread.currentThread().isInterrupted())
            return PasswordHashResult.unavailable(PasswordUnavailableReason.INTERRUPTED);
        PreparedInput prepared = prepare(password, LegacyPasswordPreparation.NFC_UTF8);
        if (prepared.reason != null) return PasswordHashResult.rejected(prepared.reason);
        byte[] input = requireNonNull(prepared.bytes);
        byte[] secret = new byte[0];
        byte[] salt = new byte[SALT_BYTES];
        byte[] tag = null;
        try {
            String keyId = null;
            if (pepperSource != null) {
                PasswordPepperSnapshot snapshot = pepperSnapshot();
                if (snapshot == null) return PasswordHashResult.unavailable(PasswordUnavailableReason.PEPPER_UNAVAILABLE);
                PasswordPepperKey key = snapshot.activeKey();
                keyId = key.getKeyId();
                secret = key.copyKeyBytes();
            }
            PasswordWorkGate.Permit permit = workGate.tryAcquire(parameters.getMemoryKiB());
            if (permit == null) return PasswordHashResult.unavailable(PasswordUnavailableReason.WORK_CAPACITY);
            try (permit) {
                if (Thread.currentThread().isInterrupted())
                    return PasswordHashResult.unavailable(PasswordUnavailableReason.INTERRUPTED);
                try {
                    new SecureRandom().nextBytes(salt);
                } catch (RuntimeException e) {
                    return PasswordHashResult.unavailable(PasswordUnavailableReason.CRYPTO_UNAVAILABLE);
                }
                tag = Argon2id.hash(input, salt, secret, parameters.getMemoryKiB(),
                        parameters.getPasses(), parameters.getLanes(), TAG_BYTES);
                return PasswordHashResult.succeeded(new PasswordHash(
                        PasswordStoredForm.encode(parameters, salt, tag, keyId)));
            }
        } catch (Argon2idInterruptedException e) {
            return PasswordHashResult.unavailable(PasswordUnavailableReason.INTERRUPTED);
        } finally {
            Arrays.fill(input, (byte) 0);
            Arrays.fill(secret, (byte) 0);
            Arrays.fill(salt, (byte) 0);
            if (tag != null) Arrays.fill(tag, (byte) 0);
        }
    }

    /** Verifies only a native Argon2id stored form under this deployment's pepper policy. It
     * parses and caps encoded length, costs, salt and tag before allocating KDF memory.
     * @param password complete submitted password; borrowed and not modified
     * @param storedForm account-owned stored verifier
     * @return a complete verification outcome
     * @since 1.0.0 */
    @CheckReturnValue
    public @NonNull PasswordVerificationResult verifyResult(char @NonNull [] password,
            @NonNull String storedForm) {
        requireNonNull(password); requireNonNull(storedForm);
        if (Thread.currentThread().isInterrupted())
            return PasswordVerificationResult.unavailable(PasswordUnavailableReason.INTERRUPTED);
        PasswordStoredForm form = PasswordStoredForm.parse(storedForm, limits);
        if (form.status() == PasswordStoredForm.Status.INVALID)
            return PasswordVerificationResult.rejected(PasswordRejectionReason.INVALID_STORED_HASH);
        if (form.status() == PasswordStoredForm.Status.UNSUPPORTED)
            return PasswordVerificationResult.rejected(PasswordRejectionReason.UNSUPPORTED_STORED_HASH);
        try {
            if (pepperSource == null && form.peppered())
                return PasswordVerificationResult.unavailable(PasswordUnavailableReason.PEPPER_UNAVAILABLE);
            if (pepperSource != null && !form.peppered())
                return PasswordVerificationResult.rejected(PasswordRejectionReason.UNSUPPORTED_STORED_HASH);
            PreparedInput prepared = prepare(password, LegacyPasswordPreparation.NFC_UTF8);
            if (prepared.reason != null) return PasswordVerificationResult.rejected(prepared.reason);
            byte[] input = requireNonNull(prepared.bytes);
            byte[] secret = new byte[0];
            byte[] actual = null;
            try {
                PasswordPepperSnapshot snapshot = null;
                if (pepperSource != null) {
                    snapshot = pepperSnapshot();
                    if (snapshot == null) return PasswordVerificationResult.unavailable(PasswordUnavailableReason.PEPPER_UNAVAILABLE);
                    PasswordPepperKey key = snapshot.keyForId(requireNonNull(form.pepperKeyId()));
                    if (key == null) return PasswordVerificationResult.unavailable(PasswordUnavailableReason.PEPPER_UNAVAILABLE);
                    secret = key.copyKeyBytes();
                }
                PasswordWorkGate.Permit permit = workGate.tryAcquire(form.memoryKiB());
                if (permit == null) return PasswordVerificationResult.unavailable(PasswordUnavailableReason.WORK_CAPACITY);
                try (permit) {
                    if (Thread.currentThread().isInterrupted())
                        return PasswordVerificationResult.unavailable(PasswordUnavailableReason.INTERRUPTED);
                    actual = Argon2id.hash(input, form.salt(), secret, form.memoryKiB(),
                            form.passes(), form.lanes(), form.tag().length);
                    if (!MessageDigest.isEqual(form.tag(), actual)) return PasswordVerificationResult.notMatched();
                    boolean policyDominates = parameters.getMemoryKiB() >= form.memoryKiB()
                            && parameters.getPasses() >= form.passes();
                    boolean staleCosts = parameters.getMemoryKiB() > form.memoryKiB()
                            || parameters.getPasses() > form.passes()
                            || parameters.getLanes() != form.lanes()
                            || form.salt().length < SALT_BYTES || form.tag().length < TAG_BYTES;
                    boolean oldPepper = snapshot != null
                            && !snapshot.getActiveKeyId().equals(form.pepperKeyId());
                    return PasswordVerificationResult.matched(policyDominates && (staleCosts || oldPepper));
                }
            } catch (Argon2idInterruptedException e) {
                return PasswordVerificationResult.unavailable(PasswordUnavailableReason.INTERRUPTED);
            } finally {
                Arrays.fill(input, (byte) 0);
                Arrays.fill(secret, (byte) 0);
                if (actual != null) Arrays.fill(actual, (byte) 0);
            }
        } finally {
            form.wipe();
        }
    }

    /** Verifies one explicitly selected historical bcrypt record. The application must select
     * this operation from trusted account provenance; no stored hash auto-selects a legacy path.
     * Candidates exceeding bcrypt's 72-byte input limit are rejected without truncation.
     * @param password submitted password; borrowed and not modified
     * @param storedForm historical modular-crypt bcrypt value
     * @return a complete verification outcome; every match recommends Argon2id rehash
     * @since 1.0.0 */
    @CheckReturnValue
    public @NonNull PasswordVerificationResult verifyLegacyBcryptResult(char @NonNull [] password,
            @NonNull String storedForm) {
        requireNonNull(password); requireNonNull(storedForm);
        if (bcryptPreparation == null)
            return PasswordVerificationResult.rejected(PasswordRejectionReason.UNSUPPORTED_STORED_HASH);
        if (storedForm.length() > limits.getMaximumStoredFormChars())
            return PasswordVerificationResult.rejected(PasswordRejectionReason.INVALID_STORED_HASH);
        if (Thread.currentThread().isInterrupted())
            return PasswordVerificationResult.unavailable(PasswordUnavailableReason.INTERRUPTED);
        PreparedInput prepared = prepare(password, bcryptPreparation);
        if (prepared.reason != null) return PasswordVerificationResult.rejected(prepared.reason);
        byte[] input = requireNonNull(prepared.bytes);
        try {
            if (input.length > 72)
                return PasswordVerificationResult.rejected(PasswordRejectionReason.LEGACY_BCRYPT_INPUT_TOO_LONG);
            PasswordWorkGate.Permit permit = workGate.tryAcquire(0);
            if (permit == null) return PasswordVerificationResult.unavailable(PasswordUnavailableReason.WORK_CAPACITY);
            try (permit) {
                LegacyPasswordVerifier.Result result = LegacyPasswordVerifier.verifyBcrypt(input, storedForm,
                        maximumBcryptLogRounds);
                if (Thread.currentThread().isInterrupted())
                    return PasswordVerificationResult.unavailable(PasswordUnavailableReason.INTERRUPTED);
                return legacyResult(result);
            }
        } finally {
            Arrays.fill(input, (byte) 0);
        }
    }

    /** Verifies one historical PBKDF2 record whose fields the application extracted from its
     * trusted legacy schema. No generic PBKDF2 string parser or format autodetection is provided.
     * @param password submitted password; borrowed and not modified
     * @param hmac historical HMAC algorithm
     * @param iterations historical iteration count
     * @param salt historical salt; borrowed and not modified
     * @param expectedTag historical derived value; borrowed and not modified
     * @return a complete verification outcome; every match recommends Argon2id rehash
     * @since 1.0.0 */
    @CheckReturnValue
    public @NonNull PasswordVerificationResult verifyLegacyPbkdf2Result(char @NonNull [] password,
            @NonNull Pbkdf2Hmac hmac, int iterations, byte @NonNull [] salt,
            byte @NonNull [] expectedTag) {
        requireNonNull(password); requireNonNull(hmac); requireNonNull(salt); requireNonNull(expectedTag);
        if (pbkdf2Preparation == null)
            return PasswordVerificationResult.rejected(PasswordRejectionReason.UNSUPPORTED_STORED_HASH);
        if (iterations < 1 || iterations > maximumPbkdf2Iterations || salt.length < 8
                || salt.length > 64 || expectedTag.length < 16 || expectedTag.length > 64)
            return PasswordVerificationResult.rejected(PasswordRejectionReason.INVALID_STORED_HASH);
        if (Thread.currentThread().isInterrupted())
            return PasswordVerificationResult.unavailable(PasswordUnavailableReason.INTERRUPTED);
        PreparedInput prepared = prepare(password, pbkdf2Preparation);
        if (prepared.reason != null) return PasswordVerificationResult.rejected(prepared.reason);
        byte[] input = requireNonNull(prepared.bytes);
        byte[] saltCopy = salt.clone();
        byte[] tagCopy = expectedTag.clone();
        try {
            PasswordWorkGate.Permit permit = workGate.tryAcquire(0);
            if (permit == null) return PasswordVerificationResult.unavailable(PasswordUnavailableReason.WORK_CAPACITY);
            try (permit) {
                LegacyPasswordVerifier.Result result = LegacyPasswordVerifier.verifyPbkdf2(input,
                        hmac.jcaName(), iterations, saltCopy, tagCopy, maximumPbkdf2Iterations);
                if (Thread.currentThread().isInterrupted())
                    return PasswordVerificationResult.unavailable(PasswordUnavailableReason.INTERRUPTED);
                return legacyResult(result);
            }
        } finally {
            Arrays.fill(input, (byte) 0);
            Arrays.fill(saltCopy, (byte) 0);
            Arrays.fill(tagCopy, (byte) 0);
        }
    }

    private @Nullable PasswordPepperSnapshot pepperSnapshot() {
        try {
            PasswordPepperSnapshotResult result = requireNonNull(pepperSource).snapshotResult();
            return result instanceof PasswordPepperSnapshotResult.Available available
                    ? available.getSnapshot() : null;
        } catch (RuntimeException e) {
            return null;
        }
    }

    private @NonNull PreparedInput prepare(char @NonNull [] password,
            @NonNull LegacyPasswordPreparation preparation) {
        if (password.length > limits.getMaximumPasswordChars())
            return PreparedInput.rejected(PasswordRejectionReason.PASSWORD_TOO_LONG);
        for (int i = 0; i < password.length; i++) {
            char ch = password[i];
            if (Character.isHighSurrogate(ch)) {
                if (++i >= password.length || !Character.isLowSurrogate(password[i]))
                    return PreparedInput.rejected(PasswordRejectionReason.INVALID_PASSWORD);
            } else if (Character.isLowSurrogate(ch)) {
                return PreparedInput.rejected(PasswordRejectionReason.INVALID_PASSWORD);
            }
        }
        String text = preparation == LegacyPasswordPreparation.NFC_UTF8
                ? Normalizer.normalize(CharBuffer.wrap(password), Normalizer.Form.NFC)
                : new String(password);
        try {
            byte[] bytes = StrictUtf8.encode(text);
            if (bytes.length > limits.getMaximumPasswordUtf8Bytes()) {
                Arrays.fill(bytes, (byte) 0);
                return PreparedInput.rejected(PasswordRejectionReason.PASSWORD_TOO_LONG);
            }
            return PreparedInput.accepted(bytes);
        } catch (EncodingException e) {
            return PreparedInput.rejected(PasswordRejectionReason.INVALID_PASSWORD);
        }
    }

    private static @NonNull PasswordVerificationResult legacyResult(LegacyPasswordVerifier.@NonNull Result result) {
        return switch (result) {
            case MATCHED -> PasswordVerificationResult.matched(true);
            case NOT_MATCHED -> PasswordVerificationResult.notMatched();
            case TRUNCATED_INPUT -> PasswordVerificationResult.rejected(PasswordRejectionReason.LEGACY_BCRYPT_INPUT_TOO_LONG);
            case MALFORMED -> PasswordVerificationResult.rejected(PasswordRejectionReason.INVALID_STORED_HASH);
            case UNAVAILABLE -> PasswordVerificationResult.unavailable(PasswordUnavailableReason.CRYPTO_UNAVAILABLE);
        };
    }

    private static final class PreparedInput {
        private final byte @Nullable [] bytes;
        private final @Nullable PasswordRejectionReason reason;
        private PreparedInput(byte @Nullable [] bytes, @Nullable PasswordRejectionReason reason) {
            this.bytes = bytes; this.reason = reason;
        }
        static @NonNull PreparedInput accepted(byte @NonNull [] bytes) { return new PreparedInput(bytes, null); }
        static @NonNull PreparedInput rejected(@NonNull PasswordRejectionReason reason) { return new PreparedInput(null, reason); }
    }

    /** Mutable configuration helper. All provider and cryptographic work occurs during operations.
     * @since 1.0.0 */
    @NotThreadSafe
    @CheckReturnValue
    public static final class Builder {
        private final @NonNull Argon2idParameters parameters;
        private @Nullable PasswordWorkGate workGate;
        private @NonNull PasswordVerificationLimits limits = PasswordVerificationLimits.fromDefaults();
        private @Nullable PasswordPepperSource pepperSource;
        private @Nullable LegacyPasswordPreparation bcryptPreparation;
        private int maximumBcryptLogRounds;
        private @Nullable LegacyPasswordPreparation pbkdf2Preparation;
        private int maximumPbkdf2Iterations;

        private Builder(@NonNull Argon2idParameters parameters) { this.parameters = parameters; }

        /** Sets the shared, process-local KDF admission gate.
         * @param gate shared gate, or null to clear this required setting
         * @return this builder
         * @since 1.0.0 */
        public @NonNull Builder workGate(@Nullable PasswordWorkGate gate) { this.workGate = gate; return this; }

        /** Sets strict input and stored-work ceilings.
         * @param limits verification ceilings, or null to restore conservative defaults
         * @return this builder
         * @since 1.0.0 */
        public @NonNull Builder verificationLimits(@Nullable PasswordVerificationLimits limits) {
            this.limits = limits == null ? PasswordVerificationLimits.fromDefaults() : limits; return this;
        }

        /** Requires RFC 9106 keyed Argon2id for new and native verified hashes. Ordinary raw PHC
         * values are refused by a pepper-enabled hasher.
         * @param source coherent active/retained key provider, or null to clear pepper policy
         * @return this builder
         * @since 1.0.0 */
        public @NonNull Builder pepperSource(@Nullable PasswordPepperSource source) {
            this.pepperSource = source; return this;
        }

        /** Enables explicit verify-only bcrypt migration. Historical preparation must be known.
         * @param preparation original character preparation
         * @param maximumLogRounds maximum accepted bcrypt log2 work cost, 4–16
         * @return this builder
         * @since 1.0.0 */
        public @NonNull Builder legacyBcrypt(@NonNull LegacyPasswordPreparation preparation, int maximumLogRounds) {
            this.bcryptPreparation = requireNonNull(preparation);
            this.maximumBcryptLogRounds = maximumLogRounds;
            return this;
        }

        /** Enables explicit verify-only PBKDF2 migration. The application supplies historical
         * salt, tag, iteration count, and HMAC selection from its trusted account schema.
         * @param preparation original character preparation
         * @param maximumIterations maximum accepted iteration count, at most 2,000,000
         * @return this builder
         * @since 1.0.0 */
        public @NonNull Builder legacyPbkdf2(@NonNull LegacyPasswordPreparation preparation, int maximumIterations) {
            this.pbkdf2Preparation = requireNonNull(preparation);
            this.maximumPbkdf2Iterations = maximumIterations;
            return this;
        }

        /** Validates local configuration without looking up keys, providers, or random bytes.
         * @return a thread-safe hasher
         * @since 1.0.0 */
        public @NonNull PasswordHasher build() {
            if (workGate == null) throw new IllegalStateException("Password work gate is required");
            if (parameters.getMemoryKiB() > workGate.getMaximumMemoryKiB()
                    || parameters.getMemoryKiB() > limits.getMaximumArgon2idMemoryKiB()
                    || parameters.getPasses() > limits.getMaximumArgon2idPasses()
                    || parameters.getLanes() > limits.getMaximumArgon2idLanes()) {
                throw new IllegalArgumentException("New-hash parameters exceed verification or work limits");
            }
            if (bcryptPreparation != null && (maximumBcryptLogRounds < 4 || maximumBcryptLogRounds > 16))
                throw new IllegalArgumentException("Invalid bcrypt migration ceiling");
            if (pbkdf2Preparation != null && (maximumPbkdf2Iterations < 1 || maximumPbkdf2Iterations > 2_000_000))
                throw new IllegalArgumentException("Invalid PBKDF2 migration ceiling");
            return new PasswordHasher(this);
        }
    }
}
