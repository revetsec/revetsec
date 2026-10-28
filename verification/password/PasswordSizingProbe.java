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

import com.revetsec.password.Argon2idParameters;
import com.revetsec.password.LegacyPasswordPreparation;
import com.revetsec.password.PasswordHashResult;
import com.revetsec.password.PasswordHasher;
import com.revetsec.password.PasswordVerificationLimits;
import com.revetsec.password.PasswordVerificationResult;
import com.revetsec.password.PasswordWorkGate;
import org.jspecify.annotations.NonNull;

import javax.annotation.concurrent.Immutable;
import javax.annotation.concurrent.ThreadSafe;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

/** Standalone, synthetic load probe. This source is test tooling, not a library API. */
@ThreadSafe
public final class PasswordSizingProbe {
    private static final @NonNull String BCRYPT_VECTOR =
            "$2a$05$CCCCCCCCCCCCCCCCCCCCC.E5YPO9kmyuRGyh0XouQYb4YMJKvyOeW";

    private PasswordSizingProbe() { }

    /**
     * Runs one warm-up wave, then emits one CSV row per measured operation. The gate is shared
     * across all workers. A capacity result is expected when workers exceed available slots.
     *
     * <pre>
     * argon2-hash   memoryKiB passes lanes gateCalls workers rounds
     * argon2-verify memoryKiB passes lanes gateCalls workers rounds
     * bcrypt-verify logRounds gateCalls workers rounds
     * </pre>
     *
     * @param arguments mode and bounded profile settings
     * @throws Exception if the probe cannot run or an unexpected result occurs
     */
    public static void main(@NonNull String @NonNull [] arguments) throws Exception {
        if (arguments.length == 0) throw new IllegalArgumentException(usage());
        String mode = arguments[0];
        boolean argon2 = mode.equals("argon2-hash") || mode.equals("argon2-verify");
        if (!(argon2 || mode.equals("bcrypt-verify"))
                || arguments.length != (argon2 ? 7 : 5)) throw new IllegalArgumentException(usage());

        int gateCalls = positive(arguments[argon2 ? 4 : 2], "gateCalls", 1, 256);
        int workers = positive(arguments[argon2 ? 5 : 3], "workers", 1, 256);
        int rounds = positive(arguments[argon2 ? 6 : 4], "rounds", 1, 100);
        int memoryKiB = argon2 ? positive(arguments[1], "memoryKiB", 19_456, 262_144) : 19_456;
        int passes = argon2 ? positive(arguments[2], "passes", 1, 10) : 2;
        int lanes = argon2 ? positive(arguments[3], "lanes", 1, 8) : 1;
        int bcryptLogRounds = argon2 ? 0 : positive(arguments[1], "logRounds", 4, 16);
        long aggregateKiB = (long) memoryKiB * gateCalls;
        if (aggregateKiB > 4_194_304L)
            throw new IllegalArgumentException("memoryKiB * gateCalls exceeds the work-gate maximum");

        Argon2idParameters parameters = Argon2idParameters.withCosts(memoryKiB, passes, lanes);
        PasswordVerificationLimits limits = PasswordVerificationLimits.builder()
                .maximumArgon2idMemoryKiB(Math.max(131_072, memoryKiB))
                .maximumArgon2idPasses(Math.max(6, passes))
                .build();
        PasswordHasher.Builder builder = PasswordHasher.withArgon2id(parameters)
                .verificationLimits(limits)
                .workGate(PasswordWorkGate.withLimits(gateCalls, (int) aggregateKiB));
        if (!argon2) builder.legacyBcrypt(LegacyPasswordPreparation.EXACT_UTF8, bcryptLogRounds);
        PasswordHasher hasher = builder.build();
        String stored = mode.equals("argon2-verify") ? newHash(hasher) : "";
        String bcryptStored = mode.equals("bcrypt-verify")
                ? BCRYPT_VECTOR.substring(0, 4) + String.format(Locale.ROOT, "%02d", bcryptLogRounds)
                    + BCRYPT_VECTOR.substring(6) : "";

        System.err.printf(Locale.ROOT,
                "mode=%s java=%s os=%s/%s processors=%d maxHeapMiB=%d memoryKiB=%d passes=%d "
                        + "lanes=%d bcryptLogRounds=%d gateCalls=%d workers=%d rounds=%d%n",
                mode, System.getProperty("java.version"), System.getProperty("os.name"),
                System.getProperty("os.arch"), Runtime.getRuntime().availableProcessors(),
                Runtime.getRuntime().maxMemory() / (1024 * 1024), memoryKiB, passes, lanes, bcryptLogRounds,
                gateCalls, workers, rounds);
        System.out.println("round,worker,elapsed_ms,outcome");
        List<Long> completedNanos = new ArrayList<>();
        int unavailable = 0;
        ExecutorService executor = Executors.newFixedThreadPool(workers);
        try {
            for (int round = 0; round <= rounds; round++) {
                CountDownLatch start = new CountDownLatch(1);
                List<Future<Sample>> futures = new ArrayList<>();
                for (int worker = 0; worker < workers; worker++) {
                    futures.add(executor.submit(() -> {
                        start.await();
                        return sample(mode, hasher, stored, bcryptStored);
                    }));
                }
                start.countDown();
                for (int worker = 0; worker < workers; worker++) {
                    Sample sample = get(futures.get(worker));
                    if (round == 0) continue; // Warm-up is deliberately excluded from results.
                    System.out.printf(Locale.ROOT, "%d,%d,%.3f,%s%n", round, worker,
                            sample.elapsedNanos() / 1_000_000.0, sample.outcome());
                    if (sample.outcome().equals("WORK_CAPACITY")) unavailable++;
                    else completedNanos.add(sample.elapsedNanos());
                }
            }
        } finally {
            executor.shutdownNow();
        }
        completedNanos.sort(Long::compareTo);
        System.err.printf(Locale.ROOT, "completed=%d work_capacity=%d p50_ms=%.3f p95_ms=%.3f%n",
                completedNanos.size(), unavailable, percentile(completedNanos, 0.50),
                percentile(completedNanos, 0.95));
    }

    private static @NonNull Sample sample(@NonNull String mode, @NonNull PasswordHasher hasher,
            @NonNull String stored, @NonNull String bcryptStored) {
        char[] password = (mode.equals("bcrypt-verify") ? "U*U" : "synthetic sizing password")
                .toCharArray();
        long start = System.nanoTime();
        try {
            if (mode.equals("argon2-hash")) {
                PasswordHashResult result = hasher.hashResult(password);
                if (result instanceof PasswordHashResult.Succeeded) return new Sample(System.nanoTime() - start, "DONE");
                if (result instanceof PasswordHashResult.Unavailable unavailable
                        && unavailable.getReason().name().equals("WORK_CAPACITY"))
                    return new Sample(System.nanoTime() - start, "WORK_CAPACITY");
                throw new IllegalStateException("Unexpected hash outcome: " + result);
            }
            PasswordVerificationResult result = mode.equals("argon2-verify")
                    ? hasher.verifyResult(password, stored)
                    : hasher.verifyLegacyBcryptResult(password, bcryptStored);
            if (mode.equals("argon2-verify") && result instanceof PasswordVerificationResult.Matched)
                return new Sample(System.nanoTime() - start, "DONE");
            if (mode.equals("bcrypt-verify") && (result instanceof PasswordVerificationResult.Matched
                    || result instanceof PasswordVerificationResult.NotMatched))
                return new Sample(System.nanoTime() - start, "DONE");
            if (result instanceof PasswordVerificationResult.Unavailable unavailable
                    && unavailable.getReason().name().equals("WORK_CAPACITY"))
                return new Sample(System.nanoTime() - start, "WORK_CAPACITY");
            throw new IllegalStateException("Unexpected verification outcome: " + result);
        } finally {
            Arrays.fill(password, '\0');
        }
    }

    private static @NonNull String newHash(@NonNull PasswordHasher hasher) {
        char[] password = "synthetic sizing password".toCharArray();
        try {
            PasswordHashResult result = hasher.hashResult(password);
            if (result instanceof PasswordHashResult.Succeeded succeeded)
                return succeeded.getPasswordHash().getStoredForm();
            throw new IllegalStateException("Unable to prepare synthetic verifier: " + result);
        } finally {
            Arrays.fill(password, '\0');
        }
    }

    private static @NonNull Sample get(@NonNull Future<@NonNull Sample> future) throws Exception {
        try {
            return future.get();
        } catch (ExecutionException e) {
            Throwable cause = e.getCause();
            if (cause instanceof Exception exception) throw exception;
            throw e;
        }
    }

    private static int positive(@NonNull String text, @NonNull String name, int minimum, int maximum) {
        int value = Integer.parseInt(text);
        if (value < minimum || value > maximum)
            throw new IllegalArgumentException(name + " must be in [" + minimum + ", " + maximum + "]");
        return value;
    }

    private static double percentile(@NonNull List<@NonNull Long> sorted, double fraction) {
        if (sorted.isEmpty()) return Double.NaN;
        return sorted.get((int) Math.ceil(fraction * sorted.size()) - 1) / 1_000_000.0;
    }

    private static @NonNull String usage() {
        return "Usage: argon2-hash|argon2-verify memoryKiB passes lanes gateCalls workers rounds; "
                + "bcrypt-verify logRounds gateCalls workers rounds";
    }

    @Immutable
    private record Sample(long elapsedNanos, @NonNull String outcome) { }
}
