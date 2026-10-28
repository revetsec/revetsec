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

import org.jspecify.annotations.NonNull;

import javax.annotation.concurrent.Immutable;

/** Argon2id version 19 parameters for newly created password hashes.
 * @since 1.0.0 */
@Immutable
public final class Argon2idParameters {
    private final int memoryKiB;
    private final int passes;
    private final int lanes;

    private Argon2idParameters(int memoryKiB, int passes, int lanes) {
        this.memoryKiB = memoryKiB;
        this.passes = passes;
        this.lanes = lanes;
    }

    /** Selects the total memory, passes, and lanes. New hashes require at least 19 MiB and two
     * passes, or at least 46 MiB for a single pass. The upper bounds protect the Java process.
     * @param memoryKiB total memory in KiB
     * @param passes number of passes
     * @param lanes degree of parallelism (Argon2 lanes, not library worker threads)
     * @return validated parameters
     * @since 1.0.0 */
    public static @NonNull Argon2idParameters withCosts(int memoryKiB, int passes, int lanes) {
        if (lanes < 1 || lanes > 8 || passes < 1 || passes > 10
                || memoryKiB > 262_144 || memoryKiB < 8 * lanes
                || (passes == 1 ? memoryKiB < 47_104 : memoryKiB < 19_456)) {
            throw new IllegalArgumentException("Invalid Argon2id creation parameters");
        }
        return new Argon2idParameters(memoryKiB, passes, lanes);
    }

    /** Returns the total memory cost.
     * @return total memory in KiB
     * @since 1.0.0 */
    public @NonNull Integer getMemoryKiB() { return memoryKiB; }

    /** Returns the time cost.
     * @return number of passes
     * @since 1.0.0 */
    public @NonNull Integer getPasses() { return passes; }

    /** Returns the parallelism setting.
     * @return number of lanes
     * @since 1.0.0 */
    public @NonNull Integer getLanes() { return lanes; }

    /** @return a non-secret parameter description
     * @since 1.0.0 */
    @Override public @NonNull String toString() {
        return "Argon2idParameters{memoryKiB=" + memoryKiB + ", passes=" + passes + ", lanes=" + lanes + "}";
    }
}
