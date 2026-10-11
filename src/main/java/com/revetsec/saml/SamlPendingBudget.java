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
package com.revetsec.saml;

import org.jspecify.annotations.NonNull;

import java.time.Duration;

/** Compares elapsed store time without converting an unbounded caller budget to nanoseconds. */
final class SamlPendingBudget {
    private SamlPendingBudget() { }

    static boolean exhausted(long started, @NonNull Duration budget) {
        long elapsed = System.nanoTime() - started;
        return Thread.currentThread().isInterrupted() || elapsed < 0
                || Duration.ofNanos(elapsed).compareTo(budget) >= 0;
    }
}
