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

package com.revetsec.scim;

import org.jspecify.annotations.NonNull;
import javax.annotation.concurrent.NotThreadSafe;

/** One operation's monotonically consumed work budget. */
@NotThreadSafe
final class ScimWork {
    private long remaining;
    private boolean exceeded;
    ScimWork(long maximum) { remaining = maximum; }
    boolean wasExceeded() { return exceeded; }
    boolean take(int amount) { return spend(amount); }
    boolean spend(long amount) {
        if (amount < 0 || amount > remaining) { remaining = 0; exceeded = true; return false; }
        remaining -= amount;
        return true;
    }
    @Override public @NonNull String toString() { return "ScimWork{remaining=<redacted>}"; }
}
