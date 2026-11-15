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
import java.util.Comparator;

/** Exact string ordering that charges only characters actually inspected. */
final class ScimChargedStringComparator implements Comparator<@NonNull String> {
    private final @NonNull ScimWork work;
    ScimChargedStringComparator(@NonNull ScimWork work) { this.work = work; }

    @Override public int compare(@NonNull String left, @NonNull String right) {
        int shared = Math.min(left.length(), right.length());
        for (int index = 0; index < shared; index++) {
            char a = left.charAt(index), b = right.charAt(index);
            if (a != b) {
                work.spend(2L * (index + 1L));
                return Character.compare(a, b);
            }
        }
        work.spend(2L * shared + 1L);
        return Integer.compare(left.length(), right.length());
    }
}
