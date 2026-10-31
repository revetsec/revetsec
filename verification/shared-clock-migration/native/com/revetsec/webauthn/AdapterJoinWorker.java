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

package com.revetsec.webauthn;

import java.time.Clock;
import org.jspecify.annotations.NonNull;

/** Test-only access to the existing separate worker clock; absent from the core artifact. */
public final class AdapterJoinWorker {
    private AdapterJoinWorker() { }
    public static WebAuthnRelyingParty.@NonNull Builder configure(WebAuthnRelyingParty.@NonNull Builder builder,@NonNull Clock worker) {
        return builder.clockForTesting(worker);
    }
}
