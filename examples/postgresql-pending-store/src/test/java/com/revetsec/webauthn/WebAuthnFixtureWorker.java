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
import java.time.Instant;
import java.time.ZoneOffset;
import org.jspecify.annotations.NonNull;

/** Test-only package bridge to the existing package-private worker clock control. */
public final class WebAuthnFixtureWorker {
    private WebAuthnFixtureWorker() { }
    public static WebAuthnRelyingParty.@NonNull Builder configure(WebAuthnRelyingParty.@NonNull Builder builder) {
        Instant time=Instant.ofEpochSecond(Long.parseLong(System.getenv().getOrDefault("REVETSEC_TEST_WA_WORKER_NOW","1700000010")));
        return builder.clockForTesting(Clock.fixed(time,ZoneOffset.UTC));
    }
}
