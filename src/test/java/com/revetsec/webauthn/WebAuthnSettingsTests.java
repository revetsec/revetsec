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

import org.junit.jupiter.api.Test;

import java.time.Duration;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

final class WebAuthnSettingsTests {
    @Test void defaultsResetAndBuiltSnapshotsAreStable() {
        var builder = WebAuthnSettings.builder();
        var defaults = builder.build();
        assertEquals(64 * 1_024, defaults.getMaximumResponseBodyBytes());
        assertEquals(8 * 1_024, defaults.getMaximumClientDataJsonBytes());
        assertEquals(16 * 1_024, defaults.getMaximumAttestationObjectBytes());
        assertEquals(8 * 1_024, defaults.getMaximumAuthenticatorDataBytes());
        assertEquals(64, defaults.getMaximumExcludedCredentials());
        assertEquals(Duration.ofMinutes(5), defaults.getCeremonyLifetime());
        assertEquals(Duration.ofSeconds(5), defaults.getOperationTimeout());
        var changed = builder.maximumResponseBodyBytes(256 * 1_024)
                .maximumClientDataJsonBytes(16 * 1_024)
                .maximumAttestationObjectBytes(64 * 1_024)
                .maximumAuthenticatorDataBytes(32 * 1_024)
                .maximumExcludedCredentials(1)
                .ceremonyLifetime(Duration.ofSeconds(30))
                .operationTimeout(Duration.ofMillis(100)).build();
        assertEquals(256 * 1_024, changed.getMaximumResponseBodyBytes());
        assertEquals(32 * 1_024, changed.getMaximumAuthenticatorDataBytes());
        assertEquals(1, changed.getMaximumExcludedCredentials());
        assertEquals(Duration.ofMillis(100), changed.getOperationTimeout());
        assertEquals(64 * 1_024, defaults.getMaximumResponseBodyBytes());
        var reset = builder.maximumResponseBodyBytes(null).maximumClientDataJsonBytes(null)
                .maximumAttestationObjectBytes(null).maximumAuthenticatorDataBytes(null)
                .maximumExcludedCredentials(null).ceremonyLifetime(null).operationTimeout(null).build();
        assertEquals(defaults.getMaximumResponseBodyBytes(), reset.getMaximumResponseBodyBytes());
        assertEquals(defaults.getMaximumClientDataJsonBytes(), reset.getMaximumClientDataJsonBytes());
        assertEquals(defaults.getMaximumAttestationObjectBytes(), reset.getMaximumAttestationObjectBytes());
        assertEquals(defaults.getMaximumAuthenticatorDataBytes(), reset.getMaximumAuthenticatorDataBytes());
        assertEquals(defaults.getMaximumExcludedCredentials(), reset.getMaximumExcludedCredentials());
        assertEquals(defaults.getCeremonyLifetime(), reset.getCeremonyLifetime());
        assertEquals(defaults.getOperationTimeout(), reset.getOperationTimeout());
    }

    @Test void rejectsSettingsOutsideFixedProfileCaps() {
        assertThrows(IllegalArgumentException.class,
                () -> WebAuthnSettings.builder().maximumResponseBodyBytes(0));
        assertThrows(IllegalArgumentException.class,
                () -> WebAuthnSettings.builder().maximumResponseBodyBytes(256 * 1_024 + 1));
        assertThrows(IllegalArgumentException.class,
                () -> WebAuthnSettings.builder().maximumClientDataJsonBytes(16 * 1_024 + 1));
        assertThrows(IllegalArgumentException.class,
                () -> WebAuthnSettings.builder().maximumAttestationObjectBytes(64 * 1_024 + 1));
        assertThrows(IllegalArgumentException.class,
                () -> WebAuthnSettings.builder().maximumAuthenticatorDataBytes(36));
        assertThrows(IllegalArgumentException.class,
                () -> WebAuthnSettings.builder().maximumAuthenticatorDataBytes(32 * 1_024 + 1));
        assertThrows(IllegalArgumentException.class,
                () -> WebAuthnSettings.builder().maximumExcludedCredentials(65));
        assertThrows(IllegalArgumentException.class,
                () -> WebAuthnSettings.builder().ceremonyLifetime(Duration.ofSeconds(29)));
        assertThrows(IllegalArgumentException.class,
                () -> WebAuthnSettings.builder().ceremonyLifetime(Duration.ofMinutes(11)));
        assertThrows(IllegalArgumentException.class,
                () -> WebAuthnSettings.builder().operationTimeout(Duration.ofMillis(99)));
        assertThrows(IllegalArgumentException.class,
                () -> WebAuthnSettings.builder().operationTimeout(Duration.ofSeconds(31)));
    }
}
