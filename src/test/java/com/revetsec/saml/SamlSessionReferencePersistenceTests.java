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

import com.revetsec.StateSealer;
import com.revetsec.testing.TestSealers;
import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

final class SamlSessionReferencePersistenceTests {
    private static final Instant NOW = Instant.parse("2026-10-15T12:00:00Z");
    private static final Clock CLOCK = Clock.fixed(NOW, ZoneOffset.UTC);

    @Test void trustedRoundTripPreservesEveryLogoutMatchingField() {
        SamlSessionReference source = new SamlSessionReference("tenant-one", "https://idp.example.test",
                new SamlNameId("alice", SamlNameId.PERSISTENT, "https://idp.example.test",
                        "https://sp.example.test", "alias"), "session-123", NOW.plusSeconds(300));
        String serialized = source.toSerializedForm();
        assertTrue(serialized.startsWith("1."));
        SamlSessionReference restored = SamlSessionReference.fromSerializedForm(serialized);
        assertEquals(source.getIdentityProviderConnectionId(), restored.getIdentityProviderConnectionId());
        assertEquals(source.getIdentityProviderEntityId(), restored.getIdentityProviderEntityId());
        assertEquals(source.getNameId().getValue(), restored.getNameId().getValue());
        assertEquals(source.getNameId().getFormat(), restored.getNameId().getFormat());
        assertEquals(source.getNameId().getNameQualifier(), restored.getNameId().getNameQualifier());
        assertEquals(source.getNameId().getSpNameQualifier(), restored.getNameId().getSpNameQualifier());
        assertEquals(source.getNameId().getSpProvidedId(), restored.getNameId().getSpProvidedId());
        assertEquals(source.getSessionIndex(), restored.getSessionIndex());
        assertEquals(source.getSessionNotOnOrAfter(), restored.getSessionNotOnOrAfter());
    }

    @Test void sealedRoundTripBindsTypeContextAndExpiry() {
        StateSealer sealer = StateSealer.withActiveKey(TestSealers.fixedKey("saml-session-reference"))
                .clock(CLOCK).build();
        SamlSessionReference source = new SamlSessionReference("tenant-one", "https://idp.example.test",
                new SamlNameId("alice", SamlNameId.PERSISTENT, null, null), null, null);
        String sealed = source.toSealedForm(sealer, "browser-session-1", NOW.plusSeconds(60));
        assertEquals("alice", SamlSessionReference.fromSealedForm(sealed, sealer,
                "browser-session-1", CLOCK).getNameId().getValue());
        assertThrows(IllegalArgumentException.class, () -> SamlSessionReference.fromSealedForm(
                sealed, sealer, "browser-session-2", CLOCK));
        assertThrows(IllegalArgumentException.class, () -> SamlSessionReference.fromSealedForm(
                sealed.substring(0, sealed.length() - 1) + "!", sealer, "browser-session-1", CLOCK));
        assertThrows(IllegalArgumentException.class, () -> SamlSessionReference.fromSealedForm(
                sealed, sealer, "browser-session-1", Clock.fixed(NOW.plusSeconds(60), ZoneOffset.UTC)));
        assertTrue(source.toString().contains("<redacted>"));
    }

    @Test void malformedAndOversizedStorageFormsAreRejected() {
        String valid = new SamlSessionReference("tenant", "idp",
                new SamlNameId("a", null, null, null), null, null).toSerializedForm();
        for (String invalid : new String[] {
                "{}", "2" + valid.substring(1), valid + ".extra",
                valid.replaceFirst("dGVuYW50", "?"),
                valid.substring(0, valid.lastIndexOf('.') + 1) + "eGJhZA",
                "x".repeat(32769)
        }) assertThrows(IllegalArgumentException.class, () -> SamlSessionReference.fromSerializedForm(invalid));
    }
}
