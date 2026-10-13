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

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

final class SamlSubjectKeyTests {
    @Test void persistentNameIdKeyPinsEveryIdentityQualifierAndStableEncoding() {
        SamlNameId complete = new SamlNameId("alice", SamlNameId.PERSISTENT,
                "idp", "sp", "provided");
        String stable = SamlSubjectKey.fromPersistentNameId(complete).toStableString();
        assertEquals("saml-nameid-v1:52:" + SamlNameId.PERSISTENT
                + "5:alice3:idp2:sp8:provided", stable);
        assertNotEquals(stable, SamlSubjectKey.fromPersistentNameId(new SamlNameId(
                "bob", SamlNameId.PERSISTENT, "idp", "sp", "provided")).toStableString());
        assertNotEquals(stable, SamlSubjectKey.fromPersistentNameId(new SamlNameId(
                "alice", SamlNameId.PERSISTENT, null, "sp", "provided")).toStableString());
        assertNotEquals(stable, SamlSubjectKey.fromPersistentNameId(new SamlNameId(
                "alice", SamlNameId.PERSISTENT, "idp", null, "provided")).toStableString());
        assertNotEquals(stable, SamlSubjectKey.fromPersistentNameId(new SamlNameId(
                "alice", SamlNameId.PERSISTENT, "idp", "sp")).toStableString());
        assertThrows(IllegalArgumentException.class, () -> SamlSubjectKey.fromPersistentNameId(
                new SamlNameId("alice", SamlNameId.TRANSIENT, "idp", "sp")));
    }

    @Test void scopedIdentifierKindAndValueAreSeparateAccountKeyComponents() {
        String subject = SamlSubjectKey.fromScopedIdentifier("subject-id", "alice@scope")
                .toStableString();
        assertEquals("saml-scoped-id-v1:10:subject-id11:alice@scope", subject);
        assertNotEquals(subject, SamlSubjectKey.fromScopedIdentifier(
                "pairwise-id", "alice@scope").toStableString());
        assertNotEquals(subject, SamlSubjectKey.fromScopedIdentifier(
                "subject-id", "bob@scope").toStableString());
        assertNotEquals(subject, SamlSubjectKey.fromPersistentNameId(new SamlNameId(
                "alice@scope", SamlNameId.PERSISTENT, null, null)).toStableString());
    }
}
