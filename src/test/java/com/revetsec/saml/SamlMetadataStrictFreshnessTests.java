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

import com.revetsec.internal.pem.Pem;
import com.revetsec.internal.xml.SamlXmlWriter;
import com.revetsec.internal.xml.SecureXmlParser;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.List;
import java.util.stream.Stream;

import static com.revetsec.saml.SamlMetadataFreshnessTests.*;
import static org.junit.jupiter.api.Assertions.*;

/** Final-only tests of the additive strict API; not counted as original runtime failures. */
final class SamlMetadataStrictFreshnessTests {
    @TestFactory Stream<DynamicTest> onlySignatureCoveredDeadlinesSatisfyTheStrictPolicy() {
        return Stream.of(0, 1, 2).flatMap(scope -> Stream.of(0, 1, 2, 3).map(location ->
                DynamicTest.dynamicTest("scope=" + scope + " deadline location=" + location, () -> {
            byte[] xml = fixture(scope, location == 1 ? END.toString() : null,
                    location == 2 ? END.toString() : null, location == 3 ? END.toString() : null);
            var result = SamlIdentityProviderMetadata.fromXmlRequiringValidUntilResult(xml, ENTITY, FIXED, keys());
            if (location == 1 || location == 2 || location == 3 && scope == 1) {
                var metadata = assertInstanceOf(SamlIdentityProviderMetadataResult.Parsed.class, result).getMetadata();
                assertEquals(END, metadata.getValidUntil().orElseThrow());
            } else assertInstanceOf(SamlIdentityProviderMetadataResult.Rejected.class, result);
        })));
    }

    @TestFactory Stream<DynamicTest> malformedAndExpiredCoveredDeadlinesFailClosed() {
        return Stream.of(0, 1, 2).flatMap(scope -> Stream.of(false, true).flatMap(role ->
                Stream.of("", "not-a-date", NOW.toString(), NOW.minusNanos(1).toString()).map(limit ->
                        DynamicTest.dynamicTest("scope=" + scope + " role=" + role + " limit=" + limit, () -> {
            byte[] xml = fixture(scope, role ? END.toString() : limit, role ? limit : null,
                    scope == 1 ? END.plusSeconds(600).toString() : null);
            assertInstanceOf(SamlIdentityProviderMetadataResult.Rejected.class,
                    SamlIdentityProviderMetadata.fromXmlRequiringValidUntilResult(xml, ENTITY, FIXED, keys()));
        }))));
    }

    @Test void unsignedParentCannotSupplyShortenExtendOrInvalidateTheDeadline() throws Exception {
        for (String parent : List.of("invalid", NOW.minusSeconds(1).toString(), END.minusNanos(1).toString(), END.plusSeconds(600).toString())) {
            var metadata = assertInstanceOf(SamlIdentityProviderMetadataResult.Parsed.class,
                    SamlIdentityProviderMetadata.fromXmlRequiringValidUntilResult(fixture(2, END.toString(), null, parent), ENTITY, FIXED, keys())).getMetadata();
            assertEquals(END, metadata.getValidUntil().orElseThrow());
        }
    }

    @Test void earliestSignedAggregateEntityOrRoleLimitIsRetained() throws Exception {
        for (int earliest = 0; earliest < 3; earliest++) {
            var metadata = assertInstanceOf(SamlIdentityProviderMetadataResult.Parsed.class,
                    SamlIdentityProviderMetadata.fromXmlRequiringValidUntilResult(fixture(1,
                            END.plusSeconds(earliest == 0 ? 0 : 20).toString(),
                            END.plusSeconds(earliest == 1 ? 0 : 20).toString(),
                            END.plusSeconds(earliest == 2 ? 0 : 20).toString()), ENTITY, FIXED, keys())).getMetadata();
            assertEquals(END, metadata.getValidUntil().orElseThrow());
        }
    }

    @TestFactory Stream<DynamicTest> completionBoundaryAndClockFailureAreAlsoEnforcedInStrictMode() {
        return Stream.of(-1, 0, 1, 2, 3).map(boundary -> DynamicTest.dynamicTest("strict completion=" + boundary, () -> {
            Instant finish = boundary == -1 ? END.minusNanos(1) : boundary == 0 ? END
                    : boundary == 1 ? END.plusNanos(1) : NOW.minusNanos(1);
            var result = SamlIdentityProviderMetadata.fromXmlRequiringValidUntilResult(fixture(0, END.toString(), null, null),
                    ENTITY, new CompletionClock(finish, boundary == 3), keys());
            if (boundary == -1) assertInstanceOf(SamlIdentityProviderMetadataResult.Parsed.class, result);
            else if (boundary <= 1) assertInstanceOf(SamlIdentityProviderMetadataResult.Rejected.class, result);
            else assertInstanceOf(SamlIdentityProviderMetadataResult.Unavailable.class, result);
        }));
    }

    @Test void policyDoesNotInventAPublicationAgeOrCertificateDeadline() throws Exception {
        Instant farFuture = Instant.parse("2099-01-01T00:00:00Z");
        var metadata = assertInstanceOf(SamlIdentityProviderMetadataResult.Parsed.class,
                SamlIdentityProviderMetadata.fromXmlRequiringValidUntilResult(fixture(0, farFuture.toString(), null, null), ENTITY, FIXED, keys())).getMetadata();
        assertEquals(farFuture, metadata.getValidUntil().orElseThrow());
        assertInstanceOf(SamlIdentityProviderMetadataResult.Rejected.class,
                SamlIdentityProviderMetadata.fromXmlRequiringValidUntilResult(fixture(0, null, null, null), ENTITY, FIXED, keys()));
    }

    @Test void strictModeStillRequiresThePinnedProofAndExpectedEntity() throws Exception {
        byte[] xml = fixture(0, END.toString(), null, null);
        var other = Pem.parseCertificate(resource("sp-signing-rsa-2048-cert.pem")).getPublicKey();
        assertInstanceOf(SamlIdentityProviderMetadataResult.Rejected.class,
                SamlIdentityProviderMetadata.fromXmlRequiringValidUntilResult(xml, ENTITY, FIXED, List.of(other)));
        assertInstanceOf(SamlIdentityProviderMetadataResult.Rejected.class,
                SamlIdentityProviderMetadata.fromXmlRequiringValidUntilResult(xml, "wrong-entity", FIXED, keys()));
        String tampered = new String(xml, StandardCharsets.UTF_8).replace("https://idp.example.test/sso", "https://evil.example.test/sso");
        assertInstanceOf(SamlIdentityProviderMetadataResult.Rejected.class,
                SamlIdentityProviderMetadata.fromXmlRequiringValidUntilResult(tampered.getBytes(StandardCharsets.UTF_8), ENTITY, FIXED, keys()));
        var document = assertInstanceOf(SecureXmlParser.Result.Accepted.class, SecureXmlParser.parseMetadata(xml)).getDocument();
        var root = document.getDocumentElement();
        root.removeChild(document.getElementsByTagNameNS("http://www.w3.org/2000/09/xmldsig#", "Signature").item(0));
        assertInstanceOf(SamlIdentityProviderMetadataResult.Rejected.class,
                SamlIdentityProviderMetadata.fromXmlRequiringValidUntilResult(SamlXmlWriter.serialize(document), ENTITY, FIXED, keys()));
    }

    @SuppressWarnings("NullAway") // Deliberate null-argument contract probes.
    @Test void nullAndInvalidConfigurationRemainProgrammerErrors() throws Exception {
        byte[] xml = fixture(0, END.toString(), null, null);
        var pins = keys();
        assertThrows(NullPointerException.class, () -> SamlIdentityProviderMetadata.fromXmlRequiringValidUntilResult(null, ENTITY, FIXED, pins));
        assertThrows(NullPointerException.class, () -> SamlIdentityProviderMetadata.fromXmlRequiringValidUntilResult(xml, ENTITY, null, pins));
        assertThrows(NullPointerException.class, () -> SamlIdentityProviderMetadata.fromXmlRequiringValidUntilResult(xml, ENTITY, FIXED, null));
        assertThrows(IllegalArgumentException.class, () -> SamlIdentityProviderMetadata.fromXmlRequiringValidUntilResult(xml, ENTITY, FIXED, List.of()));
        var five = java.util.Collections.nCopies(5, pins.get(0));
        assertThrows(IllegalArgumentException.class, () -> SamlIdentityProviderMetadata.fromXmlRequiringValidUntilResult(xml, ENTITY, FIXED, five));
    }
}
