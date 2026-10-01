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

package com.revetsec.oauth;

import org.junit.jupiter.api.*;
import static org.junit.jupiter.api.Assertions.*;
import com.revetsec.testing.*;
import com.revetsec.jose.*;
import com.revetsec.json.*;
import com.revetsec.internal.http.*;
import com.revetsec.internal.jose.*;
import com.revetsec.OutboundUriPolicy;
import org.jspecify.annotations.Nullable;
import java.net.*;
import java.net.http.*;
import java.time.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.*;
import java.util.function.*;
import java.util.stream.*;
import static com.revetsec.oauth.Phase2Fixtures.*;

/** RFC7662 section2.2 and approved G11 audience boundary; no positive/inactive credential cache. */
final class IntrospectionResponseTests {
    private static VerifiedAccessToken validate(String json) { return IntrospectionResponse.parse(raw(200,json),NOW).validate(ISSUER,Set.of(AUD),Set.of(),NOW,Duration.ZERO); }
    @Test void activeResponseRequiresAudienceAndAbsentIssuerNamesAuthoritativeAs() {
        VerifiedAccessToken proof=validate(active());assertEquals(ISSUER,proof.getIssuer());assertTrue(proof.getSubject().isEmpty());assertTrue(proof.getClientId().isEmpty());assertTrue(proof.getExpiresAt().isEmpty());assertFalse(proof.getClaims().getMembers().containsKey("iss"));
        assertEquals(Set.of("read","write"),proof.getScopes());redacted(proof,"resource","read","write");
        assertEquals(AccessTokenValidationException.Reason.AUDIENCE_MISSING,assertThrows(AccessTokenValidationException.class,()->validate("{\"active\":true}")).getReason());
        assertEquals(AccessTokenValidationException.Reason.AUDIENCE_MISMATCH,assertThrows(AccessTokenValidationException.class,()->validate("{\"active\":true,\"aud\":\"other\"}")).getReason());
        assertEquals(List.of("other",AUD),validate("{\"active\":true,\"aud\":[\"other\",\"resource\"]}").getAudiences());
        assertEquals(AccessTokenValidationException.Reason.INACTIVE,assertThrows(AccessTokenValidationException.class,()->validate("{\"active\":false,\"sub\":42}")).getReason());
    }
    @TestFactory Stream<DynamicTest> activeMustBeJsonBoolean() { return Stream.of("{}","[]","{\"active\":null}","{\"active\":\"true\"}","{\"active\":1}","{\"active\":true,\"active\":false}","garbage").map(v->DynamicTest.dynamicTest(v,()->assertThrows(OAuthResponseException.class,()->validate(v)))); }
    @TestFactory Stream<DynamicTest> malformedTypedMembersAreProviderFailures() {
        return Stream.of("aud","iss","sub","client_id","scope","token_type","exp","iat","nbf").flatMap(n->Stream.of("null","{}","42.5").map(v->DynamicTest.dynamicTest(n+v,()-> {
            String json="{\"active\":true,"+(n.equals("aud")?"":"\"aud\":\"resource\",")+JsonText.string(n)+":"+v+"}";
            assertThrows(OAuthResponseException.class,()->validate(json));
        })));
    }
    @TestFactory Stream<DynamicTest> timestampsAreIntegralNumbersInInstantRange() {
        return Stream.of("exp","iat","nbf").flatMap(n->Stream.of("\"1800000000\"","1e999","999999999999999999999999","31556889864403200").map(v->DynamicTest.dynamicTest(n+v,()->assertThrows(OAuthResponseException.class,()->validate("{\"active\":true,\"aud\":\"resource\","+JsonText.string(n)+":"+v+"}")))));
    }
    @Test void exactTimeBoundariesAndTypedOptionalClaims() {
        long now=NOW.getEpochSecond();assertEquals(AccessTokenValidationException.Reason.EXPIRED,assertThrows(AccessTokenValidationException.class,()->validate("{\"active\":true,\"aud\":\"resource\",\"exp\":"+now+"}")).getReason());
        assertEquals(AccessTokenValidationException.Reason.ISSUED_IN_FUTURE,assertThrows(AccessTokenValidationException.class,()->validate("{\"active\":true,\"aud\":\"resource\",\"iat\":"+(now+1)+"}")).getReason());
        assertEquals(AccessTokenValidationException.Reason.NOT_YET_VALID,assertThrows(AccessTokenValidationException.class,()->validate("{\"active\":true,\"aud\":\"resource\",\"nbf\":"+(now+1)+"}")).getReason());
        IntrospectionResponse parsed=IntrospectionResponse.parse(raw(200,"{\"active\":true,\"aud\":\"resource\",\"exp\":"+now+",\"iat\":"+(now+1)+",\"nbf\":"+(now+1)+"}"),NOW);
        assertNotNull(parsed.validate(ISSUER,Set.of(AUD),Set.of(),NOW,Duration.ofSeconds(1)));
        VerifiedAccessToken proof=validate("{\"active\":true,\"aud\":\"resource\",\"iss\":\"https://issuer.example\",\"sub\":\"TEST-ONLY-sub\",\"client_id\":\"TEST-ONLY-client\",\"token_type\":\"bEaReR\",\"scope\":\"\",\"exp\":"+(now+30)+".0}");
        assertEquals(Optional.of("TEST-ONLY-sub"),proof.getSubject());assertEquals(Optional.of("TEST-ONLY-client"),proof.getClientId());assertTrue(proof.getScopes().isEmpty());assertEquals(Optional.of(NOW.plusSeconds(30)),proof.getExpiresAt());
    }
    @TestFactory Stream<DynamicTest> localPolicyRejectionNeverReleasesClaims() {
        return Stream.of(Map.entry("iss","\"https://other.example\""),Map.entry("cnf","null"),Map.entry("cnf","{}"),Map.entry("token_type","\"DPoP\""),Map.entry("scope","\"read  write\"")).map(e->DynamicTest.dynamicTest(e.toString(),()->assertThrows(AccessTokenValidationException.class,()->validate("{\"active\":true,\"aud\":\"resource\","+JsonText.string(e.getKey())+":"+e.getValue()+"}"))));
    }
    @Test void requiredClaimsArePresenceChecksAndUnknownClaimsRemainExplicitSensitiveAccess() {
        IntrospectionResponse parsed=IntrospectionResponse.parse(raw(200,"{\"active\":true,\"aud\":\"resource\",\"app\":true,\"other\":null}"),NOW);
        assertEquals(AccessTokenValidationException.Reason.REQUIRED_CLAIM_MISSING,assertThrows(AccessTokenValidationException.class,()->parsed.validate(ISSUER,Set.of(AUD),Set.of("missing"),NOW,Duration.ZERO)).getReason());
        assertThrows(AccessTokenValidationException.class,()->parsed.validate(ISSUER,Set.of(AUD),Set.of("other"),NOW,Duration.ZERO));
        assertNotNull(parsed.validate(ISSUER,Set.of(AUD),Set.of("app"),NOW,Duration.ZERO).getClaims().getMembers().get("app"));redacted(parsed,"resource","app");
        assertThrows(OAuthErrorResponseException.class,()->IntrospectionResponse.parse(raw(401,"{\"error\":\"invalid_client\"}"),NOW));
    }
}
