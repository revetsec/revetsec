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

/** RFC9068 sections2.1,2.2,4; RFC7519 sections4.1.3--6; explicit untyped substitution boundary. */
final class JwtAccessTokenValidatorTests {
    @TestFactory Stream<DynamicTest> strictTypesAndCaseFolding() {
        return Stream.of("at+jwt","application/at+jwt","AT+JWT","APPLICATION/AT+JWT").map(t->DynamicTest.dynamicTest(t,()-> {
            VerifiedAccessToken result=jwt().build().validate(bearer(token(claims(ISSUER),t)));
            assertEquals(ISSUER,result.getIssuer());assertEquals(Set.of("read","write"),result.getScopes());assertEquals(List.of(AUD),result.getAudiences());
            assertEquals(Optional.of("TEST-ONLY-client"),result.getClientId());assertEquals(Optional.of("TEST-ONLY-subject"),result.getSubject());assertTrue(result.getExpiresAt().isPresent());
            redacted(result,"TEST-ONLY-client","TEST-ONLY-subject","read","jti");
        }));
    }
    @TestFactory Stream<DynamicTest> strictAndCompatibilityNeverAcceptOtherExplicitProfiles() {
        return Stream.of("JWT","application/jwt","logout+jwt","secevent+jwt","dpop+jwt","id_token+jwt","").map(t->DynamicTest.dynamicTest("type="+t,()-> {
            Map<String,String> c=claims(ISSUER);c.put("app","true");
            assertInstanceOf(AccessTokenValidationResult.Rejected.class,jwt().build().validateResult(bearer(token(c,t))));
            if(!Set.of("JWT","application/jwt").contains(t)) assertInstanceOf(AccessTokenValidationResult.Rejected.class,
                    jwt().compatibility(AccessTokenCompatibilityMode.UNTYPED_ACCESS_TOKENS).requiredClaims(Set.of("app")).build().validateResult(bearer(token(c,t))));
        }));
    }
    @Test void untypedRequiresAdditionalClaimAndOnlyRelaxesClientAndJwtId() {
        assertThrows(IllegalArgumentException.class,()->jwt().compatibility(AccessTokenCompatibilityMode.UNTYPED_ACCESS_TOKENS).build());
        assertThrows(IllegalArgumentException.class,()->jwt().compatibility(AccessTokenCompatibilityMode.UNTYPED_ACCESS_TOKENS).requiredClaims(Set.of("exp")).build());
        Map<String,String> c=claims(ISSUER);c.remove("client_id");c.remove("jti");c.put("app","true");
        JwtAccessTokenValidator validator=jwt().compatibility(AccessTokenCompatibilityMode.UNTYPED_ACCESS_TOKENS).requiredClaims(Set.of("app")).build();
        assertTrue(validator.validate(bearer(token(c,null))).getClientId().isEmpty());assertTrue(validator.validate(bearer(token(c,"JWT"))).getClientId().isEmpty());
        c.remove("iat");assertInstanceOf(AccessTokenValidationResult.Rejected.class,validator.validateResult(bearer(token(c,null))));
        c.put("iat",Long.toString(NOW.getEpochSecond()));c.remove("exp");assertInstanceOf(AccessTokenValidationResult.Rejected.class,validator.validateResult(bearer(token(c,"JWT"))));
        assertInstanceOf(AccessTokenValidationResult.Rejected.class,jwt().build().validateResult(bearer(token(claims(ISSUER),null))));
    }
    @TestFactory Stream<DynamicTest> identityClaimsRejectEvenWhenNull() {
        return Stream.of("nonce","at_hash","c_hash","auth_time").flatMap(n->Stream.of("null","\"TEST-ONLY-identity\"").map(v->DynamicTest.dynamicTest(n+v,()-> {
            Map<String,String> c=claims(ISSUER);c.put("app","true");c.put(n,v);
            AccessTokenValidationResult.Rejected rejected=assertInstanceOf(AccessTokenValidationResult.Rejected.class,jwt().compatibility(AccessTokenCompatibilityMode.UNTYPED_ACCESS_TOKENS).requiredClaims(Set.of("app")).build().validateResult(bearer(token(c,"JWT"))));
            assertEquals(AccessTokenValidationException.Reason.UNTYPED_IDENTITY_CLAIM_PRESENT,rejected.getReason());redacted(rejected,"TEST-ONLY-identity","TEST-ONLY-subject");
        })));
    }
    @TestFactory Stream<DynamicTest> requiredClaimsAreTypedPresentAndNonempty() {
        return Stream.of("iss","aud","sub","client_id","jti","exp","iat").flatMap(n->Stream.of("absent","null","42","\"\"").filter(v->!(v.equals("42")&&Set.of("exp","iat").contains(n))).map(v->DynamicTest.dynamicTest(n+v,()-> {
            Map<String,String> c=claims(ISSUER);if(v.equals("absent"))c.remove(n);else c.put(n,v);
            assertInstanceOf(AccessTokenValidationResult.Rejected.class,jwt().build().validateResult(bearer(token(c,"at+jwt"))));
        })));
    }
    @TestFactory Stream<DynamicTest> audienceIssuerConfirmationAndRequiredClaimFailuresReleaseNoProof() {
        return Stream.of(Map.entry("aud","\"other\""),Map.entry("iss","\"https://other.example\""),Map.entry("cnf","null"),Map.entry("cnf","{}"),Map.entry("app","null")).map(e->DynamicTest.dynamicTest(e.toString(),()-> {
            Map<String,String> c=claims(ISSUER);c.put(e.getKey(),e.getValue());
            assertInstanceOf(AccessTokenValidationResult.Rejected.class,jwt().requiredClaims(e.getKey().equals("app")?Set.of("app"):Set.of()).build().validateResult(bearer(token(c,"at+jwt"))));
        }));
    }
    @Test void exactExpiryAndSkewEdgesAndFractionalNumericDate() {
        Map<String,String> c=claims(ISSUER);c.put("exp",Long.toString(NOW.getEpochSecond()));
        AccessTokenValidationResult.Rejected r=assertInstanceOf(AccessTokenValidationResult.Rejected.class,jwt().build().validateResult(bearer(token(c,"at+jwt"))));assertEquals(Optional.of(JoseException.Reason.EXPIRED),r.getJoseReason());
        JwtAccessTokenValidator skew=jwt().clockSkew(Duration.ofSeconds(1)).build();assertNotNull(skew.validate(bearer(token(c,"at+jwt"))));
        c.put("exp",Long.toString(NOW.minusSeconds(1).getEpochSecond()));assertInstanceOf(AccessTokenValidationResult.Rejected.class,skew.validateResult(bearer(token(c,"at+jwt"))));
        c=claims(ISSUER);c.put("iat",Long.toString(NOW.plusSeconds(1).getEpochSecond()));c.put("nbf",Long.toString(NOW.plusSeconds(1).getEpochSecond()));assertNotNull(skew.validate(bearer(token(c,"at+jwt"))));
        c.put("iat",Long.toString(NOW.plusSeconds(2).getEpochSecond()));assertInstanceOf(AccessTokenValidationResult.Rejected.class,skew.validateResult(bearer(token(c,"at+jwt"))));
        c=claims(ISSUER);c.put("nbf",Long.toString(NOW.plusSeconds(2).getEpochSecond()));assertInstanceOf(AccessTokenValidationResult.Rejected.class,skew.validateResult(bearer(token(c,"at+jwt"))));
        c=claims(ISSUER);c.put("exp",NOW.plusSeconds(1).getEpochSecond()+".5");assertNotNull(jwt().build().validate(bearer(token(c,"at+jwt"))));
    }
    @TestFactory Stream<DynamicTest> scopeFormsAreExplicitAndInvalidFormsReject() {
        return Stream.of("null","42","[\"read\",null]","\"read  write\"","\"read\\twrite\"",JsonText.string("read "+(char)34+"bad")).map(v->DynamicTest.dynamicTest(v,()-> {
            Map<String,String> c=claims(ISSUER);c.put("scope",v);assertInstanceOf(AccessTokenValidationResult.Rejected.class,jwt().build().validateResult(bearer(token(c,"at+jwt"))));
            c.remove("scope");c.put("scp",v);assertInstanceOf(AccessTokenValidationResult.Rejected.class,jwt().scopeClaimName("scp").build().validateResult(bearer(token(c,"at+jwt"))));
        }));
    }
    @Test void scopeAbsentEmptyAndScpArrayHaveNoImplicitPermission() {
        Map<String,String> c=claims(ISSUER);c.remove("scope");assertEquals(Set.of(),jwt().build().validate(bearer(token(c,"at+jwt"))).getScopes());
        c.put("scope","\"\"");assertEquals(Set.of(),jwt().build().validate(bearer(token(c,"at+jwt"))).getScopes());
        c.put("scp","[\"read\",\"write\"]");assertEquals(Set.of("read","write"),jwt().scopeClaimName("scp").build().validate(bearer(token(c,"at+jwt"))).getScopes());
        c.put("scp","\"read write\"");assertEquals(Set.of("read","write"),jwt().scopeClaimName("scp").build().validate(bearer(token(c,"at+jwt"))).getScopes());
    }
    @Test void malformedHeaderAndSignatureShapePrecedeEveryNetworkRequest() throws Exception {
        try(TestHttpsServer server=TestHttpsServer.start()) {
            JwtAccessTokenValidator validator=JwtAccessTokenValidator.withIssuer(server.getBaseUri().toString()).expectedAudiences(Set.of(AUD)).httpClient(TestTls.httpClient()).build();
            Map<String,String> c=claims(server.getBaseUri().toString());
            List<String> bad=new ArrayList<>(List.of("broken",token(c,"JWT"),TestJws.withAlgorithm(TestJws.Algorithm.RS256).typ("at+jwt").headerMember("jku","\"https://evil.example\"").payload("{}").sign(TestJsonWebKeys.Fixture.IDP_SIGNING_RSA_2048.getPrivateKey()),
                    TestJws.withAlgorithm(TestJws.Algorithm.RS256).typ("at+jwt").headerMember("crit","[]").payload("{}").sign(TestJsonWebKeys.Fixture.IDP_SIGNING_RSA_2048.getPrivateKey()),
                    TestJws.builder().alg("none").typ("at+jwt").payload("{}").withSignature(new byte[0])));
            String valid=token(c,"at+jwt");bad.add(valid.substring(0,valid.lastIndexOf('.')+1)+"AQ");
            for(String token:bad) assertInstanceOf(AccessTokenValidationResult.Rejected.class,validator.validateResult(bearer(token)));
            assertEquals(0,server.getRequests().size());
            response(server,"/.well-known/oauth-authorization-server",503,"application/json","{}");
            assertThrows(OAuthErrorResponseException.class,()->validator.validateResult(bearer(valid)));assertEquals(1,server.getRequests().size());
        }
    }
    @Test void signatureFailureAndRemoteJwksOutageKeepTheirDistinctPaths() throws Exception {
        String forged=TestJws.withAlgorithm(TestJws.Algorithm.RS256).kid("key").typ("at+jwt").payload(JsonText.object(new ArrayList<>(claims(ISSUER).entrySet()))).sign(TestJsonWebKeys.Fixture.NEGATIVE_ATTACKER_RSA_2048.getPrivateKey());
        assertEquals(Optional.of(JoseException.Reason.SIGNATURE_MISMATCH),assertInstanceOf(AccessTokenValidationResult.Rejected.class,jwt().build().validateResult(bearer(forged))).getJoseReason());
        try(TestHttpsServer server=TestHttpsServer.start()) {
            response(server,"/jwks",503,"application/json","{}");JwtAccessTokenValidator validator=jwt().jsonWebKeySource(RemoteJsonWebKeySource.withUri(server.uri("/jwks")).httpClient(TestTls.httpClient()).build()).build();
            assertThrows(JsonWebKeySetUnavailableException.class,()->validator.validateResult(bearer(token(claims(ISSUER),"at+jwt"))));assertEquals(1,server.getRequests().size());
        }
    }
    @TestFactory Stream<DynamicTest> explicitlyConfiguredPublicKeyAlgorithmsUseTheExistingEngine() {
        return Stream.of(TestJws.Algorithm.RS256,TestJws.Algorithm.PS256,TestJws.Algorithm.ES256,TestJws.Algorithm.ES384,TestJws.Algorithm.ES512,TestJws.Algorithm.EDDSA,TestJws.Algorithm.ED25519).map(a->DynamicTest.dynamicTest(a.name(),()->{
            TestJsonWebKeys.Fixture f=switch(a) {case ES256->TestJsonWebKeys.Fixture.IDP_SIGNING_EC_P256;case ES384->TestJsonWebKeys.Fixture.IDP_SIGNING_EC_P384;case ES512->TestJsonWebKeys.Fixture.IDP_SIGNING_EC_P521;case EDDSA,ED25519->TestJsonWebKeys.Fixture.ED25519;default->TestJsonWebKeys.Fixture.IDP_SIGNING_RSA_2048;};
            JwsAlgorithm algorithm=JwsAlgorithm.valueOf(a.name());StaticJsonWebKeySource source=StaticJsonWebKeySource.fromJsonWebKeySet(JsonWebKeySet.fromJson(TestJsonWebKeys.withFixture(f).kid("key").alg(a.getWireValue()).toKeySetJson()));
            String compact=TestJws.withAlgorithm(a).kid("key").typ("at+jwt").payload(JsonText.object(new ArrayList<>(claims(ISSUER).entrySet()))).sign(f.getPrivateKey());
            assertNotNull(jwt().jsonWebKeySource(source).allowedAlgorithms(Set.of(algorithm)).build().validate(bearer(compact)));
            if(algorithm!=JwsAlgorithm.RS256)assertInstanceOf(AccessTokenValidationResult.Rejected.class,jwt().jsonWebKeySource(source).build().validateResult(bearer(compact)));
        }));
    }
    @Test void allHmacAlgorithmsAreInvalidConfigurationAndNeverCauseKeyRequests() {
        for(JwsAlgorithm a:Set.of(JwsAlgorithm.HS256,JwsAlgorithm.HS384,JwsAlgorithm.HS512))assertThrows(IllegalArgumentException.class,()->jwt().allowedAlgorithms(Set.of(a)).build());
    }
    @Test void preparedOperationRechecksLengthAndAlgorithmBeforeSelectingKeys() throws Exception {
        Map<String,String> c=claims(ISSUER);c.put("large",JsonText.string("x".repeat(9000)));PreparedJws p=JwtProcessor.prepare(token(c,"at+jwt"),JoseHeaderPolicy.fromSettings(65536,Set.of(JwsAlgorithm.RS256),Set.of("at+jwt"),true));
        JwtValidator v=JwtValidator.withIssuer(ISSUER).jsonWebKeySource(keys()).expectedAudiences(Set.of(AUD)).allowedTypes(Set.of("at+jwt")).maximumTokenLength(8192).clock(CLOCK).build();assertEquals(JoseException.Reason.TOKEN_TOO_LARGE,assertThrows(JoseException.class,()->JwtValidationAccess.get().validatePrepared(v,p,()->Duration.ofSeconds(1).toNanos())).getReason());
        JwtValidator wrong=JwtValidator.withIssuer(ISSUER).jsonWebKeySource(keys()).expectedAudiences(Set.of(AUD)).allowedTypes(Set.of("at+jwt")).allowedAlgorithms(Set.of(JwsAlgorithm.PS256)).clock(CLOCK).build();assertEquals(JoseException.Reason.ALGORITHM_NOT_ALLOWED,assertThrows(JoseException.class,()->JwtValidationAccess.get().validatePrepared(wrong,p,()->Duration.ofSeconds(1).toNanos())).getReason());
    }

    @Test void clockRegressionStillChecksCurrentIssuedAtAndExactZeroSkew() {
        RewindableClock clock=RewindableClock.fromInstant(NOW);JwtAccessTokenValidator validator=jwt().clock(clock).clockSkew(Duration.ZERO).build();BearerToken input=bearer(token(claims(ISSUER),"at+jwt"));assertNotNull(validator.validate(input));clock.rewind(Duration.ofSeconds(1));assertEquals(Optional.of(JoseException.Reason.ISSUED_IN_FUTURE),assertInstanceOf(AccessTokenValidationResult.Rejected.class,validator.validateResult(input)).getJoseReason());clock.advance(Duration.ofSeconds(1));assertNotNull(validator.validate(input));
    }

}
