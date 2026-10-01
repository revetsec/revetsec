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

/** Approved G13 nullable/reset/build/proof conventions and M5 no-I/O runtime boundary. */
final class AccessTokenPhase2ContractTests {
    @Test void proofAndOutcomesCannotBeConstructedOrMintedByPublicFactories() {
        for(Class<?> type:List.of(VerifiedAccessToken.class,AccessTokenValidationResult.class,AccessTokenValidationResult.Succeeded.class,AccessTokenValidationResult.Rejected.class)) {
            for(var c:type.getDeclaredConstructors()) assertFalse(java.lang.reflect.Modifier.isPublic(c.getModifiers())||java.lang.reflect.Modifier.isProtected(c.getModifiers()));
            for(var m:type.getDeclaredMethods()) assertFalse(java.lang.reflect.Modifier.isStatic(m.getModifiers())&&java.lang.reflect.Modifier.isPublic(m.getModifiers()));
        }
        assertTrue(AccessTokenValidator.class.isSealed());assertEquals(Set.of(JwtAccessTokenValidator.class,TokenIntrospectionClient.class),Set.of(AccessTokenValidator.class.getPermittedSubclasses()));
        VerifiedAccessToken proof=jwt().build().validate(bearer(token(claims(ISSUER),"at+jwt")));
        assertFalse(Arrays.stream(VerifiedAccessToken.class.getDeclaredFields()).anyMatch(f->f.getType()==Jwt.class||f.getName().equals("token")));
        assertThrows(UnsupportedOperationException.class,()->proof.getScopes().add("write-other"));assertThrows(UnsupportedOperationException.class,()->proof.getAudiences().add("other"));
    }
    @Test void mutableBuilderChangesCannotAffectBuiltValidatorAndAllSettersReset() {
        JwtAccessTokenValidator.Builder builder=jwt().expectedAudiences(Set.of(AUD)).allowedAlgorithms(Set.of(JwsAlgorithm.RS256)).requiredClaims(Set.of("app")).scopeClaimName("scp").compatibility(AccessTokenCompatibilityMode.UNTYPED_ACCESS_TOKENS)
                .maximumTokenLength(8192).clockSkew(Duration.ofSeconds(5)).clock(CLOCK).httpClient(TestTls.httpClient()).outboundUriPolicy(OutboundUriPolicy.publicAddressesOnlyInstance())
                .requestTimeout(Duration.ofSeconds(1)).totalDeadline(Duration.ofSeconds(2)).minimumTimeToLive(Duration.ofSeconds(30)).defaultTimeToLive(Duration.ofSeconds(30)).maximumTimeToLive(Duration.ofSeconds(60)).discoveryCooldown(Duration.ofSeconds(1))
                .allowInsecureLoopback(true).acknowledgeUnpatchedRuntime(true).observer(new AccessTokenObserver(){});
        assertSame(builder,builder.allowedAlgorithms(null).requiredClaims(null).scopeClaimName(null).compatibility(null).maximumTokenLength(null).clockSkew(null).clock(null).httpClient(null).outboundUriPolicy(null).requestTimeout(null).totalDeadline(null)
                .minimumTimeToLive(null).defaultTimeToLive(null).maximumTimeToLive(null).discoveryCooldown(null).allowInsecureLoopback(null).acknowledgeUnpatchedRuntime(null).observer(null).clock(CLOCK).clockSkew(Duration.ZERO));
        JwtAccessTokenValidator before=builder.build();assertSame(builder,builder.expectedAudiences(Set.of("other")));assertNotNull(before.validate(bearer(token(claims(ISSUER),"at+jwt"))));
        assertSame(builder,builder.expectedAudiences(null));assertThrows(IllegalStateException.class,builder::build);
        assertThrows(IllegalArgumentException.class,()->jwt().expectedAudiences(Set.of()));assertThrows(IllegalArgumentException.class,()->jwt().expectedAudiences(Set.of("")));assertThrows(IllegalArgumentException.class,()->jwt().requiredClaims(Set.of("")));
        assertThrows(IllegalArgumentException.class,()->jwt().scopeClaimName("custom"));assertThrows(IllegalArgumentException.class,()->jwt().allowedAlgorithms(Set.of()).build());assertThrows(IllegalArgumentException.class,()->jwt().allowedAlgorithms(Set.of(JwsAlgorithm.HS256)).build());
        assertThrows(IllegalArgumentException.class,()->jwt().maximumTokenLength(8191));assertThrows(IllegalArgumentException.class,()->jwt().clockSkew(Duration.ofSeconds(-1)));assertThrows(IllegalArgumentException.class,()->jwt().requestTimeout(Duration.ofSeconds(20)).totalDeadline(Duration.ofSeconds(15)).build());
        assertThrows(IllegalArgumentException.class,()->jwt().minimumTimeToLive(Duration.ofHours(1)).defaultTimeToLive(Duration.ofMinutes(1)).build());
    }
    @Test void staticKeysBypassNetworkRuntimeGuardButNetworkedBuildFailsClosed() throws Exception {
        Runtime.Version old=Runtime.Version.parse("17.0.1");JwtAccessTokenValidator staticKeys=jwt().build(old);staticKeys.warmUp();assertNotNull(staticKeys.validate(bearer(token(claims(ISSUER),"at+jwt"))));
        assertThrows(IllegalStateException.class,()->JwtAccessTokenValidator.withIssuer(ISSUER).expectedAudiences(Set.of(AUD)).build(old));
        AtomicInteger warnings=new AtomicInteger();assertNotNull(JwtAccessTokenValidator.withIssuer(ISSUER).expectedAudiences(Set.of(AUD)).acknowledgeUnpatchedRuntime(true).observer(new AccessTokenObserver(){@Override public void didUseUnpatchedRuntime(String v){warnings.incrementAndGet();}}).build(old));assertEquals(1,warnings.get());
        assertThrows(IllegalArgumentException.class,()->JwtAccessTokenValidator.withIssuer("https://issuer.example?bad").expectedAudiences(Set.of(AUD)).build());
        assertThrows(IllegalArgumentException.class,()->JwtAccessTokenValidator.withIssuer("http://10.0.0.1").expectedAudiences(Set.of(AUD)).build());
        try(TestHttpsServer server=TestHttpsServer.start()) {
            assertNotNull(JwtAccessTokenValidator.withIssuer(server.getBaseUri().toString()).expectedAudiences(Set.of(AUD)).jsonWebKeySource(null).httpClient(TestTls.httpClient()).build());assertEquals(0,server.getRequests().size());
        }
    }
    @Test void introspectionSettersResetAndBoundsRejectBeforeIo() throws Exception {
        try(TestHttpsServer server=TestHttpsServer.start()) {
            TokenIntrospectionClient.Builder b=inspect(server).requiredClaims(Set.of("app")).maximumTokenLength(8192).introspectionEndpoint(server.uri("/override")).clockSkew(Duration.ofSeconds(5)).observer(new AccessTokenObserver(){});
            TokenIntrospectionClient c=b.requiredClaims(null).maximumTokenLength(null).introspectionEndpoint(null).clockSkew(null).observer(null).build();c.warmUp();assertEquals(0,server.getRequests().size());
            assertSame(b,b.expectedAudiences(null));assertThrows(IllegalStateException.class,b::build);assertThrows(IllegalArgumentException.class,()->inspect(server).expectedAudiences(Set.of()));assertThrows(IllegalArgumentException.class,()->inspect(server).requiredClaims(Set.of("")));assertThrows(IllegalArgumentException.class,()->inspect(server).maximumTokenLength(8191));
            assertThrows(IllegalArgumentException.class,()->inspect(server).introspectionEndpoint(URI.create("http://10.0.0.1/inspect")).build());
            TokenIntrospectionClient small=inspect(server).maximumTokenLength(8192).build();assertEquals(AccessTokenValidationException.Reason.MALFORMED_REQUEST,assertInstanceOf(AccessTokenValidationResult.Rejected.class,small.validateResult(bearer("x".repeat(8193)))).getReason());assertEquals(0,server.getRequests().size());
        }
        JwtAccessTokenValidator small=jwt().maximumTokenLength(8192).build();AccessTokenValidationResult.Rejected r=assertInstanceOf(AccessTokenValidationResult.Rejected.class,small.validateResult(bearer("x".repeat(8193))));assertEquals(BearerError.INVALID_REQUEST,r.getBearerError());
    }
    @SuppressWarnings("NullAway") @Test void requiredNullsRemainCallerMisuse() {
        assertThrows(NullPointerException.class,()->JwtAccessTokenValidator.withIssuer(null));assertThrows(NullPointerException.class,()->TokenIntrospectionClient.withOAuthClient(null));
        JwtAccessTokenValidator v=jwt().build();assertThrows(NullPointerException.class,()->v.validateResult(null));
    }
    @Test void duplicateClaimsAndPreparedOperationCannotWeakenTheConfiguredPolicy() throws Exception {
        String payload=JsonText.object(new ArrayList<>(claims(ISSUER).entrySet()));payload=payload.substring(0,payload.length()-1)+",\"aud\":\"resource\"}";
        String duplicate=TestJws.withAlgorithm(TestJws.Algorithm.RS256).kid("key").typ("at+jwt").payload(payload).sign(TestJsonWebKeys.Fixture.IDP_SIGNING_RSA_2048.getPrivateKey());assertInstanceOf(AccessTokenValidationResult.Rejected.class,jwt().build().validateResult(bearer(duplicate)));
        String compact=token(claims(ISSUER),"at+jwt");PreparedJws prepared=JwtProcessor.prepare(compact,JoseHeaderPolicy.fromSettings(65536,Set.of(JwsAlgorithm.RS256),Set.of("at+jwt"),true));
        JwtValidator mismatch=JwtValidator.withIssuer(ISSUER).jsonWebKeySource(keys()).expectedAudiences(Set.of(AUD)).clock(CLOCK).build();assertEquals(JoseException.Reason.INVALID_TYPE,assertThrows(JoseException.class,()->JwtValidationAccess.get().validatePrepared(mismatch,prepared,()->Duration.ofSeconds(10).toNanos())).getReason());
    }
    @Test void resourceBuildsStartNoThreadsAndNeverLoadTheDefaultHttpClient(@org.junit.jupiter.api.io.TempDir java.nio.file.Path directory) throws Exception {
        java.nio.file.Path log=directory.resolve("class-load.log");ChildJvm.Result result=ChildJvm.withMainClass(ResourceBuildChild.class).jvmOptions(List.of("-Xlog:class+load=info:file=\""+log+"\":none:filecount=0")).timeout(Duration.ofSeconds(60)).build().run();
        assertEquals(0,result.getExitCode(),result::toString);assertEquals("5000 resource builds; threads started: 0",result.getStandardOutput().strip(),result::toString);String loaded=java.nio.file.Files.readString(log);assertFalse(loaded.contains("jdk.internal.net.http.HttpClientImpl"));assertFalse(loaded.contains("com.revetsec.internal.http.DefaultHttpClientHolder"));assertTrue(loaded.contains(JwtAccessTokenValidator.class.getName()));assertTrue(loaded.contains(TokenIntrospectionClient.class.getName()));
    }
    public static final class ResourceBuildChild {
        private ResourceBuildChild() { }
        public static void main(String[] arguments) {
            StaticJsonWebKeySource staticKeys=keys();RemoteJsonWebKeySource remote=RemoteJsonWebKeySource.withUri(URI.create(ISSUER+"/keys")).build();
            OAuthClient discovered=OAuthClient.withIssuer(ISSUER).clientId("app").clientAuthentication(ClientAuthentication.fromClientSecretBasic(SECRET)).build();
            OAuthClient configured=OAuthClient.withAuthorizationServerMetadata(AuthorizationServerMetadata.withIssuer(ISSUER).authorizationEndpoint(URI.create(ISSUER+"/authorize")).tokenEndpoint(URI.create(ISSUER+"/token")).introspectionEndpoint(URI.create(ISSUER+"/inspect")).build()).clientId("app").clientAuthentication(ClientAuthentication.fromClientSecretBasic(SECRET)).build();
            java.lang.management.ThreadMXBean threads=java.lang.management.ManagementFactory.getThreadMXBean();long before=threads.getTotalStartedThreadCount();
            for(int i=0;i<1000;i++) {
                assertNotNull(JwtAccessTokenValidator.withIssuer(ISSUER).expectedAudiences(Set.of(AUD)).build());assertNotNull(JwtAccessTokenValidator.withIssuer(ISSUER).expectedAudiences(Set.of(AUD)).jsonWebKeySource(staticKeys).build());assertNotNull(JwtAccessTokenValidator.withIssuer(ISSUER).expectedAudiences(Set.of(AUD)).jsonWebKeySource(remote).build());assertNotNull(TokenIntrospectionClient.withOAuthClient(discovered).expectedAudiences(Set.of(AUD)).build());assertNotNull(TokenIntrospectionClient.withOAuthClient(configured).expectedAudiences(Set.of(AUD)).build());
            }
            System.out.println("5000 resource builds; threads started: "+(threads.getTotalStartedThreadCount()-before));
        }
    }

}
