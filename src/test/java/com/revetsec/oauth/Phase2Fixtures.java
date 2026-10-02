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

import org.jspecify.annotations.NonNull;

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

/** Synthetic signed fixtures; signatures use the independent JDK test signer, never Revetsec validation. */
final class Phase2Fixtures {
    static final String ISSUER="https://issuer.example", AUD="resource", SECRET="TEST-ONLY-confidential-secret";
    static final Instant NOW=Instant.parse("2026-10-01T12:00:00Z");
    static final Clock CLOCK=Clock.fixed(NOW,ZoneOffset.UTC);
    private Phase2Fixtures() { }
    static @NonNull Map<@NonNull String,@NonNull String> claims(@NonNull String issuer) {
        Map<String,String> c=new LinkedHashMap<>(); c.put("iss",JsonText.string(issuer));c.put("sub","\"TEST-ONLY-subject\"");c.put("aud",JsonText.string(AUD));
        c.put("exp",Long.toString(NOW.plusSeconds(300).getEpochSecond()));c.put("iat",Long.toString(NOW.getEpochSecond()));c.put("client_id","\"TEST-ONLY-client\"");c.put("jti","\"TEST-ONLY-jti\"");c.put("scope","\"read write\"");return c;
    }
    static @NonNull String token(@NonNull Map<@NonNull String,@NonNull String> claims,@Nullable String typ) {
        return TestJws.withAlgorithm(TestJws.Algorithm.RS256).kid("key").typ(typ).payload(JsonText.object(new ArrayList<>(claims.entrySet()))).sign(TestJsonWebKeys.Fixture.IDP_SIGNING_RSA_2048.getPrivateKey());
    }
    static @NonNull String keyJson() { return TestJsonWebKeys.withFixture(TestJsonWebKeys.Fixture.IDP_SIGNING_RSA_2048).kid("key").alg("RS256").toKeySetJson(); }
    static @NonNull StaticJsonWebKeySource keys() { return StaticJsonWebKeySource.fromJsonWebKeySet(JsonWebKeySet.fromJson(keyJson())); }
    static @NonNull BearerToken bearer(@NonNull String token) { return BearerToken.fromAuthorizationHeaderValues(List.of("Bearer "+token),1_048_576).orElseThrow(); }
    static JwtAccessTokenValidator.@NonNull Builder jwt() { return JwtAccessTokenValidator.withIssuer(ISSUER).expectedAudiences(Set.of(AUD)).jsonWebKeySource(keys()).clock(CLOCK).clockSkew(Duration.ZERO); }
    static @NonNull RawResponse raw(int status,@NonNull String json) { return new RawResponse(status,HttpHeaders.of(Map.of(),(a,b)->true),json.getBytes(StandardCharsets.UTF_8),null,false,Duration.ZERO); }
    static void response(@NonNull TestHttpsServer server,@NonNull String path,int status,@NonNull String type,@NonNull String json) {
        server.script(path,TestHttpsServer.Script.fromResponse(TestHttpsServer.Response.withStatus(status).header("Content-Type",type).body(json).build()));
    }
    static OAuthClient.@NonNull Builder oauth(@NonNull TestHttpsServer server) {
        return OAuthClient.withAuthorizationServerMetadata(AuthorizationServerMetadata.withIssuer(server.getBaseUri().toString())
                .authorizationEndpoint(server.uri("/authorize")).tokenEndpoint(server.uri("/token")).introspectionEndpoint(server.uri("/inspect")).build())
                .clientId("client").clientAuthentication(ClientAuthentication.fromClientSecretBasic(SECRET)).clock(CLOCK).httpClient(TestTls.httpClient());
    }
    static TokenIntrospectionClient.@NonNull Builder inspect(@NonNull TestHttpsServer server) { return TokenIntrospectionClient.withOAuthClient(oauth(server).build()).expectedAudiences(Set.of(AUD)).clockSkew(Duration.ZERO); }
    static @NonNull String active() { return "{\"active\":true,\"aud\":\"resource\",\"scope\":\"read write\"}"; }
    static void redacted(@NonNull Object value,@NonNull String @NonNull ...secrets) { for(String secret:secrets) assertFalse(value.toString().contains(secret),value.getClass().getSimpleName()); }
}
