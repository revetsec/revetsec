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

package verification.store;

import com.revetsec.StateSealer;
import com.revetsec.SealingKey;
import com.revetsec.oauth.BearerToken;
import com.revetsec.oauth.server.*;
import org.jspecify.annotations.NonNull;
import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.*;

/** Fixed test application configuration; private keys/credentials live only in an ephemeral owned directory. */
final class IssuerFixture {
    static final @NonNull String RESOURCE="https://resource.example/mcp";
    static final @NonNull String REDIRECT="https://client.example/cb";
    static final @NonNull String BROWSER="A".repeat(43);
    static final @NonNull String VERIFIER="dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    final @NonNull OAuthAuthorizationServer server;
    IssuerFixture(@NonNull OAuthAuthorizationServerStore store,@NonNull Path secrets,@NonNull String issuer,@NonNull Instant now) throws Exception {
        this(store,secrets,issuer,now,"old");
    }
    IssuerFixture(@NonNull OAuthAuthorizationServerStore store,@NonNull Path secrets,@NonNull String issuer,@NonNull Instant now,@NonNull String sealingMode) throws Exception {
        KeyFactory factory=KeyFactory.getInstance("RSA");
        var privateKey=factory.generatePrivate(new PKCS8EncodedKeySpec(Files.readAllBytes(secrets.resolve("private.der"))));
        var publicKey=factory.generatePublic(new X509EncodedKeySpec(Files.readAllBytes(secrets.resolve("public.der"))));
        var keys=OAuthIssuerKeySnapshot.withActiveKey(OAuthIssuerSigningKey.fromKeyPair("fixture",privateKey,publicKey))
            .generation("g1").publishedAt(Instant.parse("2026-10-06T11:00:00Z")).build();
        var resources=Map.of(RESOURCE,Set.of("read"));
        var client=OAuthServerClientRegistration.withClientId("client").configurationVersion("v1")
            .redirectUris(List.of(URI.create(REDIRECT))).allowedScopesByResource(resources).refreshTokenPermitted(true).build();
        var resource=OAuthServerClientRegistration.withClientId("resource").configurationVersion("v1").authorizationCodePermitted(false)
            .introspectionResources(Set.of(RESOURCE)).authentication(OAuthServerClientAuthentication.fromClientSecretVerifier(
                (id,secret,budget)->Arrays.equals(secret,"fixture-secret".getBytes(StandardCharsets.UTF_8)))).build();
        this.server=OAuthAuthorizationServer.withIssuer(issuer).authorizationEndpoint(URI.create(issuer+"/authorize"))
            .tokenEndpoint(URI.create(issuer+"/token")).jsonWebKeySetEndpoint(URI.create(issuer+"/jwks"))
            .revocationEndpoint(URI.create(issuer+"/revoke")).introspectionEndpoint(URI.create(issuer+"/introspect")).clientRepository((id,budget)->Optional.ofNullable(
                id.equals("client")?client:id.equals("resource")?resource:null)).store(store)
            .signingKeys(OAuthIssuerKeyProvider.fromSnapshot(keys)).resources(resources)
            .stateSealer(sealer(secrets,sealingMode))
            .grantPolicy((context,budget)->decision()).refreshTokensEnabled(true).clock(Clock.fixed(now,ZoneOffset.UTC))
            .totalDeadline(java.time.Duration.ofSeconds(30)).build();
    }
    private static @NonNull StateSealer sealer(@NonNull Path secrets,@NonNull String mode) throws Exception {
        SealingKey old=SealingKey.fromBase64("fixture",Files.readString(secrets.resolve("sealer.txt")).strip());
        SealingKey next=SealingKey.fromBase64("fixture-next",Files.readString(secrets.resolve("sealer-next.txt")).strip());
        return switch(mode) {
            case "old"->StateSealer.withActiveKey(old).build();
            case "old-with-next"->StateSealer.withActiveKey(old).verificationKeys(List.of(next)).build();
            case "next-with-old"->StateSealer.withActiveKey(next).verificationKeys(List.of(old)).build();
            case "next-only"->StateSealer.withActiveKey(next).build();
            case "lost"->StateSealer.withActiveKey(SealingKey.fromBase64("fixture",Files.readString(secrets.resolve("sealer-next.txt")).strip())).build();
            default->throw new IllegalArgumentException("Unknown sealing profile");
        };
    }
    @NonNull String begin() {
        String query=form(Map.of("client_id","client","response_type","code","redirect_uri",REDIRECT,"resource",RESOURCE,
            "code_challenge","E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM","code_challenge_method","S256","state","fixture"));
        return ((OAuthAuthorizationResult.InteractionRequired)this.server.beginAuthorizationResult("GET",query,new byte[0],Map.of(),BROWSER)).getInteraction().getInteractionValue();
    }
    @NonNull OAuthAuthorizationResult complete(@NonNull String handle) {
        return this.server.completeAuthorizationResult(handle,BROWSER,decision());
    }
    static @NonNull OAuthAuthorizationDecision decision() {
        return OAuthAuthorizationDecision.withSubject("subject").authorizedScopesByResource(Map.of(RESOURCE,Set.of("read"))).refreshTokenPermitted(true).build();
    }
    static @NonNull String form(@NonNull Map<@NonNull String,@NonNull String> values) {
        List<String> pairs=new ArrayList<>();
        values.forEach((key,value)->pairs.add(URLEncoder.encode(key,StandardCharsets.UTF_8)+"="+URLEncoder.encode(value,StandardCharsets.UTF_8)));
        return String.join("&",pairs);
    }
    static byte @NonNull [] body(@NonNull Map<@NonNull String,@NonNull String> values) {return form(values).getBytes(StandardCharsets.UTF_8);}
    static @NonNull Map<@NonNull String,@NonNull List<@NonNull String>> headers() {return Map.of("Content-Type",List.of("application/x-www-form-urlencoded"));}
    @NonNull String code() {
        String query=form(Map.of("client_id","client","response_type","code","redirect_uri",REDIRECT,"resource",RESOURCE,
            "code_challenge","E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM","code_challenge_method","S256","state","fixture"));
        var interaction=((OAuthAuthorizationResult.InteractionRequired)this.server.beginAuthorizationResult("GET",query,new byte[0],Map.of(),BROWSER)).getInteraction();
        var completed=(OAuthAuthorizationResult.Completed)this.server.completeAuthorizationResult(interaction.getInteractionValue(),BROWSER,decision());
        String location=completed.getResponse().getLocationWithCredentials().orElseThrow().toString();
        return location.substring(location.indexOf("code=")+5,location.indexOf("&state="));
    }
    @NonNull OAuthTokenResult redeem(@NonNull String code) {
        return this.server.tokenResult("POST",null,body(Map.of("grant_type","authorization_code","client_id","client","code",code,
            "code_verifier",VERIFIER,"resource",RESOURCE,"redirect_uri",REDIRECT)),headers());
    }
    @NonNull OAuthTokenResult refresh(@NonNull String token) {
        return this.server.tokenResult("POST",null,body(Map.of("grant_type","refresh_token","client_id","client","refresh_token",token,"resource",RESOURCE)),headers());
    }
    // Test-only extraction of the two fixed ASCII fields emitted by this issuer profile.
    // This is not an application JSON parser or an authorization decision.
    static @NonNull String tokenField(@NonNull OAuthServerResponse response,@NonNull String name) {
        if (!Set.of("access_token","refresh_token").contains(name)) throw new IllegalArgumentException("Unknown field");
        String body=new String(response.toHttpBodyWithCredentials(),StandardCharsets.UTF_8);
        var matcher=java.util.regex.Pattern.compile("\""+name+"\"\\s*:\\s*\"([A-Za-z0-9_.-]+)\"").matcher(body);
        if(!matcher.find())throw new IllegalStateException("Missing credential field");String value=matcher.group(1);
        if(matcher.find())throw new IllegalStateException("Duplicate credential field");return value;
    }
    boolean active(@NonNull String token) {
        var bearer=BearerToken.fromAuthorizationHeaderValues(List.of("Bearer "+token)).orElseThrow();
        return this.server.validateAccessTokenResult(bearer,RESOURCE) instanceof OAuthIssuerAccessTokenResult.Succeeded;
    }
}
