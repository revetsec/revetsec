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
package example.issuer;

import com.revetsec.SealingKey;
import com.revetsec.StateSealer;
import com.revetsec.oauth.BearerToken;
import com.revetsec.oauth.server.OAuthAuthorizationDecision;
import com.revetsec.oauth.server.OAuthAuthorizationResult;
import com.revetsec.oauth.server.OAuthIssuerAccessTokenResult;
import com.revetsec.oauth.server.OAuthIssuerKeyProvider;
import com.revetsec.oauth.server.OAuthIssuerKeySnapshot;
import com.revetsec.oauth.server.OAuthIssuerSigningKey;
import com.revetsec.oauth.server.OAuthServerStoreException;
import com.soklet.HttpMethod;
import com.soklet.MarshaledResponse;
import com.soklet.MarshaledResponseBody;
import com.soklet.Request;
import com.soklet.Soklet;
import example.pending.PostgresqlIssuerStore;
import org.jspecify.annotations.NonNull;

import java.net.URI;
import java.net.URLEncoder;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.SecureRandom;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** Separate-JVM application startup probe. SQL and transactions remain owned by the Pyranid store. */
public final class PostgresqlIssuerApplicationProbe {
    private static final @NonNull String BROWSER="A".repeat(43);
    private static final @NonNull String VERIFIER="dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    private PostgresqlIssuerApplicationProbe() { }

    private static @NonNull Connection connection(@NonNull Duration remaining) throws SQLException {
        if(remaining.isZero() || remaining.isNegative() || Thread.currentThread().isInterrupted())
            throw new SQLException("Application connection budget expired.");
        int seconds=Math.max(1,(int)Math.min(30,(remaining.toMillis()+999)/1_000));
        Properties properties=new Properties();
        properties.setProperty("user",java.util.Objects.requireNonNull(System.getenv("REVETSEC_TEST_DB_USER")));
        properties.setProperty("password",java.util.Objects.requireNonNull(System.getenv("REVETSEC_TEST_DB_PASSWORD")));
        properties.setProperty("connectTimeout",Integer.toString(seconds));
        properties.setProperty("socketTimeout",Integer.toString(seconds));
        properties.setProperty("gssEncMode","disable");
        return DriverManager.getConnection(java.util.Objects.requireNonNull(System.getenv("REVETSEC_TEST_DB_URL")),properties);
    }

    private static @NonNull IssuerResources app(IssuerResources.@NonNull StartupMode mode,
            boolean wrongSealingKey) throws Exception {
        Path directory=Path.of(java.util.Objects.requireNonNull(System.getenv("REVETSEC_TEST_ISSUER_SECRET_DIR")));
        KeyFactory factory=KeyFactory.getInstance("RSA");
        var privateKey=factory.generatePrivate(new PKCS8EncodedKeySpec(Files.readAllBytes(directory.resolve("private.der"))));
        var publicKey=factory.generatePublic(new X509EncodedKeySpec(Files.readAllBytes(directory.resolve("public.der"))));
        var nextPrivateKey=factory.generatePrivate(new PKCS8EncodedKeySpec(Files.readAllBytes(directory.resolve("private-next.der"))));
        var nextPublicKey=factory.generatePublic(new X509EncodedKeySpec(Files.readAllBytes(directory.resolve("public-next.der"))));
        Clock clock=Clock.fixed(Instant.ofEpochSecond(Long.parseLong(
                java.util.Objects.requireNonNull(System.getenv("REVETSEC_TEST_ISSUER_TIME")))),ZoneOffset.UTC);
        Instant retirement=clock.instant().plusSeconds(3_600);
        OAuthIssuerKeySnapshot first=OAuthIssuerKeySnapshot.withActiveKey(
                OAuthIssuerSigningKey.fromKeyPair("fixture",privateKey,publicKey))
                .generation("g1").publishedAt(clock.instant().minusSeconds(2))
                .retirementNotBefore(Map.of("fixture",retirement)).build();
        OAuthIssuerKeySnapshot second=OAuthIssuerKeySnapshot.withActiveKey(
                OAuthIssuerSigningKey.fromKeyPair("fixture-next",nextPrivateKey,nextPublicKey))
                .verificationKeys(Map.of("fixture",publicKey))
                .generation("g2").publishedAt(clock.instant().minusSeconds(1))
                .retirementNotBefore(Map.of("fixture",retirement)).build();
        OAuthIssuerKeySnapshot earlyRemoval=OAuthIssuerKeySnapshot.withActiveKey(
                OAuthIssuerSigningKey.fromKeyPair("fixture-next",nextPrivateKey,nextPublicKey))
                .generation("g3").publishedAt(clock.instant()).build();
        Path generation=directory.resolve("key-generation.txt");
        OAuthIssuerKeyProvider keys=remainingBudget -> {
            if(remainingBudget.isZero() || remainingBudget.isNegative() || Thread.currentThread().isInterrupted())
                throw new IllegalStateException("Application key lookup budget expired.");
            try {
                return switch(Files.readString(generation,StandardCharsets.US_ASCII)) {
                    case "g1" -> first;
                    case "g2" -> second;
                    case "g3" -> earlyRemoval;
                    default -> throw new IllegalStateException("Unknown application key generation.");
                };
            } catch(IOException failure) {throw new IllegalStateException("Application key generation unavailable.",failure);}
        };
        byte[] sealing=wrongSealingKey?new byte[32]:null;
        if(sealing!=null)new SecureRandom().nextBytes(sealing);
        String encoded=sealing==null?Files.readString(directory.resolve("sealer.txt"))
                :Base64.getEncoder().encodeToString(sealing);
        if(sealing!=null)java.util.Arrays.fill(sealing,(byte)0);
        StateSealer sealer=StateSealer.withActiveKey(SealingKey.fromBase64("fixture",encoded)).build();
        int httpPort=Integer.parseInt(java.util.Objects.requireNonNull(System.getenv("REVETSEC_TEST_ISSUER_HTTP_PORT")));
        int mcpPort=Integer.parseInt(java.util.Objects.requireNonNull(System.getenv("REVETSEC_TEST_ISSUER_MCP_PORT")));
        IssuerConfig config=new IssuerConfig(URI.create("http://127.0.0.1:"+httpPort),
                URI.create("http://127.0.0.1:"+mcpPort+"/mcp"),URI.create("https://client.example/cb"),
                httpPort,mcpPort,"A".repeat(43),"B".repeat(42)+"A","C".repeat(42)+"A",true);
        PostgresqlIssuerStore store=new PostgresqlIssuerStore("fixture_issuer_app",
                PostgresqlIssuerApplicationProbe::connection,256);
        return new IssuerResources(config,clock,store,keys,sealer,mode);
    }

    private static @NonNull String form(@NonNull Map<@NonNull String,@NonNull String> values) {
        return values.entrySet().stream().map(item->URLEncoder.encode(item.getKey(),StandardCharsets.UTF_8)
                +"="+URLEncoder.encode(item.getValue(),StandardCharsets.UTF_8))
                .reduce((left,right)->left+"&"+right).orElse("");
    }

    private static @NonNull String field(@NonNull String json,@NonNull String name) {
        Matcher match=Pattern.compile("\\\""+name+"\\\"\\s*:\\s*\\\"([A-Za-z0-9_.-]+)\\\"").matcher(json);
        if(!match.find())throw new IllegalStateException("Missing application token field.");
        String value=match.group(1);
        if(match.find())throw new IllegalStateException("Duplicate application token field.");
        return value;
    }

    private static @NonNull String issue(@NonNull IssuerResources app) {
        String resource=app.config.resource.toString();
        String query=form(Map.of("response_type","code","client_id","demo-public",
                "redirect_uri",app.config.redirect.toString(),"resource",resource,
                "scope","mcp:discover mcp:whoami","state","fixture",
                "code_challenge","E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
                "code_challenge_method","S256"));
        var interaction=((OAuthAuthorizationResult.InteractionRequired)app.server.beginAuthorizationResult(
                "GET",query,new byte[0],Map.of(),BROWSER)).getInteraction();
        var completed=(OAuthAuthorizationResult.Completed)app.server.completeAuthorizationResult(
                interaction.getInteractionValue(),BROWSER,OAuthAuthorizationDecision.withSubject(IssuerConfig.SUBJECT)
                        .authorizedScopesByResource(interaction.getRequestedScopesByResource())
                        .refreshTokenPermitted(true).build());
        String location=completed.getResponse().getLocationWithCredentials().orElseThrow().toString();
        int start=location.indexOf("code="),end=location.indexOf("&state=",start);
        if(start<0 || end<=start)throw new IllegalStateException("Missing application code.");
        return location.substring(start+5,end);
    }

    private static @NonNull String token(@NonNull IssuerResources app,@NonNull Map<@NonNull String,@NonNull String> fields) {
        byte[] body=form(fields).getBytes(StandardCharsets.UTF_8);
        Request request=Request.withRawUrl(HttpMethod.POST,"/token")
                .headers(Map.of("Host",Set.of(app.config.origin.getRawAuthority()),
                        "Content-Type",Set.of("application/x-www-form-urlencoded")))
                .body(body).build();
        MarshaledResponse response=app.token(request);
        if(response.getStatusCode()!=200)return "REJECTED";
        String json=new String(((MarshaledResponseBody.Bytes)response.getBody().orElseThrow()).getBytes(),
                StandardCharsets.UTF_8);
        return "PAIR:"+field(json,"access_token")+"\t"+field(json,"refresh_token");
    }

    public static void main(@NonNull String @NonNull [] args) throws Exception {
        switch(args[0]) {
            case "fresh" -> {
                IssuerResources app=app(IssuerResources.StartupMode.FRESH,false);
                System.out.println(token(app,Map.of("grant_type","authorization_code","client_id","demo-public",
                        "code",issue(app),"code_verifier",VERIFIER,"resource",app.config.resource.toString(),
                        "redirect_uri",app.config.redirect.toString())));
            }
            case "fresh-again" -> {
                try {app(IssuerResources.StartupMode.FRESH,false);throw new IllegalStateException("Reinitialized issuer.");}
                catch(IllegalStateException expected) {
                    if(!"Fresh demo store initialization failed.".equals(expected.getMessage()))throw expected;
                    System.out.println("FRESH_CONFLICT");
                }
            }
            case "wrong-seal" -> {
                try {app(IssuerResources.StartupMode.ESTABLISHED,true);
                    throw new IllegalStateException("Opened issuer with wrong sealing key.");}
                catch(OAuthServerStoreException expected) {System.out.println("SEALED_FENCE_REJECTED");}
            }
            case "established-active" -> {
                IssuerResources app=app(IssuerResources.StartupMode.ESTABLISHED,false);
                var status=app.server.validateAccessTokenResult(BearerToken.fromAuthorizationHeaderValues(
                        List.of("Bearer "+args[1])).orElseThrow(),app.config.resource.toString());
                System.out.println(status instanceof OAuthIssuerAccessTokenResult.Succeeded?"ACTIVE":"INACTIVE");
            }
            case "established-refresh" -> {
                IssuerResources app=app(IssuerResources.StartupMode.ESTABLISHED,false);
                System.out.println(token(app,Map.of("grant_type","refresh_token","client_id","demo-public",
                        "refresh_token",args[1],"resource",app.config.resource.toString())));
            }
            case "serve" -> {
                IssuerResources app=app(IssuerResources.StartupMode.ESTABLISHED,false);
                try(Soklet soklet=Soklet.fromConfig(IssuerPlayground.sokletConfig(app))) {
                    soklet.start();
                    System.out.println("READY");System.out.flush();
                    if(System.in.read()==-1)return;
                }
            }
            default -> throw new IllegalArgumentException("Unknown application probe mode.");
        }
    }
}
