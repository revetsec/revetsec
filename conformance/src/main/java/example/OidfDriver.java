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

package example;

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

import com.revetsec.*;
import com.revetsec.internal.json.JsonCodec;
import com.revetsec.internal.json.JsonLimits;
import com.revetsec.json.*;
import com.revetsec.jose.RemoteJsonWebKeySource;
import com.revetsec.oauth.*;
import com.revetsec.oidc.*;
import javax.net.ssl.*;
import java.net.*;
import java.net.http.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.*;
import java.security.cert.CertificateFactory;
import java.time.Duration;
import java.util.*;
import java.util.regex.*;

// Unpublished local harness. Uses only disposable suite credentials; raw suite logs contain those values.
public final class OidfDriver {
    static final URI BASE = URI.create("https://localhost.emobix.co.uk:8443");
    static final URI CALLBACK = URI.create("http://localhost:18080/callback");
    static final String CLIENT = "revetsec-rp";
    static final String SECRET = "test-only-revetsec-rp-secret";
    static final List<String> PLANS = List.of("oidcc-client-basic-certification-test-plan",
        "oidcc-client-config-certification-test-plan", "oidcc-client-formpost-basic-certification-test-plan",
        "oidcc-client-refreshtoken-test-plan");
    static final Map<String, Set<String>> REJECTIONS = Map.ofEntries(
        Map.entry("oidcc-client-test-invalid-iss", Set.of("ISSUER_MISMATCH")),
        Map.entry("oidcc-client-test-missing-sub", Set.of("MISSING_CLAIM", "INVALID_SUBJECT")),
        Map.entry("oidcc-client-test-invalid-aud", Set.of("AUDIENCE_MISMATCH")),
        Map.entry("oidcc-client-test-missing-iat", Set.of("MISSING_CLAIM")),
        Map.entry("oidcc-client-test-kid-absent-multiple-jwks", Set.of("ID_TOKEN_SIGNATURE_INVALID:AMBIGUOUS_KEY")),
        Map.entry("oidcc-client-test-idtoken-sig-none", Set.of("ALGORITHM_NOT_ALLOWED")),
        Map.entry("oidcc-client-test-invalid-sig-rs256", Set.of("ID_TOKEN_SIGNATURE_INVALID")),
        Map.entry("oidcc-client-test-userinfo-invalid-sub", Set.of("USERINFO_SUBJECT_MISMATCH")),
        Map.entry("oidcc-client-test-nonce-invalid", Set.of("NONCE_MISMATCH")),
        Map.entry("oidcc-client-test-discovery-issuer-mismatch", Set.of("OAUTH:ISSUER_MISMATCH")),
        Map.entry("oidcc-client-test-refresh-token-invalid-issuer", Set.of("ISSUER_MISMATCH")),
        Map.entry("oidcc-client-test-refresh-token-invalid-sub", Set.of("REFRESHED_ID_TOKEN_MISMATCH")));
    final HttpClient http;
    final Path output;
    final StateSealer sealer;
    final List<JsonValue> outcomes = new ArrayList<>();
    OidfDriver(@NonNull Path cert, @NonNull Path output) throws Exception {
        this.output = output; Files.createDirectories(output);
        KeyStore store = KeyStore.getInstance(KeyStore.getDefaultType()); store.load(null, null);
        try (var in = Files.newInputStream(cert)) { store.setCertificateEntry("local-suite", CertificateFactory.getInstance("X.509").generateCertificate(in)); }
        TrustManagerFactory trust = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm()); trust.init(store);
        SSLContext tls = SSLContext.getInstance("TLS"); tls.init(null, trust.getTrustManagers(), null);
        this.http = HttpClient.newBuilder().sslContext(tls).followRedirects(HttpClient.Redirect.NEVER).connectTimeout(Duration.ofSeconds(5)).build();
        byte[] key = new byte[32]; new SecureRandom().nextBytes(key);
        this.sealer = StateSealer.withActiveKey(SealingKey.fromBase64("local-run", Base64.getEncoder().encodeToString(key))).build(); Arrays.fill(key, (byte)0);
    }
    public static void main(@NonNull String @NonNull [] args) throws Exception {
        if (args.length != 2) throw new IllegalArgumentException("Usage: OidfDriver certificate output-directory");
        new OidfDriver(Path.of(args[0]), Path.of(args[1])).run();
    }
    void run() throws Exception {
        JsonObject server = object(api("GET", "/api/server", null)); save(output.resolve("server.json"), server);
        check(text(server,"tag").equals("release-v5.3.1") && text(server,"revision").equals("440eec8"), "Unexpected suite revision");
        for (String plan : PLANS) runPlan(plan);
        save(output.resolve("outcomes.json"), JsonArray.fromElements(outcomes));
        check(outcomes.size() == 37, "Unexpected module count");
        check(outcomes.stream().allMatch(v -> ((JsonObject)v).findBoolean("accepted").orElse(false)), "OIDF gate failed; see module evidence");
        System.out.println("Completed 37 module runs.");
    }
    void runPlan(@NonNull String plan) throws Exception {
        Path dir = output.resolve(plan); Files.createDirectories(dir);
        var variants = JsonObject.builder().put("client_registration", "static_client").put("request_type", "plain_http_request");
        if (plan.contains("config") || plan.contains("refreshtoken")) variants.put("response_mode", "default").put("client_auth_type", "client_secret_basic");
        if (plan.contains("refreshtoken")) variants.put("response_type", "code");
        JsonObject variant = variants.build();
        JsonObject config = JsonObject.builder().put("alias", "revetsec-"+UUID.randomUUID()).put("description", "Local Revetsec RP test")
            .put("waitTimeoutSeconds", 3L).put("client", JsonObject.builder().put("client_id", CLIENT).put("client_secret", SECRET)
            .put("redirect_uri", CALLBACK.toString()).build()).build();
        JsonObject created = object(api("POST", "/api/plan?planName="+plan+"&variant="+encode(json(variant)), config));
        save(dir.resolve("created.json"), created);
        String planId = text(created,"id");
        for (JsonValue entry : array(created,"modules").getElements()) runModule(planId, object(entry), dir);
        save(dir.resolve("plan-final.json"), api("GET", "/api/plan/"+planId, null));
        byte[] export = request("GET", BASE.resolve("/api/plan/export/"+planId), null).body(); Files.write(dir.resolve("suite-export.zip"), export);
    }
    void runModule(@NonNull String planId, @NonNull JsonObject module, @NonNull Path dir) throws Exception {
        String name = text(module,"testModule"); Path evidence = dir.resolve(name); Files.createDirectories(evidence);
        JsonObject created = object(api("POST", "/api/runner?test="+name+"&plan="+planId, null)); save(evidence.resolve("created.json"), created);
        String id = text(created,"id");
        JsonObject state = waitFor(id, Set.of("WAITING","FINISHED","INTERRUPTED"), 20);
        save(evidence.resolve("started.json"), state);
        String rp = "HARNESS_ERROR"; String detail = "";
        try {
            check(text(state,"status").equals("WAITING"), "Module did not wait for RP");
            JsonObject running = object(api("GET", "/api/runner/"+id, null)); save(evidence.resolve("runner.json"), running);
            String issuer = text(object(running.getMembers().get("exposed")),"issuer");
            check(issuer.startsWith(BASE.toString()+"/test/"), "Issuer outside local suite");
            OidcClient.Builder builder = OidcClient.withIssuer(issuer).clientId(CLIENT).clientAuthentication(ClientAuthentication.fromClientSecretBasic(SECRET))
                .redirectUri(CALLBACK).scopes(Set.of("profile", "email", "address", "phone")).httpClient(http).allowInsecureLoopback(true);
            if (name.contains("signing-key-rotation")) {
                JsonObject metadata = object(parse(request("GET", URI.create(text(object(running.getMembers().get("exposed")), "discoveryUrl")),null).body()));
                builder.jsonWebKeySource(RemoteJsonWebKeySource.withUri(URI.create(text(metadata,"jwks_uri"))).httpClient(http)
                    .unknownKeyRefreshCooldown(Duration.ofSeconds(1)).build());
            }
            OidcClient client = builder.build();
            boolean form = module.getMembers().get("variant") instanceof JsonObject selected && selected.findString("response_mode").orElse("default").equals("form_post");
            if (name.equals("oidcc-client-test-discovery-openid-config")) { client.beginAuthentication(); rp = "SUCCESS"; }
            else if (name.equals("oidcc-client-test-discovery-jwks-uri-keys")) { client.warmUp(); rp = "SUCCESS"; }
            else {
            OidcAuthentication auth = login(client, form);
            if (name.contains("refresh-token")) {
                OidcRefreshResult refresh = client.refresh(auth.getTokens().getRefreshToken().orElseThrow(),
                    OidcSessionReference.fromSerializedForm(auth.getSessionReference().toSerializedForm()));
                check(refresh.getIdToken().isPresent(), "Expected verified refresh ID token");
                client.fetchUserInfo(auth, refresh);
            } else {
                client.fetchUserInfo(auth);
                if (name.equals("oidcc-client-test-signing-key-rotation")) {
                    Thread.sleep(1100); client.fetchUserInfo(login(client, form));
                }
            }
            rp = "SUCCESS";
            }
        } catch (OidcValidationException failure) {
            rp = failure.getReason().name(); detail = failure.getJoseReason().map(Enum::name).orElse("");
        } catch (OAuthException failure) {
            rp = "OAUTH:"+failure.getReason().name();
        } catch (Exception failure) { detail = failure.getClass().getName(); }
        JsonObject end = waitFor(id, Set.of("FINISHED","INTERRUPTED"), 12); save(evidence.resolve("final.json"), end);
        JsonValue logs = api("GET", "/api/log/"+id, null); save(evidence.resolve("log.json"),logs);
        Set<String> expected = REJECTIONS.getOrDefault(name, Set.of("SUCCESS"));
        boolean rejectedCorrectly = expected.contains(rp) || expected.contains(rp+":"+detail);
        String status = text(end,"status"), result = end.findString("result").orElse("NO_RESULT");
        // Any non-success suite outcome requires an explicit source-based disposition (filled below after inspection).
        boolean accepted = rejectedCorrectly && status.equals("FINISHED") && (result.equals("PASSED") || (result.equals("SKIPPED") && name.equals("oidcc-client-test-idtoken-sig-none")));
        JsonObject outcome = JsonObject.builder().put("plan",dir.getFileName().toString()).put("module",name).put("id",id)
            .put("status",status).put("result",result).put("rp",rp).put("detail",detail).put("accepted",accepted).build();
        outcomes.add(outcome); save(evidence.resolve("outcome.json"),outcome);
        System.out.println(name+" suite="+status+"/"+result+" RP="+rp+(detail.isEmpty()?"":":"+detail)+" accepted="+accepted);
        if (!status.equals("FINISHED")) api("DELETE", "/api/runner/"+id,null);
    }
    @NonNull OidcAuthentication login(@NonNull OidcClient client, boolean form) throws Exception {
        var options = OidcAuthenticationOptions.builder();
        if (form) options.responseMode(AuthorizationRequestOptions.ResponseMode.FORM_POST);
        AuthorizationRedirect begin = client.beginAuthentication(options.build());
        String sealed = begin.getPendingAuthorization().toSealedForm(sealer,"oidf-callback");
        HttpResponse<byte[]> page = request("GET", begin.getAuthorizationUri(), null);
        AuthorizationResponse response;
        if (!form) {
            check(page.statusCode()==302 || page.statusCode()==303, "Expected query redirect");
            URI location = URI.create(page.headers().firstValue("Location").orElseThrow());
            check(location.getScheme().equals(CALLBACK.getScheme()) && location.getAuthority().equals(CALLBACK.getAuthority())
                && location.getPath().equals(CALLBACK.getPath()) && location.getFragment()==null,"Wrong callback location");
            response = AuthorizationResponse.fromQueryString(location.getRawQuery());
        } else {
            check(page.statusCode()==200,"Expected form post HTML");
            String html = new String(page.body(),StandardCharsets.UTF_8);
            Matcher formTag = Pattern.compile("<form\\b([^>]*)>(.*?)</form>",Pattern.CASE_INSENSITIVE|Pattern.DOTALL).matcher(html);
            check(formTag.find(),"Missing callback form");
            check(attribute(formTag.group(1),"action").equals(CALLBACK.toString()) && attribute(formTag.group(1),"method").equalsIgnoreCase("post"),"Wrong form target");
            StringJoiner body = new StringJoiner("&"); Matcher input = Pattern.compile("<input\\b[^>]*>",Pattern.CASE_INSENSITIVE).matcher(formTag.group(2));
            while (input.find()) if(attribute(input.group(),"type").equalsIgnoreCase("hidden")) body.add(encode(attribute(input.group(),"name"))+"="+encode(attribute(input.group(),"value")));
            response = AuthorizationResponse.fromFormBody(body.toString().getBytes(StandardCharsets.UTF_8),StandardCharsets.UTF_8,null);
        }
        return client.completeAuthentication(response,PendingAuthorizationSource.fromSealedForm(sealed,sealer,"oidf-callback"),CALLBACK);
    }
    static @NonNull String attribute(@NonNull String tag,@NonNull String name) {
        Matcher value=Pattern.compile("\\b"+name+"=[\"']([^\"']*)[\"']",Pattern.CASE_INSENSITIVE).matcher(tag);
        check(value.find(),"Missing form attribute");
        return value.group(1).replace("&quot;","\"").replace("&#39;","'").replace("&lt;","<").replace("&gt;",">").replace("&amp;","&");
    }
    @NonNull JsonObject waitFor(@NonNull String id,@NonNull Set<@NonNull String> states,int seconds) throws Exception {
        long deadline=System.nanoTime()+Duration.ofSeconds(seconds).toNanos(); JsonObject info;
        do { info=object(api("GET","/api/info/"+id,null)); if(states.contains(text(info,"status"))) return info; Thread.sleep(100); } while(System.nanoTime()<deadline);
        return info;
    }
    @NonNull JsonValue api(@NonNull String method,@NonNull String path,@Nullable JsonObject body) throws Exception {
        HttpResponse<byte[]> response=request(method,BASE.resolve(path),body==null?null:JsonCodec.toUtf8Bytes(body));
        return parse(response.body());
    }
    @NonNull HttpResponse<byte @NonNull []> request(@NonNull String method,@NonNull URI uri,byte @Nullable [] body) throws Exception {
        check(uri.getScheme().equals(BASE.getScheme()) && uri.getAuthority().equals(BASE.getAuthority()),"Request outside local suite");
        var request=HttpRequest.newBuilder(uri).timeout(Duration.ofSeconds(10)).method(method,body==null?HttpRequest.BodyPublishers.noBody():HttpRequest.BodyPublishers.ofByteArray(body));
        if (method.equals("POST")) request.header("Content-Type","application/json");
        var response=http.send(request.build(),HttpResponse.BodyHandlers.ofByteArray());
        check(response.statusCode()>=200 && response.statusCode()<400,"Suite HTTP status "+response.statusCode()); return response;
    }
    static @NonNull JsonValue parse(byte @NonNull [] body) throws Exception { return JsonCodec.parse(body,JsonLimits.protocolDocument(4*1024*1024)); }
    static @NonNull JsonObject object(@NonNull JsonValue value) { check(value instanceof JsonObject,"Expected object"); return (JsonObject)value; }
    static @Nullable JsonArray array(@NonNull JsonObject value,@NonNull String name) { return (JsonArray)value.getMembers().get(name); }
    static @NonNull String text(@NonNull JsonObject value,@NonNull String name) { return value.findString(name).orElseThrow(()->new IllegalStateException("Missing field "+name)); }
    static @NonNull String json(@NonNull JsonValue value) { return new String(JsonCodec.toUtf8Bytes(value),StandardCharsets.UTF_8); }
    static void save(@NonNull Path path,@NonNull JsonValue value) throws Exception { Files.write(path,JsonCodec.toUtf8Bytes(value)); }
    static @NonNull String encode(@NonNull String value) { return URLEncoder.encode(value,StandardCharsets.UTF_8); }
    static void check(boolean value,@NonNull String message) { if(!value) throw new IllegalStateException(message); }
}
