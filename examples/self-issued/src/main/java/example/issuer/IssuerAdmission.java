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

import com.revetsec.oauth.*;
import com.revetsec.oauth.server.*;
import com.revetsec.soklet.SokletBearer;
import com.soklet.*;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

/** Every MCP operation validates online, then performs independent scope/tool/tenant/object authorization. */
final class IssuerAdmission implements McpAdmissionController {
    private final IssuerResources app;
    private final byte[] partitionKey=LocalInputs.randomBytes();
    IssuerAdmission(@NonNull IssuerResources app) {this.app=app;}
    @Override public @NonNull McpAdmissionDecision admit(@NonNull McpAdmissionContext context) {
        Request request=context.getRequest();
        URI resource=app.config.resourceForEndpoint(context.getEndpoint().getPath()).orElse(null);
        if(resource==null) return fixed(403,"Operation not permitted");
        if(!LocalInputs.headers(request,"Host").equals(List.of(resource.getRawAuthority()))) return fixed(403,"Operation not permitted");
        List<String> origins=LocalInputs.headers(request,"Origin");
        if(!origins.isEmpty() && !origins.equals(List.of(app.config.origin.toString()))) return fixed(403,"Operation not permitted");
        String scope=switch(context.getOperationType()) {
            case INITIALIZE,NOTIFICATIONS_INITIALIZED,PING,SERVER_DISCOVER,TOOLS_LIST,PROMPTS_LIST,RESOURCES_LIST,RESOURCES_TEMPLATES_LIST,SKILLS_LIST -> "mcp:discover";
            case TOOLS_CALL -> context.getOperationName().filter("whoami"::equals).isPresent()?"mcp:whoami":null;
            default -> null;
        };
        if(scope==null) return fixed(403,"Operation not permitted");
        try {
            Optional<BearerToken> token=SokletBearer.bearerTokenFor(request);
            if(token.isEmpty()) return challenge(401,null,scope,resource);
            OAuthIssuerAccessTokenResult result=app.server.validateAccessTokenResult(token.orElseThrow(),resource.toString());
            if(!(result instanceof OAuthIssuerAccessTokenResult.Succeeded success)) return challenge(401,((OAuthIssuerAccessTokenResult.Rejected)result).getBearerError(),scope,resource);
            VerifiedAccessToken proof=success.getAccessToken();
            if(!proof.getIssuer().equals(app.config.origin.toString()) || !proof.getAudiences().contains(resource.toString())) return challenge(401,BearerError.INVALID_TOKEN,scope,resource);
            if(!proof.getScopes().contains(scope)) return challenge(403,BearerError.INSUFFICIENT_SCOPE,scope,resource);
            String partition=partition(proof.getSubject().orElseThrow());
            return McpAdmissionDecision.accepted(McpAdmissionIdentity.withRateLimitPartitionKey(partition).authorizationPartitionKey(partition)
                    .principal(new Principal(proof,partition)).build());
        } catch(AccessTokenValidationException malformed) {return challenge(400,BearerError.INVALID_REQUEST,scope,resource);}
        catch(OAuthServerException unavailable) {return fixed(503,"Validation service unavailable");}
    }
    private @NonNull String partition(@NonNull String subject) {
        try {
            Mac mac=Mac.getInstance("HmacSHA256");mac.init(new SecretKeySpec(partitionKey,"HmacSHA256"));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(mac.doFinal(subject.getBytes(StandardCharsets.UTF_8)));
        } catch(java.security.GeneralSecurityException unavailable) {throw new IllegalStateException("Partition service unavailable.");}
    }
    private @NonNull McpAdmissionDecision challenge(int status,@Nullable BearerError error,@NonNull String scope,@NonNull URI resource) {
        BearerChallenge.Builder b=BearerChallenge.builder().resourceMetadata(app.config.origin.resolve("/.well-known/oauth-protected-resource"+resource.getRawPath())).scopes(List.of(scope)).allowInsecureLoopback(app.config.loopback);
        if(error!=null) b.error(error);
        return McpAdmissionDecision.rejected(McpAdmissionRejection.withStatusCodeAndError(status,McpJsonRpcError.fromApplication(-31901,"Credential or permission required"))
                .headers(Map.of("WWW-Authenticate",List.of(b.build().getHeaderValue()))).build());
    }
    private static @NonNull McpAdmissionDecision fixed(int status,@NonNull String message) {
        return McpAdmissionDecision.rejected(McpAdmissionRejection.withStatusCodeAndError(status,McpJsonRpcError.fromApplication(-31903,message)).build());
    }
    static final class Principal {
        final VerifiedAccessToken proof;
        final String partition;
        Principal(@NonNull VerifiedAccessToken proof,@NonNull String partition) {this.proof=proof;this.partition=partition;}
        @Override public @NonNull String toString() {return "IssuerPrincipal{<redacted>}";}
    }
}
