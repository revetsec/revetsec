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
package example.playground;

import com.revetsec.RevetsecException;
import com.revetsec.oauth.*;
import com.revetsec.soklet.SokletBearer;
import com.soklet.*;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Supplier;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

/** Every structurally valid MCP message gets an independent checked credential and app policy decision. */
final class PlaygroundAdmission implements McpAdmissionController {
    @FunctionalInterface
    interface TokenValidator {
        @NonNull AccessTokenValidationResult validate(@NonNull BearerToken token);
    }
    private final Supplier<@NonNull RuntimeProfile> profiles;
    private final SafeViews views;
    private final AtomicInteger inFlight = new AtomicInteger();

    PlaygroundAdmission(@NonNull Supplier<@NonNull RuntimeProfile> profiles, @NonNull SafeViews views) {
        this.profiles = profiles; this.views = views;
    }

    @Override public @NonNull McpAdmissionDecision admit(@NonNull McpAdmissionContext context) {
        RuntimeProfile profile = profiles.get();
        if (!trusted(context.getRequest(), profile.config, false)) return fixed(403, "Operation not permitted");
        String scope = requiredScope(context);
        if (scope == null) return fixed(403, "Operation not permitted");
        Optional<BearerToken> token;
        try { token = SokletBearer.bearerTokenFor(context.getRequest()); }
        catch (AccessTokenValidationException malformed) { return challenge(profile.config, 400, BearerError.INVALID_REQUEST, scope); }
        if (token.isEmpty()) return challenge(profile.config, 401, null, scope);
        if (inFlight.incrementAndGet() > 8) {
            inFlight.decrementAndGet();
            return fixed(503, "Validation service unavailable");
        }
        try {
            AccessTokenValidationResult result = profile.validator.validate(token.orElseThrow());
            if (!(result instanceof AccessTokenValidationResult.Succeeded success)) {
                if (result instanceof AccessTokenValidationResult.Rejected rejected)
                    return challenge(profile.config, rejected.getBearerError() == BearerError.INVALID_REQUEST ? 400 : 401,
                            rejected.getBearerError(), scope);
                return fixed(503, "Validation service unavailable");
            }
            VerifiedAccessToken proof = success.getAccessToken();
            // These are additional app invariants; library validation already checks the exact configured profile.
            if (!proof.getIssuer().equals(profile.config.issuer)
                    || !proof.getAudiences().contains(profile.config.resourceUri().toString()))
                return challenge(profile.config, 401, BearerError.INVALID_TOKEN, scope);
            if (!proof.getScopes().contains(scope))
                return challenge(profile.config, 403, BearerError.INSUFFICIENT_SCOPE, scope);
            String tenant = proof.getClaims().findString("tenant").orElse("local");
            if (!tenant.equals("local")) return fixed(403, "Operation not permitted");
            String subject = proof.getSubject().orElseGet(() -> proof.getClientId().orElse("anonymous-client"));
            String partition = views.partition(proof.getIssuer(), subject, tenant);
            return McpAdmissionDecision.accepted(McpAdmissionIdentity.withRateLimitPartitionKey(partition)
                    .authorizationPartitionKey(partition).principal(new Principal(proof, partition)).build());
        } catch (RevetsecException unavailable) {
            // Endpoint, JWKS, metadata and transport failures are infrastructure; no fabricated invalid_token.
            return fixed(503, "Validation service unavailable");
        } catch (RuntimeException unavailable) {
            return fixed(503, "Validation service unavailable");
        } finally { inFlight.decrementAndGet(); }
    }

    private static @Nullable String requiredScope(@NonNull McpAdmissionContext context) {
        return switch (context.getOperationType()) {
            case INITIALIZE, NOTIFICATIONS_INITIALIZED, PING, SERVER_DISCOVER, TOOLS_LIST, PROMPTS_LIST,
                    RESOURCES_LIST, RESOURCES_TEMPLATES_LIST, SKILLS_LIST -> "mcp:discover";
            case TOOLS_CALL -> context.getOperationName().filter("whoami"::equals).isPresent() ? "mcp:whoami" : null;
            default -> null;
        };
    }

    static boolean trusted(@NonNull Request request, @NonNull PlaygroundConfig config, boolean providerOrigin) {
        List<String> hosts = headerValues(request, "Host");
        if (hosts.size() != 1 || !(hosts.get(0).equals(config.origin.getRawAuthority())
                || hosts.get(0).equals("127.0.0.1:" + config.mcpPort))) return false;
        List<String> origins = headerValues(request, "Origin");
        if (origins.isEmpty()) return true;
        if (origins.size() != 1) return false;
        if (origins.get(0).equals(config.origin.toString())) return true;
        if (!providerOrigin) return false;
        java.net.URI issuer = java.net.URI.create(config.issuer);
        return origins.get(0).equals(issuer.getScheme() + "://" + issuer.getRawAuthority());
    }

    static @NonNull List<@NonNull String> headerValues(@NonNull Request request, @NonNull String name) {
        return request.getHeaders().entrySet().stream().filter(e -> e.getKey().equalsIgnoreCase(name))
                .flatMap(e -> e.getValue().stream()).toList();
    }

    private static @NonNull McpAdmissionDecision challenge(@NonNull PlaygroundConfig config, int status,
            @Nullable BearerError error, @NonNull String scope) {
        BearerChallenge.Builder challenge = BearerChallenge.builder().resourceMetadata(config.metadataUri())
                .scopes(List.of(scope));
        if (error != null) challenge.error(error);
        return McpAdmissionDecision.rejected(McpAdmissionRejection.withStatusCodeAndError(status,
                McpJsonRpcError.fromApplication(-31901, "Credential or permission required"))
                .headers(Map.of("WWW-Authenticate", List.of(challenge.build().getHeaderValue()))).build());
    }

    private static @NonNull McpAdmissionDecision fixed(int status, @NonNull String message) {
        return McpAdmissionDecision.rejected(McpAdmissionRejection.withStatusCodeAndError(status,
                McpJsonRpcError.fromApplication(-31903, message)).build());
    }

    static final class RuntimeProfile {
        final PlaygroundConfig config;
        final TokenValidator validator;
        RuntimeProfile(@NonNull PlaygroundConfig config, @NonNull TokenValidator validator) {
            this.config = config; this.validator = validator;
        }
    }

    static final class Principal {
        final VerifiedAccessToken proof;
        final String partition;
        Principal(@NonNull VerifiedAccessToken proof, @NonNull String partition) {
            this.proof = proof; this.partition = partition;
        }
        @Override public @NonNull String toString() { return "Principal{data=<redacted>}"; }
    }
}
