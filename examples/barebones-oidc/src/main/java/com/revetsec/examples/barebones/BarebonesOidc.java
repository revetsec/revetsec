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
package com.revetsec.examples.barebones;

import com.revetsec.oauth.AuthorizationRequestOptions;
import com.revetsec.oauth.ClientAuthentication;
import com.revetsec.oidc.OidcClient;
import com.soklet.Soklet;
import org.jspecify.annotations.NonNull;
import javax.annotation.concurrent.ThreadSafe;
import java.net.URI;
import java.time.Clock;
import java.time.Duration;
import java.util.Map;
import static java.util.Objects.requireNonNull;

/** Runs the local OIDC example behind the documented HTTPS loopback proxy.
 * @since 1.0.0
 */
@ThreadSafe
public final class BarebonesOidc {
    private BarebonesOidc() { }

    /** Uses trusted startup environment only; never derives an issuer or callback from a request.
     * @param arguments no command-line arguments are accepted
     * @since 1.0.0
     */
    public static void main(@NonNull String @NonNull [] arguments) {
        try {
            if (requireNonNull(arguments).length != 0) throw new IllegalArgumentException("Use environment configuration");
            Map<String, String> environment = System.getenv();
            URI origin = OidcApplication.checkedOrigin(URI.create(required(environment, "APP_ORIGIN")));
            URI issuer = URI.create(required(environment, "OIDC_ISSUER"));
            if (!"https".equals(issuer.getScheme()) || issuer.getHost() == null || issuer.getRawUserInfo() != null)
                throw new IllegalArgumentException("OIDC issuer requires HTTPS");
            String secret = environment.get("OIDC_CLIENT_SECRET");
            Clock clock = Clock.systemUTC();
            OidcClient client = OidcClient.withIssuer(issuer.toString())
                    .clientId(required(environment, "OIDC_CLIENT_ID"))
                    .clientAuthentication(secret == null ? ClientAuthentication.noneInstance()
                            : ClientAuthentication.fromClientSecretBasic(secret))
                    .redirectUri(origin.resolve("/callback")).clock(clock).requirePkceAdvertised(true)
                    .pendingAuthorizationLifetime(Duration.ofMinutes(5)).build();
            client.warmUp();
            String mode = environment.getOrDefault("OIDC_RESPONSE_MODE", "query");
            if (!mode.equals("query") && !mode.equals("form_post")) throw new IllegalArgumentException("Invalid response mode");
            OidcApplication app = new OidcApplication(client, origin, issuer, clock, 128,
                    new PendingStore(clock, 128, 262_144), mode.equals("form_post")
                    ? AuthorizationRequestOptions.ResponseMode.FORM_POST : AuthorizationRequestOptions.ResponseMode.QUERY);
            int port = Integer.parseInt(environment.getOrDefault("APP_UPSTREAM_PORT", "8080"));
            try (Soklet soklet = Soklet.fromConfig(app.configuration(port))) {
                soklet.start();
                System.out.println("Revetsec OIDC example listening on IPv4 loopback; open the configured HTTPS origin.");
                soklet.awaitShutdown();
            }
        } catch (InterruptedException exception) {
            Thread.currentThread().interrupt();
        } catch (Exception exception) {
            // No exception message, stack trace, configuration URI or credential is emitted.
            System.err.println("Revetsec OIDC example could not start. Check the local configuration and provider.");
            System.exit(1);
        }
    }

    private static @NonNull String required(@NonNull Map<@NonNull String, @NonNull String> environment,
                                            @NonNull String name) {
        String value = environment.get(name);
        if (value == null || value.isBlank() || value.length() > 2048)
            throw new IllegalArgumentException("Required configuration missing or too large");
        return value;
    }
}
