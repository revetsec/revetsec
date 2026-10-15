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
package com.revetsec;

import com.revetsec.scim.ScimCompatibilityFeature;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertTrue;

/** Guards the public compatibility registry against omissions as switches are added. */
final class CompatibilityRegistryTests {
    @Test void releaseRegistryNamesEveryScimFeatureAndOtherExplicitRelaxations() throws IOException {
        String registry = Files.readString(Path.of("docs/compatibility-modes.md"))
                .replaceAll("\\[([^\\]]+)\\]\\([^\\s)]+\\)", "$1").replace("``", "");
        for (ScimCompatibilityFeature feature : ScimCompatibilityFeature.values())
            assertTrue(registry.contains("`" + feature.name() + "`"), feature.name());
        for (String name : new String[] {
                "AccessTokenCompatibilityMode.UNTYPED_ACCESS_TOKENS",
                "ClientAssertionAudience.TOKEN_ENDPOINT",
                "OidcIssuerPolicy.fromMicrosoftEntraMultiTenant",
                "ScimCompatibility.strictInstance()",
                "microsoftEntraIdInstance()",
                "oktaInstance()",
                "OAuthAuthorizationServer.Builder.allowInsecureLoopback(true)",
                "allowNativeLoopbackRedirects(true)",
                "allowLocalhostRedirects(true)"
        }) assertTrue(registry.contains("`" + name + "`"), name);
    }
}
