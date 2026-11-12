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

import com.revetsec.totp.TotpAuthenticator;
import com.revetsec.totp.TotpRecoveryGate;
import com.revetsec.totp.TotpStore;
import com.revetsec.webauthn.WebAuthnRecoveryGate;
import com.revetsec.webauthn.WebAuthnRelyingParty;
import com.revetsec.webauthn.WebAuthnStore;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.lang.reflect.Proxy;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import org.jspecify.annotations.NonNull;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/** Configuration-shape checks never invoke the application-owned dependencies. */
final class ConfigurationDiagnosticsTests {
    private static final @NonNull String KEY = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=";
    private static final @NonNull StateSealer SEALER = StateSealer.withActiveKey(SealingKey.fromBase64("diagnostics", KEY)).build();
    private static final @NonNull TotpStore TOTP_STORE = forbidden(TotpStore.class);
    private static final @NonNull TotpRecoveryGate TOTP_GATE = (context, budget) -> { throw new AssertionError("TOTP gate called"); };
    private static final @NonNull WebAuthnStore WEBAUTHN_STORE = forbidden(WebAuthnStore.class);
    private static final @NonNull WebAuthnRecoveryGate WEBAUTHN_GATE = budget -> { throw new AssertionError("WebAuthn gate called"); };

    @Test void totpReportsEveryMissingSettingAndBuildAgreesForAllCombinations() {
        List<ConfigurationDiagnostic> ordered = List.of(
                ConfigurationDiagnostic.TOTP_CREDENTIAL_NAMESPACE_REQUIRED,
                ConfigurationDiagnostic.TOTP_RECOVERY_EPOCH_REQUIRED,
                ConfigurationDiagnostic.TOTP_STORE_REQUIRED,
                ConfigurationDiagnostic.TOTP_STATE_SEALER_REQUIRED,
                ConfigurationDiagnostic.TOTP_RECOVERY_GATE_REQUIRED);
        for (int mask = 0; mask < 32; mask++) {
            TotpAuthenticator.Builder builder = TotpAuthenticator.withIssuer("secret-issuer");
            if ((mask & 1) != 0) builder = builder.credentialNamespace("secret-namespace");
            if ((mask & 2) != 0) builder = builder.recoveryEpoch("secret-epoch");
            if ((mask & 4) != 0) builder = builder.store(TOTP_STORE);
            if ((mask & 8) != 0) builder = builder.stateSealer(SEALER);
            if ((mask & 16) != 0) builder = builder.recoveryGate(TOTP_GATE);
            List<ConfigurationDiagnostic> expected = missing(ordered, mask);
            final var configured = builder;
            assertEquals(expected, configured.configurationDiagnostics());
            assertEquals(expected, configured.configurationDiagnostics());
            assertThrows(UnsupportedOperationException.class, () -> configured.configurationDiagnostics().clear());
            if (expected.isEmpty()) assertNotNull(configured.build());
            else assertEquals(expected.get(0).getFieldCode(), assertThrows(NullPointerException.class, configured::build).getMessage());
            assertRedacted(configured.configurationDiagnostics());
        }
    }

    @Test void webAuthnReportsEveryMissingSettingAndBuildAgreesForAllCombinations() {
        List<ConfigurationDiagnostic> ordered = List.of(
                ConfigurationDiagnostic.WEBAUTHN_RELYING_PARTY_NAME_REQUIRED,
                ConfigurationDiagnostic.WEBAUTHN_CREDENTIAL_NAMESPACE_REQUIRED,
                ConfigurationDiagnostic.WEBAUTHN_ALLOWED_ORIGINS_REQUIRED,
                ConfigurationDiagnostic.WEBAUTHN_STORE_REQUIRED,
                ConfigurationDiagnostic.WEBAUTHN_STATE_SEALER_REQUIRED,
                ConfigurationDiagnostic.WEBAUTHN_RECOVERY_GATE_REQUIRED);
        for (int mask = 0; mask < 64; mask++) {
            WebAuthnRelyingParty.Builder builder = WebAuthnRelyingParty.withRelyingPartyId("login.example.com");
            if ((mask & 1) != 0) builder = builder.relyingPartyName("secret-display-name");
            if ((mask & 2) != 0) builder = builder.credentialNamespace("secret-namespace");
            if ((mask & 4) != 0) builder = builder.allowedOrigins(Set.of("https://login.example.com"));
            if ((mask & 8) != 0) builder = builder.store(WEBAUTHN_STORE);
            if ((mask & 16) != 0) builder = builder.stateSealer(SEALER);
            if ((mask & 32) != 0) builder = builder.recoveryGate(WEBAUTHN_GATE);
            List<ConfigurationDiagnostic> expected = missing(ordered, mask);
            final var configured = builder;
            assertEquals(expected, configured.configurationDiagnostics());
            assertEquals(expected, configured.configurationDiagnostics());
            assertThrows(UnsupportedOperationException.class, () -> configured.configurationDiagnostics().clear());
            if (expected.isEmpty()) assertNotNull(configured.build());
            else assertEquals(expected.get(0).getFieldCode(), assertThrows(NullPointerException.class, configured::build).getMessage());
            assertRedacted(configured.configurationDiagnostics());
        }
    }

    @Test void rejectedSetterInputNeverBecomesDiagnosticDataOrReplacesAcceptedState() {
        TotpAuthenticator.Builder totp = TotpAuthenticator.withIssuer("secret-issuer")
                .credentialNamespace("secret-namespace").recoveryEpoch("secret-epoch")
                .store(TOTP_STORE).stateSealer(SEALER).recoveryGate(TOTP_GATE);
        assertThrows(IllegalArgumentException.class, () -> totp.credentialNamespace("secret invalid namespace"));
        assertThrows(IllegalArgumentException.class, () -> totp.recoveryEpoch("secret invalid epoch"));
        assertThrows(IllegalArgumentException.class, () -> totp.operationTimeout(Duration.ZERO));
        assertTrue(totp.configurationDiagnostics().isEmpty());
        assertNotNull(totp.build());
        assertEquals("TotpAuthenticator.Builder{configuration=<redacted>}", totp.toString());

        WebAuthnRelyingParty.Builder webAuthn = WebAuthnRelyingParty.withRelyingPartyId("login.example.com")
                .relyingPartyName("secret-display-name").credentialNamespace("secret-namespace")
                .allowedOrigins(Set.of("https://login.example.com")).store(WEBAUTHN_STORE)
                .stateSealer(SEALER).recoveryGate(WEBAUTHN_GATE);
        assertThrows(IllegalArgumentException.class, () -> webAuthn.relyingPartyName(""));
        assertThrows(IllegalArgumentException.class,
                () -> webAuthn.allowedOrigins(Set.of("https://secret-attacker.example.org")));
        assertThrows(IllegalArgumentException.class, () -> webAuthn.credentialNamespace("secret invalid namespace"));
        Set<String> maximumOrigins = Set.of(
                "https://login.example.com", "https://a.login.example.com",
                "https://b.login.example.com", "https://c.login.example.com",
                "https://d.login.example.com", "https://e.login.example.com",
                "https://f.login.example.com", "https://g.login.example.com");
        assertSame(webAuthn, webAuthn.allowedOrigins(maximumOrigins));
        assertThrows(IllegalArgumentException.class, () -> webAuthn.allowedOrigins(Set.of(
                "https://login.example.com", "https://a.login.example.com",
                "https://b.login.example.com", "https://c.login.example.com",
                "https://d.login.example.com", "https://e.login.example.com",
                "https://f.login.example.com", "https://g.login.example.com",
                "https://h.login.example.com")));
        assertTrue(webAuthn.configurationDiagnostics().isEmpty());
        assertNotNull(webAuthn.build());
        assertEquals("WebAuthnRelyingParty.Builder{<redacted>}", webAuthn.toString());
        assertRedacted(totp.configurationDiagnostics());
        assertRedacted(webAuthn.configurationDiagnostics());
    }

    @Test void diagnosticResultsArePointInTimeSnapshotsAcrossBuilderMutation() {
        TotpAuthenticator.Builder totp = TotpAuthenticator.withIssuer("secret-issuer");
        List<ConfigurationDiagnostic> initialTotp = totp.configurationDiagnostics();
        assertEquals(5, initialTotp.size());
        assertSame(totp, totp.credentialNamespace("secret-namespace").recoveryEpoch("secret-epoch")
                .store(TOTP_STORE).stateSealer(SEALER).recoveryGate(TOTP_GATE));
        List<ConfigurationDiagnostic> validTotp = totp.configurationDiagnostics();
        assertTrue(validTotp.isEmpty());
        assertEquals(5, initialTotp.size());
        assertNotNull(totp.build());
        assertSame(totp, totp.store(null));
        assertEquals(List.of(ConfigurationDiagnostic.TOTP_STORE_REQUIRED), totp.configurationDiagnostics());
        assertTrue(validTotp.isEmpty());

        WebAuthnRelyingParty.Builder webAuthn = WebAuthnRelyingParty.withRelyingPartyId("login.example.com");
        List<ConfigurationDiagnostic> initialWebAuthn = webAuthn.configurationDiagnostics();
        assertEquals(6, initialWebAuthn.size());
        assertSame(webAuthn, webAuthn.relyingPartyName("secret-display-name").credentialNamespace("secret-namespace")
                .allowedOrigins(Set.of("https://login.example.com")).store(WEBAUTHN_STORE)
                .stateSealer(SEALER).recoveryGate(WEBAUTHN_GATE));
        List<ConfigurationDiagnostic> validWebAuthn = webAuthn.configurationDiagnostics();
        assertTrue(validWebAuthn.isEmpty());
        assertEquals(6, initialWebAuthn.size());
        assertNotNull(webAuthn.build());
        assertSame(webAuthn, webAuthn.allowedOrigins(null));
        assertEquals(List.of(ConfigurationDiagnostic.WEBAUTHN_ALLOWED_ORIGINS_REQUIRED),
                webAuthn.configurationDiagnostics());
        assertTrue(validWebAuthn.isEmpty());
    }

    @Test void diagnosticMetadataIsFixedBoundedAndValueFree() {
        Set<String> reasons = Set.of("REQUIRED", "INVALID", "INCOMPATIBLE");
        Set<String> messages = Set.of(
                "Required configuration is missing.",
                "Configured route is invalid or conflicts with another route.",
                "Configuration value is outside its supported range.",
                "Configured resources are invalid.",
                "Configuration settings are incompatible.");
        for (ConfigurationDiagnostic diagnostic : ConfigurationDiagnostic.values()) {
            assertTrue(diagnostic.getFieldCode().matches("[a-z][A-Za-z0-9]*"));
            assertTrue(reasons.contains(diagnostic.getReasonCode()));
            assertTrue(messages.contains(diagnostic.getMessage()));
            assertTrue(diagnostic.getMessage().length() <= 64);
            assertTrue(diagnostic.getDocumentationReference().matches("com\\.revetsec\\.[A-Za-z0-9.]+#[A-Za-z0-9]+"));
            assertEquals(diagnostic.name(), diagnostic.toString());
            assertFalse((diagnostic.getFieldCode() + diagnostic.getReasonCode() + diagnostic.getMessage()
                    + diagnostic.getDocumentationReference()).contains(KEY));
        }
    }

    @Test void diagnosticMetadataIsUniqueAndEveryDocumentationReferenceResolves() {
        Map<String, Class<?>> builders = Map.of(
                TotpAuthenticator.Builder.class.getCanonicalName(), TotpAuthenticator.Builder.class,
                WebAuthnRelyingParty.Builder.class.getCanonicalName(), WebAuthnRelyingParty.Builder.class,
                com.revetsec.oauth.server.OAuthAuthorizationServer.Builder.class.getCanonicalName(),
                com.revetsec.oauth.server.OAuthAuthorizationServer.Builder.class);
        Set<List<String>> metadata = new HashSet<>();
        for (ConfigurationDiagnostic diagnostic : ConfigurationDiagnostic.values()) {
            assertTrue(metadata.add(List.of(diagnostic.getFieldCode(), diagnostic.getReasonCode(),
                    diagnostic.getMessage(), diagnostic.getDocumentationReference())), diagnostic::name);
            String reference = diagnostic.getDocumentationReference();
            int separator = reference.indexOf('#');
            String builderName = reference.substring(0, separator);
            String expectedBuilderName;
            if (diagnostic.name().startsWith("TOTP_")) {
                expectedBuilderName = TotpAuthenticator.Builder.class.getCanonicalName();
            } else if (diagnostic.name().startsWith("WEBAUTHN_")) {
                expectedBuilderName = WebAuthnRelyingParty.Builder.class.getCanonicalName();
            } else {
                assertTrue(diagnostic.name().startsWith("OAUTH_"), diagnostic::name);
                expectedBuilderName = com.revetsec.oauth.server.OAuthAuthorizationServer.Builder.class.getCanonicalName();
            }
            assertEquals(expectedBuilderName, builderName, diagnostic::name);
            Class<?> builder = builders.get(builderName);
            assertNotNull(builder, reference);
            String methodName = reference.substring(separator + 1);
            if (diagnostic == ConfigurationDiagnostic.OAUTH_ISSUER_SCHEME_INCOMPATIBLE) {
                assertEquals("issuer", diagnostic.getFieldCode());
                assertEquals("allowInsecureLoopback", methodName);
            } else {
                assertEquals(diagnostic.getFieldCode(), methodName, diagnostic::name);
            }
            if (diagnostic.getReasonCode().equals("REQUIRED")) assertTrue(diagnostic.name().endsWith("_REQUIRED"));
            if (diagnostic.getReasonCode().equals("INVALID")) assertTrue(diagnostic.name().endsWith("_INVALID"));
            long matches = Arrays.stream(builder.getMethods())
                    .filter(method -> method.getName().equals(methodName)
                            && Modifier.isPublic(method.getModifiers())
                            && !Modifier.isStatic(method.getModifiers())
                            && method.getReturnType() == builder)
                    .count();
            assertEquals(1L, matches, reference);
        }
    }

    @Test void diagnosticCatalogContainsOnlyTheExercisedComponentReasonFamilies() {
        Map<String, Long> families = Arrays.stream(ConfigurationDiagnostic.values()).collect(Collectors.groupingBy(
                diagnostic -> diagnostic.name().substring(0, diagnostic.name().indexOf('_'))
                        + '/' + diagnostic.getReasonCode(), Collectors.counting()));
        assertEquals(Map.of(
                "TOTP/REQUIRED", 5L,
                "WEBAUTHN/REQUIRED", 6L,
                "OAUTH/REQUIRED", 9L,
                "OAUTH/INVALID", 28L,
                "OAUTH/INCOMPATIBLE", 9L), families);
        assertEquals(57, ConfigurationDiagnostic.values().length);
    }

    @Test void selectedBuilderDiagnosticMethodsHaveExactPublicShape() {
        for (Class<?> builder : List.of(
                TotpAuthenticator.Builder.class,
                WebAuthnRelyingParty.Builder.class,
                com.revetsec.oauth.server.OAuthAuthorizationServer.Builder.class)) {
            List<Method> methods = Arrays.stream(builder.getDeclaredMethods())
                    .filter(method -> method.getName().equals("configurationDiagnostics")
                            && Modifier.isPublic(method.getModifiers()))
                    .toList();
            assertEquals(1, methods.size(), builder.getName());
            Method method = methods.get(0);
            assertFalse(Modifier.isStatic(method.getModifiers()), builder.getName());
            assertEquals(0, method.getParameterCount(), builder.getName());
            assertEquals(List.class, method.getReturnType(), builder.getName());
            assertEquals("java.util.List<com.revetsec.ConfigurationDiagnostic>",
                    method.getGenericReturnType().getTypeName(), builder.getName());
            assertArrayEquals(new Class<?>[0], method.getExceptionTypes(), builder.getName());
        }
    }

    private static @NonNull List<@NonNull ConfigurationDiagnostic> missing(@NonNull List<@NonNull ConfigurationDiagnostic> ordered, int mask) {
        List<ConfigurationDiagnostic> result = new ArrayList<>();
        for (int i = 0; i < ordered.size(); i++) if ((mask & (1 << i)) == 0) result.add(ordered.get(i));
        return List.copyOf(result);
    }

    private static void assertRedacted(@NonNull List<@NonNull ConfigurationDiagnostic> diagnostics) {
        for (ConfigurationDiagnostic diagnostic : diagnostics) {
            String text = diagnostic + " " + diagnostic.getFieldCode() + " " + diagnostic.getReasonCode()
                    + " " + diagnostic.getDocumentationReference() + " " + diagnostic.getMessage();
            for (String secret : List.of("secret-issuer", "secret-namespace", "secret-epoch", "secret-display-name", KEY))
                assertFalse(text.contains(secret));
            assertEquals("REQUIRED", diagnostic.getReasonCode());
            assertFalse(diagnostic.getDocumentationReference().isEmpty());
        }
    }

    private static <T extends @NonNull Object> @NonNull T forbidden(@NonNull Class<@NonNull T> type) {
        Object instance = Proxy.newProxyInstance(type.getClassLoader(), new Class<?>[]{type},
                (proxy, method, args) -> { throw new AssertionError("Configuration inspection called " + method.getName()); });
        return type.cast(instance);
    }
}
