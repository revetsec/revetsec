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

import com.revetsec.oauth.PendingAuthorization;
import com.revetsec.oauth.PendingAuthorizationSource;
import com.revetsec.oauth.PendingAuthorizationStore;
import com.revetsec.oauth.server.OAuthAuthorizationDecision;
import com.revetsec.oauth.server.OAuthAuthorizationServer;
import com.revetsec.oidc.PendingOidcLogout;
import com.revetsec.oidc.PendingOidcLogoutSource;
import com.revetsec.saml.PendingSamlAuthentication;
import com.revetsec.saml.PendingSamlAuthenticationSource;
import com.revetsec.saml.PendingSamlAuthenticationStore;
import com.revetsec.saml.PendingSamlLogout;
import com.revetsec.saml.PendingSamlLogoutSource;
import com.revetsec.totp.TotpAuthenticator;
import com.revetsec.totp.TotpEnrollmentOptions;
import com.revetsec.webauthn.WebAuthnRegistrationOptions;
import com.revetsec.webauthn.WebAuthnRelyingParty;
import org.jspecify.annotations.NonNull;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Method;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

final class BindingPublicApiTests {
    @Test void everyHighLevelBrowserBindingEntryPointIsTypedAndTheStringOverloadIsNotPublic() {
        typed(PendingAuthorization.class, "saveToResult", PendingAuthorizationStore.class,
                BrowserBinding.class);
        typed(PendingAuthorization.class, "saveToResult", PendingAuthorizationStore.class,
                BrowserBinding.class, Duration.class);
        typed(PendingAuthorizationSource.class, "fromStore", PendingAuthorizationStore.class,
                BrowserBinding.class);

        typed(PendingOidcLogout.class, "saveToResult", PendingAuthorizationStore.class,
                BrowserBinding.class);
        typed(PendingOidcLogout.class, "saveToResult", PendingAuthorizationStore.class,
                BrowserBinding.class, Duration.class);
        typed(PendingOidcLogoutSource.class, "fromStore", PendingAuthorizationStore.class,
                BrowserBinding.class);

        for (Class<?> pending : List.of(PendingSamlAuthentication.class, PendingSamlLogout.class))
            typed(pending, "saveToResult", PendingSamlAuthenticationStore.class, StateSealer.class,
                    String.class, BrowserBinding.class, Duration.class);
        for (Class<?> source : List.of(PendingSamlAuthenticationSource.class, PendingSamlLogoutSource.class))
            typed(source, "fromStore", PendingSamlAuthenticationStore.class, BrowserBinding.class,
                    StateSealer.class, String.class);

        typed(OAuthAuthorizationServer.class, "beginAuthorizationResult", String.class, String.class,
                byte[].class, Map.class, BrowserBinding.class);
        typed(OAuthAuthorizationServer.class, "resumeAuthorizationResult", String.class,
                BrowserBinding.class);
        typed(OAuthAuthorizationServer.class, "completeAuthorizationResult", String.class,
                BrowserBinding.class, OAuthAuthorizationDecision.class);

        absent(PendingAuthorization.class, "saveToResult", PendingAuthorizationStore.class,
                String.class);
        absent(PendingAuthorizationSource.class, "fromStore", PendingAuthorizationStore.class,
                String.class);
        absent(PendingOidcLogout.class, "saveToResult", PendingAuthorizationStore.class,
                String.class);
        absent(PendingOidcLogoutSource.class, "fromStore", PendingAuthorizationStore.class,
                String.class);
        absent(PendingSamlAuthentication.class, "saveToResult", PendingSamlAuthenticationStore.class,
                StateSealer.class, String.class, String.class, Duration.class);
        absent(PendingSamlLogout.class, "saveToResult", PendingSamlAuthenticationStore.class,
                StateSealer.class, String.class, String.class, Duration.class);
        absent(OAuthAuthorizationServer.class, "beginAuthorizationResult", String.class, String.class,
                byte[].class, Map.class, String.class);
        absent(OAuthAuthorizationServer.class, "resumeAuthorizationResult", String.class, String.class);
        absent(OAuthAuthorizationServer.class, "completeAuthorizationResult", String.class,
                String.class, OAuthAuthorizationDecision.class);
    }

    @Test void everyHighLevelCredentialOperationBindingEntryPointIsTypedAndTheStringOverloadIsNotPublic() {
        typed(TotpAuthenticator.class, "beginEnrollmentResult", TotpEnrollmentOptions.class,
                OperationBinding.class);
        typed(TotpAuthenticator.class, "confirmEnrollmentResult", String.class, String.class,
                String.class, OperationBinding.class);
        typed(TotpAuthenticator.class, "verifyResult", String.class, String.class,
                OperationBinding.class);
        typed(TotpAuthenticator.class, "consumeRecoveryCodeResult", String.class, String.class,
                OperationBinding.class);
        typed(TotpAuthenticator.class, "cancelEnrollmentResult", String.class, String.class,
                OperationBinding.class);

        typed(WebAuthnRelyingParty.class, "beginRegistrationResult", WebAuthnRegistrationOptions.class,
                OperationBinding.class);
        typed(WebAuthnRelyingParty.class, "beginAuthenticationResult", OperationBinding.class);
        typed(WebAuthnRelyingParty.class, "beginReauthenticationResult", byte[].class, String.class,
                OperationBinding.class);
        typed(WebAuthnRelyingParty.class, "completeRegistrationResult", String.class, byte[].class,
                OperationBinding.class);
        typed(WebAuthnRelyingParty.class, "completeAuthenticationResult", String.class, byte[].class,
                OperationBinding.class);
        typed(WebAuthnRelyingParty.class, "completeReauthenticationResult", byte[].class, String.class,
                String.class, byte[].class, OperationBinding.class);

        absent(TotpAuthenticator.class, "beginEnrollmentResult", TotpEnrollmentOptions.class,
                String.class);
        absent(TotpAuthenticator.class, "confirmEnrollmentResult", String.class, String.class,
                String.class, String.class);
        absent(TotpAuthenticator.class, "verifyResult", String.class, String.class, String.class);
        absent(TotpAuthenticator.class, "consumeRecoveryCodeResult", String.class, String.class,
                String.class);
        absent(TotpAuthenticator.class, "cancelEnrollmentResult", String.class, String.class,
                String.class);
        absent(WebAuthnRelyingParty.class, "beginRegistrationResult", WebAuthnRegistrationOptions.class,
                String.class);
        absent(WebAuthnRelyingParty.class, "beginAuthenticationResult", String.class);
        absent(WebAuthnRelyingParty.class, "beginReauthenticationResult", byte[].class, String.class,
                String.class);
        absent(WebAuthnRelyingParty.class, "completeRegistrationResult", String.class, byte[].class,
                String.class);
        absent(WebAuthnRelyingParty.class, "completeAuthenticationResult", String.class, byte[].class,
                String.class);
        absent(WebAuthnRelyingParty.class, "completeReauthenticationResult", byte[].class, String.class,
                String.class, byte[].class, String.class);
    }

    @Test void lowLevelStoreSpiStringsRemainTheOpaqueCompatibilityBoundary() throws Exception {
        Method save = PendingAuthorizationStore.class.getMethod("save", String.class, String.class,
                String.class, Instant.class, Duration.class);
        Method consume = PendingAuthorizationStore.class.getMethod("consume", String.class, String.class,
                Duration.class);
        assertEquals(String.class, save.getParameterTypes()[0]);
        assertEquals(String.class, consume.getParameterTypes()[0]);

        Method samlSave = PendingSamlAuthenticationStore.class.getMethod("save", String.class,
                String.class, String.class, Instant.class, Duration.class);
        Method samlConsume = PendingSamlAuthenticationStore.class.getMethod("consume", String.class,
                String.class, Duration.class);
        assertEquals(String.class, samlSave.getParameterTypes()[0]);
        assertEquals(String.class, samlConsume.getParameterTypes()[0]);
    }

    private static void typed(@NonNull Class<?> owner, @NonNull String name,
            @NonNull Class<?> @NonNull ... parameters) {
        Method method = assertDoesNotThrow(() -> owner.getMethod(name, parameters));
        assertTrue(java.lang.reflect.Modifier.isPublic(method.getModifiers()));
    }

    private static void absent(@NonNull Class<?> owner, @NonNull String name,
            @NonNull Class<?> @NonNull ... parameters) {
        assertThrows(NoSuchMethodException.class, () -> owner.getMethod(name, parameters));
    }
}
