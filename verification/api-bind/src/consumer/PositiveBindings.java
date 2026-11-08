/* Copyright 2026 Revetware LLC. Licensed under the Apache License, Version 2.0. */
package consumer;

import com.revetsec.BrowserBinding;
import com.revetsec.OperationBinding;
import com.revetsec.StateSealer;
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

import java.time.Duration;
import java.util.List;
import java.util.Map;

/** External public-only compile and carrier boundary consumer. */
public final class PositiveBindings {
    private PositiveBindings() { }

    static void browserFamilies(PendingAuthorization pending, PendingAuthorizationStore oauthStore,
            PendingOidcLogout logout, PendingSamlAuthentication samlAuthentication,
            PendingSamlLogout samlLogout, PendingSamlAuthenticationStore samlStore,
            StateSealer sealer, OAuthAuthorizationServer issuer, OAuthAuthorizationDecision decision,
            BrowserBinding binding) {
        pending.saveToResult(oauthStore, binding);
        pending.saveToResult(oauthStore, binding, Duration.ofSeconds(1));
        PendingAuthorizationSource.fromStore(oauthStore, binding);
        logout.saveToResult(oauthStore, binding);
        logout.saveToResult(oauthStore, binding, Duration.ofSeconds(1));
        PendingOidcLogoutSource.fromStore(oauthStore, binding);
        samlAuthentication.saveToResult(samlStore, sealer, "authentication", binding,
                Duration.ofSeconds(1));
        PendingSamlAuthenticationSource.fromStore(samlStore, binding, sealer, "authentication");
        samlLogout.saveToResult(samlStore, sealer, "logout", binding, Duration.ofSeconds(1));
        PendingSamlLogoutSource.fromStore(samlStore, binding, sealer, "logout");
        issuer.beginAuthorizationResult("GET", null, new byte[0], Map.of(), binding);
        issuer.resumeAuthorizationResult("interaction", binding);
        issuer.completeAuthorizationResult("interaction", binding, decision);
    }

    static void operationFamilies(TotpAuthenticator totp, TotpEnrollmentOptions enrollment,
            WebAuthnRelyingParty relyingParty, WebAuthnRegistrationOptions registration,
            OperationBinding binding) {
        totp.beginEnrollmentResult(enrollment, binding);
        totp.confirmEnrollmentResult("account", "enrollment", "123456", binding);
        totp.verifyResult("account", "123456", binding);
        totp.consumeRecoveryCodeResult("account", "recovery", binding);
        totp.cancelEnrollmentResult("account", "enrollment", binding);
        relyingParty.beginRegistrationResult(registration, binding);
        relyingParty.beginAuthenticationResult(binding);
        relyingParty.beginReauthenticationResult(new byte[]{1}, "action", binding);
        relyingParty.completeRegistrationResult("ceremony", new byte[0], binding);
        relyingParty.completeAuthenticationResult("ceremony", new byte[0], binding);
        relyingParty.completeReauthenticationResult(new byte[]{1}, "action", "ceremony",
                new byte[0], binding);
    }

    public static void main(String[] arguments) {
        check(arguments.length == 2, "exact JAR paths required");
        String browserBoundary = "\uD83D\uDE00".repeat(BrowserBinding.MAXIMUM_CODE_UNITS / 2);
        check(BrowserBinding.fromTrustedPersistence(browserBoundary).toSecretString()
                .equals(browserBoundary), "browser exact 65536 code-unit restoration");
        rejected(() -> BrowserBinding.fromTrustedPersistence(browserBoundary + "x"));

        String samlSurrogate = "saml-\uD800-binding";
        check(BrowserBinding.fromTrustedPersistence(samlSurrogate).toSecretString()
                .equals(samlSurrogate), "SAML unmatched-surrogate spelling preserved");

        String operationBoundary = "o".repeat(OperationBinding.MAXIMUM_CODE_UNITS);
        check(OperationBinding.fromTrustedPersistence(operationBoundary).toSecretString()
                .equals(operationBoundary), "operation exact 1024 code-unit restoration");
        rejected(() -> OperationBinding.fromTrustedPersistence(operationBoundary + "o"));
        rejected(() -> OperationBinding.fromTrustedPersistence("operation-\uD800"));

        for (String value : List.of(BrowserBinding.fresh().toSecretString(),
                OperationBinding.fresh().toSecretString()))
            check(value.matches("[A-Za-z0-9_-]{43}"), "fresh canonical 43 format");
        check(BrowserBinding.fromTrustedPersistence("TEST-ONLY-browser").toString()
                .equals("BrowserBinding{<redacted>}")
                && OperationBinding.fromTrustedPersistence("TEST-ONLY-operation").toString()
                .equals("OperationBinding{<redacted>}"), "fixed redaction");
        System.out.println("API_BIND_PUBLIC_PASS");
    }

    private static void rejected(Runnable operation) {
        try {
            operation.run();
            throw new AssertionError("Expected rejection");
        } catch (IllegalArgumentException expected) {
            // Expected fixed carrier rejection.
        }
    }

    private static void check(boolean condition, String label) {
        if (!condition) throw new AssertionError(label);
    }
}
