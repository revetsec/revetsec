/* Copyright 2026 Revetware LLC. Licensed under the Apache License, Version 2.0. */
package consumer;

import com.revetsec.oauth.PendingAuthorizationSource;
import com.revetsec.oauth.PendingAuthorizationStore;
import com.revetsec.oauth.server.OAuthAuthorizationDecision;
import com.revetsec.oauth.server.OAuthAuthorizationServer;
import com.revetsec.totp.TotpAuthenticator;

/** Must compile before API-BIND and fail against the typed current API. */
final class LegacyStringBindings {
    static void raw(PendingAuthorizationStore store, TotpAuthenticator totp,
            OAuthAuthorizationServer issuer, OAuthAuthorizationDecision decision) {
        PendingAuthorizationSource.fromStore(store, "raw-browser");
        totp.verifyResult("account", "123456", "raw-operation");
        issuer.resumeAuthorizationResult("interaction", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
        issuer.completeAuthorizationResult("interaction",
                "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", decision);
    }
}
