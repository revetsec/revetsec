/* Copyright 2026 Revetware LLC. Licensed under the Apache License, Version 2.0. */
package consumer;

import com.revetsec.BrowserBinding;
import com.revetsec.totp.TotpAuthenticator;

/** Must not compile: browser and credential-operation roles are not interchangeable. */
final class BrowserAsOperation {
    static void misuse(TotpAuthenticator authenticator, BrowserBinding browser) {
        authenticator.verifyResult("account", "123456", browser);
    }
}
