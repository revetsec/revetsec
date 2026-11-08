/* Copyright 2026 Revetware LLC. Licensed under the Apache License, Version 2.0. */
package consumer;

import com.revetsec.OperationBinding;
import com.revetsec.oauth.PendingAuthorizationSource;
import com.revetsec.oauth.PendingAuthorizationStore;

/** Must not compile: credential-operation and browser roles are not interchangeable. */
final class OperationAsBrowser {
    static void misuse(PendingAuthorizationStore store, OperationBinding operation) {
        PendingAuthorizationSource.fromStore(store, operation);
    }
}
