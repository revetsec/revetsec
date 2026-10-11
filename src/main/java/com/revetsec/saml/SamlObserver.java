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

package com.revetsec.saml;

import com.google.errorprone.annotations.CheckReturnValue;
import org.jspecify.annotations.NonNull;

import javax.annotation.concurrent.Immutable;
import javax.annotation.concurrent.ThreadSafe;
import java.time.Duration;

/**
 * Redacted caller-thread events for SAML service-provider operations. Hooks must be fast and
 * thread-safe. Revetsec contains hook failures except virtual-machine errors and restores
 * interruption. Events contain no connection, subject, request ID, XML, key or browser state.
 * A terminal event follows each start event when an operation returns or throws an ordinary
 * runtime exception. A {@link Outcome#SUCCEEDED} login means Revetsec authenticated the SAML
 * response; the application still decides whether to create a local session.
 *
 * @since 1.0.0
 */
@ThreadSafe
public interface SamlObserver {
    /**
     * Returns the shared observer whose hooks do nothing.
     *
     * @return disabled observer
     * @since 1.0.0
     */
    @CheckReturnValue
    static @NonNull SamlObserver disabledInstance() { return DisabledSamlObserver.INSTANCE; }

    /**
     * Called before a SAML SP operation.
     *
     * @param operation fixed operation kind
     * @since 1.0.0
     */
    default void willHandleOperation(@NonNull Operation operation) {}

    /**
     * Called when an operation returns a sealed result or throws an ordinary runtime exception.
     *
     * @param operation fixed operation kind
     * @param outcome fixed result classification
     * @param elapsed monotonic elapsed duration
     * @since 1.0.0
     */
    default void didHandleOperation(@NonNull Operation operation, @NonNull Outcome outcome,
            @NonNull Duration elapsed) {}

    /**
     * Called when an SP builds after explicitly acknowledging disabled JVM-global XML-signature
     * secure validation. No runtime property value or protocol data is exposed.
     *
     * @since 1.0.0
     */
    default void didAcknowledgeGlobalSecureValidationDisabled() {}

    /**
     * Fixed SAML SP operation kinds.
     *
     * @since 1.0.0
     */
    @Immutable
    enum Operation {
        /** Prepare a Redirect sign-in request. */ BEGIN_AUTHENTICATION,
        /** Prepare a POST sign-in request. */ BEGIN_POST_AUTHENTICATION,
        /** Complete a request-bound sign-in. */ COMPLETE_AUTHENTICATION,
        /** Complete an explicitly permitted IdP-initiated sign-in. */ COMPLETE_UNSOLICITED_AUTHENTICATION,
        /** Check an IdP-initiated logout request. */ ACCEPT_LOGOUT_REQUEST,
        /** Prepare an SP-initiated logout request. */ BEGIN_LOGOUT,
        /** Complete an SP-initiated logout response. */ COMPLETE_LOGOUT,
        /** Prepare a response to a checked IdP logout request. */ RESPOND_TO_LOGOUT_REQUEST
    }

    /**
     * Fixed outcomes without protocol payloads.
     *
     * @since 1.0.0
     */
    @Immutable
    enum Outcome {
        /** A checked identity, request, response or redirect was produced. */ SUCCEEDED,
        /** A request-bound, non-success IdP status was received. */ STATUS_RECEIVED,
        /** Revetsec rejected input or configuration. */ REJECTED,
        /** Required local work or infrastructure was unavailable. */ UNAVAILABLE,
        /** A required state transition may have occurred. */ INDETERMINATE,
        /** An unexpected runtime exception escaped unchanged. */ FAILED
    }
}

final class DisabledSamlObserver implements SamlObserver {
    static final @NonNull SamlObserver INSTANCE = new DisabledSamlObserver();
    private DisabledSamlObserver() {}
}
