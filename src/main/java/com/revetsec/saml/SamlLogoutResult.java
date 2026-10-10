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

import org.jspecify.annotations.NonNull;
import javax.annotation.concurrent.Immutable;

/**
 * Result of a signed, pending-bound IdP LogoutResponse. Success means the IdP reported success;
 * it does not claim that application sessions were terminated.
 *
 * @since 1.0.0
 */
@Immutable
public sealed interface SamlLogoutResult permits SamlLogoutResult.Succeeded,
        SamlLogoutResult.StatusReceived, SamlLogoutResult.Rejected,
        SamlLogoutResult.Unavailable, SamlLogoutResult.Indeterminate {
    /**
     * The IdP returned a verified Success status.
     *
     * @since 1.0.0
     */
    @Immutable
    enum Succeeded implements SamlLogoutResult {
        /** Verified IdP completion. */ INSTANCE
    }
    /**
     * The IdP returned a verified non-success status.
     *
     * @since 1.0.0
     */
    @Immutable
    enum StatusReceived implements SamlLogoutResult {
        /** The provider did not report success. */ NON_SUCCESS
    }
    /**
     * The response was invalid, expired, unbound or replayed.
     *
     * @since 1.0.0
     */
    @Immutable
    enum Rejected implements SamlLogoutResult {
        /** No provider outcome was established. */ INSTANCE
    }
    /**
     * A required local capability or replay store was unavailable.
     *
     * @since 1.0.0
     */
    @Immutable
    enum Unavailable implements SamlLogoutResult {
        /** No provider outcome was established. */ INSTANCE
    }
    /**
     * A pending or replay consume may have occurred.
     *
     * @since 1.0.0
     */
    @Immutable
    enum Indeterminate implements SamlLogoutResult {
        /** Reconciliation is required. */ INSTANCE
    }
}
