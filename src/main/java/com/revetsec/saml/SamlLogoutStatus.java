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
 * Status chosen by the application after handling a verified logout request.
 *
 * @since 1.0.0
 */
@Immutable
public enum SamlLogoutStatus {
    /** Matching application sessions were terminated. */ SUCCESS("urn:oasis:names:tc:SAML:2.0:status:Success"),
    /** The application could not process the request. */ RESPONDER("urn:oasis:names:tc:SAML:2.0:status:Responder"),
    /** The application rejected the request semantics. */ REQUESTER("urn:oasis:names:tc:SAML:2.0:status:Requester");

    private final @NonNull String uri;
    SamlLogoutStatus(@NonNull String uri) { this.uri = uri; }
    @NonNull String uri() { return uri; }
}
