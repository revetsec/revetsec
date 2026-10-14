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
import org.jspecify.annotations.Nullable;
import java.net.URI;
import java.security.PrivateKey;
import java.time.Instant;
import java.util.Base64;

/** Signed HTTP-POST logout forms using the common logout XML writer and signature profile. */
final class SamlPostLogout {
    private SamlPostLogout() { }

    static @Nullable SamlPostForm request(@NonNull URI destination, @NonNull String spEntityId,
            @NonNull SamlSessionReference session, @NonNull String requestId, @NonNull String relay,
            @NonNull Instant issued, @NonNull PrivateKey key) {
        try {
            byte[] signed = SamlRedirectAuthnRequest.signPostXml(SamlRedirectLogout.requestXml(
                    destination, spEntityId, session, requestId, issued), requestId, key);
            return signed == null ? null : new SamlPostForm(destination, "SAMLRequest",
                    Base64.getEncoder().encodeToString(signed), relay);
        } catch (javax.xml.stream.XMLStreamException | java.security.GeneralSecurityException
                | javax.xml.crypto.MarshalException | javax.xml.crypto.dsig.XMLSignatureException
                | javax.xml.transform.TransformerException exception) {
            return null;
        }
    }

    static @Nullable SamlPostForm response(@NonNull URI destination, @NonNull String spEntityId,
            @NonNull String responseId, @NonNull String inResponseTo, @Nullable String relay,
            @NonNull Instant issued, @NonNull SamlLogoutStatus status, @NonNull PrivateKey key) {
        try {
            byte[] signed = SamlRedirectAuthnRequest.signPostXml(SamlRedirectLogout.responseXml(
                    destination, spEntityId, responseId, inResponseTo, issued, status), responseId, key);
            return signed == null ? null : new SamlPostForm(destination, "SAMLResponse",
                    Base64.getEncoder().encodeToString(signed), relay);
        } catch (javax.xml.stream.XMLStreamException | java.security.GeneralSecurityException
                | javax.xml.crypto.MarshalException | javax.xml.crypto.dsig.XMLSignatureException
                | javax.xml.transform.TransformerException exception) {
            return null;
        }
    }
}
