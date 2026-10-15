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

import com.revetsec.oauth.AuthorizationServerMetadata;
import com.revetsec.oauth.AuthorizationServerMetadataParseResult;
import com.revetsec.oauth.OAuthException;
import com.revetsec.oidc.OidcProviderMetadata;
import com.revetsec.oidc.OidcProviderMetadataParseResult;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

final class MetadataParseResultTests {
    @Test void metadataParsersDistinguishAcceptedMalformedAndMismatchedDocuments() {
        String issuer = "https://issuer.example";
        String json = "{\"issuer\":\"https://issuer.example\",\"authorization_endpoint\":\"https://issuer.example/auth\","
                + "\"token_endpoint\":\"https://issuer.example/token\",\"jwks_uri\":\"https://issuer.example/keys\","
                + "\"subject_types_supported\":[\"public\"],\"id_token_signing_alg_values_supported\":[\"RS256\"],"
                + "\"response_types_supported\":[\"code\"]}";
        var oauth = assertInstanceOf(AuthorizationServerMetadataParseResult.Succeeded.class,
                AuthorizationServerMetadata.fromJsonResult(issuer, json));
        assertEquals(issuer, oauth.getMetadata().getIssuer());
        var oidc = assertInstanceOf(OidcProviderMetadataParseResult.Succeeded.class,
                OidcProviderMetadata.fromJsonResult(issuer, json));
        assertEquals(issuer, oidc.getMetadata().getIssuer());
        assertEquals(OAuthException.Reason.DOCUMENT_MALFORMED,
                assertInstanceOf(AuthorizationServerMetadataParseResult.Rejected.class,
                        AuthorizationServerMetadata.fromJsonResult(issuer, "[]")).getReason());
        assertEquals(OAuthException.Reason.DOCUMENT_MALFORMED,
                assertInstanceOf(OidcProviderMetadataParseResult.Rejected.class,
                        OidcProviderMetadata.fromJsonResult(issuer, "{\"sentinel_secret\":true}")).getReason());
        assertEquals(OAuthException.Reason.ISSUER_MISMATCH,
                assertInstanceOf(AuthorizationServerMetadataParseResult.Rejected.class,
                        AuthorizationServerMetadata.fromJsonResult("https://other.example", json)).getReason());
        assertEquals(OAuthException.Reason.ISSUER_MISMATCH,
                assertInstanceOf(OidcProviderMetadataParseResult.Rejected.class,
                        OidcProviderMetadata.fromJsonResult("https://other.example", json)).getReason());
        assertFalse(oidc.toString().contains(issuer));
        assertFalse(oauth.toString().contains(issuer));
    }
}
