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
import javax.annotation.concurrent.Immutable;
import java.net.URI;
import java.util.Map;

/**
 * A prepared browser form for a SAML HTTP-POST AuthnRequest. Render only over HTTPS, with a
 * Secure, HttpOnly, SameSite=None pending cookie set before delivery.
 *
 * @since 1.0.0
 */
@Immutable
public final class SamlPostForm {
    private final @NonNull URI action;
    private final @NonNull Map<@NonNull String, @NonNull String> fields;

    SamlPostForm(@NonNull URI action, @NonNull String request, @NonNull String relayState) {
        this.action = action;
        this.fields = Map.of("SAMLRequest", request, "RelayState", relayState);
    }

    /**
     * Returns the approved IdP form action.
     *
     * @return HTTPS action
     * @since 1.0.0
     */
    public @NonNull URI getAction() { return action; }
    /**
     * Returns the form fields for framework rendering.
     *
     * @return immutable field map
     * @since 1.0.0
     */
    public @NonNull Map<@NonNull String, @NonNull String> getFields() { return fields; }
    /**
     * Returns response headers for a transient form page.
     *
     * @return immutable headers
     * @since 1.0.0
     */
    public @NonNull Map<@NonNull String, @NonNull String> getHeaders() {
        return Map.of("Cache-Control", "no-store", "Pragma", "no-cache",
                "Referrer-Policy", "no-referrer", "Content-Type", "text/html; charset=UTF-8",
                "X-Content-Type-Options", "nosniff");
    }
    /**
     * Renders an escaped HTML form. A supplied CSP nonce adds automatic submission; otherwise the
     * page shows a submit button. The caller sets its own Content-Security-Policy header.
     *
     * @param cspNonce validated application-generated nonce, or null for manual submission
     * @return complete HTML document
     * @since 1.0.0
     */
    public @NonNull String toHtml(@Nullable String cspNonce) {
        if (cspNonce != null && !cspNonce.matches("[A-Za-z0-9_+/-]{16,128}={0,2}"))
            throw new IllegalArgumentException("Invalid CSP nonce");
        StringBuilder html = new StringBuilder(1024);
        html.append("<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">")
                .append("<title>Continue sign-in</title></head><body>")
                .append("<form id=\"saml-post-form\" method=\"post\" action=\"")
                .append(escape(action.toASCIIString()))
                .append("\" autocomplete=\"off\">");
        for (Map.Entry<String, String> field : fields.entrySet())
            html.append("<input type=\"hidden\" name=\"").append(escape(field.getKey()))
                    .append("\" value=\"").append(escape(field.getValue())).append("\">");
        html.append("<noscript><button type=\"submit\">Continue</button></noscript>")
                .append("</form>");
        if (cspNonce != null) html.append("<script nonce=\"").append(cspNonce)
                .append("\">document.forms[0].submit();</script>");
        else html.append("<button type=\"submit\" form=\"saml-post-form\">Continue</button>");
        html.append("</body></html>");
        return html.toString();
    }

    private static @NonNull String escape(@NonNull String value) {
        return value.replace("&", "&amp;").replace("\"", "&quot;")
                .replace("<", "&lt;").replace(">", "&gt;").replace("'", "&#39;");
    }

    /**
     * Redacts request values.
     *
     * @return redacted description
     * @since 1.0.0
     */
    @Override public @NonNull String toString() { return "SamlPostForm{<redacted>}"; }
}
