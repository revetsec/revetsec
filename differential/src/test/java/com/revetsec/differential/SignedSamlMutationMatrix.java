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
package com.revetsec.differential;

import org.jspecify.annotations.NonNull;

import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** The same signed-envelope mutations used by the core SP XSW regression corpus. */
final class SignedSamlMutationMatrix {
    private static final @NonNull Pattern SIGNATURE = Pattern.compile(
            "<ds:Signature\\b[^>]*>.*?</ds:Signature>", Pattern.DOTALL);

    private SignedSamlMutationMatrix() { }

    static @NonNull List<@NonNull Mutation> from(@NonNull String original) {
        return from(original, "minted-user");
    }

    static @NonNull List<@NonNull Mutation> from(@NonNull String original,
            @NonNull String originalIdentity) {
        if (originalIdentity.isEmpty()) throw new IllegalArgumentException("Missing original identity");
        String assertion = OpenSamlSpComparatorTests.section(original,
                "<saml:Assertion ", "</saml:Assertion>");
        String assertionId = OpenSamlSpComparatorTests.id(original, "saml:Assertion");
        String attacker = SIGNATURE.matcher(assertion).replaceFirst("")
                .replace(originalIdentity, "attacker-user")
                .replace(assertionId, "_attacker_assertion");
        String duplicateId = SIGNATURE.matcher(assertion).replaceFirst("")
                .replace(originalIdentity, "attacker-user");
        Matcher signature = SIGNATURE.matcher(original);
        if (!signature.find()) throw new IllegalArgumentException("fixture signature missing");
        String copiedSignature = signature.group();
        String extension = "<samlp:Extensions>" + attacker + "</samlp:Extensions>";
        String issuer = "<saml:Issuer>https://attacker.example.test/</saml:Issuer>";
        return List.of(
                new Mutation("attacker-sibling-before", original.replace(assertion, attacker + assertion)),
                new Mutation("attacker-sibling-after", original.replace(assertion, assertion + attacker)),
                new Mutation("duplicate-id-before", original.replace(assertion, duplicateId + assertion)),
                new Mutation("duplicate-id-after", original.replace(assertion, assertion + duplicateId)),
                new Mutation("attacker-extension", original.replace("<samlp:Status>",
                        extension + "<samlp:Status>")),
                new Mutation("extension-replaces-assertion", original.replace(assertion,
                        extension + attacker)),
                new Mutation("signed-assertion-in-extension", original.replace(assertion,
                        "<samlp:Extensions>" + assertion + "</samlp:Extensions>" + attacker)),
                new Mutation("signed-assertion-in-object", original.replace(assertion,
                        "<ds:Object xmlns:ds='http://www.w3.org/2000/09/xmldsig#'>"
                                + assertion + "</ds:Object>" + attacker)),
                new Mutation("duplicate-issuer", original.replace("<samlp:Status>",
                        issuer + "<samlp:Status>")),
                new Mutation("attacker-sibling-end", original.replace("</samlp:Response>",
                        attacker + "</samlp:Response>")),
                new Mutation("nameid-tamper", original.replace(originalIdentity, "attacker-user")),
                new Mutation("destination-tamper", original.replace("https://sp.test/acs",
                        "https://attacker.example.test/acs")),
                new Mutation("duplicate-nameid", original.replace("<saml:Subject>",
                        "<saml:Subject><saml:NameID>attacker-user</saml:NameID>")),
                new Mutation("duplicate-status", original.replace("<samlp:Status>",
                        "<samlp:Status><samlp:StatusCode "
                                + "Value='urn:oasis:names:tc:SAML:2.0:status:Success'/>"
                                + "</samlp:Status><samlp:Status>")),
                new Mutation("qualified-response-id", original.replace("<samlp:Response ",
                        "<samlp:Response samlp:ID='_attacker_response' ")),
                new Mutation("qualified-assertion-id", original.replace("<saml:Assertion ",
                        "<saml:Assertion saml:ID='_attacker_assertion' ")),
                new Mutation("copied-signature-extension", original.replace("<samlp:Status>",
                        "<samlp:Extensions><Parent xmlns='http://www.w3.org/2000/09/xmldsig#'>"
                                + "<Child xml:xmlns='#other'>" + copiedSignature
                                + "</Child></Parent></samlp:Extensions><samlp:Status>")),
                new Mutation("relative-namespace-sibling", original.replace("<samlp:Response ",
                        "<samlp:Response xmlns:ns='1' ").replace(assertion, attacker + assertion)),
                new Mutation("comment-split-nameid", original.replace(originalIdentity,
                        originalIdentity.substring(0, Math.max(1, originalIdentity.indexOf('-') + 1))
                                + "<!-- -->attacker")));
    }

    record Mutation(@NonNull String name, @NonNull String xml) { }
}
