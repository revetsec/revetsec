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

package com.revetsec.internal.xml;

import org.jspecify.annotations.NonNull;
import org.junit.jupiter.api.Test;
import org.w3c.dom.Element;

import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;

final class SamlResponseStructureTests {
    private static final String OPEN = "<p:Response xmlns:p='urn:oasis:names:tc:SAML:2.0:protocol' "
            + "xmlns:a='urn:oasis:names:tc:SAML:2.0:assertion' "
            + "xmlns:ds='http://www.w3.org/2000/09/xmldsig#' "
            + "ID='_response' Version='2.0' IssueInstant='2026-10-09T00:00:00Z'>";
    private static final String CLOSE = "</p:Response>";
    private static final String SUCCESS = "<p:Status><p:StatusCode "
            + "Value='urn:oasis:names:tc:SAML:2.0:status:Success'/></p:Status>";
    private static final String DENIED = "<p:Status><p:StatusCode "
            + "Value='urn:oasis:names:tc:SAML:2.0:status:Responder'/></p:Status>";
    private static final String ASSERTION = "<a:Assertion ID='_assertion'/>";

    @Test void selectsOnlyOriginalDirectChildNodesWithoutTreatingThemAsVerified() {
        SecureXmlParser.Result.Accepted parsed = parse(OPEN + "<a:Issuer>idp</a:Issuer>"
                + "<ds:Signature/>" + SUCCESS + ASSERTION + CLOSE);
        SamlResponseStructure.Accepted accepted = assertInstanceOf(SamlResponseStructure.Accepted.class,
                SamlResponseStructure.inspect(parsed.getDocument()));
        SamlResponseStructure.Shape shape = accepted.getShape();
        Element root = parsed.getDocument().getDocumentElement();
        assertSame(root, shape.getResponse());
        assertSame(root.getFirstChild(), shape.getIssuer());
        assertSame(root.getLastChild(), shape.getAssertion());
        assertNull(shape.getEncryptedAssertion());
        assertEquals("<unverified>", accepted.toString().substring(accepted.toString().indexOf('{') + 1,
                accepted.toString().length() - 1));
    }

    @Test void permitsAStatusOnlyErrorAndOneEncryptedAssertionOnSuccess() {
        assertInstanceOf(SamlResponseStructure.Accepted.class, inspect(OPEN + DENIED + CLOSE));
        assertInstanceOf(SamlResponseStructure.Accepted.class,
                inspect(OPEN + SUCCESS + "<a:EncryptedAssertion/>" + CLOSE));
    }

    @Test void rejectsWrappedDuplicatedAndMisorderedAssertions() {
        rejected(OPEN + SUCCESS + "<p:Extensions>" + ASSERTION + "</p:Extensions>" + CLOSE);
        rejected(OPEN + SUCCESS + ASSERTION + "<a:Assertion ID='_second'/>" + CLOSE);
        rejected(OPEN + SUCCESS + ASSERTION + "<a:EncryptedAssertion/>" + CLOSE);
        rejected(OPEN + DENIED + ASSERTION + CLOSE);
        rejected(OPEN + SUCCESS + CLOSE);
        rejected(OPEN + ASSERTION + SUCCESS + CLOSE);
        rejected(OPEN + SUCCESS + "<a:Assertion ID='_assertion'><a:Advice>"
                + "<a:Assertion ID='_nested'/></a:Advice></a:Assertion>" + CLOSE);
    }

    @Test void rejectsSignatureWrappingAndNamespaceAndAttributePollution() {
        rejected(OPEN + "<ds:Signature/>" + "<ds:Signature/>" + SUCCESS + ASSERTION + CLOSE);
        rejected(OPEN + SUCCESS + "<a:Assertion ID='_assertion'><a:Advice>"
                + "<ds:Signature/></a:Advice></a:Assertion>" + CLOSE);
        rejected(OPEN + SUCCESS + "<a:Assertion ID='_assertion' xmlns:evil='relative/path'/>" + CLOSE);
        rejected(OPEN + SUCCESS + "<a:Assertion ID='_assertion' a:ID='_spoof'/>" + CLOSE);
        rejected(OPEN + SUCCESS + "<a:Assertion ID='_assertion'>"
                + "<old:Assertion xmlns:old='urn:oasis:names:tc:SAML:1.0:assertion'/></a:Assertion>" + CLOSE);
        rejected(OPEN + SUCCESS + "<foreign:Assertion xmlns:foreign='urn:foreign'/>" + CLOSE);
        rejected(OPEN.replace("Version='2.0'", "Version='1.1'") + SUCCESS + ASSERTION + CLOSE);
    }

    private static void rejected(@NonNull String xml) {
        assertSame(SamlResponseStructure.Rejected.INSTANCE, inspect(xml));
    }

    private static SamlResponseStructure.@NonNull Result inspect(@NonNull String xml) {
        return SamlResponseStructure.inspect(parse(xml).getDocument());
    }

    private static SecureXmlParser.Result.@NonNull Accepted parse(@NonNull String xml) {
        return assertInstanceOf(SecureXmlParser.Result.Accepted.class,
                SecureXmlParser.parseResponse(xml.getBytes(StandardCharsets.UTF_8)));
    }
}
