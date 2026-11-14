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

import com.revetsec.internal.xml.SecureXmlParser;
import org.jspecify.annotations.NonNull;
import org.junit.jupiter.api.TestFactory;
import org.junit.jupiter.api.DynamicTest;
import org.w3c.dom.Element;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.*;
import java.util.concurrent.atomic.AtomicInteger;
import static org.junit.jupiter.api.Assertions.*;

final class SamlNamespaceCoverageTests {
    private static final String A="urn:oasis:names:tc:SAML:2.0:assertion", P="urn:oasis:names:tc:SAML:2.0:protocol", X="http://www.w3.org/2001/XMLSchema", I="http://www.w3.org/2001/XMLSchema-instance";
    private record Shape(@NonNull String element,@NonNull String elementNs,@NonNull String type,@NonNull String typeNs) {}
    private static @NonNull List<@NonNull Shape> shapes() {
        var out=new ArrayList<Shape>();
        for(String name:List.of("Assertion","Subject","NameID","Issuer","SubjectConfirmation","SubjectConfirmationData","Conditions","AudienceRestriction","OneTimeUse","ProxyRestriction","SubjectLocality","AuthnContext","AuthnStatement","AuthzDecisionStatement","Advice","AttributeStatement","Attribute"))
            out.add(new Shape(name,A,name.equals("Issuer")?"NameIDType":name+"Type",A));
        for(String name:List.of("Response","Status","StatusCode","StatusDetail","LogoutRequest","LogoutResponse"))
            out.add(new Shape(name,P,name.equals("LogoutResponse")?"StatusResponseType":name+"Type",P));
        for(String name:List.of("Audience","AuthnContextClassRef","AuthnContextDeclRef","AuthenticatingAuthority"))out.add(new Shape(name,A,"anyURI",X));
        out.add(new Shape("SessionIndex",P,"string",X));out.add(new Shape("StatusMessage",P,"string",X));return out;
    }
    private static @NonNull Element element(@NonNull Shape shape,@NonNull String attributes) {
        String xml="<n:"+shape.element()+" xmlns:n='"+shape.elementNs()+"' xmlns:xsi='"+I+"' xmlns:t='"+shape.typeNs()+"' "+attributes+"/>";
        return Objects.requireNonNull(assertInstanceOf(SecureXmlParser.Result.Accepted.class,SecureXmlParser.parseResponse(xml.getBytes(StandardCharsets.UTF_8))).getDocument().getDocumentElement());
    }
    @TestFactory @NonNull List<@NonNull DynamicTest> everyConsumedDeclarationUsesItsOwnElementNamespaceInsteadOfAnUnusedTypeAlias() {
        var tests=new ArrayList<DynamicTest>();for(Shape shape:shapes())for(String mode:List.of("absent","visible","unused-alias","wrong-type","nil"))
            tests.add(DynamicTest.dynamicTest(shape.element()+"/"+shape.type()+"/"+mode,()->{
                String attributes=switch(mode){case "absent"->"";case "visible"->"xsi:type='n:"+shape.type()+"'";case "unused-alias"->"xsi:type='t:"+shape.type()+"'";case "wrong-type"->"xsi:type='n:DifferentType'";case "nil"->"xsi:nil='true'";default->throw new AssertionError();};
                boolean expected=mode.equals("absent") || (mode.equals("visible")&&shape.elementNs().equals(shape.typeNs()));
                assertEquals(expected,SamlResponseSemantics.scalarDeclarationAllowed(element(shape,attributes),shape.typeNs(),shape.type()));
            }));return tests;
    }
    @TestFactory @NonNull List<@NonNull DynamicTest> genuineSignaturesCannotAuthorizeARebindableStructuralTypeNamespace() {
        var tests=new ArrayList<DynamicTest>();for(String target:List.of("NameID","SubjectConfirmationData","Audience"))for(boolean responseSigned:List.of(false,true))
            tests.add(DynamicTest.dynamicTest(target+"/responseSigned="+responseSigned,()->{
                String type=target.equals("NameID")?"NameIDType":target.equals("SubjectConfirmationData")?"SubjectConfirmationDataType":"anyURI";
                String namespace=target.equals("Audience")?X:A;
                String marker="<a:"+target+(target.equals("SubjectConfirmationData")?" ":">");String input=SamlResponseSemanticsTests.BASE.replace(marker,"<a:"+target+" xmlns:xsi='"+I+"' xmlns:t='"+namespace+"' xsi:type='t:"+type+"'"+(target.equals("SubjectConfirmationData")?" ":">"));
                KeyPairGenerator generator=KeyPairGenerator.getInstance("RSA");generator.initialize(2048);KeyPair key=generator.generateKeyPair();
                String signed=SamlResponseSemanticsTests.signedXml(input,responseSigned,!responseSigned,key.getPrivate());
                String rebound=signed.replace("xmlns:t=\""+namespace+"\"","xmlns:t=\"urn:example:uncovered-shadow\"");assertNotEquals(signed,rebound);
                var writes=new AtomicInteger();var outcomes=new ArrayList<SamlResponseSemantics.Result>();
                for(String document:List.of(signed,rebound)){
                    String encoded=Base64.getEncoder().encodeToString(document.getBytes(StandardCharsets.UTF_8)).replace("+","%2B").replace("/","%2F").replace("=","%3D");
                    var inbound=assertInstanceOf(SamlInboundResponse.Accepted.class,SamlInboundResponse.parse(("SAMLResponse="+encoded+"&RelayState=relay").getBytes(StandardCharsets.UTF_8),List.of("application/x-www-form-urlencoded"),null));
                    var verified=assertInstanceOf(SamlInboundResponse.SignaturesVerified.class,SamlInboundResponse.verifySuccessSignatures(inbound,List.of(key.getPublic())),"both namespace variants must really verify before semantic comparison");
                    var expected=new SamlResponseSemantics.Expectation("https://sp.example.test/saml","tenant-one","https://idp.example.test/saml","https://sp.example.test/acs","_request","relay",Instant.parse("2026-10-09T00:10:00Z"),Clock.fixed(Instant.parse("2026-10-09T00:01:00Z"),ZoneOffset.UTC),Duration.ofMinutes(3),Duration.ofMinutes(5),false,List.of(),(k,e,b)->{writes.incrementAndGet();return SamlReplayCache.MarkResult.MARKED;},Duration.ofSeconds(5));
                    outcomes.add(SamlResponseSemantics.validate(verified,expected));
                }
                assertTrue(outcomes.stream().allMatch(SamlResponseSemantics.Rejected.class::isInstance),"an unused namespace alias cannot decide semantic acceptance");assertEquals(0,writes.get(),"no replay state may be charged on refusal");
            }));return tests;
    }
}
