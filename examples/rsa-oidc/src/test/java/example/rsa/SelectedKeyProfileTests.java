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
package example.rsa;

import com.revetsec.jose.JwsAlgorithm;
import org.jspecify.annotations.NonNull;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.TestFactory;
import javax.annotation.concurrent.ThreadSafe;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.spec.ECGenParameterSpec;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import static org.junit.jupiter.api.Assertions.*;

/** Selected application key profiles; live provider/hardware support is a separate qualification. */
final class SelectedKeyProfileTests {
    static final @NonNull List<@NonNull JwsAlgorithm> SELECTED=List.of(JwsAlgorithm.RS256,JwsAlgorithm.RS384,JwsAlgorithm.RS512,JwsAlgorithm.PS256,JwsAlgorithm.PS384,JwsAlgorithm.PS512,JwsAlgorithm.ES256,JwsAlgorithm.ES384,JwsAlgorithm.ED25519);

    @TestFactory @NonNull List<@NonNull DynamicTest> everySelectedFamilyCanConfigureTheActualRecipe(){
        List<DynamicTest> cells=new ArrayList<>();for(JwsAlgorithm algorithm:SELECTED)cells.add(DynamicTest.dynamicTest("recipe-selected-"+algorithm.getWireValue(),()->{
            KeyPair pair=fresh(algorithm);var provider=assertDoesNotThrow(()->PrivateKeyClients.registeredKey(pair,algorithm,"registered-key"));
            assertEquals("registered-key",provider.getSigningKey(Duration.ofSeconds(1)).getKeyId().orElseThrow());
        }));return cells;
    }

    @TestFactory @NonNull List<@NonNull DynamicTest> signOnlyRecipeDoesNotEncodeOpaquePrivateKeysAtConstruction(){
        List<DynamicTest> cells=new ArrayList<>();for(JwsAlgorithm algorithm:List.of(JwsAlgorithm.PS256,JwsAlgorithm.ES256,JwsAlgorithm.ED25519))cells.add(DynamicTest.dynamicTest("opaque-recipe-"+algorithm.getWireValue(),()->{
            KeyPair pair=fresh(algorithm);String family=algorithm==JwsAlgorithm.PS256?"RSA":algorithm==JwsAlgorithm.ES256?"EC":"Ed25519";
            var provider=assertDoesNotThrow(()->PrivateKeyClients.registeredKey(new KeyPair(pair.getPublic(),new OpaquePrivate(family)),algorithm,"registered-key"));
            assertEquals("registered-key",provider.getSigningKey(Duration.ofSeconds(1)).getKeyId().orElseThrow());
        }));return cells;
    }

    static @NonNull KeyPair fresh(@NonNull JwsAlgorithm algorithm)throws Exception{
        if(algorithm==JwsAlgorithm.ES256 || algorithm==JwsAlgorithm.ES384){var generator=KeyPairGenerator.getInstance("EC");generator.initialize(new ECGenParameterSpec(algorithm==JwsAlgorithm.ES256?"secp256r1":"secp384r1"));return generator.generateKeyPair();}
        if(algorithm==JwsAlgorithm.ED25519)return KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
        var generator=KeyPairGenerator.getInstance("RSA");generator.initialize(2048);return generator.generateKeyPair();
    }
    @ThreadSafe private static final class OpaquePrivate implements PrivateKey {
        private static final long serialVersionUID=1L;
        private final @NonNull String algorithm;
        OpaquePrivate(@NonNull String algorithm){this.algorithm=algorithm;}
        @Override public @NonNull String getAlgorithm(){return this.algorithm;}
        @Override public @NonNull String getFormat(){throw new AssertionError("Private format must remain opaque");}
        @Override public byte @NonNull [] getEncoded(){throw new AssertionError("Private bytes must never be exported");}
    }

    @TestFactory @NonNull List<@NonNull DynamicTest> everyRegistrationPublishesTheMatchingSelectedPublicProfile(){
        List<DynamicTest> cells=new ArrayList<>();for(JwsAlgorithm algorithm:SELECTED)cells.add(DynamicTest.dynamicTest("registered-public-profile-"+algorithm.getWireValue(),()->{
            var registration=PrivateKeyClients.registration(fresh(algorithm),algorithm,"registered-key");var response=registration.getJwksPublisher().responseFor("GET");
            assertEquals(200,response.getStatusCode());var parsed=assertInstanceOf(com.revetsec.jose.JwksParseResult.Succeeded.class,com.revetsec.jose.Jwks.fromJsonResult(new String(response.toHttpBody(),java.nio.charset.StandardCharsets.UTF_8))).getJwks();
            assertEquals(1,parsed.getKeys().size());assertEquals(algorithm,parsed.getKeys().get(0).getAlgorithm().orElseThrow());assertEquals("registered-key",parsed.getKeys().get(0).getKeyId().orElseThrow());assertEquals("sig",parsed.getKeys().get(0).getUse().orElseThrow());
            var material=registration.getJwksPublisher().getKeys().get(0).toJsonObject().getMembers();for(String name:List.of("d","p","q","dp","dq","qi","oth","k"))assertFalse(material.containsKey(name));
            assertEquals("registered-key",registration.getKeyProvider().getSigningKey(Duration.ofSeconds(1)).getKeyId().orElseThrow());assertEquals("PrivateKeyClients.Registration{<redacted>}",registration.toString());
        }));return cells;
    }

    @TestFactory @NonNull List<@NonNull DynamicTest> publicationUsesTheSignerSnapshotRatherThanResnapshottingMutableInput(){
        List<DynamicTest> cells=new ArrayList<>();for(JwsAlgorithm algorithm:List.of(JwsAlgorithm.RS256,JwsAlgorithm.ES256,JwsAlgorithm.ED25519))cells.add(DynamicTest.dynamicTest("joint-public-snapshot-"+algorithm.getWireValue(),()->{
            KeyPair first=fresh(algorithm),second=fresh(algorithm);var calls=new java.util.concurrent.atomic.AtomicInteger();java.security.PublicKey mutable;
            if(algorithm==JwsAlgorithm.RS256)mutable=new MutableRsa((java.security.interfaces.RSAPublicKey)first.getPublic(),(java.security.interfaces.RSAPublicKey)second.getPublic(),calls);
            else if(algorithm==JwsAlgorithm.ES256)mutable=new MutableEc((java.security.interfaces.ECPublicKey)first.getPublic(),(java.security.interfaces.ECPublicKey)second.getPublic(),calls);
            else mutable=new MutableEd((java.security.interfaces.EdECPublicKey)first.getPublic(),(java.security.interfaces.EdECPublicKey)second.getPublic(),calls);
            var registration=PrivateKeyClients.registration(new KeyPair(mutable,first.getPrivate()),algorithm,"registered-key");var material=registration.getJwksPublisher().getKeys().get(0).toJsonObject();assertEquals(1,calls.get(),"Original public material must be inspected only by the signer snapshot");
            var expected=com.revetsec.jose.PublishedJwk.withPublicKey(first.getPublic()).algorithm(algorithm).keyId("registered-key").build().toJsonObject();assertEquals(expected,material);
        }));return cells;
    }

    @TestFactory @NonNull List<@NonNull DynamicTest> unsupportedAlgorithmsAreExplicitlyRefusedWithoutFamilyFallback(){
        List<DynamicTest> cells=new ArrayList<>();for(JwsAlgorithm algorithm:List.of(JwsAlgorithm.HS256,JwsAlgorithm.HS384,JwsAlgorithm.HS512,JwsAlgorithm.ES512,JwsAlgorithm.EDDSA))cells.add(DynamicTest.dynamicTest("unsupported-recipe-"+algorithm.getWireValue(),()->{
            KeyPair pair=fresh(JwsAlgorithm.RS256);assertThrows(IllegalArgumentException.class,()->PrivateKeyClients.registeredKey(pair,algorithm,"registered-key"));assertThrows(IllegalArgumentException.class,()->PrivateKeyClients.registration(pair,algorithm,"registered-key"));
        }));return cells;
    }

    @TestFactory @NonNull List<@NonNull DynamicTest> mismatchedCurveAndFamilyProfilesFailBeforeCredentialUse(){
        List<DynamicTest> cells=new ArrayList<>();
        for(String label:List.of("P256-as-ES384","P384-as-ES256","RSA-as-ES256","EC-as-RS256","ED-as-RS256","RSA-as-ED25519","Ed448-as-ED25519","X25519-as-ED25519"))cells.add(DynamicTest.dynamicTest(label,()->{
            KeyPair pair;JwsAlgorithm selected;
            switch(label){
                case "P256-as-ES384"->{pair=fresh(JwsAlgorithm.ES256);selected=JwsAlgorithm.ES384;}
                case "P384-as-ES256"->{pair=fresh(JwsAlgorithm.ES384);selected=JwsAlgorithm.ES256;}
                case "RSA-as-ES256"->{pair=fresh(JwsAlgorithm.RS256);selected=JwsAlgorithm.ES256;}
                case "EC-as-RS256"->{pair=fresh(JwsAlgorithm.ES256);selected=JwsAlgorithm.RS256;}
                case "ED-as-RS256"->{pair=fresh(JwsAlgorithm.ED25519);selected=JwsAlgorithm.RS256;}
                case "RSA-as-ED25519"->{pair=fresh(JwsAlgorithm.RS256);selected=JwsAlgorithm.ED25519;}
                default->{pair=KeyPairGenerator.getInstance(label.startsWith("Ed448")?"Ed448":"X25519").generateKeyPair();selected=JwsAlgorithm.ED25519;}
            }
            assertThrows(IllegalArgumentException.class,()->PrivateKeyClients.registeredKey(pair,selected,"registered-key"));assertThrows(IllegalArgumentException.class,()->PrivateKeyClients.registration(pair,selected,"registered-key"));
        }));return cells;
    }

    @org.junit.jupiter.api.Test void aValidEd25519PairDoesNotAuthorizeTheLegacyEdDsaWireAlgorithm() throws Exception {
        KeyPair pair=fresh(JwsAlgorithm.ED25519);
        assertThrows(IllegalArgumentException.class,()->PrivateKeyClients.registeredKey(pair,JwsAlgorithm.EDDSA,"registered-key"));
        assertThrows(IllegalArgumentException.class,()->PrivateKeyClients.registration(pair,JwsAlgorithm.EDDSA,"registered-key"));
    }

    @org.junit.jupiter.api.Test void restrictedPssSignOnlySupportDoesNotPretendGenericRsaPublication() throws Exception {
        var generator=KeyPairGenerator.getInstance("RSASSA-PSS");var pss=new java.security.spec.PSSParameterSpec("SHA-256","MGF1",java.security.spec.MGF1ParameterSpec.SHA256,32,1);generator.initialize(new java.security.spec.RSAKeyGenParameterSpec(2048,java.security.spec.RSAKeyGenParameterSpec.F4,pss));KeyPair pair=generator.generateKeyPair();
        var signing=assertDoesNotThrow(()->PrivateKeyClients.registeredKey(pair,JwsAlgorithm.PS256,"registered-key"));assertEquals("registered-key",signing.getSigningKey(Duration.ofSeconds(1)).getKeyId().orElseThrow());
        assertThrows(IllegalArgumentException.class,()->PrivateKeyClients.registration(pair,JwsAlgorithm.PS256,"registered-key"));
    }

    @ThreadSafe private static final class MutableRsa implements java.security.interfaces.RSAPublicKey {
        private static final long serialVersionUID=1L;private final java.security.interfaces.@NonNull RSAPublicKey first,second;private final java.util.concurrent.atomic.@NonNull AtomicInteger calls;
        MutableRsa(java.security.interfaces.@NonNull RSAPublicKey first,java.security.interfaces.@NonNull RSAPublicKey second,java.util.concurrent.atomic.@NonNull AtomicInteger calls){this.first=first;this.second=second;this.calls=calls;}
        @Override public java.math.@NonNull BigInteger getModulus(){return this.calls.getAndIncrement()==0?this.first.getModulus():this.second.getModulus();}
        @Override public java.math.@NonNull BigInteger getPublicExponent(){return this.first.getPublicExponent();}
        @Override public @NonNull String getAlgorithm(){return "RSA";}@Override public @NonNull String getFormat(){throw new AssertionError("No public encoding needed");}@Override public byte @NonNull [] getEncoded(){throw new AssertionError("No public encoding needed");}
    }
    @ThreadSafe private static final class MutableEc implements java.security.interfaces.ECPublicKey {
        private static final long serialVersionUID=1L;private final java.security.interfaces.@NonNull ECPublicKey first,second;private final java.util.concurrent.atomic.@NonNull AtomicInteger calls;
        MutableEc(java.security.interfaces.@NonNull ECPublicKey first,java.security.interfaces.@NonNull ECPublicKey second,java.util.concurrent.atomic.@NonNull AtomicInteger calls){this.first=first;this.second=second;this.calls=calls;}
        @Override public java.security.spec.@NonNull ECPoint getW(){return this.calls.getAndIncrement()==0?this.first.getW():this.second.getW();}
        @Override public java.security.spec.@NonNull ECParameterSpec getParams(){return this.first.getParams();}
        @Override public @NonNull String getAlgorithm(){return "EC";}@Override public @NonNull String getFormat(){throw new AssertionError("No public encoding needed");}@Override public byte @NonNull [] getEncoded(){throw new AssertionError("No public encoding needed");}
    }
    @ThreadSafe private static final class MutableEd implements java.security.interfaces.EdECPublicKey {
        private static final long serialVersionUID=1L;private final java.security.interfaces.@NonNull EdECPublicKey first,second;private final java.util.concurrent.atomic.@NonNull AtomicInteger calls;
        MutableEd(java.security.interfaces.@NonNull EdECPublicKey first,java.security.interfaces.@NonNull EdECPublicKey second,java.util.concurrent.atomic.@NonNull AtomicInteger calls){this.first=first;this.second=second;this.calls=calls;}
        @Override public java.security.spec.@NonNull EdECPoint getPoint(){return this.calls.getAndIncrement()==0?this.first.getPoint():this.second.getPoint();}
        @Override public java.security.spec.@NonNull NamedParameterSpec getParams(){return this.first.getParams();}
        @Override public @NonNull String getAlgorithm(){return "Ed25519";}@Override public @NonNull String getFormat(){throw new AssertionError("No public encoding needed");}@Override public byte @NonNull [] getEncoded(){throw new AssertionError("No public encoding needed");}
    }
}
