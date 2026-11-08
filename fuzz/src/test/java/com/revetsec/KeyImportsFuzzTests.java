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

import com.code_intelligence.jazzer.junit.FuzzTest;
import java.io.InputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.*;
import java.security.interfaces.*;
import java.security.spec.*;
import java.time.Duration;
import java.util.*;
import javax.annotation.concurrent.ThreadSafe;
import org.jspecify.annotations.NonNull;
import static org.junit.jupiter.api.Assertions.*;

/** Public import/pair paths, bounded framing and independent JCA/profile checks; certificates imply no trust. */
@ThreadSafe
public final class KeyImportsFuzzTests {
    private static final @NonNull List<@NonNull String> LABELS=List.of("CERTIFICATE","PUBLIC KEY","PRIVATE KEY","RSA PRIVATE KEY");
    private static final @NonNull List<@NonNull String> FAMILIES=List.of("rsa","p256","p384","ed25519");
    private static final @NonNull List<@NonNull KeyPair> WRONG=otherKeys();

    /** Arbitrary DER/armor either yields a selected independently checked profile or one fixed failure. */
    @FuzzTest(maxDuration="5m")
    public void publicImportPathsAreBoundedAndAgreeWithArmor(byte @NonNull [] input)throws Exception {
        if(input.length>65537)return; // The campaign's declared maximum, without truncating accepted input.
        byte[] before=input.clone();
        for(int kind=0;kind<4;kind++) {
            String armored="-----BEGIN "+LABELS.get(kind)+"-----\n"+Base64.getEncoder().encodeToString(input)+"\n-----END "+LABELS.get(kind)+"-----\n";
            boolean derAccepted=attemptDer(kind,input),pemAccepted=attemptPem(kind,armored);
            assertEquals(derAccepted,pemAccepted,"der-armor-acceptance");
            if(derAccepted)assertTrue(outerSequence(input),"independent-canonical-outer-frame");
        }
        String raw=new String(input,StandardCharsets.ISO_8859_1);
        for(int kind=0;kind<3;kind++)attemptPem(kind,raw);
        assertArrayEquals(before,input,"caller-der-preserved");
    }

    /** Ordinary OpenSSL fixtures supply four real families; mismatch and zero budget cannot pass a pair check. */
    @FuzzTest(maxDuration="5m")
    public void ordinaryFixturePairsAgreeWithIndependentJca(byte @NonNull [] input)throws Exception {
        int family=choice(input,0,4),mode=choice(input,1,3);String name=FAMILIES.get(family);
        String certificate=fixture(name+"-certificate.pem"),privatePem=fixture(name+"-private.pem"),publicPem=fixture(name+"-public.pem");
        PublicKey imported=KeyImports.publicKeyFromPem(publicPem),certificateKey=KeyImports.certificateFromPem(certificate).getPublicKey();
        PrivateKey secret=KeyImports.privateKeyFromPem(privatePem);profile(imported);profile(secret);profile(certificateKey);
        assertArrayEquals(imported.getEncoded(),certificateKey.getEncoded(),"ordinary-public-certificate-agree");
        PublicKey independent=CertificateFactory.getInstance("X.509").generateCertificate(new java.io.ByteArrayInputStream(body(certificate))).getPublicKey();
        assertArrayEquals(independent.getEncoded(),imported.getEncoded(),"independent-certificate-parser");
        PublicKey selected=mode==1?WRONG.get(family).getPublic():imported;
        try {
            KeyImports.checkKeyPair(secret,selected,mode==2?Duration.ZERO:Duration.ofSeconds(5));
            assertEquals(0,mode,"mismatch-or-zero-budget-cannot-pass-pair");
            String algorithm=family==0?"SHA256withRSA":family==1?"SHA256withECDSA":family==2?"SHA384withECDSA":"Ed25519";
            byte[] challenge=Arrays.copyOf(input,Math.min(256,input.length));Signature signer=Signature.getInstance(algorithm);signer.initSign(secret);signer.update(challenge);byte[] signature=signer.sign();
            try {Signature verifier=Signature.getInstance(algorithm);verifier.initVerify(independent);verifier.update(challenge);assertTrue(verifier.verify(signature),"independent-pair-verification");}
            finally{Arrays.fill(challenge,(byte)0);Arrays.fill(signature,(byte)0);}
        }catch(KeyImportException refused){fixed(refused);assertEquals(mode==2?KeyImportException.Reason.BUDGET_EXHAUSTED:KeyImportException.Reason.KEY_PAIR_MISMATCH,refused.getReason());assertNotEquals(0,mode);}
    }
    private static boolean attemptDer(int kind,byte @NonNull [] input)throws Exception {
        try {Object value=switch(kind){case 0->KeyImports.certificateFromDer(input);case 1->KeyImports.publicKeyFromSpkiDer(input);case 2->KeyImports.privateKeyFromPkcs8Der(input);default->KeyImports.rsaPrivateKeyFromPkcs1Der(input);};accepted(value);return true;}
        catch(KeyImportException refused){fixed(refused);if(input.length>65536)assertEquals(KeyImportException.Reason.INPUT_TOO_LARGE,refused.getReason());return false;}
    }
    private static boolean attemptPem(int kind,@NonNull String input)throws Exception {
        try{Object value=switch(kind){case 0->KeyImports.certificateFromPem(input);case 1->KeyImports.publicKeyFromPem(input);default->KeyImports.privateKeyFromPem(input);};accepted(value);return true;}
        catch(KeyImportException refused){fixed(refused);return false;}
    }
    private static void accepted(@NonNull Object value)throws Exception {if(value instanceof X509Certificate certificate)profile(certificate.getPublicKey());else profile((Key)value);}
    private static void profile(@NonNull Key key)throws Exception {
        if(key instanceof RSAKey rsa){assertTrue(rsa.getModulus().bitLength()>=2048&&rsa.getModulus().bitLength()<=16384&&rsa.getModulus().testBit(0));assertTrue(key instanceof RSAPublicKey||key instanceof RSAPrivateCrtKey);BigInteger exponent=key instanceof RSAPublicKey pub?pub.getPublicExponent():((RSAPrivateCrtKey)key).getPublicExponent();assertTrue(exponent.testBit(0)&&exponent.compareTo(BigInteger.valueOf(65537))>=0&&exponent.bitLength()<=32);return;}
        if(key instanceof ECKey ec){ECParameterSpec parameters=ec.getParams();int bits=parameters.getCurve().getField().getFieldSize();assertTrue(bits==256||bits==384);AlgorithmParameters named=AlgorithmParameters.getInstance("EC");named.init(new ECGenParameterSpec(bits==256?"secp256r1":"secp384r1"));ECParameterSpec expected=named.getParameterSpec(ECParameterSpec.class);assertEquals(expected.getCurve(),parameters.getCurve());assertEquals(expected.getGenerator(),parameters.getGenerator());assertEquals(expected.getOrder(),parameters.getOrder());assertEquals(expected.getCofactor(),parameters.getCofactor());if(key instanceof ECPrivateKey privateKey)assertTrue(privateKey.getS().signum()>0&&privateKey.getS().compareTo(parameters.getOrder())<0);if(key instanceof ECPublicKey publicKey){BigInteger p=((ECFieldFp)parameters.getCurve().getField()).getP(),x=publicKey.getW().getAffineX(),y=publicKey.getW().getAffineY();assertTrue(x.signum()>=0&&x.compareTo(p)<0&&y.signum()>=0&&y.compareTo(p)<0);assertEquals(y.multiply(y).mod(p),x.multiply(x).multiply(x).add(parameters.getCurve().getA().multiply(x)).add(parameters.getCurve().getB()).mod(p));}return;}
        assertTrue(key instanceof EdECKey,"selected-key-family");assertEquals("Ed25519",((EdECKey)key).getParams().getName());
    }
    private static boolean outerSequence(byte @NonNull [] bytes){if(bytes.length<2||bytes[0]!=0x30)return false;int header=2,length=Byte.toUnsignedInt(bytes[1]);if(length>=128){int count=length&127;if(count<1||count>3||bytes.length<2+count||bytes[2]==0)return false;header+=count;length=0;for(int i=0;i<count;i++)length=(length<<8)|Byte.toUnsignedInt(bytes[2+i]);if(length<128)return false;}return header+length==bytes.length;}
    private static void fixed(@NonNull KeyImportException refused){assertNull(refused.getCause());assertEquals(0,refused.getSuppressed().length);String message=switch(refused.getReason()){case INPUT_TOO_LARGE->"The key import input exceeds its size limit.";case MALFORMED_INPUT->"The key import input is malformed.";case UNSUPPORTED_KEY->"The key import profile is not supported.";case KEY_REJECTED->"The imported key does not satisfy the key policy.";case KEY_PAIR_MISMATCH->"The key pair does not match.";case OPERATION_UNAVAILABLE->"The key import operation is unavailable.";case BUDGET_EXHAUSTED->"The key pair check budget is exhausted.";case CANCELLED->"The key pair check was interrupted.";};assertEquals(message,refused.getMessage());}
    private static @NonNull String fixture(@NonNull String name)throws Exception {try(InputStream stream=Objects.requireNonNull(KeyImportsFuzzTests.class.getResourceAsStream("/fixtures/key-import-profile/"+name))){return new String(stream.readAllBytes(),StandardCharsets.US_ASCII);}}
    private static byte @NonNull [] body(@NonNull String pem){return Base64.getMimeDecoder().decode(pem.replaceAll("-----[^\\r\\n]+-----", ""));}
    private static int choice(byte @NonNull [] input,int at,int count){return(at<input.length?Byte.toUnsignedInt(input[at]):0)%count;}
    private static @NonNull List<@NonNull KeyPair> otherKeys(){try{KeyPairGenerator rsa=KeyPairGenerator.getInstance("RSA");rsa.initialize(2048);KeyPairGenerator p256=KeyPairGenerator.getInstance("EC");p256.initialize(new ECGenParameterSpec("secp256r1"));KeyPairGenerator p384=KeyPairGenerator.getInstance("EC");p384.initialize(new ECGenParameterSpec("secp384r1"));return List.of(rsa.generateKeyPair(),p256.generateKeyPair(),p384.generateKeyPair(),KeyPairGenerator.getInstance("Ed25519").generateKeyPair());}catch(GeneralSecurityException failure){throw new AssertionError(failure);}}
}
