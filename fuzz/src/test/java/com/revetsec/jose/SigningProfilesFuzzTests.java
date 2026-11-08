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

package com.revetsec.jose;

import com.code_intelligence.jazzer.junit.FuzzTest;
import com.revetsec.json.JsonObject;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.*;
import java.time.Duration;
import java.util.*;
import javax.annotation.concurrent.ThreadSafe;
import org.jspecify.annotations.NonNull;
import static org.junit.jupiter.api.Assertions.*;

/** Selected nine signing algorithms checked by independent JCA engines, including fixed-length EC. */
@ThreadSafe
public final class SigningProfilesFuzzTests {
    private static final @NonNull List<@NonNull JwsAlgorithm> ALGORITHMS = List.of(JwsAlgorithm.RS256,JwsAlgorithm.RS384,JwsAlgorithm.RS512,JwsAlgorithm.PS256,JwsAlgorithm.PS384,JwsAlgorithm.PS512,JwsAlgorithm.ES256,JwsAlgorithm.ES384,JwsAlgorithm.ED25519);
    private static final @NonNull List<@NonNull KeyPair> KEYS = keys();
    private static final @NonNull List<@NonNull KeyPair> OTHERS = keys();

    /** Arbitrary data reaches all selected algorithms; same-family mismatches and zero budgets release no credential. */
    @FuzzTest(maxDuration="5m")
    public void allSelectedAlgorithmsMatchIndependentJcaAndPreservePayload(byte @NonNull [] input)throws Exception {
        int selected=choice(input,0,9),family=selected<6?0:selected-5;
        boolean mismatch=choice(input,1,3)==1,exhausted=choice(input,1,3)==2;
        JwsAlgorithm algorithm=ALGORITHMS.get(selected);KeyPair pair=KEYS.get(family);
        PublicKey publicKey=(mismatch?OTHERS:KEYS).get(family).getPublic();
        JwsSigner signer=selected<6?JwsSigner.fromRsaKeyPair(pair.getPrivate(),publicKey,algorithm):selected<8?JwsSigner.fromEcKeyPair(pair.getPrivate(),publicKey,algorithm):JwsSigner.fromEd25519KeyPair(pair.getPrivate(),publicKey);
        String value=new String(Arrays.copyOfRange(input,Math.min(2,input.length),Math.min(2050,input.length)),StandardCharsets.ISO_8859_1);
        byte[] payload=JsonObject.builder().put("value",value).build().toJson().getBytes(StandardCharsets.UTF_8),before=payload.clone();
        try {
            String compact=signer.toCompactSerialization("JWT","fuzz",null,payload,exhausted?Duration.ZERO:Duration.ofSeconds(5));
            assertFalse(mismatch||exhausted,"mismatch-or-exhaustion-must-withhold");
            String[] parts=compact.split("\\.",-1);assertEquals(3,parts.length);
            assertArrayEquals(before,Base64.getUrlDecoder().decode(parts[1]),"exact-caller-payload");
            assertTrue(new String(Base64.getUrlDecoder().decode(parts[0]),StandardCharsets.UTF_8).contains("\"alg\":\""+algorithm.getWireValue()+"\""));
            Signature verifier=engine(selected);verifier.initVerify(pair.getPublic());
            byte[] signing=(parts[0]+"."+parts[1]).getBytes(StandardCharsets.US_ASCII),signature=Base64.getUrlDecoder().decode(parts[2]);
            try {
                verifier.update(signing);assertTrue(verifier.verify(signature),"independent-jca-signature");
                signing[0]^=1;verifier.initVerify(pair.getPublic());verifier.update(signing);assertFalse(verifier.verify(signature),"changed-signing-input-rejected");
            } finally {Arrays.fill(signing,(byte)0);Arrays.fill(signature,(byte)0);}
        } catch(JwsSigningException refused) {
            assertTrue(mismatch||exhausted,"valid-profile-must-sign");assertNull(refused.getCause());assertEquals(0,refused.getSuppressed().length);
            assertEquals(exhausted?JwsSigningException.Reason.BUDGET_EXHAUSTED:JwsSigningException.Reason.KEY_PAIR_MISMATCH,refused.getReason());
        } finally {assertArrayEquals(before,payload,"caller-payload-not-mutated");Arrays.fill(payload,(byte)0);Arrays.fill(before,(byte)0);}
    }
    private static int choice(byte @NonNull [] input,int at,int count){return(at<input.length?Byte.toUnsignedInt(input[at]):0)%count;}
    private static @NonNull Signature engine(int selected)throws GeneralSecurityException {
        if(selected>=6)return Signature.getInstance(selected==6?"SHA256withECDSAinP1363Format":selected==7?"SHA384withECDSAinP1363Format":"Ed25519");
        String hash=List.of("SHA-256","SHA-384","SHA-512").get(selected%3);
        Signature value=Signature.getInstance(selected<3?hash.replace("-","")+"withRSA":"RSASSA-PSS");
        if(selected>=3)value.setParameter(new PSSParameterSpec(hash,"MGF1",new MGF1ParameterSpec(hash),List.of(32,48,64).get(selected%3),1));
        return value;
    }
    private static @NonNull List<@NonNull KeyPair> keys(){
        try {
            KeyPairGenerator rsa=KeyPairGenerator.getInstance("RSA");rsa.initialize(2048);
            KeyPairGenerator p256=KeyPairGenerator.getInstance("EC");p256.initialize(new ECGenParameterSpec("secp256r1"));
            KeyPairGenerator p384=KeyPairGenerator.getInstance("EC");p384.initialize(new ECGenParameterSpec("secp384r1"));
            return List.of(rsa.generateKeyPair(),p256.generateKeyPair(),p384.generateKeyPair(),KeyPairGenerator.getInstance("Ed25519").generateKeyPair());
        }catch(GeneralSecurityException failure){throw new AssertionError(failure);}
    }
}
