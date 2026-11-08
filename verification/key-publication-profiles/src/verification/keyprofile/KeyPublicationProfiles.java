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
package verification.keyprofile;

import com.revetsec.KeyImportException;
import com.revetsec.KeyImports;
import com.revetsec.jose.*;
import org.jspecify.annotations.NonNull;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.*;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.*;
import java.time.Duration;
import java.util.Arrays;
import java.util.Base64;
import java.util.HexFormat;
import java.util.List;

/** Public-only characterization of distinct signing, import and publication profiles. */
public final class KeyPublicationProfiles {
    private KeyPublicationProfiles() {}
    public static void main(@NonNull String @NonNull [] args) throws Exception {
        if(args.length!=1)throw new IllegalArgumentException("Expected selected core SHA-256.");
        Path origin=Path.of(JwsSigner.class.getProtectionDomain().getCodeSource().getLocation().toURI());
        String actual=HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(Files.readAllBytes(origin)));
        check(actual.equals(args[0]),"Selected core origin mismatch.");
        KeyPairGenerator generator=KeyPairGenerator.getInstance("RSA");generator.initialize(2048);KeyPair pair=generator.generateKeyPair();
        RSAPublicKey generic=(RSAPublicKey)pair.getPublic();
        for(JwsAlgorithm algorithm:List.of(JwsAlgorithm.RS256,JwsAlgorithm.RS384,JwsAlgorithm.RS512,JwsAlgorithm.PS256,JwsAlgorithm.PS384,JwsAlgorithm.PS512)) {
            var published=PublishedJwk.withPublicKey(generic).algorithm(algorithm).build();
            check(published.getAlgorithm().orElseThrow()==algorithm,"Generic RSA publication lost selected algorithm.");
        }
        for(JwsAlgorithm algorithm:List.of(JwsAlgorithm.PS256,JwsAlgorithm.PS384,JwsAlgorithm.PS512)) {
            String digest=algorithm==JwsAlgorithm.PS256?"SHA-256":algorithm==JwsAlgorithm.PS384?"SHA-384":"SHA-512";
            int salt=algorithm==JwsAlgorithm.PS256?32:algorithm==JwsAlgorithm.PS384?48:64;
            PSSParameterSpec parameters=new PSSParameterSpec(digest,"MGF1",new MGF1ParameterSpec(digest),salt,1);
            PublicKey typed=KeyFactory.getInstance("RSASSA-PSS").generatePublic(new RSAPublicKeySpec(generic.getModulus(),generic.getPublicExponent(),parameters));
            var signer=JwsSigner.fromRsaKeyPair(pair.getPrivate(),typed,algorithm);
            String compact=signer.withHeaderAndClaims(JwtSigningHeader.fromType(JwtType.values()[0]),JwtClaimsSet.builder().subject("synthetic-profile").build()).remainingBudget(Duration.ofSeconds(5)).build();
            String[] parts=compact.split("\\.",-1);Signature verifier=Signature.getInstance("RSASSA-PSS");verifier.setParameter(parameters);verifier.initVerify(typed);
            verifier.update((parts[0]+"."+parts[1]).getBytes(StandardCharsets.US_ASCII));
            check(verifier.verify(Base64.getUrlDecoder().decode(parts[2])),"Typed PSS signing did not verify independently.");
            boolean publicationRejected=false;
            try { var unexpected=PublishedJwk.withPublicKey(signer.getPublicKey()).algorithm(algorithm).build(); }
            catch(IllegalArgumentException expected) { publicationRejected=true; }
            check(publicationRejected,"Typed PSS must not silently lose its restrictions during publication.");
            byte[] encoded=typed.getEncoded();check(encoded!=null,"Fixture requires real encoded public material.");boolean importRejected=false;
            try { var unexpected=KeyImports.publicKeyFromSpkiDer(encoded); }
            catch(KeyImportException expected) { importRejected=true; }
            finally { Arrays.fill(encoded,(byte)0); }
            check(importRejected,"Typed PSS containers are outside the selected import profile.");
        }
        System.out.println("PASS generic-publication=6 typed-PSS-sign/verify/refusal=3 exact-core="+actual);
    }
    private static void check(boolean value,@NonNull String reason) { if(!value)throw new AssertionError(reason); }
}
