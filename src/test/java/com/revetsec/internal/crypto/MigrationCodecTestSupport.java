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

package com.revetsec.internal.crypto;

import com.revetsec.SealingKey;
import com.revetsec.StateSealer;
import com.revetsec.internal.encoding.Base64Url;
import org.jspecify.annotations.NonNull;
import java.io.InputStreamReader;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.List;
import java.util.Objects;
import java.util.Properties;
import static org.junit.jupiter.api.Assertions.*;

/** Test-only raw authenticated malformed bytes; never exposed by a production writer or public API. */
public final class MigrationCodecTestSupport {
    private static final @NonNull Properties DATA=load();
    public static final @NonNull Clock CLOCK=Clock.fixed(Instant.EPOCH,ZoneOffset.UTC);
    private MigrationCodecTestSupport(){}
    public static @NonNull StateSealer sealer(){return StateSealer.withActiveKey(key(0)).verificationKeys(List.of(key(1),key(2))).maximumSealedLength(16384).clock(CLOCK).build();}
    private static @NonNull SealingKey key(int n){return SealingKey.fromBase64("m4"+"x".repeat(n),java.util.Base64.getEncoder().encodeToString(master(n)));}
    private static byte @NonNull [] master(int n){byte[] b=new byte[32];for(int i=0;i<b.length;i++)b[i]=(byte)(i+n+1);return b;}
    public static void verifyCorpus()throws Exception{try(var in=Objects.requireNonNull(MigrationCodecTestSupport.class.getResourceAsStream("/fixtures/migration/mig-04.properties"))){assertEquals("41d5de45133599ccfe06a279ae59299f0b3d4c5b6c0c28ee7c7eca7e597aaafe",HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(in.readAllBytes())));}assertEquals(3954,Integer.parseInt(DATA.getProperty("caseCount")));assertEquals(56,Integer.parseInt(DATA.getProperty("specCount")));}
    public static @NonNull List<@NonNull Spec> specs(@NonNull String family){List<Spec> rows=new ArrayList<>();for(int n=0;n<Integer.parseInt(DATA.getProperty("specCount"));n++){Spec s=new Spec(n);if(s.get("family").equals(family))rows.add(s);}return rows;}
    public static @NonNull List<@NonNull Case> cases(@NonNull String family){List<Case> rows=new ArrayList<>();for(int n=0;n<Integer.parseInt(DATA.getProperty("caseCount"));n++){Case c=new Case(n);if(c.spec().get("family").equals(family))rows.add(c);}return rows;}
    public static final class Spec{
        private final int index;Spec(int index){this.index=index;}
        public @NonNull String get(@NonNull String field){return Objects.requireNonNull(DATA.getProperty("s."+this.index+'.'+field));}
        public byte @NonNull [] bytes(){return HexFormat.of().parseHex(get("plain"));}
        public int format(){return Integer.parseInt(get("format"));}
        public @NonNull String name(){return this.index+"/"+get("family")+"/v"+format()+"/"+get("name");}
    }
    public static final class Case{
        private final int index;Case(int index){this.index=index;}
        public @NonNull String get(@NonNull String field){return Objects.requireNonNull(DATA.getProperty("c."+this.index+'.'+field));}
        public @NonNull Spec spec(){return new Spec(Integer.parseInt(get("spec")));}
        public byte @NonNull [] body(){return HexFormat.of().parseHex(get("body"));}
        public @NonNull String op(){return get("op");}
        public @NonNull String name(){return "MIG-04/"+spec().name()+"/"+get("category")+"/"+get("name");}
    }
    public static @NonNull String seal(@NonNull SealedStateType type,@NonNull String context,long notAfter,byte @NonNull [] raw,boolean forceSpare)throws Exception{
        int n=0;if(forceSpare)while((SealerV1.FIXED_OVERHEAD+2+n+raw.length)%3==0)n++;
        String id="m4"+"x".repeat(n);var key=SealerV1.Key.fromMasterKey(id,master(n));var entropy=EntropySource.fromDefaults();byte[] salt=entropy.nextBytes(16),iv=entropy.nextBytes(12);
        String sealed=SealerV1.seal(key,type,context,notAfter,raw,salt,iv);byte[] wire=Base64Url.decode(sealed);int headerLength=2+id.length()+16+12;
        byte[] header=Arrays.copyOf(wire,headerLength),ciphertext=Arrays.copyOfRange(wire,headerLength,wire.length),derived=SealerV1.messageKey(key,type,salt),body=null;
        try{body=AesGcm.decrypt(derived,iv,SealerV1.additionalData(header,type,context.getBytes(StandardCharsets.UTF_8)),ciphertext);assertEquals(notAfter,ByteBuffer.wrap(body).getLong());assertArrayEquals(raw,Arrays.copyOfRange(body,8,body.length));}
        finally{Arrays.fill(derived,(byte)0);if(body!=null)Arrays.fill(body,(byte)0);}
        return sealed;
    }
    public static @NonNull String encode(byte @NonNull [] bytes){return Base64Url.encode(bytes);}
    public static @NonNull String alias(@NonNull String canonical){assertTrue(canonical.length()%4==2 || canonical.length()%4==3);String alphabet="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";int i=alphabet.indexOf(canonical.charAt(canonical.length()-1));String alias=canonical.substring(0,canonical.length()-1)+alphabet.charAt(i+1);assertArrayEquals(java.util.Base64.getUrlDecoder().decode(canonical),java.util.Base64.getUrlDecoder().decode(alias));assertNotEquals(canonical,alias);return alias;}
    public static @NonNull String alter(@NonNull String value,@NonNull String op){return switch(op){case "outer-padding","inner-padding"->value+'=';case "outer-alphabet","inner-alphabet"->'+'+value.substring(1);case "outer-spare-bits","inner-spare-bits","chunk-noncanonical"->alias(value);case "outer-truncated"->value.substring(0,value.length()-1);case "outer-tag"->value.substring(0,value.length()-1)+(value.endsWith("A")?"E":"A");default->value;};}
    public static @NonNull String digest(@NonNull String value)throws Exception{return encode(MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.US_ASCII)));}
    private static @NonNull Properties load(){Properties data=new Properties();try(var reader=new InputStreamReader(Objects.requireNonNull(MigrationCodecTestSupport.class.getResourceAsStream("/fixtures/migration/mig-04.properties")),StandardCharsets.UTF_8)){data.load(reader);}catch(Exception e){throw new ExceptionInInitializerError(e);}return data;}
}
