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

package com.revetsec.internal.webauthn;

import com.revetsec.SealingKey;
import com.revetsec.StateSealer;
import com.revetsec.internal.crypto.SealedStateAccess;
import com.revetsec.internal.encoding.Base64Url;
import com.revetsec.webauthn.WebAuthnStoreEntry;
import com.revetsec.webauthn.WebAuthnStoreKey;
import org.jspecify.annotations.NonNull;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;

import java.nio.ByteBuffer;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/** CAP-07: exhaustive WAR2 capacity arithmetic and actual envelopes. */
final class WebAuthnCap07ConformanceTests {
    private static final @NonNull String MASTER="AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA=";
    private static final @NonNull Instant PERMANENT=Instant.ofEpochSecond(Instant.MAX.getEpochSecond());

    @TestFactory @NonNull List<@NonNull DynamicTest> everySupportedCapacityAndKeyEndpoint() {
        List<DynamicTest> tests=new ArrayList<>();
        for(int start=1024;start<=16384;start+=256) {
            int first=start,last=Math.min(16384,start+255);
            tests.add(DynamicTest.dynamicTest("CAP-07/all-C/"+first+".."+last,()->{
                var key=WebAuthnStoreKey.forCredential("capacity","login.example.test",new byte[]{1});
                for(int cap=first;cap<=last;cap++) for(int keyLength:List.of(1,64)) {
                    var sealer=sealer(cap,keyLength);
                    byte[] frame=new WebAuthnRecordCodecV2(sealer).seal(key,new byte[]{42},PERMANENT);
                    assertEquals(rawChunk(cap),Short.toUnsignedInt(ByteBuffer.wrap(frame).getShort(6)),"C="+cap);
                    assertFrame(frame,1,cap,keyLength);
                    assertArrayEquals(new byte[]{42},new WebAuthnRecordCodecV2(sealer).open(key,frame,clock(Instant.EPOCH)));
                }
            }));
        }
        return tests;
    }

    @Test void exhaustiveLengthEquationsLocateThe1026Maximum() {
        long maximum=0;int firstMaximum=0;
        // These are independent length equations, not a claim of 110000-byte inner payloads.
        for(int cap=1024;cap<=16384;cap++) for(int keyLength:List.of(1,64)) {
            int chunk=rawChunk(cap);assertTrue(chunk>=1&&chunk<=16384);
            for(int length:new int[]{1,45,79,1103,2136,2412,65679,110000}) {
                long frame=frameLength(length,chunk,keyLength);
                assertTrue(frame<=262144);assertTrue(encodedLength(frame)<=350000);
                assertTrue((length+chunk-1)/chunk<=256);
                if(length==110000&&keyLength==64&&frame>maximum){maximum=frame;firstMaximum=cap;}
            }
            assertTrue(encodedLength(54+keyLength+encodedLength(chunk))<=cap);
        }
        assertEquals(233340,maximum);assertEquals(1026,firstMaximum);
        assertEquals(311120,encodedLength(maximum));assertEquals(349526,encodedLength(262144));
        assertEquals(467,rawChunk(1024));assertEquals(468,rawChunk(1026));
        assertEquals(236,(110000+rawChunk(1026)-1)/rawChunk(1026));
    }

    @TestFactory @NonNull List<@NonNull DynamicTest> actualWorstCaseEnvelopes() {
        List<DynamicTest> tests=new ArrayList<>();
        for(int cap:List.of(1024,1026,3800,16384)) for(int keyLength:List.of(1,64))
            tests.add(DynamicTest.dynamicTest("CAP-07/110000/C"+cap+"/K"+keyLength,()->{
                var codec=new WebAuthnRecordCodecV2(sealer(cap,keyLength));
                var key=WebAuthnStoreKey.forCredential("capacity","login.example.test",new byte[]{1});
                byte[] raw=new byte[110000];for(int i=0;i<raw.length;i++)raw[i]=(byte)i;
                byte[] frame=codec.seal(key,raw,PERMANENT);assertFrame(frame,raw.length,cap,keyLength);
                assertArrayEquals(raw,codec.open(key,frame,clock(Instant.EPOCH)));
                // Generic envelope upper bound only: arbitrary bytes are not an admitted credential.
                assertThrows(WebAuthnRecordException.class,()->codec.openRecord(key,frame,clock(Instant.EPOCH)));
                if(cap==1026&&keyLength==64){assertEquals(233340,frame.length);assertEquals(311120,Base64Url.encode(frame).length());}
            }));
        return tests;
    }

    @Test void publicCarrierAndDefaultRecipeCapacityStayExact() {
        assertEquals(3800,SealedStateAccess.get().getMaximumSealedLength(StateSealer.withActiveKey(SealingKey.fromBase64("recipe",MASTER)).build()));
        for(int size:new int[]{0,1,262143,262144,262145}) {
            byte[] raw=new byte[size];
            if(size==0||size>262144)assertThrows(IllegalArgumentException.class,()->WebAuthnStoreEntry.Present.fromVersionAndSealedBytes(new byte[]{1},raw));
            else assertEquals(size,WebAuthnStoreEntry.Present.fromVersionAndSealedBytes(new byte[]{1},raw).getSealedBytes().length);
        }
        assertThrows(IllegalArgumentException.class,()->sealer(1023,1));assertThrows(IllegalArgumentException.class,()->sealer(16385,1));
    }

    private static void assertFrame(byte @NonNull [] frame,int plaintext,int cap,int keyLength) {
        ByteBuffer b=ByteBuffer.wrap(frame);byte[] magic=new byte[4];b.get(magic);assertArrayEquals(new byte[]{'W','A','R','2'},magic);
        int chunk=rawChunk(cap),count=(plaintext+chunk-1)/chunk;
        assertEquals(count,Short.toUnsignedInt(b.getShort()));assertEquals(chunk,Short.toUnsignedInt(b.getShort()));b.position(24);
        for(int i=0;i<count;i++) {
            int actual=Short.toUnsignedInt(b.getShort());int raw=Math.min(chunk,plaintext-i*chunk);
            assertEquals(encodedLength(54+keyLength+encodedLength(raw)),actual);assertTrue(actual<=cap);
            b.position(b.position()+actual);
        }
        assertFalse(b.hasRemaining());assertEquals(frameLength(plaintext,chunk,keyLength),frame.length);
        assertTrue(frame.length<=262144);assertTrue(Base64Url.encode(frame).length()<=350000);
    }
    private static int rawChunk(int cap){return Math.floorDiv(3*(Math.floorDiv(3*cap,4)-134),4)-8;}
    private static long encodedLength(long bytes){return (8*bytes+5)/6;}
    private static long frameLength(int length,int chunk,int keyLength) {
        long full=length/chunk,last=length%chunk;
        return 24+full*(2+encodedLength(54+keyLength+encodedLength(chunk)))+(last==0?0:2+encodedLength(54+keyLength+encodedLength(last)));
    }
    private static @NonNull StateSealer sealer(int cap,int keyLength){return StateSealer.withActiveKey(SealingKey.fromBase64("k".repeat(keyLength),"ISIjJCUmJygpKissLS4vMDEyMzQ1Njc4OTo7PD0+P0A=")).verificationKeys(List.of(SealingKey.fromBase64("f".repeat(64),MASTER))).maximumSealedLength(cap).build();}
    private static @NonNull Clock clock(@NonNull Instant time){return Clock.fixed(time,ZoneOffset.UTC);}
}
