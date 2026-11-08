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
package com.revetsec.totp;

import com.revetsec.SealingKey;
import com.revetsec.StateSealer;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;
import javax.annotation.concurrent.ThreadSafe;
import javax.annotation.concurrent.NotThreadSafe;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.SecureRandomSpi;
import java.security.Security;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;
import static org.junit.jupiter.api.Assertions.*;

/** Encoded URI and display-label policy at the real public enrollment boundary. */
final class TotpProvisioningTests {
    private static final @NonNull Instant NOW=Instant.ofEpochSecond(1700000010);
    private static final @NonNull String BROWSER="application-owned-browser-binding";

    @TestFactory @NonNull List<@NonNull DynamicTest> encodedAsciiBoundaryIncludesBothIssuerOccurrencesAndEveryFixedParameter() {
        List<DynamicTest> cells=new ArrayList<>();
        for(int length:List.of(511,512,513))cells.add(DynamicTest.dynamicTest("encoded-bytes-"+length,()->{
            String issuer="i".repeat(128),label="a".repeat(length-354);
            Fixture fixture=new Fixture(issuer);TotpEnrollmentOptions options=options(label);
            if(length>512){assertRefusesBeforeAdmission(fixture,options);return;}
            TotpEnrollment enrollment=assertDoesNotThrow(()->fixture.begin(options));String uri=enrollment.getProvisioningUri();
            assertEquals(length,uri.length());assertEquals(length,uri.getBytes(StandardCharsets.US_ASCII).length);
            assertTrue(uri.chars().allMatch(point->point<128));assertEquals(32,enrollment.getManualEntryKey().length());
            assertEquals(issuer+":"+label,URI.create(uri).getPath().substring(1));
            assertEquals("secret="+enrollment.getManualEntryKey()+"&issuer="+issuer+"&algorithm=SHA1&digits=6&period=30",URI.create(uri).getRawQuery());
            assertEquals(1,fixture.gates.get());assertEquals(2,fixture.reads.get());assertEquals(1,fixture.commits.get());
        }));return cells;
    }

    @TestFactory @NonNull List<@NonNull DynamicTest> exactEncodedUtf8BoundaryDoesNotCountSourceCodePoints() {
        List<DynamicTest> cells=new ArrayList<>();
        for(int length:List.of(511,512,513))cells.add(DynamicTest.dynamicTest("utf8-encoded-bytes-"+length,()->{
            String label="é".repeat(68)+"a".repeat(length-508);Fixture fixture=new Fixture("I");
            if(length>512){assertRefusesBeforeAdmission(fixture,options(label));return;}
            String uri=assertDoesNotThrow(()->fixture.begin(options(label))).getProvisioningUri();assertEquals(length,uri.length());
            assertEquals("I:"+label,URI.create(uri).getPath().substring(1));assertTrue(uri.contains("%C3%A9"));
        }));return cells;
    }

    @TestFactory @NonNull List<@NonNull DynamicTest> encodedBudgetChargesUtf8PercentExpansionRatherThanJavaCharacters() {
        List<DynamicTest> cells=new ArrayList<>();
        for(String label:List.of("é".repeat(80),"😀".repeat(40),"a".repeat(256))){cells.add(DynamicTest.dynamicTest("encoded-budget-"+label.codePointAt(0),()->{
            Fixture fixture=new Fixture("I".repeat(128));assertRefusesBeforeAdmission(fixture,options(label));
        }));}return cells;
    }

    @TestFactory @NonNull List<@NonNull DynamicTest> displayLabelsRejectControlsFormattingAndLineSeparatorsWithoutEchoingThem() {
        List<DynamicTest> cells=new ArrayList<>();
        for(int point:List.of(0,9,10,13,0x7f,0x85,0xad,0x61c,0x200b,0x200c,0x200d,0x200e,0x200f,0x2028,0x2029,0x202a,0x202b,0x202c,0x202d,0x202e,0x2060,0x2066,0x2067,0x2068,0x2069,0xfeff)){
            String label="visible"+Character.toString(point)+"tail";
            cells.add(DynamicTest.dynamicTest("issuer-U+"+Integer.toHexString(point),()->redacted(assertThrows(IllegalArgumentException.class,()->TotpAuthenticator.withIssuer(label)),label)));
            cells.add(DynamicTest.dynamicTest("account-U+"+Integer.toHexString(point),()->redacted(assertThrows(IllegalArgumentException.class,()->options(label)),label)));
        }return cells;
    }

    @TestFactory @NonNull List<@NonNull DynamicTest> displayLabelsRejectLeadingOrTrailingUnicodeWhitespaceWithoutTrimming() {
        List<DynamicTest> cells=new ArrayList<>();
        for(String space:List.of(" ","\u00a0","\u1680","\u2000","\u202f","\u3000"))for(String label:List.of(space+"name","name"+space,space)){
            cells.add(DynamicTest.dynamicTest("issuer-edge-space-"+Integer.toHexString(space.codePointAt(0))+"-"+label.length(),()->{var unused=assertThrows(IllegalArgumentException.class,()->TotpAuthenticator.withIssuer(label));}));
            cells.add(DynamicTest.dynamicTest("account-edge-space-"+Integer.toHexString(space.codePointAt(0))+"-"+label.length(),()->{var unused=assertThrows(IllegalArgumentException.class,()->options(label));}));
        }return cells;
    }

    @TestFactory @NonNull List<@NonNull DynamicTest> ordinaryUnicodeAndUriDelimitersRoundTripExactlyWithoutNormalization() {
        List<DynamicTest> cells=new ArrayList<>();
        for(String label:List.of("Alice Smith","e\u0301","é","東京","שלום","علي","😀","user+tag@example.com","a/b?c&d=e#f%g"))cells.add(DynamicTest.dynamicTest("exact-label-"+label.codePointAt(0),()->{
            String issuer="Café & Co";Fixture fixture=new Fixture(issuer);String uri=assertDoesNotThrow(()->fixture.begin(options(label))).getProvisioningUri();URI parsed=URI.create(uri);
            assertEquals(issuer+":"+label,parsed.getPath().substring(1));assertEquals(1,parsed.getRawPath().chars().filter(point->point==':').count());
            assertTrue(parsed.getRawQuery().contains("&issuer="+java.net.URLEncoder.encode(issuer,StandardCharsets.UTF_8).replace("+","%20")+"&algorithm=SHA1"));
            assertEquals(5,parsed.getRawQuery().split("&",-1).length);assertFalse(uri.contains("+"));assertTrue(uri.length()<=512);
            assertEquals(label,options(label).getAccountName());
        }));return cells;
    }

    @Test void oversizedUriDoesNotTouchAUsableDefaultEntropyProvider() {
        Fixture fixture=new Fixture("Issuer");Provider provider=new CountingProvider();assertEquals(1,Security.insertProviderAt(provider,1));
        try{
            CountingSpi.calls.set(0);assertRefusesBeforeAdmission(fixture,options("😀".repeat(256)));assertEquals(0,CountingSpi.calls.get());
            byte[] probe=new byte[1];new SecureRandom().nextBytes(probe);assertEquals(2,CountingSpi.calls.get(),"Provider construction and fill control must be live");Arrays.fill(probe,(byte)0);
        }finally{Security.removeProvider(provider.getName());CountingSpi.calls.set(0);}
    }

    @Test void originalIndividualLimitsAndNullableClearSemanticsRemain() {
        assertThrows(IllegalArgumentException.class,()->TotpAuthenticator.withIssuer("a".repeat(129)));
        assertThrows(IllegalArgumentException.class,()->TotpAuthenticator.withIssuer("😀".repeat(65)));
        assertThrows(IllegalArgumentException.class,()->options("a".repeat(257)));
        assertThrows(IllegalArgumentException.class,()->options("😀".repeat(257)));
        assertThrows(IllegalArgumentException.class,()->options("bad\ud800"));
        assertThrows(IllegalArgumentException.class,()->TotpAuthenticator.withIssuer("bad\ud800"));
        assertThrows(IllegalArgumentException.class,()->options("a:b"));
        assertThrows(IllegalArgumentException.class,()->TotpAuthenticator.withIssuer("a:b"));
        assertThrows(NullPointerException.class,()->TotpEnrollmentOptions.withAccountId("account").accountName("name").accountName(null).build());
        assertEquals("factor\u200d",TotpEnrollmentOptions.withAccountId("account").accountName("name").replacingFactorId("factor\u200d").build().getReplacingFactorId().orElseThrow(),"Display policy must not reinterpret management identifiers");
    }

    private static void redacted(@NonNull IllegalArgumentException failure,@NonNull String label){String message=java.util.Objects.requireNonNull(failure.getMessage());assertFalse(message.contains(label));assertNull(failure.getCause());assertEquals(0,failure.getSuppressed().length);}
    private static @NonNull TotpEnrollmentOptions options(@NonNull String label){return TotpEnrollmentOptions.withAccountId("account").accountName(label).build();}
    private static void assertRefusesBeforeAdmission(@NonNull Fixture fixture,@NonNull TotpEnrollmentOptions options){var failure=assertThrows(IllegalArgumentException.class,()->fixture.totp.beginEnrollmentResult(options,BROWSER));redacted(failure,options.getAccountName());assertEquals(0,fixture.gates.get());assertEquals(0,fixture.reads.get());assertEquals(0,fixture.commits.get());}

    @NotThreadSafe private static final class Fixture {
        final @NonNull AtomicInteger reads=new AtomicInteger(),commits=new AtomicInteger(),gates=new AtomicInteger();
        final @NonNull TotpAuthenticator totp;
        Fixture(@NonNull String issuer){
            ScriptedTotpStore delegate=new ScriptedTotpStore("provisioning","epoch",NOW);
            TotpStore store=new TotpStore(){
                @Override public @NonNull TotpStoreReadResult read(@NonNull Set<@NonNull TotpStoreKey> keys,@NonNull Duration budget){reads.incrementAndGet();return delegate.read(keys,budget);}
                @Override public @NonNull TotpStoreCommitReceipt compareAndCommit(@NonNull TotpStoreWrite write,@NonNull Duration budget){commits.incrementAndGet();return delegate.compareAndCommit(write,budget);}
            };
            TotpRecoveryGate gate=(context,budget)->{this.gates.incrementAndGet();return new TotpRecoveryGate.Permit(){@Override public @NonNull Boolean isCurrent(){return Boolean.TRUE;}@Override public void close(){}};};
            byte[] key=new byte[32];for(int i=0;i<key.length;i++)key[i]=(byte)(i+7);StateSealer sealer=StateSealer.withActiveKey(SealingKey.fromBase64("key",Base64.getEncoder().encodeToString(key))).build();Arrays.fill(key,(byte)0);
            this.totp=TotpAuthenticator.withIssuer(issuer).credentialNamespace("provisioning").recoveryEpoch("epoch").store(store).recoveryGate(gate).stateSealer(sealer).clock(Clock.fixed(NOW,ZoneOffset.UTC)).build();
            assertEquals(0,this.gates.get());assertEquals(0,this.reads.get());assertEquals(0,this.commits.get());
            assertInstanceOf(TotpNamespaceInitializationResult.Initialized.class,this.totp.initializeNamespaceResult());this.gates.set(0);this.reads.set(0);this.commits.set(0);
        }
        @NonNull TotpEnrollment begin(@NonNull TotpEnrollmentOptions options){return assertInstanceOf(TotpEnrollmentRequestResult.Prepared.class,this.totp.beginEnrollmentResult(options,BROWSER)).getEnrollment();}
    }
    @ThreadSafe private static final class CountingProvider extends Provider {
        private static final long serialVersionUID=1L;
        CountingProvider(){super("RevetsecTotpEntropyAudit","1","Isolated test-only entropy call counter");putService(new Service(this,"SecureRandom","TOTP-AUDIT",CountingSpi.class.getName(),List.of(),java.util.Map.of()){@Override public @NonNull Object newInstance(@Nullable Object ignored){return new CountingSpi();}});}
    }
    @ThreadSafe private static final class CountingSpi extends SecureRandomSpi {
        private static final long serialVersionUID=1L;
        static final @NonNull AtomicInteger calls=new AtomicInteger();
        CountingSpi(){calls.incrementAndGet();}
        @Override protected void engineSetSeed(byte @NonNull [] seed){}
        @Override protected void engineNextBytes(byte @NonNull [] bytes){calls.incrementAndGet();Arrays.fill(bytes,(byte)1);}
        @Override protected byte @NonNull [] engineGenerateSeed(int length){byte[] result=new byte[length];engineNextBytes(result);return result;}
    }
}
