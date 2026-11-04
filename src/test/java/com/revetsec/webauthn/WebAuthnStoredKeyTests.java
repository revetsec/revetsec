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

package com.revetsec.webauthn;

import com.revetsec.SealingKey;
import com.revetsec.StateSealer;
import org.jspecify.annotations.NonNull;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;

import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.*;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;

/** Direct typed-factory tests are final-only; absent entry API is not counted as semantic regression. */
final class WebAuthnStoredKeyTests {
    private static final String RP="login.example.com",NS="tenant:two";
    private static final String MAX_RP="a".repeat(63)+"."+"b".repeat(63)+"."+"c".repeat(63)+"."+"d".repeat(61);
    private static final String DIGEST=Base64.getUrlEncoder().withoutPadding().encodeToString(new byte[32]);
    private static String b64(String value){return Base64.getUrlEncoder().withoutPadding().encodeToString(value.getBytes(StandardCharsets.UTF_8));}
    private static String form(String ns,String rp,String kind,String digest){return "wa1:"+b64(ns)+":"+b64(rp)+":"+kind+":"+digest;}
    @TestFactory Stream<DynamicTest> everyKindRoundTripsMinimumNormalAndMaximumScopes() {
        List<DynamicTest> cases=new ArrayList<>();
        for(String[] scope:List.of(new String[]{"!","a.co"},new String[]{NS,RP},new String[]{"~".repeat(128),MAX_RP}))
            for(var kind:WebAuthnStoreKey.Kind.values())for(int seed=0;seed<(kind==WebAuthnStoreKey.Kind.NAMESPACE_CLOCK?1:2);seed++){
                byte[] id=new byte[kind==WebAuthnStoreKey.Kind.CEREMONY?32:kind==WebAuthnStoreKey.Kind.CREDENTIAL?1023:64];
                if(seed!=0)for(int i=0;i<id.length;i++)id[i]=(byte)(37*i+11);
                var key=switch(kind){case CEREMONY->WebAuthnStoreKey.forCeremony(scope[0],scope[1],id);case CREDENTIAL->WebAuthnStoreKey.forCredential(scope[0],scope[1],id);case ACCOUNT_CREDENTIAL_INDEX->WebAuthnStoreKey.forAccountCredentialIndex(scope[0],scope[1],id);case ACCOUNT_FENCE->WebAuthnStoreKey.forAccountFence(scope[0],scope[1],id);case NAMESPACE_CLOCK->WebAuthnStoreKey.forNamespaceClock(scope[0],scope[1]);};
                cases.add(DynamicTest.dynamicTest(kind+"/"+scope[0].length()+"/"+seed,()->{
                    var copy=assertDoesNotThrow(()->WebAuthnStoreKey.fromStoredForm(key.getStorageKey()));assertEquals(key,copy);assertEquals(key.hashCode(),copy.hashCode());assertEquals(key.getKind(),copy.getKind());assertEquals(key.getStorageKey(),copy.getStorageKey());assertTrue(Set.of(key).contains(copy));assertEquals("WebAuthnStoreKey{address=<redacted>}",copy.toString());
                }));
            }
        return cases.stream();
    }
    @Test void exactMaximumAddressAndOpaqueDigestsArePreservedWithoutRehashing() {
        assertEquals(253,MAX_RP.length());var maximum=WebAuthnStoreKey.forAccountCredentialIndex("~".repeat(128),MAX_RP,new byte[]{1});assertEquals(583,maximum.getStorageKey().length());assertEquals(maximum,assertDoesNotThrow(()->WebAuthnStoreKey.fromStoredForm(maximum.getStorageKey())));
        String opaque=form(NS,RP,"CREDENTIAL",DIGEST);assertEquals(opaque,WebAuthnStoreKey.fromStoredForm(opaque).getStorageKey());
        assertNotEquals(WebAuthnStoreKey.forCredential(NS,RP,new byte[32]),WebAuthnStoreKey.fromStoredForm(opaque));
        assertNotEquals(WebAuthnStoreKey.fromStoredForm(opaque),WebAuthnStoreKey.fromStoredForm(form("other",RP,"CREDENTIAL",DIGEST)));
    }
    @TestFactory Stream<DynamicTest> malformedAndNoncanonicalAddressesRejectWithFixedRedactedErrors() {
        String valid=form(NS,RP,"CREDENTIAL",DIGEST);String[] parts=valid.split(":",-1);List<String> values=new ArrayList<>(List.of("",valid+":extra",valid+":",":"+valid,valid.replace("wa1:","wa2:"),valid.replace("wa1:","WA1:"),valid+"\n"," "+valid,valid+" ","x".repeat(584),"x".repeat(100000)));
        for(int i:new int[]{1,2,4})for(String replacement:List.of("",parts[i]+"=",parts[i]+"==","+","/","%41","\n"," ","é","Ａ","AA=A")){
            String[] copy=parts.clone();copy[i]=replacement;values.add(String.join(":",copy));
        }
        for(String ns:List.of("", "x".repeat(129),"space here","\u0000","\t","\u007f","é"))values.add(form(ns,RP,"CREDENTIAL",DIGEST));
        for(String rp:List.of("","LOCALHOST","localhost","Login.example.com","login.example.com.","-a.example","a-.example","a..example","a_b.example","127.0.0.1","[::1]","https://example.com","é.example","a".repeat(64)+".example",MAX_RP+"x"))values.add(form(NS,rp,"CREDENTIAL",DIGEST));
        for(String kind:List.of("","credential","CREDENTIAL ","CREDENTIAL\n","UNKNOWN","ACCOUNT"))values.add(form(NS,RP,kind,DIGEST));
        for(int size:new int[]{0,1,31,33,64})values.add(form(NS,RP,"CREDENTIAL",Base64.getUrlEncoder().withoutPadding().encodeToString(new byte[size])));
        values.add("wa1:YR:"+b64(RP)+":CREDENTIAL:"+DIGEST); // nonzero unused bits, same decoded namespace
        values.add("wa1:"+b64(NS)+":YS5jbx:CREDENTIAL:"+DIGEST); // same decoded a.co
        values.add(form(NS,RP,"CREDENTIAL",DIGEST.substring(0,42)+"B"));
        values.add(form(NS,RP,"NAMESPACE_CLOCK",DIGEST));
        return java.util.stream.IntStream.range(0,values.size()).mapToObj(i->DynamicTest.dynamicTest("invalid address "+i,()->{
            var failure=assertThrows(IllegalArgumentException.class,()->WebAuthnStoreKey.fromStoredForm(values.get(i)));assertEquals("Invalid WebAuthn storage address",failure.getMessage());assertNull(failure.getCause());
        }));
    }
    @Test @SuppressWarnings("NullAway") // Deliberate required-argument misuse.
    void nullRejectsAndOrdinaryValuesDoNotAcquireProofOrMaintenanceAuthority() {
        assertThrows(NullPointerException.class,()->WebAuthnStoreKey.fromStoredForm(null));
        WebAuthnStore store=new WebAuthnStore(){
            @Override public @NonNull WebAuthnStoreReadResult read(@NonNull Set<@NonNull WebAuthnStoreKey> keys,@NonNull Duration budget){fail("Scope and ceremony checks must precede store access");return WebAuthnStoreReadResult.Unavailable.get();}
            @Override public @NonNull WebAuthnStoreCommitReceipt compareAndCommit(@NonNull WebAuthnStoreWrite write,@NonNull Duration budget){fail("No write is authorized by an address");return WebAuthnStoreCommitReceipt.unknownInstance();}
        };
        var rp=WebAuthnRelyingParty.withRelyingPartyId(RP).relyingPartyName("Test").credentialNamespace(NS).allowedOrigins(Set.of("https://"+RP)).store(store).stateSealer(StateSealer.withActiveKey(SealingKey.fromBase64("k","AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=")).build()).recoveryGate(budget->{fail("Invalid scope is rejected before admission");return null;}).build();
        for(var key:List.of(WebAuthnStoreKey.forCredential("other",RP,new byte[]{1}),WebAuthnStoreKey.forCredential(NS,"other.example.com",new byte[]{1}),WebAuthnStoreKey.forCeremony(NS,RP,new byte[32])))assertThrows(IllegalArgumentException.class,()->rp.resealStoreEntry(WebAuthnStoreKey.fromStoredForm(key.getStorageKey())));
    }
}
