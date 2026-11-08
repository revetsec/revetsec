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

import org.jspecify.annotations.NonNull;

import com.revetsec.SealingKey;
import com.revetsec.StateSealer;
import com.revetsec.internal.encoding.Base64Url;
import com.revetsec.json.JsonObject;
import com.revetsec.webauthn.WebAuthnRelyingParty;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.*;
import java.util.stream.Stream;
import static org.junit.jupiter.api.Assertions.*;

/** Adopted SR-2 configuration expands eligible hosts, never the exact per-ceremony origin set. */
final class WebAuthnSr2OriginTests {
    private static final String RP="login.example.com",PARENT="https://"+RP,CHILD="https://sub."+RP;
    private static final String MAX_HOST="a".repeat(63)+"."+"b".repeat(63)+"."+"c".repeat(63)+"."+"d".repeat(43)+"."+RP;
    private static final byte[] CHALLENGE=new byte[32];
    private record Profile(@NonNull String origin,boolean accepted){}
    private static @NonNull List<@NonNull Profile> profiles(){
        List<Profile> rows=new ArrayList<>();
        for(String value:List.of(PARENT,PARENT+":8443",CHILD,"https://a.b."+RP,CHILD+":8443",CHILD+":65535",CHILD+":1","https://xn--bcher-kva."+RP,"https://a-0."+RP,"https://0."+RP,"https://"+MAX_HOST+":65535"))rows.add(new Profile(value,true));
        for(String value:List.of("https://sibling.example.com","https://notlogin.example.com","https://evil-login.example.com",PARENT+".evil.test",CHILD+".evil.test","https://."+RP,"https://Sub."+RP,"https://sub.LOGIN.example.com",CHILD+".","HTTPS://sub."+RP,"http://sub."+RP,"null","data:text/plain,test","https://127.0.0.1","https://[::1]","https://*."+RP,"https://sub_."+RP,"https://-sub."+RP,"https://sub-."+RP,"https://"+"a".repeat(64)+"."+RP,CHILD+":-1",CHILD+":0",CHILD+":65536",CHILD+":0443",CHILD+":08443",CHILD+":",CHILD+":word","https://user@sub."+RP,CHILD+"@evil.test","https://sub%2e"+RP,"https://bücher."+RP,CHILD+"/",CHILD+"/path",CHILD+"?",CHILD+"#",CHILD+"\n"," https://sub."+RP,"https://"+MAX_HOST.replace("d".repeat(43),"d".repeat(44))+":65535"))rows.add(new Profile(value,false));
        return rows;
    }
    @TestFactory @NonNull Stream<@NonNull DynamicTest> publicConfigurationUsesCanonicalRpOrDescendantHosts(){
        return profiles().stream().map(p->DynamicTest.dynamicTest("public / "+p.origin,()->{
            if(p.accepted)assertDoesNotThrow(()->WebAuthnRelyingParty.withRelyingPartyId(RP).allowedOrigins(Set.of(p.origin)));
            else assertThrows(IllegalArgumentException.class,()->WebAuthnRelyingParty.withRelyingPartyId(RP).allowedOrigins(Set.of(p.origin)));
        }));
    }
    @TestFactory @NonNull Stream<@NonNull DynamicTest> clientAndStoredPolicyUseCanonicalRpOrDescendantHosts(){
        return profiles().stream().map(p->DynamicTest.dynamicTest("client policy / "+p.origin,()->{
            if(p.accepted){
                var policy=assertDoesNotThrow(()->policy(Set.of(p.origin)));
                assertDoesNotThrow(()->policy.verify(document(p.origin,"webauthn.create",CHALLENGE),WebAuthnClientData.Ceremony.REGISTRATION,CHALLENGE));
                assertDoesNotThrow(()->policy.verify(document(p.origin,"webauthn.get",CHALLENGE),WebAuthnClientData.Ceremony.AUTHENTICATION,CHALLENGE));
            }else assertThrows(IllegalArgumentException.class,()->policy(Set.of(p.origin)));
        }));
    }
    @Test void exactAllowlistDoesNotBecomeAWildcardAndIsSnapshotted(){
        Set<String> origins=new HashSet<>(Set.of(CHILD+":8443"));var policy=assertDoesNotThrow(()->policy(origins));origins.clear();
        assertDoesNotThrow(()->policy.verify(document(CHILD+":8443","webauthn.get",CHALLENGE),WebAuthnClientData.Ceremony.AUTHENTICATION,CHALLENGE));
        for(String unlisted:List.of(PARENT,CHILD,CHILD+":8444",CHILD+":443","https://other."+RP,"https://nested.sub."+RP,"https://Sub."+RP+":8443"))
            assertThrows(WebAuthnClientDataException.class,()->policy.verify(document(unlisted,"webauthn.get",CHALLENGE),WebAuthnClientData.Ceremony.AUTHENTICATION,CHALLENGE));
    }
    @Test void parentOriginDoesNotImplicitlyAuthorizeAnyChild(){
        var parent=policy(Set.of(PARENT));assertThrows(WebAuthnClientDataException.class,()->parent.verify(document(CHILD,"webauthn.get",CHALLENGE),WebAuthnClientData.Ceremony.AUTHENTICATION,CHALLENGE));
    }
    @Test void eightOriginCapAndExactPortsRemain(){
        Set<String> eight=new HashSet<>();for(int i=0;i<8;i++)eight.add("https://c"+i+"."+RP+":8443");
        var policy=assertDoesNotThrow(()->policy(eight));assertDoesNotThrow(()->WebAuthnRelyingParty.withRelyingPartyId(RP).allowedOrigins(eight));
        for(String origin:eight)assertDoesNotThrow(()->policy.verify(document(origin,"webauthn.get",CHALLENGE),WebAuthnClientData.Ceremony.AUTHENTICATION,CHALLENGE));
        Set<String> nine=new HashSet<>(eight);nine.add(PARENT);
        assertThrows(IllegalArgumentException.class,()->policy(nine));assertThrows(IllegalArgumentException.class,()->WebAuthnRelyingParty.withRelyingPartyId(RP).allowedOrigins(nine));
        assertThrows(IllegalArgumentException.class,()->WebAuthnRelyingParty.withRelyingPartyId(RP).allowedOrigins(Set.of(CHILD+":443")));
    }
    @Test void existingInternalExplicitDefaultPortRemainsReadableButPublicConfigurationRejectsIt(){
        var old=policy(Set.of(PARENT+":443"));assertDoesNotThrow(()->old.verify(document(PARENT+":443","webauthn.get",CHALLENGE),WebAuthnClientData.Ceremony.AUTHENTICATION,CHALLENGE));
        assertThrows(IllegalArgumentException.class,()->WebAuthnRelyingParty.withRelyingPartyId(RP).allowedOrigins(Set.of(PARENT+":443")));
    }
    @Test void subdomainCannotChangeRpHashChallengeTypeOrCrossOriginBindings() throws Exception {
        var policy=assertDoesNotThrow(()->policy(Set.of(CHILD)));byte[] expected=MessageDigest.getInstance("SHA-256").digest(RP.getBytes(StandardCharsets.US_ASCII));assertArrayEquals(expected,policy.relyingPartyIdHash());
        byte[] auth=new byte[37];System.arraycopy(expected,0,auth,0,32);auth[32]=5;assertDoesNotThrow(()->WebAuthnAuthenticatorData.parseAssertion(auth,policy.relyingPartyIdHash()));
        byte[] wrong=auth.clone();System.arraycopy(MessageDigest.getInstance("SHA-256").digest(("sub."+RP).getBytes(StandardCharsets.US_ASCII)),0,wrong,0,32);assertThrows(WebAuthnCborException.class,()->WebAuthnAuthenticatorData.parseAssertion(wrong,policy.relyingPartyIdHash()));
        byte[] other=CHALLENGE.clone();other[0]=1;
        assertThrows(WebAuthnClientDataException.class,()->policy.verify(document(CHILD,"webauthn.get",other),WebAuthnClientData.Ceremony.AUTHENTICATION,CHALLENGE));
        assertThrows(WebAuthnClientDataException.class,()->policy.verify(document(CHILD,"webauthn.create",CHALLENGE),WebAuthnClientData.Ceremony.AUTHENTICATION,CHALLENGE));
        String body=new String(document(CHILD,"webauthn.get",CHALLENGE),StandardCharsets.UTF_8);
        for(String extra:List.of("\"crossOrigin\":true","\"topOrigin\":\""+PARENT+"\"")){
            byte[] value=(body.substring(0,body.length()-1)+","+extra+"}").getBytes(StandardCharsets.UTF_8);
            assertThrows(WebAuthnClientDataException.class,()->policy.verify(value,WebAuthnClientData.Ceremony.AUTHENTICATION,CHALLENGE));
        }
    }
    @TestFactory @NonNull Stream<@NonNull DynamicTest> allCeremonyKindsPersistTheirExactOriginSnapshot(){
        return Arrays.stream(WebAuthnCeremonyState.Kind.values()).map(kind->DynamicTest.dynamicTest(kind.name(),()->{
            Instant now=Instant.parse("2026-11-03T12:00:00Z");Clock clock=Clock.fixed(now,ZoneOffset.UTC);Set<String> origins=Set.of(PARENT,CHILD+":8443");byte[] binding=new byte[32];binding[0]=1;byte[] id=new byte[32];id[0]=2;
            var state=switch(kind){case REGISTRATION->WebAuthnCeremonyState.registration(id,CHALLENGE,binding,origins,new byte[]{1},now,now.plusSeconds(300));case DISCOVERABLE_AUTHENTICATION->WebAuthnCeremonyState.discoverableAuthentication(id,CHALLENGE,binding,origins,now,now.plusSeconds(300));case ACCOUNT_REAUTHENTICATION->WebAuthnCeremonyState.accountReauthentication(id,CHALLENGE,binding,origins,new byte[]{1},"transfer",now,now.plusSeconds(300));};
            var sealer=StateSealer.withActiveKey(SealingKey.fromBase64("test","AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=")).clock(clock).build();var codec=new WebAuthnCeremonyRecordCodec("sr2-tests",RP,new WebAuthnRecordCodec(sealer));
            var encoded=assertDoesNotThrow(()->codec.encode(state,now));var decoded=assertDoesNotThrow(()->codec.decode(encoded.key(),encoded.sealedBytes(),clock));
            assertEquals(origins,decoded.allowedOrigins());assertTrue(state.samePendingAs(decoded));assertEquals(now.plusSeconds(300),decoded.expiresAt());
            var restored=policy(decoded.allowedOrigins());assertThrows(WebAuthnClientDataException.class,()->restored.verify(document("https://unlisted."+RP,"webauthn.get",CHALLENGE),WebAuthnClientData.Ceremony.AUTHENTICATION,CHALLENGE));
        }));
    }
    private static @NonNull WebAuthnClientData policy(@NonNull Set<@NonNull String> origins){return new WebAuthnClientData(RP,origins,8192);}
    private static byte @NonNull [] document(@NonNull String origin,@NonNull String type,byte @NonNull [] challenge){return JsonObject.builder().put("type",type).put("challenge",Base64Url.encode(challenge)).put("origin",origin).build().toJson().getBytes(StandardCharsets.UTF_8);}
}
