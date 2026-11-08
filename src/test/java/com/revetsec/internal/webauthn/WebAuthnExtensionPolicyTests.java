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

import com.revetsec.internal.encoding.Base64Url;
import org.jspecify.annotations.NonNull;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;
import org.junit.jupiter.api.DynamicTest;
import java.util.List;
import java.util.ArrayList;
import java.util.stream.Stream;
import java.util.Arrays;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.HexFormat;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertThrows;

final class WebAuthnExtensionPolicyTests {
    private static final String RP_ID = "login.example.com";
    private static final byte[] RP_HASH = rpHash();
    private static final byte[] CHALLENGE = new byte[32];
    private static final byte[] CREDENTIAL_ID = {1, 2, 3};
    private static final byte[] USER_HANDLE = {4, 5, 6};
    private static final byte[] ES_X = HexFormat.of().parseHex(
            "65eda5a12577c2bae829437fe338701a10aaa375e1bb5b5de108de439c08551d");
    private static final byte[] ES_Y = HexFormat.of().parseHex(
            "1e52ed75701163f7f9e40ddf9f341b3dc9ba860af7e0ca7ca7e9eecd0084d19c");


    @TestFactory @NonNull Stream<@NonNull DynamicTest> registrationClientExtensionPolicy() {
        List<String> values=List.of(
            "{\"credProps\":{\"rk\":true}}", "{}", "null", "[]", "true",
            "{\"credProps\":null}", "{\"credProps\":{}}", "{\"credProps\":{\"rk\":false}}",
            "{\"credProps\":{\"rk\":\"true\"}}", "{\"credProps\":{\"rk\":1}}",
            "{\"credProps\":{\"rk\":true,\"authenticatorDisplayName\":\"synthetic\"}}",
            "{\"credProps\":{\"rk\":true,\"authenticatorDisplayName\":null}}",
            "{\"credProps\":{\"rk\":true},\"authenticatorDisplayName\":\"synthetic\"}",
            "{\"credProps\":{\"rk\":true},\"prf\":{}}",
            "{\"credProps\":{\"rk\":true},\"largeBlob\":{\"supported\":true}}",
            "{\"credProps\":{\"rk\":true},\"appid\":false}",
            "{\"credProps\":{\"rk\":true},\"future\":null}",
            "{\"credProps\":{\"rk\":true,\"future\":false}}");
        byte[] auth=registrationData(CREDENTIAL_ID);String base=registrationJson(CREDENTIAL_ID,auth,attestation(auth));
        return java.util.stream.IntStream.range(0,values.size()).mapToObj(i->DynamicTest.dynamicTest("registration client extension "+i,()->{
            byte[] body=json(base.replace("{\"credProps\":{\"rk\":true}}",values.get(i)));
            if(i==0)assertDoesNotThrow(()->decoder().parseRegistration(body,CHALLENGE));
            else assertThrows(WebAuthnResponseException.class,()->decoder().parseRegistration(body,CHALLENGE));
        }));
    }
    @TestFactory @NonNull Stream<@NonNull DynamicTest> authenticationClientExtensionPolicy() {
        List<String> values=List.of("{}","null","[]","false","{\"credProps\":{\"rk\":true}}","{\"authenticatorDisplayName\":\"synthetic\"}","{\"prf\":{}}","{\"largeBlob\":{}}","{\"appid\":false}","{\"future\":null}");
        String base=assertionJson(CREDENTIAL_ID,assertionData(),new byte[]{1},USER_HANDLE);
        return java.util.stream.IntStream.range(0,values.size()).mapToObj(i->DynamicTest.dynamicTest("authentication client extension "+i,()->{
            byte[] body=json(base.replace("\"clientExtensionResults\":{}","\"clientExtensionResults\":"+values.get(i)));
            if(i==0)assertDoesNotThrow(()->decoder().parseAssertion(body,CHALLENGE));
            else assertThrows(WebAuthnResponseException.class,()->decoder().parseAssertion(body,CHALLENGE));
        }));
    }
    @TestFactory @NonNull Stream<@NonNull DynamicTest> registrationAuthenticatorExtensionPolicy() {
        List<byte[]> values=new ArrayList<>();
        for(int n:new int[]{1,2,3,0,4})values.add(extension("credProtect",n));
        values.add(extension("future",1));values.add(new byte[]{(byte)0xa0});
        byte[] one=extension("credProtect",1);byte[] two=extension("future",1);byte[] joined=Arrays.copyOf(one,one.length+two.length-1);joined[0]=(byte)0xa2;System.arraycopy(two,1,joined,one.length,two.length-1);values.add(joined);
        return java.util.stream.IntStream.range(0,values.size()).mapToObj(i->DynamicTest.dynamicTest("authenticator extension "+i,()->{
            byte[] auth=registrationData(CREDENTIAL_ID);auth[32]|=(byte)0x80;byte[] combined=Arrays.copyOf(auth,auth.length+values.get(i).length);System.arraycopy(values.get(i),0,combined,auth.length,values.get(i).length);
            byte[] body=json(registrationJson(CREDENTIAL_ID,combined,attestation(combined)));
            if(i<3)assertDoesNotThrow(()->decoder().parseRegistration(body,CHALLENGE));
            else assertThrows(WebAuthnResponseException.class,()->decoder().parseRegistration(body,CHALLENGE));
        }));
    }
    @Test void residentKeyOutputCannotReplaceUserVerificationAndBounds() {
        byte[] auth=registrationData(CREDENTIAL_ID);auth[32]&=(byte)~4;
        assertThrows(WebAuthnResponseException.class,()->decoder().parseRegistration(json(registrationJson(CREDENTIAL_ID,auth,attestation(auth))),CHALLENGE));
        byte[] assertion=assertionData();assertion[32]|=(byte)0x80;byte[] extended=Arrays.copyOf(assertion,assertion.length+1);extended[extended.length-1]=(byte)0xa0;
        assertThrows(WebAuthnResponseException.class,()->decoder().parseAssertion(json(assertionJson(CREDENTIAL_ID,extended,new byte[]{1},USER_HANDLE)),CHALLENGE));
        byte[] normal=registrationData(CREDENTIAL_ID);String base=registrationJson(CREDENTIAL_ID,normal,attestation(normal));String large=base.replace("{\"credProps\":{\"rk\":true}}","{\"credProps\":{\"rk\":true},\"future\":\""+"x".repeat(65536)+"\"}");
        assertThrows(WebAuthnResponseException.class,()->decoder().parseRegistration(json(large),CHALLENGE));
    }
    private static byte @NonNull [] extension(@NonNull String name,int value){ByteArrayOutputStream out=new ByteArrayOutputStream();out.write(0xa1);text(out,name);out.write(value);return out.toByteArray();}
    private static @NonNull WebAuthnResponseJson decoder() {
        return new WebAuthnResponseJson(clientPolicy(), WebAuthnResponseJson.DEFAULT_MAXIMUM_BODY_BYTES);
    }

    private static @NonNull WebAuthnClientData clientPolicy() {
        return new WebAuthnClientData(RP_ID, Set.of("https://" + RP_ID),
                WebAuthnClientData.DEFAULT_MAXIMUM_BYTES);
    }

    private static @NonNull String registrationJson(byte @NonNull [] id, byte @NonNull [] auth,
            byte @NonNull [] attestation) {
        String encodedId = Base64Url.encode(id);
        return "{\"id\":\"" + encodedId + "\",\"rawId\":\"" + encodedId
                + "\",\"type\":\"public-key\",\"response\":{\"clientDataJSON\":\""
                + Base64Url.encode(clientJson("webauthn.create")) + "\",\"authenticatorData\":\""
                + Base64Url.encode(auth) + "\",\"attestationObject\":\"" + Base64Url.encode(attestation)
                + "\",\"publicKeyAlgorithm\":-7,\"transports\":[\"internal\"]},"
                + "\"clientExtensionResults\":{\"credProps\":{\"rk\":true}}}";
    }

    private static @NonNull String assertionJson(byte @NonNull [] id, byte @NonNull [] auth,
            byte @NonNull [] signature, byte @NonNull [] handle) {
        String encodedId = Base64Url.encode(id);
        return "{\"id\":\"" + encodedId + "\",\"rawId\":\"" + encodedId
                + "\",\"type\":\"public-key\",\"response\":{\"clientDataJSON\":\""
                + Base64Url.encode(clientJson("webauthn.get")) + "\",\"authenticatorData\":\""
                + Base64Url.encode(auth) + "\",\"signature\":\"" + Base64Url.encode(signature)
                + "\",\"userHandle\":\"" + Base64Url.encode(handle) + "\"},"
                + "\"clientExtensionResults\":{}}";
    }

    private static byte @NonNull [] clientJson(@NonNull String type) {
        return json("{\"type\":\"" + type + "\",\"challenge\":\"" + Base64Url.encode(CHALLENGE)
                + "\",\"origin\":\"https://" + RP_ID + "\",\"crossOrigin\":false}");
    }

    private static byte @NonNull [] registrationData(byte @NonNull [] id) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.writeBytes(RP_HASH); out.write(0x45); out.writeBytes(new byte[4]);
        out.writeBytes(new byte[16]); out.write(id.length >>> 8); out.write(id.length);
        out.writeBytes(id); out.writeBytes(esKey());
        return out.toByteArray();
    }

    private static byte @NonNull [] assertionData() {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.writeBytes(RP_HASH); out.write(0x05);
        out.write(0); out.write(0); out.write(0); out.write(7);
        return out.toByteArray();
    }

    private static byte @NonNull [] esKey() {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(0xa5); out.write(1); out.write(2); out.write(3); out.write(0x26);
        out.write(0x20); out.write(1); out.write(0x21); bytes(out, ES_X);
        out.write(0x22); bytes(out, ES_Y);
        return out.toByteArray();
    }

    private static byte @NonNull [] attestation(byte @NonNull [] auth) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(0xa3); text(out, "fmt"); text(out, "none");
        text(out, "authData"); bytes(out, auth);
        text(out, "attStmt"); out.write(0xa0);
        return out.toByteArray();
    }

    private static void text(@NonNull ByteArrayOutputStream out, @NonNull String value) {
        byte[] bytes = value.getBytes(StandardCharsets.US_ASCII);
        out.write(0x60 | bytes.length); out.writeBytes(bytes);
    }

    private static void bytes(@NonNull ByteArrayOutputStream out, byte @NonNull [] value) {
        if (value.length < 24) out.write(0x40 | value.length);
        else if (value.length < 256) { out.write(0x58); out.write(value.length); }
        else { out.write(0x59); out.write(value.length >>> 8); out.write(value.length); }
        out.writeBytes(value);
    }

    private static byte @NonNull [] rpHash() {
        try {
            return MessageDigest.getInstance("SHA-256").digest(RP_ID.getBytes(StandardCharsets.US_ASCII));
        } catch (java.security.NoSuchAlgorithmException exception) {
            throw new IllegalStateException(exception);
        }
    }

    private static byte @NonNull [] json(@NonNull String text) {
        return text.getBytes(StandardCharsets.UTF_8);
    }
}
