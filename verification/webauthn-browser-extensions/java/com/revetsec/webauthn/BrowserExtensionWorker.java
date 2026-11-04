/* Copyright 2026 Revetware LLC. Licensed under the Apache License, Version 2.0. */
package com.revetsec.webauthn;

import com.revetsec.SealingKey;
import com.revetsec.StateSealer;
import com.revetsec.internal.json.JsonCodec;
import com.revetsec.internal.json.JsonLimits;
import com.revetsec.json.*;
import com.revetsec.testing.ScriptedWebAuthnStore;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.time.*;
import java.util.*;

/** Test-only bounded stdin peer. Browser credentials stay in the private pipe, never in receipts. */
public final class BrowserExtensionWorker {
    private static final Clock CLOCK=Clock.fixed(Instant.parse("2026-11-03T12:00:00Z"),ZoneOffset.UTC);
    private static final byte[] HANDLE={4,5,6};
    private static final String BINDING="AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    private final ScriptedWebAuthnStore store=new ScriptedWebAuthnStore(CLOCK.instant());
    private final WebAuthnRelyingParty party;
    private BrowserExtensionWorker(String origin){
        var sealer=StateSealer.withActiveKey(SealingKey.fromBase64("disposable","AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=")).clock(CLOCK).build();
        party=WebAuthnRelyingParty.withRelyingPartyId("passkeys.example.test").relyingPartyName("Disposable extension evidence")
                .credentialNamespace("browser-extension-evidence").allowedOrigins(Set.of(origin)).store(store).stateSealer(sealer)
                .recoveryGate(budget->new WebAuthnRecoveryGate.Permit(){public Boolean isCurrent(){return true;}public void close(){}}).clockForTesting(CLOCK).build();
    }
    public static void main(String[] args) throws Exception {
        if(args.length!=1)throw new IllegalArgumentException("One test origin required");
        var in=new InputStreamReader(System.in,StandardCharsets.UTF_8);var out=new PrintWriter(new OutputStreamWriter(System.out,StandardCharsets.UTF_8),true);
        BrowserExtensionWorker worker;
        try{worker=new BrowserExtensionWorker(args[0]);}
        catch(IllegalArgumentException unsupported){out.println(JsonObject.builder().put("status","OriginConfigurationRejected").build().toJson());return;}
        out.println(JsonObject.builder().put("status","Ready").build().toJson());
        for(int commands=0;commands<64;commands++){
            String line=readLine(in);if(line==null)return;
            try{var request=(JsonObject)JsonCodec.parse(line.getBytes(StandardCharsets.UTF_8),JsonLimits.webauthnResponse(262144));out.println(worker.run(request).toJson());}
            catch(Exception invalid){out.println(JsonObject.builder().put("status","fixture-error").build().toJson());}
        }
    }
    private static String readLine(Reader in) throws IOException {
        StringBuilder line=new StringBuilder();int ch;
        while((ch=in.read())!=-1 && ch!='\n'){if(line.length()>=262144)throw new IOException("Fixture command too large");line.append((char)ch);}
        return ch==-1&&line.length()==0?null:line.toString();
    }
    private JsonObject run(JsonObject request){
        String op=text(request,"op");
        if(op.equals("register-start")){
            var result=party.beginRegistrationResult(WebAuthnRegistrationOptions.withUserHandle(HANDLE).userName("disposable").userDisplayName("Disposable evidence").build(),BINDING);
            return result instanceof WebAuthnRegistrationRequestResult.Prepared ready?prepared(ready.getRequest()):status(result.getClass().getSimpleName(),true);
        }
        if(op.equals("authenticate-start")){
            var result=party.beginAuthenticationResult(BINDING);
            return result instanceof WebAuthnAuthenticationRequestResult.Prepared ready?prepared(ready.getRequest()):status(result.getClass().getSimpleName(),true);
        }
        var before=store.records();byte[] body=request.find("response").orElseThrow().toJson().getBytes(StandardCharsets.UTF_8);String ceremony=text(request,"ceremonyId");
        Object result=op.equals("register-finish")?party.completeRegistrationResult(ceremony,body,BINDING):party.completeAuthenticationResult(ceremony,body,BINDING);
        var after=store.records();boolean same=before.keySet().equals(after.keySet());
        if(same)for(var key:before.keySet()){var a=Objects.requireNonNull(before.get(key));var b=Objects.requireNonNull(after.get(key));same&=Arrays.equals(a.getVersion(),b.getVersion())&&Arrays.equals(a.getSealedBytes(),b.getSealedBytes());}
        return status(result.getClass().getSimpleName(),same);
    }
    private static String text(JsonObject object,String key){return ((JsonString)object.find(key).orElseThrow()).getValue();}
    private static JsonObject prepared(WebAuthnBrowserRequest request){return JsonObject.builder().put("status","Prepared").put("ceremonyId",request.getCeremonyId()).put("publicKey",request.getPublicKeyOptions()).build();}
    private static JsonObject status(String result,boolean same){return JsonObject.builder().put("status",result).put("recordsUnchanged",same).build();}
}
