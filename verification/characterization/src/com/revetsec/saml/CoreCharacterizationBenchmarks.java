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
package com.revetsec.saml;

import com.revetsec.internal.json.JsonCodec;
import com.revetsec.internal.json.JsonLimits;
import com.revetsec.internal.jose.JwsVerifier;
import com.revetsec.internal.crypto.VerifyResult;
import com.revetsec.internal.pem.Pem;
import com.revetsec.internal.xml.EnvelopedSignatureVerifier;
import com.revetsec.internal.xml.SamlXmlWriter;
import com.revetsec.internal.xml.SecureXmlParser;
import com.revetsec.json.JsonValue;
import com.revetsec.jose.JwsAlgorithm;
import com.revetsec.scim.ScimFilter;
import com.revetsec.scim.ScimFilterParseResult;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.openjdk.jmh.annotations.*;
import org.w3c.dom.Element;
import javax.xml.crypto.dsig.*;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec;
import javax.xml.crypto.dsig.spec.TransformParameterSpec;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.Signature;
import java.util.Arrays;
import java.util.List;
import java.util.HexFormat;
import java.util.Base64;
import java.util.concurrent.TimeUnit;
import static java.util.Objects.requireNonNull;

/** Unpublished component characterization; setup, controls and release acceptance are separate. */
@State(Scope.Thread)
@BenchmarkMode(Mode.AverageTime)
@OutputTimeUnit(TimeUnit.MICROSECONDS)
@Warmup(iterations=3,time=1)
@Measurement(iterations=5,time=1)
@Fork(2)
public class CoreCharacterizationBenchmarks {
    private byte @NonNull [] json=new byte[0],input=new byte[0],signature=new byte[0],signedXml=new byte[0];
    private @NonNull String filter="";
    private final @NonNull JsonLimits jsonLimits=JsonLimits.protocolDocument(4096);
    private @Nullable PublicKey key;
    private SecureXmlParser.Result.@Nullable Accepted xml;
    private @NonNull List<@NonNull PublicKey> keys=List.of();

    /** File I/O, key parsing, signing, XML parsing and controls run outside measurement. */
    @Setup(Level.Trial)
    public void setup()throws Exception {
        String[] binding=new String(resource("core-binding.txt"),StandardCharsets.UTF_8).split("\n",-1);
        Path expected=Path.of(binding[0]);check(HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(Files.readAllBytes(expected))).equals(binding[1]),"exact selected core hash");
        for(Class<?> type:List.of(JsonCodec.class,JwsVerifier.class,EnvelopedSignatureVerifier.class,ScimFilter.class))check(Path.of(type.getProtectionDomain().getCodeSource().getLocation().toURI()).equals(expected),"actual selected core origin");
        this.json=resource("document.json");this.filter=new String(resource("filter.txt"),StandardCharsets.UTF_8);
        String privatePem=new String(resource("idp-signing-rsa-2048-key.pem"),StandardCharsets.US_ASCII);var privateKey=Pem.parsePrivateKey(privatePem);this.key=Pem.parseCertificate(new String(resource("idp-signing-rsa-2048-cert.pem"),StandardCharsets.US_ASCII)).getPublicKey();this.keys=List.of(this.key);
        this.input=(Base64.getUrlEncoder().withoutPadding().encodeToString("{\"alg\":\"RS256\",\"typ\":\"JWT\"}".getBytes(StandardCharsets.US_ASCII))+'.'+Base64.getUrlEncoder().withoutPadding().encodeToString(this.json)).getBytes(StandardCharsets.US_ASCII);Signature signer=Signature.getInstance("SHA256withRSA");signer.initSign(privateKey);signer.update(this.input);this.signature=signer.sign();
        String text="<md:EntityDescriptor xmlns:md='urn:oasis:names:tc:SAML:2.0:metadata' ID='_characterization' entityID='https://idp.example.test'><md:IDPSSODescriptor protocolSupportEnumeration='urn:oasis:names:tc:SAML:2.0:protocol'/></md:EntityDescriptor>";
        var original=accepted(SecureXmlParser.parseMetadata(text.getBytes(StandardCharsets.UTF_8)));Element root=original.getDocument().getDocumentElement();root.setIdAttributeNS(null,"ID",true);var factory=XMLSignatureFactory.getInstance("DOM","XMLDSig");var reference=factory.newReference("#_characterization",factory.newDigestMethod(DigestMethod.SHA256,null),List.of(factory.newTransform(Transform.ENVELOPED,(TransformParameterSpec)null),factory.newTransform(CanonicalizationMethod.EXCLUSIVE,(TransformParameterSpec)null)),null,null);var info=factory.newSignedInfo(factory.newCanonicalizationMethod(CanonicalizationMethod.EXCLUSIVE,(C14NMethodParameterSpec)null),factory.newSignatureMethod(SignatureMethod.RSA_SHA256,null),List.of(reference));var context=new DOMSignContext(privateKey,root);context.setDefaultNamespacePrefix("ds");context.setNextSibling(root.getFirstChild());factory.newXMLSignature(info,null).sign(context);this.signedXml=SamlXmlWriter.serialize(original.getDocument());this.xml=accepted(SecureXmlParser.parseMetadata(this.signedXml));
        controls();
        System.out.println("FIXTURE-BINDING:"+fingerprints());
    }

    @Benchmark public @NonNull JsonValue jsonParse()throws Exception {return JsonCodec.parse(this.json,this.jsonLimits);}
    @Benchmark public @NonNull VerifyResult jwsVerify(){VerifyResult value=JwsVerifier.verify(JwsAlgorithm.RS256,requireNonNull(this.key),this.input,this.signature);check(value==VerifyResult.VALID,"JWS verification each invocation");return value;}
    @Benchmark public EnvelopedSignatureVerifier.@NonNull Result xmlSignatureVerify(){var parsed=requireNonNull(this.xml);var result=EnvelopedSignatureVerifier.verifyMetadata(parsed,parsed.getDocument().getDocumentElement(),this.keys);check(result instanceof EnvelopedSignatureVerifier.Verified,"XML verification each invocation");return result;}
    @Benchmark public @NonNull ScimFilterParseResult scimFilterParse(){var result=ScimFilter.fromExpressionResult(this.filter);check(result instanceof ScimFilterParseResult.Succeeded,"SCIM syntax each invocation");return result;}

    /** Reuses the exact parsed DOM across positive/tampered/restored calls to detect cached success. */
    public void controls()throws Exception {
        check(jsonParse() instanceof com.revetsec.json.JsonObject,"JSON accepted tree");check(scimFilterParse() instanceof ScimFilterParseResult.Succeeded,"SCIM accepted tree");check(jwsVerify()==VerifyResult.VALID,"JWS accepted signature");
        byte[] changed=this.signature.clone();try{changed[0]^=1;check(JwsVerifier.verify(JwsAlgorithm.RS256,requireNonNull(this.key),this.input,changed)!=VerifyResult.VALID,"changed JWS signature rejected");}finally{Arrays.fill(changed,(byte)0);}
        check(xmlSignatureVerify() instanceof EnvelopedSignatureVerifier.Verified,"XML first positive");var parsed=requireNonNull(this.xml);Element root=parsed.getDocument().getDocumentElement();String entity=root.getAttribute("entityID");root.setAttribute("entityID","https://tampered.example.test");check(EnvelopedSignatureVerifier.verifyMetadata(parsed,root,this.keys) instanceof EnvelopedSignatureVerifier.Rejected,"same-DOM tamper cannot inherit cached XMLDSig success");root.setAttribute("entityID",entity);check(xmlSignatureVerify() instanceof EnvelopedSignatureVerifier.Verified,"same-DOM restored signature reverified");
        check(ScimFilter.fromExpressionResult("userName eq") instanceof ScimFilterParseResult.Rejected,"malformed SCIM rejected");check(JsonCodec.parseResult("{\"x\":1,\"x\":2}".getBytes(StandardCharsets.US_ASCII),this.jsonLimits) instanceof com.revetsec.internal.json.JsonParseResult.Rejected,"duplicate JSON rejected");
    }
    private static SecureXmlParser.Result.@NonNull Accepted accepted(SecureXmlParser.@NonNull Result result){if(result instanceof SecureXmlParser.Result.Accepted value)return value;throw new AssertionError("Expected controlled XML fixture");}
    private static byte @NonNull [] resource(@NonNull String name)throws Exception{try(var input=CoreCharacterizationBenchmarks.class.getResourceAsStream("/characterization/"+name)){return requireNonNull(input).readAllBytes();}}
    private static void check(boolean value,@NonNull String reason){if(!value)throw new AssertionError(reason);}
    private @NonNull String fingerprints()throws Exception{return "{\"jsonBytes\":"+this.json.length+",\"jsonSha256\":\""+hash(this.json)+"\",\"scimUtf16Units\":"+this.filter.length()+",\"scimSha256\":\""+hash(this.filter.getBytes(StandardCharsets.UTF_8))+"\",\"jwsInputBytes\":"+this.input.length+",\"jwsInputSha256\":\""+hash(this.input)+"\",\"jwsSignatureBytes\":"+this.signature.length+",\"jwsSignatureSha256\":\""+hash(this.signature)+"\",\"signedXmlBytes\":"+this.signedXml.length+",\"signedXmlSha256\":\""+hash(this.signedXml)+"\"}";}
    private static @NonNull String hash(byte @NonNull [] bytes)throws Exception{return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));}
    public static void main(@NonNull String @NonNull [] args)throws Exception{var fixture=new CoreCharacterizationBenchmarks();fixture.setup();fixture.controls();if(args.length>0){Path out=Path.of(args[0]);Files.createDirectories(out);Files.write(out.resolve("signed-metadata.xml"),fixture.signedXml);Files.write(out.resolve("jws-signing-input.bin"),fixture.input);Files.write(out.resolve("jws-signature.bin"),fixture.signature);Files.writeString(out.resolve("FINGERPRINTS.json"),fixture.fingerprints());}System.out.println("{\"cases\":4,\"inputControls\":9,\"sameDomXmlTamperRestored\":true,\"artifactOriginChecks\":4}");}
}
