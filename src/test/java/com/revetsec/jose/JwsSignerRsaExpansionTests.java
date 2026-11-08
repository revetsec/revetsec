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

import com.revetsec.internal.json.JsonCodec;
import com.revetsec.internal.json.JsonLimits;
import com.revetsec.json.JsonObject;
import com.revetsec.json.JsonString;
import com.revetsec.testing.ChildJvm;
import com.revetsec.testing.TestJwk;
import com.revetsec.testing.TestHttpsServer;
import com.revetsec.testing.TestTls;
import com.revetsec.oauth.AuthorizationServerMetadata;
import com.revetsec.oauth.ClientAssertionSigningKey;
import com.revetsec.oauth.ClientAuthentication;
import com.revetsec.oauth.OAuthClient;
import com.revetsec.oauth.OAuthConfigurationException;
import com.revetsec.oauth.OAuthException;
import com.revetsec.oauth.OAuthTokenRequestResult;
import com.revetsec.oauth.TokenRequestOptions;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.net.URLDecoder;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.time.Duration;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Set;
import java.util.Map;
import java.util.HashMap;
import java.util.concurrent.atomic.AtomicInteger;
import static java.util.Objects.requireNonNull;
import static org.junit.jupiter.api.Assertions.*;

/** Selected RSA signing expansion; independent raw JCA oracle, never issuer profile widening. */
final class JwsSignerRsaExpansionTests {
 private static final @NonNull List<@NonNull JwsAlgorithm> ADDED=List.of(JwsAlgorithm.RS512,JwsAlgorithm.PS384,JwsAlgorithm.PS512);
 private static final @NonNull List<@NonNull JwsAlgorithm> PSS=List.of(JwsAlgorithm.PS384,JwsAlgorithm.PS512);
 private static final TestJwk.@NonNull Fixture KEY=TestJwk.Fixture.IDP_SIGNING_RSA_2048;
 private static final @NonNull Duration BUDGET=Duration.ofSeconds(5);
 private static final @NonNull String CLAIMS=" \n{\"subject\":\"é😀\",\"value\":1e+0}\t";
 @TestFactory @NonNull List<@NonNull DynamicTest> addedAlgorithmsSignAndIndependentlyVerifyExactBytes(){
  List<DynamicTest> cases=new ArrayList<>();for(JwsAlgorithm algorithm:ADDED)cases.add(DynamicTest.dynamicTest("SIGN-01/raw/"+algorithm,()->{
   JwsSigner signer=signer(KEY.getPrivateKey(),KEY.getPublicKey(),algorithm);byte[] input=CLAIMS.getBytes(StandardCharsets.UTF_8),before=input.clone();
   String compact=signer.toCompactSerialization("JWT","rsa-expansion",null,input,BUDGET);String[] parts=compact.split("\\.",-1);
   assertEquals(3,parts.length);assertTrue(Arrays.equals(before,input));assertTrue(Arrays.equals(before,Base64.getUrlDecoder().decode(parts[1])));
   JsonObject header=(JsonObject)JsonCodec.parse(Base64.getUrlDecoder().decode(parts[0]),JsonLimits.jose(4096));
   assertEquals(Set.of("alg","typ","kid"),header.getMembers().keySet());assertEquals(JsonString.fromValue(algorithm.getWireValue()),header.getMembers().get("alg"));
   assertEquals(algorithm,signer.getAlgorithm());assertTrue(verify(algorithm,compact,KEY.getPublicKey(),null));assertFalse(compact.contains("="));
   signer.warmUp(BUDGET);
  }));return cases;
 }
 @TestFactory @NonNull List<@NonNull DynamicTest> typedBuilderKeepsTheSelectedAlgorithmForEveryTokenType(){
  List<DynamicTest> cases=new ArrayList<>();for(JwsAlgorithm algorithm:ADDED)cases.add(DynamicTest.dynamicTest("SIGN-01/typed/"+algorithm,()->{
   JwsSigner signer=signer(KEY.getPrivateKey(),KEY.getPublicKey(),algorithm);JwtClaimsSet claims=JwtClaimsSet.builder().subject("application-owned").build();
   for(JwtType type:JwtType.values()){
    String compact=signer.withHeaderAndClaims(JwtSigningHeader.fromType(type),claims).remainingBudget(BUDGET).build();
    assertTrue(verify(algorithm,compact,KEY.getPublicKey(),null));String[] parts=compact.split("\\.",-1);JsonObject header=(JsonObject)JsonCodec.parse(Base64.getUrlDecoder().decode(parts[0]),JsonLimits.jose(4096));
    assertEquals(JsonString.fromValue(type.getWireValue()),header.getMembers().get("typ"));assertEquals(JsonString.fromValue(algorithm.getWireValue()),header.getMembers().get("alg"));assertEquals(claims.toJsonObject(),JsonCodec.parse(Base64.getUrlDecoder().decode(parts[1]),JsonLimits.jose(32768)));
   }
  }));return cases;
 }
 @TestFactory @NonNull List<@NonNull DynamicTest> pssPinsDigestMgfSaltAndTrailer(){
  List<DynamicTest> cases=new ArrayList<>();for(JwsAlgorithm algorithm:PSS)cases.add(DynamicTest.dynamicTest("SIGN-01/pss-parameters/"+algorithm,()->{
   String compact=signer(KEY.getPrivateKey(),KEY.getPublicKey(),algorithm).toCompactSerialization("JWT",null,null,"{}".getBytes(StandardCharsets.UTF_8),BUDGET);
   assertTrue(verify(algorithm,compact,KEY.getPublicKey(),parameters(algorithm,length(algorithm))));
   assertFalse(verify(algorithm,compact,KEY.getPublicKey(),parameters(algorithm,length(algorithm)-1)));
   assertFalse(verify(algorithm,compact,KEY.getPublicKey(),new PSSParameterSpec(digest(algorithm),"MGF1",MGF1ParameterSpec.SHA256,length(algorithm),1)));
  }));return cases;
 }
 @TestFactory @NonNull List<@NonNull DynamicTest> pssPublicMinimumRestrictionsAreStableCanonicalSnapshots(){
  List<DynamicTest> cases=new ArrayList<>();for(JwsAlgorithm algorithm:PSS)for(int minimum:List.of(0,20,length(algorithm)))cases.add(DynamicTest.dynamicTest("SIGN-01/pss-public-minimum/"+algorithm+"/"+minimum,()->{
   RSAPublicKey real=(RSAPublicKey)KEY.getPublicKey();MutableParameters supplied=new MutableParameters(algorithm,minimum);MutablePublic publicKey=new MutablePublic(real.getModulus(),real.getPublicExponent(),supplied,"RSASSA-PSS");
   JwsSigner signer=signer(KEY.getPrivateKey(),publicKey,algorithm);supplied.salt=length(algorithm)+1;supplied.digest="SHA-1";
   PSSParameterSpec projected=(PSSParameterSpec)requireNonNull(((RSAPublicKey)signer.getPublicKey()).getParams());assertEquals(PSSParameterSpec.class,projected.getClass());assertEquals(digest(algorithm),projected.getDigestAlgorithm());assertEquals("MGF1",projected.getMGFAlgorithm());assertEquals(digest(algorithm),((MGF1ParameterSpec)projected.getMGFParameters()).getDigestAlgorithm());assertEquals(minimum,projected.getSaltLength());assertEquals(1,projected.getTrailerField());assertNotSame(projected,((RSAPublicKey)signer.getPublicKey()).getParams());
   assertTrue(verify(algorithm,signer.toCompactSerialization("JWT",null,null,"{}".getBytes(StandardCharsets.UTF_8),BUDGET),real,null));
  }));return cases;
 }
 @TestFactory @NonNull List<@NonNull DynamicTest> realPssPrivateRestrictionsRemainProviderOwned(){
  List<DynamicTest> cases=new ArrayList<>();for(JwsAlgorithm algorithm:PSS)cases.add(DynamicTest.dynamicTest("SIGN-01/pss-private-restrictions/"+algorithm,()->{
   RSAPrivateCrtKey real=(RSAPrivateCrtKey)KEY.getPrivateKey();KeyFactory factory=KeyFactory.getInstance("RSASSA-PSS");PSSParameterSpec good=parameters(algorithm,length(algorithm));
   PrivateKey restricted=restricted(factory,real,good);PublicKey publicKey=factory.generatePublic(new RSAPublicKeySpec(real.getModulus(),real.getPublicExponent(),good));
   JwsSigner accepted=signer(restricted,publicKey,algorithm);assertTrue(verify(algorithm,accepted.toCompactSerialization("JWT",null,null,"{}".getBytes(StandardCharsets.UTF_8),BUDGET),publicKey,null));
   PrivateKey incompatible=restricted(factory,real,new PSSParameterSpec("SHA-256","MGF1",MGF1ParameterSpec.SHA256,32,1));JwsSigner deferred=signer(incompatible,KEY.getPublicKey(),algorithm);
   assertEquals(JwsSigningException.Reason.SIGNING_UNAVAILABLE,assertThrows(JwsSigningException.class,()->deferred.warmUp(BUDGET)).getReason());
   for(PSSParameterSpec bad:List.of(parameters(algorithm,length(algorithm)+1),new PSSParameterSpec(digest(algorithm),"MGF1",MGF1ParameterSpec.SHA256,length(algorithm),1)))assertThrows(IllegalArgumentException.class,()->JwsSigner.fromRsaKeyPair(KEY.getPrivateKey(),new MutablePublic(real.getModulus(),real.getPublicExponent(),bad,"RSA"),algorithm));
  }));return cases;
 }
 @Test void pssOnlyKeysCannotBecomeRs512(){
  RSAPublicKey real=(RSAPublicKey)KEY.getPublicKey();assertThrows(IllegalArgumentException.class,()->JwsSigner.fromRsaKeyPair(new RefusingPrivate("RSASSA-PSS"),KEY.getPublicKey(),JwsAlgorithm.RS512));
  assertThrows(IllegalArgumentException.class,()->JwsSigner.fromRsaKeyPair(KEY.getPrivateKey(),new MutablePublic(real.getModulus(),real.getPublicExponent(),null,"RSASSA-PSS"),JwsAlgorithm.RS512));
  assertThrows(IllegalArgumentException.class,()->JwsSigner.fromRsaKeyPair(KEY.getPrivateKey(),new MutablePublic(real.getModulus(),real.getPublicExponent(),parameters(JwsAlgorithm.PS512,64),"RSA"),JwsAlgorithm.RS512));
 }
 @TestFactory @NonNull List<@NonNull DynamicTest> constructionNeverEncodesPrivateOrPublicKeysAndPublicProjectionIsStable(){
  List<DynamicTest> cases=new ArrayList<>();for(JwsAlgorithm algorithm:ADDED)cases.add(DynamicTest.dynamicTest("SIGN-01/inert-snapshot/"+algorithm,()->{
   RSAPublicKey real=(RSAPublicKey)KEY.getPublicKey();MutablePublic supplied=new MutablePublic(real.getModulus(),real.getPublicExponent(),null,"RSA");
   JwsSigner inert=signer(new RefusingPrivate("RSA"),supplied,algorithm);assertEquals(algorithm,inert.getAlgorithm());assertNull(inert.getPublicKey().getEncoded());assertNull(inert.getPublicKey().getFormat());
   JwsSigner usable=signer(KEY.getPrivateKey(),supplied,algorithm);supplied.modulus=BigInteger.valueOf(3);supplied.exponent=BigInteger.valueOf(3);supplied.parameters=new MGF1ParameterSpec("SHA-1");
   assertEquals(real.getModulus(),((RSAPublicKey)usable.getPublicKey()).getModulus());assertEquals(real.getPublicExponent(),((RSAPublicKey)usable.getPublicKey()).getPublicExponent());assertNull(((RSAPublicKey)usable.getPublicKey()).getParams());
   assertTrue(verify(algorithm,usable.toCompactSerialization("JWT",null,null,"{}".getBytes(StandardCharsets.UTF_8),BUDGET),real,null));
  }));return cases;
 }
 @TestFactory @NonNull List<@NonNull DynamicTest> actualSignatureMustAgreeWithTheSuppliedPublicProjection(){
  List<DynamicTest> cases=new ArrayList<>();for(JwsAlgorithm algorithm:ADDED)cases.add(DynamicTest.dynamicTest("SIGN-01/mismatched-pair/"+algorithm,()->{
   JwsSigner signer=signer(KEY.getPrivateKey(),TestJwk.Fixture.NEGATIVE_ATTACKER_RSA_2048.getPublicKey(),algorithm);
   assertEquals(JwsSigningException.Reason.KEY_PAIR_MISMATCH,assertThrows(JwsSigningException.class,()->signer.toCompactSerialization("JWT",null,null,"{}".getBytes(StandardCharsets.UTF_8),BUDGET)).getReason());
   assertEquals(JwsSigningException.Reason.KEY_PAIR_MISMATCH,assertThrows(JwsSigningException.class,()->signer.warmUp(BUDGET)).getReason());
  }));return cases;
 }
 @TestFactory @NonNull List<@NonNull DynamicTest> newAlgorithmsReuseOpaqueProviderFailureAndDeadlineChecksInOwnedChildJvms(){
  List<DynamicTest> cases=new ArrayList<>();for(JwsAlgorithm algorithm:ADDED)for(String mode:List.of("opaque","mismatch","malformed","late-init","late-sign","late-verify","throwing-verifier","vm-error","interrupt"))cases.add(providerCase(algorithm,mode));
  for(JwsAlgorithm algorithm:PSS)cases.add(providerCase(algorithm,"restricted"));return cases;
 }
 @TestFactory @NonNull List<@NonNull DynamicTest> newRsaClientAssertionsRetainAdvertisedMetadataPolicy(){
  List<DynamicTest> cases=new ArrayList<>();for(JwsAlgorithm algorithm:ADDED)for(String policy:List.of("match","empty","exclude"))cases.add(DynamicTest.dynamicTest("SIGN-01/assertion-metadata/"+algorithm+"/"+policy,()->{
   JwsSigner signer=signer(KEY.getPrivateKey(),KEY.getPublicKey(),algorithm);AtomicInteger providerReads=new AtomicInteger();
   ClientAuthentication authentication=ClientAuthentication.fromPrivateKeyJwt(budget->{providerReads.incrementAndGet();return ClientAssertionSigningKey.withSigner(signer).keyId("rsa-expansion").build();});
   try(TestHttpsServer server=TestHttpsServer.start()){
    Set<String> algorithms=policy.equals("match")?Set.of(algorithm.getWireValue()):policy.equals("empty")?Set.of():Set.of("RS256");
    AuthorizationServerMetadata metadata=AuthorizationServerMetadata.withIssuer(server.getBaseUri().toString()).authorizationEndpoint(server.uri("/authorize")).tokenEndpoint(server.uri("/token")).tokenEndpointAuthMethodsSupported(Set.of("private_key_jwt")).tokenEndpointAuthSigningAlgValuesSupported(algorithms).build();
    OAuthClient client=OAuthClient.withAuthorizationServerMetadata(metadata).clientId("rsa-expansion-client").clientAuthentication(authentication).httpClient(TestTls.httpClient()).clock(Clock.fixed(Instant.ofEpochSecond(1800000000),ZoneOffset.UTC)).build();assertEquals(0,providerReads.get());
    if(policy.equals("match")){
     server.script("/token",TestHttpsServer.Script.fromResponse(TestHttpsServer.Response.fromJson(200,"{\"access_token\":\"TEST-ONLY-rsa-token\",\"token_type\":\"Bearer\",\"expires_in\":300}")));
     assertInstanceOf(OAuthTokenRequestResult.Succeeded.class,client.requestClientCredentialsResult(TokenRequestOptions.builder().build()));assertEquals(1,providerReads.get());assertEquals(1,server.getRequests("/token").size());
     var request=server.getRequests("/token").get(0);assertTrue(request.getHeader("Authorization").isEmpty());Map<String,String> form=new HashMap<>();for(String field:request.getBodyAsString().split("&",-1)){String[] pair=field.split("=",2);assertNull(form.put(URLDecoder.decode(pair[0],StandardCharsets.UTF_8),URLDecoder.decode(pair[1],StandardCharsets.UTF_8)));}
     assertEquals("rsa-expansion-client",form.get("client_id"));assertFalse(form.containsKey("client_secret"));assertEquals("urn:ietf:params:oauth:client-assertion-type:jwt-bearer",form.get("client_assertion_type"));String compact=requireNonNull(form.get("client_assertion"));assertTrue(verify(algorithm,compact,KEY.getPublicKey(),null));
     JsonObject header=(JsonObject)JsonCodec.parse(Base64.getUrlDecoder().decode(compact.split("\\.",-1)[0]),JsonLimits.jose(4096));assertEquals(JsonString.fromValue(algorithm.getWireValue()),header.getMembers().get("alg"));
    }else{
     assertEquals(OAuthException.Reason.CLIENT_ASSERTION_ENDPOINT_MISMATCH,assertThrows(OAuthConfigurationException.class,()->client.requestClientCredentialsResult(TokenRequestOptions.builder().build())).getReason());assertEquals(policy.equals("empty")?0:1,providerReads.get());assertTrue(server.getRequests().isEmpty());
    }
   }
  }));return cases;
 }
 private static @NonNull DynamicTest providerCase(@NonNull JwsAlgorithm algorithm,@NonNull String mode){return DynamicTest.dynamicTest("SIGN-01/provider/"+algorithm+"/"+mode,()->{
  ChildJvm.Result result=ChildJvm.withMainClass(JwsSignerTestProvider.class).arguments(List.of(mode,algorithm.name())).build().run();assertEquals(0,result.getExitCode(),()->result.getStandardOutput()+result.getStandardError());assertEquals("scenario="+mode+" passed\n",result.getStandardOutput());assertFalse(result.isTimedOut());
 });}
 private static @NonNull JwsSigner signer(@NonNull PrivateKey privateKey,@NonNull PublicKey publicKey,@NonNull JwsAlgorithm algorithm){return assertDoesNotThrow(()->JwsSigner.fromRsaKeyPair(privateKey,publicKey,algorithm),"Selected RSA algorithm must be available.");}
 private static @NonNull PrivateKey restricted(@NonNull KeyFactory factory,@NonNull RSAPrivateCrtKey key,@NonNull PSSParameterSpec parameters)throws Exception{return factory.generatePrivate(new RSAPrivateCrtKeySpec(key.getModulus(),key.getPublicExponent(),key.getPrivateExponent(),key.getPrimeP(),key.getPrimeQ(),key.getPrimeExponentP(),key.getPrimeExponentQ(),key.getCrtCoefficient(),parameters));}
 private static @NonNull String digest(@NonNull JwsAlgorithm algorithm){return switch(algorithm){case PS384->"SHA-384";case RS512,PS512->"SHA-512";default->throw new AssertionError("Unexpected selected RSA algorithm");};}
 private static int length(@NonNull JwsAlgorithm algorithm){return algorithm==JwsAlgorithm.PS384?48:64;}
 private static @NonNull PSSParameterSpec parameters(@NonNull JwsAlgorithm algorithm,int salt){return new PSSParameterSpec(digest(algorithm),"MGF1",new MGF1ParameterSpec(digest(algorithm)),salt,1);}
 private static boolean verify(@NonNull JwsAlgorithm algorithm,@NonNull String compact,@NonNull PublicKey publicKey,@Nullable PSSParameterSpec parameters)throws Exception{
  String[] parts=compact.split("\\.",-1);Signature verifier=Signature.getInstance(algorithm==JwsAlgorithm.RS512?"SHA512withRSA":"RSASSA-PSS");verifier.initVerify(publicKey);if(algorithm!=JwsAlgorithm.RS512)verifier.setParameter(parameters==null?parameters(algorithm,length(algorithm)):parameters);verifier.update((parts[0]+"."+parts[1]).getBytes(StandardCharsets.US_ASCII));return verifier.verify(Base64.getUrlDecoder().decode(parts[2]));
 }
 private static final class RefusingPrivate implements PrivateKey {
  private static final long serialVersionUID=1L;private final @NonNull String algorithm;private RefusingPrivate(@NonNull String algorithm){this.algorithm=algorithm;}
  @Override public @NonNull String getAlgorithm(){return this.algorithm;}@Override public @Nullable String getFormat(){throw new AssertionError("Private format inspected");}@Override public byte @Nullable [] getEncoded(){throw new AssertionError("Private encoding inspected");}
 }
 private static final class MutablePublic implements RSAPublicKey {
  private static final long serialVersionUID=1L;private @NonNull BigInteger modulus,exponent;@SuppressWarnings("serial") private @Nullable AlgorithmParameterSpec parameters;private final @NonNull String algorithm;
  private MutablePublic(@NonNull BigInteger modulus,@NonNull BigInteger exponent,@Nullable AlgorithmParameterSpec parameters,@NonNull String algorithm){this.modulus=modulus;this.exponent=exponent;this.parameters=parameters;this.algorithm=algorithm;}
  @Override public @NonNull BigInteger getModulus(){return this.modulus;}@Override public @NonNull BigInteger getPublicExponent(){return this.exponent;}@Override public @Nullable AlgorithmParameterSpec getParams(){return this.parameters;}@Override public @NonNull String getAlgorithm(){return this.algorithm;}@Override public @Nullable String getFormat(){throw new AssertionError("Public format inspected");}@Override public byte @Nullable [] getEncoded(){throw new AssertionError("Public encoding inspected");}
 }
 private static final class MutableParameters extends PSSParameterSpec {
  private int salt;private @NonNull String digest;private MutableParameters(@NonNull JwsAlgorithm algorithm,int salt){super(digest(algorithm),"MGF1",new MGF1ParameterSpec(digest(algorithm)),salt,1);this.salt=salt;this.digest=digest(algorithm);}
  @Override public int getSaltLength(){return this.salt;}@Override public @NonNull String getDigestAlgorithm(){return this.digest;}
 }
}
