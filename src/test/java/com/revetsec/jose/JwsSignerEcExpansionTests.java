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

import com.revetsec.internal.crypto.EcCurve;
import com.revetsec.internal.json.JsonCodec;
import com.revetsec.internal.json.JsonLimits;
import com.revetsec.json.JsonObject;
import com.revetsec.json.JsonString;
import com.revetsec.oauth.*;
import com.revetsec.oauth.server.OAuthIssuerSigningKey;
import com.revetsec.testing.ChildJvm;
import com.revetsec.testing.TestHttpsServer;
import com.revetsec.testing.TestJwk;
import com.revetsec.testing.TestTls;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.TestFactory;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.math.BigInteger;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.interfaces.ECPublicKey;
import java.security.spec.*;
import java.time.Clock;
import java.time.Duration;
import java.time.ZoneOffset;
import java.util.*;
import java.util.concurrent.atomic.AtomicInteger;
import static java.util.Objects.requireNonNull;
import static org.junit.jupiter.api.Assertions.*;

/** Selected EC signing: genuine signatures, independent P1363 oracle and exact structural boundaries. */
final class JwsSignerEcExpansionTests {
 private static final @NonNull List<@NonNull JwsAlgorithm> ALGORITHMS=List.of(JwsAlgorithm.ES256,JwsAlgorithm.ES384);
 private static final @NonNull Duration BUDGET=Duration.ofSeconds(5);
 private static final @NonNull String CLAIMS=" \n{\"subject\":\"é😀\",\"value\":1e+0}\t";
 @TestFactory @NonNull List<@NonNull DynamicTest> rawEcSignaturesHaveExactJoseLengthAndIndependentVerification(){
  List<DynamicTest> tests=new ArrayList<>();for(JwsAlgorithm algorithm:ALGORITHMS)tests.add(DynamicTest.dynamicTest("SIGN-02/raw/"+algorithm,()->{
   var key=key(algorithm);JwsSigner signer=signer(key.getPrivateKey(),key.getPublicKey(),algorithm);byte[] input=CLAIMS.getBytes(StandardCharsets.UTF_8),before=input.clone();String compact=signer.toCompactSerialization("JWT","ec-key",null,input,BUDGET);String[] pieces=compact.split("\\.",-1);
   assertEquals(3,pieces.length);assertTrue(Arrays.equals(before,input));assertTrue(Arrays.equals(before,Base64.getUrlDecoder().decode(pieces[1])));assertEquals(curve(algorithm).getSignatureLength(),Base64.getUrlDecoder().decode(pieces[2]).length);assertTrue(verify(algorithm,compact,key.getPublicKey()));assertFalse(compact.contains("="));
   JsonObject header=(JsonObject)JsonCodec.parse(Base64.getUrlDecoder().decode(pieces[0]),JsonLimits.jose(4096));assertEquals(Set.of("alg","typ","kid"),header.getMembers().keySet());assertEquals(JsonString.fromValue(algorithm.getWireValue()),header.getMembers().get("alg"));assertEquals(algorithm,signer.getAlgorithm());signer.warmUp(BUDGET);
  }));return tests;
 }
 @TestFactory @NonNull List<@NonNull DynamicTest> typedEcJwtWorksForEachTypeAndTheExistingValidator(){
  List<DynamicTest> tests=new ArrayList<>();for(JwsAlgorithm algorithm:ALGORITHMS)tests.add(DynamicTest.dynamicTest("SIGN-02/typed/"+algorithm,()->{
   var key=key(algorithm);JwsSigner signer=signer(key.getPrivateKey(),key.getPublicKey(),algorithm);JwtClaimsSet claims=JwtClaimsSet.builder().issuer(JwtFixtures.ISSUER).subject("subject-1").audiences(List.of(JwtFixtures.AUDIENCE)).issuedAt(JwtFixtures.NOW).expiresAt(JwtFixtures.NOW.plusSeconds(300)).build();
   for(JwtType type:JwtType.values()){
    String compact=signer.withHeaderAndClaims(JwtSigningHeader.fromType(type),claims).remainingBudget(BUDGET).build();assertTrue(verify(algorithm,compact,key.getPublicKey()));
    JwtValidator validator=JwtFixtures.validator(JwtFixtures.source(key)).allowedAlgorithms(Set.of(algorithm)).allowedTypes(Set.of(type.getWireValue())).typeRequired(true).requiredClaims(Set.of("sub")).build();assertInstanceOf(JwtValidationResult.Succeeded.class,validator.validateResult(compact));
   }
  }));return tests;
 }
 @TestFactory @NonNull List<@NonNull DynamicTest> publicPointAndEveryDomainFactMustMatchTheSelectedCurve(){
  List<DynamicTest> tests=new ArrayList<>();for(JwsAlgorithm algorithm:ALGORITHMS)for(String fault:List.of("null-params","null-point","infinity","other-curve","off-curve","negative-x","x-at-p","y-at-p","cofactor","order","generator","a","b","prime","wrong-algorithm","throw-point","throw-params","lying-order"))tests.add(DynamicTest.dynamicTest("SIGN-02/public-structure/"+algorithm+"/"+fault,()->{
   ECPublicKey real=(ECPublicKey)key(algorithm).getPublicKey();ECParameterSpec good=real.getParams();MutablePublic supplied=new MutablePublic(real.getW(),good);EcCurve selected=curve(algorithm);
   switch(fault){
    case "null-params"->supplied.parameters=null;case "null-point"->supplied.point=null;case "infinity"->supplied.point=ECPoint.POINT_INFINITY;case "other-curve"->supplied.parameters=(algorithm==JwsAlgorithm.ES256?EcCurve.P_384:EcCurve.P_256).getParameterSpec();case "off-curve"->supplied.point=new ECPoint(BigInteger.ZERO,BigInteger.ZERO);case "negative-x"->supplied.point=new ECPoint(BigInteger.valueOf(-1),real.getW().getAffineY());case "x-at-p"->supplied.point=new ECPoint(selected.getFieldPrime(),real.getW().getAffineY());case "y-at-p"->supplied.point=new ECPoint(real.getW().getAffineX(),selected.getFieldPrime());
    case "cofactor"->supplied.parameters=new ECParameterSpec(good.getCurve(),good.getGenerator(),good.getOrder(),2);case "order"->supplied.parameters=new ECParameterSpec(good.getCurve(),good.getGenerator(),good.getOrder().subtract(BigInteger.ONE),1);case "generator"->supplied.parameters=new ECParameterSpec(good.getCurve(),new ECPoint(BigInteger.ZERO,BigInteger.ZERO),good.getOrder(),1);case "a"->supplied.parameters=new ECParameterSpec(new EllipticCurve(good.getCurve().getField(),BigInteger.ONE,good.getCurve().getB()),good.getGenerator(),good.getOrder(),1);case "b"->supplied.parameters=new ECParameterSpec(new EllipticCurve(good.getCurve().getField(),good.getCurve().getA(),BigInteger.ONE),good.getGenerator(),good.getOrder(),1);case "prime"->supplied.parameters=new ECParameterSpec(new EllipticCurve(new ECFieldFp(selected.getFieldPrime().subtract(BigInteger.TWO)),good.getCurve().getA(),good.getCurve().getB()),good.getGenerator(),good.getOrder(),1);case "wrong-algorithm"->supplied.algorithm="RSA";case "throw-point"->supplied.failure=1;case "throw-params"->supplied.failure=2;case "lying-order"->supplied.parameters=new ECParameterSpec(good.getCurve(),good.getGenerator(),new LyingInteger(),1);default->throw new AssertionError("Unknown structural cell");
   }
   IllegalArgumentException failure=assertThrows(IllegalArgumentException.class,()->construct(key(algorithm).getPrivateKey(),supplied,algorithm));assertEquals("The EC signing key or algorithm is invalid.",failure.getMessage());assertNull(failure.getCause());
  }));return tests;
 }

 @TestFactory @NonNull List<@NonNull DynamicTest> validZeroXCoordinateIsAcceptedAndSnapshottedAtBothIntegerLowerBounds(){
  List<DynamicTest> tests=new ArrayList<>();for(JwsAlgorithm algorithm:ALGORITHMS)tests.add(DynamicTest.dynamicTest("SIGN/valid-zero-x/"+algorithm,()->{
   EcCurve selected=curve(algorithm);BigInteger prime=selected.getFieldPrime();
   assertEquals(BigInteger.valueOf(3),prime.mod(BigInteger.valueOf(4)));
   BigInteger y=selected.getB().modPow(prime.add(BigInteger.ONE).shiftRight(2),prime);
   assertEquals(selected.getB(),y.multiply(y).mod(prime));
   ECPoint point=new ECPoint(BigInteger.ZERO,y);MutablePublic supplied=new MutablePublic(point,selected.getParameterSpec());
   // This is a structural factory control with an opaque reference, not a claimed usable private/public pair.
   JwsSigner accepted=signer(new RefusingPrivate("EC"),supplied,algorithm);
   supplied.point=ECPoint.POINT_INFINITY;supplied.parameters=EcCurve.P_521.getParameterSpec();
   ECPublicKey snapshot=assertInstanceOf(ECPublicKey.class,accepted.getPublicKey());
   assertEquals(algorithm,accepted.getAlgorithm());assertEquals(BigInteger.ZERO,snapshot.getW().getAffineX());
   assertEquals(y,snapshot.getW().getAffineY());assertTrue(selected.isDescribedBy(snapshot.getParams()));
   assertNull(snapshot.getFormat());assertNull(snapshot.getEncoded());assertEquals("EcPublicKey{material=<redacted>}",snapshot.toString());
  }));return tests;
 }

 @TestFactory @NonNull List<@NonNull DynamicTest> ecFactoryRejectsEveryUnselectedAlgorithmAndWrongPrivateFamily(){
  List<DynamicTest> tests=new ArrayList<>();for(JwsAlgorithm algorithm:JwsAlgorithm.values())if(!ALGORITHMS.contains(algorithm))tests.add(DynamicTest.dynamicTest("SIGN-02/unsupported/"+algorithm,()->assertThrows(IllegalArgumentException.class,()->construct(key(JwsAlgorithm.ES256).getPrivateKey(),key(JwsAlgorithm.ES256).getPublicKey(),algorithm))));
  for(JwsAlgorithm algorithm:ALGORITHMS)tests.add(DynamicTest.dynamicTest("SIGN-02/private-family/"+algorithm,()->{
   assertThrows(IllegalArgumentException.class,()->construct(new RefusingPrivate("RSA"),key(algorithm).getPublicKey(),algorithm));assertThrows(IllegalArgumentException.class,()->construct(key(algorithm).getPrivateKey(),TestJwk.Fixture.IDP_SIGNING_RSA_2048.getPublicKey(),algorithm));
  }));return tests;
 }
 @TestFactory @NonNull List<@NonNull DynamicTest> constructionIsInertAndPublicPointAndParametersAreIndependentSnapshots(){
  List<DynamicTest> tests=new ArrayList<>();for(JwsAlgorithm algorithm:ALGORITHMS)tests.add(DynamicTest.dynamicTest("SIGN-02/inert-snapshot/"+algorithm,()->{
   ECPublicKey real=(ECPublicKey)key(algorithm).getPublicKey();MutablePublic supplied=new MutablePublic(real.getW(),real.getParams());JwsSigner inert=signer(new RefusingPrivate("EC"),supplied,algorithm);assertEquals(algorithm,inert.getAlgorithm());
   JwsSigner usable=signer(key(algorithm).getPrivateKey(),supplied,algorithm);supplied.point=ECPoint.POINT_INFINITY;supplied.parameters=EcCurve.P_521.getParameterSpec();supplied.algorithm="RSA";ECPublicKey snapshot=(ECPublicKey)usable.getPublicKey();assertEquals("EC",snapshot.getAlgorithm());assertNull(snapshot.getFormat());assertNull(snapshot.getEncoded());assertEquals(real.getW(),snapshot.getW());assertTrue(curve(algorithm).isDescribedBy(snapshot.getParams()));assertNotSame(snapshot.getParams(),snapshot.getParams());assertNotSame(snapshot.getW(),snapshot.getW());assertEquals(ECPoint.class,snapshot.getW().getClass());assertEquals(ECParameterSpec.class,snapshot.getParams().getClass());assertEquals("EcPublicKey{material=<redacted>}",snapshot.toString());assertTrue(verify(algorithm,usable.toCompactSerialization("JWT",null,null,"{}".getBytes(StandardCharsets.UTF_8),BUDGET),real));
  }));return tests;
 }
 @TestFactory @NonNull List<@NonNull DynamicTest> actualEcPairAgreementAndPrivateCurveAreCheckedBeforeOutput(){
  List<DynamicTest> tests=new ArrayList<>();for(JwsAlgorithm algorithm:ALGORITHMS)for(boolean otherCurve:List.of(false,true))tests.add(DynamicTest.dynamicTest("SIGN-02/pair/"+algorithm+"/otherCurve="+otherCurve,()->{
   KeyPairGenerator generator=KeyPairGenerator.getInstance("EC");generator.initialize(new ECGenParameterSpec((otherCurve?(algorithm==JwsAlgorithm.ES256?EcCurve.P_384:EcCurve.P_256):curve(algorithm)).getStandardName()));KeyPair wrong=generator.generateKeyPair();JwsSigner signer=signer(wrong.getPrivate(),key(algorithm).getPublicKey(),algorithm);JwsSigningException.Reason expected=otherCurve&&algorithm==JwsAlgorithm.ES256?JwsSigningException.Reason.SIGNING_UNAVAILABLE:JwsSigningException.Reason.KEY_PAIR_MISMATCH;
   assertEquals(expected,assertThrows(JwsSigningException.class,()->signer.toCompactSerialization("JWT",null,null,"{}".getBytes(StandardCharsets.UTF_8),BUDGET)).getReason());assertEquals(expected,assertThrows(JwsSigningException.class,()->signer.warmUp(BUDGET)).getReason());
  }));return tests;
 }
 @TestFactory @NonNull List<@NonNull DynamicTest> issuerRemainsRsaOnlyEvenWhenGeneralEcSigningExists(){
  List<DynamicTest> tests=new ArrayList<>();for(JwsAlgorithm algorithm:ALGORITHMS)tests.add(DynamicTest.dynamicTest("SIGN-02/issuer-rsa-only/"+algorithm,()->assertThrows(IllegalArgumentException.class,()->OAuthIssuerSigningKey.fromRsaKeyPair("ec",key(algorithm).getPrivateKey(),key(algorithm).getPublicKey()))));return tests;
 }
 @TestFactory @NonNull List<@NonNull DynamicTest> ecClientAssertionsUseTheExistingAdvertisedMetadataGate(){
  List<DynamicTest> tests=new ArrayList<>();for(JwsAlgorithm algorithm:ALGORITHMS)for(String policy:List.of("match","empty","exclude"))tests.add(DynamicTest.dynamicTest("SIGN-02/assertion-metadata/"+algorithm+"/"+policy,()->{
   JwsSigner signer=signer(key(algorithm).getPrivateKey(),key(algorithm).getPublicKey(),algorithm);AtomicInteger reads=new AtomicInteger();ClientAuthentication auth=ClientAuthentication.fromPrivateKeyJwt(budget->{reads.incrementAndGet();return ClientAssertionSigningKey.withSigner(signer).keyId("ec").build();});
   try(TestHttpsServer server=TestHttpsServer.start()){
    Set<String> allowed=policy.equals("match")?Set.of(algorithm.getWireValue()):policy.equals("empty")?Set.of():Set.of("RS256");AuthorizationServerMetadata metadata=AuthorizationServerMetadata.withIssuer(server.getBaseUri().toString()).authorizationEndpoint(server.uri("/authorize")).tokenEndpoint(server.uri("/token")).tokenEndpointAuthMethodsSupported(Set.of("private_key_jwt")).tokenEndpointAuthSigningAlgValuesSupported(allowed).build();OAuthClient client=OAuthClient.withAuthorizationServerMetadata(metadata).clientId("ec-client").clientAuthentication(auth).httpClient(TestTls.httpClient()).clock(Clock.fixed(JwtFixtures.NOW,ZoneOffset.UTC)).build();assertEquals(0,reads.get());
    if(policy.equals("match")){server.script("/token",TestHttpsServer.Script.fromResponse(TestHttpsServer.Response.fromJson(200,"{\"access_token\":\"TEST-ONLY-ec\",\"token_type\":\"Bearer\",\"expires_in\":300}")));assertInstanceOf(OAuthTokenRequestResult.Succeeded.class,client.requestClientCredentialsResult(TokenRequestOptions.builder().build()));assertEquals(1,reads.get());assertEquals(1,server.getRequests().size());Map<String,String> form=new HashMap<>();var request=server.getRequests("/token").get(0);assertTrue(request.getHeader("Authorization").isEmpty());for(String field:request.getBodyAsString().split("&",-1)){String[] pair=field.split("=",2);assertNull(form.put(URLDecoder.decode(pair[0],StandardCharsets.UTF_8),URLDecoder.decode(pair[1],StandardCharsets.UTF_8)));}assertEquals("ec-client",form.get("client_id"));assertEquals("urn:ietf:params:oauth:client-assertion-type:jwt-bearer",form.get("client_assertion_type"));assertFalse(form.containsKey("client_secret"));assertTrue(verify(algorithm,requireNonNull(form.get("client_assertion")),key(algorithm).getPublicKey()));}
    else{assertEquals(OAuthException.Reason.CLIENT_ASSERTION_ENDPOINT_MISMATCH,assertThrows(OAuthConfigurationException.class,()->client.requestClientCredentialsResult(TokenRequestOptions.builder().build())).getReason());assertEquals(policy.equals("empty")?0:1,reads.get());assertTrue(server.getRequests().isEmpty());}
   }
  }));return tests;
 }
 @TestFactory @NonNull List<@NonNull DynamicTest> opaqueProvidersMalformedDerBuffersAndLateWorkRunInOwnedChildJvms(){
  List<DynamicTest> tests=new ArrayList<>();for(JwsAlgorithm algorithm:ALGORITHMS)for(String mode:List.of("opaque","zero","range","nonminimal","trailing","oversized","mismatch","late-init","late-update","late-sign","late-verify","throwing","throwing-verifier","vm-error","verify-vm-error","interrupt"))tests.add(DynamicTest.dynamicTest("SIGN-02/provider/"+algorithm+"/"+mode,()->{ChildJvm.Result result=ChildJvm.withMainClass(JwsSignerEcTestProvider.class).arguments(List.of(algorithm.name(),mode)).build().run();assertEquals(0,result.getExitCode(),()->result.getStandardOutput()+result.getStandardError());assertEquals("scenario="+mode+" passed\n",result.getStandardOutput());assertFalse(result.isTimedOut());}));return tests;
 }
 private static @NonNull Method factory(){Method method=assertDoesNotThrow(()->JwsSigner.class.getMethod("fromEcKeyPair",PrivateKey.class,PublicKey.class,JwsAlgorithm.class),"Selected EC signing factory must be available.");assertEquals(JwsSigner.class,method.getReturnType());return method;}
 static @NonNull JwsSigner construct(@NonNull PrivateKey privateKey,@NonNull PublicKey publicKey,@NonNull JwsAlgorithm algorithm){try{return (JwsSigner)factory().invoke(null,privateKey,publicKey,algorithm);}catch(InvocationTargetException wrapped){Throwable cause=wrapped.getCause();if(cause instanceof RuntimeException runtime)throw runtime;if(cause instanceof Error error)throw error;throw new AssertionError("Unexpected checked EC factory failure");}catch(ReflectiveOperationException failure){throw new AssertionError("EC factory linkage failure");}}
 private static @NonNull JwsSigner signer(@NonNull PrivateKey privateKey,@NonNull PublicKey publicKey,@NonNull JwsAlgorithm algorithm){return assertDoesNotThrow(()->construct(privateKey,publicKey,algorithm),"Valid EC key pair must construct without provider work.");}
 static TestJwk.@NonNull Fixture key(@NonNull JwsAlgorithm algorithm){return algorithm==JwsAlgorithm.ES256?TestJwk.Fixture.IDP_SIGNING_EC_P256:TestJwk.Fixture.IDP_SIGNING_EC_P384;}
 static @NonNull EcCurve curve(@NonNull JwsAlgorithm algorithm){return algorithm==JwsAlgorithm.ES256?EcCurve.P_256:EcCurve.P_384;}
 static boolean verify(@NonNull JwsAlgorithm algorithm,@NonNull String compact,@NonNull PublicKey publicKey)throws Exception{String[] pieces=compact.split("\\.",-1);Signature verifier=Signature.getInstance((algorithm==JwsAlgorithm.ES256?"SHA256":"SHA384")+"withECDSAinP1363Format");verifier.initVerify(publicKey);verifier.update((pieces[0]+"."+pieces[1]).getBytes(StandardCharsets.US_ASCII));return verifier.verify(Base64.getUrlDecoder().decode(pieces[2]));}
 private static final class RefusingPrivate implements PrivateKey {private static final long serialVersionUID=1L;private final @NonNull String algorithm;private RefusingPrivate(@NonNull String algorithm){this.algorithm=algorithm;}@Override public @NonNull String getAlgorithm(){return this.algorithm;}@Override public @Nullable String getFormat(){throw new AssertionError("Private format inspected");}@Override public byte @Nullable [] getEncoded(){throw new AssertionError("Private encoded");}}
 private static final class MutablePublic implements ECPublicKey {private static final long serialVersionUID=1L;private @Nullable ECPoint point;@SuppressWarnings("serial") private @Nullable ECParameterSpec parameters;private @NonNull String algorithm="EC";private int failure;private MutablePublic(@NonNull ECPoint point,@NonNull ECParameterSpec parameters){this.point=point;this.parameters=parameters;}@Override public @NonNull ECPoint getW(){if(this.failure==1)throw new IllegalStateException("TEST-ONLY-private-public-getter");return this.point==null?nullValue():this.point;}@Override public @NonNull ECParameterSpec getParams(){if(this.failure==2)throw new IllegalStateException("TEST-ONLY-private-params");return this.parameters==null?nullValue():this.parameters;}@Override public @NonNull String getAlgorithm(){return this.algorithm;}@Override public @Nullable String getFormat(){throw new AssertionError("Public format inspected");}@Override public byte @Nullable [] getEncoded(){throw new AssertionError("Public encoded");}}
 private static final class LyingInteger extends BigInteger {private static final long serialVersionUID=1L;private LyingInteger(){super("3");}@Override public int compareTo(@NonNull BigInteger other){return 0;}}
 @SuppressWarnings({"NullAway","TypeParameterUnusedInFormals"}) private static <T> @NonNull T nullValue(){return null;}
}
