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
import java.math.BigInteger;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.interfaces.EdECPrivateKey;
import java.security.interfaces.EdECPublicKey;
import java.security.spec.*;
import java.time.Clock;
import java.time.Duration;
import java.time.ZoneOffset;
import java.util.*;
import java.util.concurrent.atomic.AtomicInteger;
import static java.util.Objects.requireNonNull;
import static org.junit.jupiter.api.Assertions.*;

/** Selected Ed25519 signing: exact wire, inert structural snapshots and independently checked output. */
final class JwsSignerEd25519ExpansionTests {
 private static final @NonNull Duration BUDGET=Duration.ofSeconds(5);
 private static final @NonNull String CLAIMS=" \n{\"subject\":\"é😀\",\"value\":1e+0}\t";
 @TestFactory @NonNull List<@NonNull DynamicTest> exactRawAndTypedEd25519CredentialsVerifyIndependently(){
  List<DynamicTest> tests=new ArrayList<>();tests.add(DynamicTest.dynamicTest("SIGN-03/raw-exact",()->{
   JwsSigner signer=signer(key().getPrivateKey(),key().getPublicKey());byte[] input=CLAIMS.getBytes(StandardCharsets.UTF_8),before=input.clone();String compact=signer.toCompactSerialization("JWT","ed-key",null,input,BUDGET);String[] parts=compact.split("\\.",-1);assertEquals(3,parts.length);assertArrayEquals(before,input);assertArrayEquals(before,Base64.getUrlDecoder().decode(parts[1]));assertEquals(64,Base64.getUrlDecoder().decode(parts[2]).length);assertTrue(verify(compact,key().getPublicKey()));assertFalse(compact.contains("="));JsonObject header=(JsonObject)JsonCodec.parse(Base64.getUrlDecoder().decode(parts[0]),JsonLimits.jose(4096));assertEquals(Set.of("alg","typ","kid"),header.getMembers().keySet());assertEquals(JsonString.fromValue("Ed25519"),header.getMembers().get("alg"));assertEquals(JwsAlgorithm.ED25519,signer.getAlgorithm());Signature oracle=Signature.getInstance("Ed25519");oracle.initSign(key().getPrivateKey());oracle.update((parts[0]+"."+parts[1]).getBytes(StandardCharsets.US_ASCII));assertArrayEquals(oracle.sign(),Base64.getUrlDecoder().decode(parts[2]),"Pure Ed25519 exact signed bytes agree with independent JCA signing");signer.warmUp(BUDGET);
  }));
  for(JwtType type:JwtType.values())tests.add(DynamicTest.dynamicTest("SIGN-03/typed/"+type,()->{
   JwsSigner signer=signer(key().getPrivateKey(),key().getPublicKey());JwtClaimsSet claims=JwtClaimsSet.builder().issuer(JwtFixtures.ISSUER).subject("subject-1").audiences(List.of(JwtFixtures.AUDIENCE)).issuedAt(JwtFixtures.NOW).expiresAt(JwtFixtures.NOW.plusSeconds(300)).build();String compact=signer.withHeaderAndClaims(JwtSigningHeader.fromType(type),claims).remainingBudget(BUDGET).build();assertTrue(verify(compact,key().getPublicKey()));JwtValidator validator=JwtFixtures.validator(JwtFixtures.source(key())).allowedAlgorithms(Set.of(JwsAlgorithm.ED25519)).allowedTypes(Set.of(type.getWireValue())).typeRequired(true).requiredClaims(Set.of("sub")).build();assertInstanceOf(JwtValidationResult.Succeeded.class,validator.validateResult(compact));
  }));return tests;
 }
 @TestFactory @NonNull List<@NonNull DynamicTest> rejectsEveryMalformedParameterAndPublicPointWithoutEncoding(){
  List<DynamicTest> tests=new ArrayList<>();for(String fault:List.of("null-params","null-point","Ed448","X25519","lowercase-params","wrong-algorithm","negative-y","p","p-plus-one","too-large-y","negative-bit-length","empty-encoding","overlong-encoding","nondecoding-y","zero-x-with-sign","throw-point","throw-params","lying-y"))tests.add(DynamicTest.dynamicTest("SIGN-03/public/"+fault,()->{
   EdECPublicKey real=(EdECPublicKey)key().getPublicKey();MutablePublic publicKey=new MutablePublic(real.getPoint(),real.getParams());switch(fault){case "null-params"->publicKey.parameters=null;case "null-point"->publicKey.point=null;case "Ed448"->publicKey.parameters=NamedParameterSpec.ED448;case "X25519"->publicKey.parameters=NamedParameterSpec.X25519;case "lowercase-params"->publicKey.parameters=new NamedParameterSpec("ed25519");case "wrong-algorithm"->publicKey.algorithm="RSA";case "negative-y"->publicKey.point=new EdECPoint(false,BigInteger.valueOf(-1));case "p"->publicKey.point=new EdECPoint(false,TestJwk.ED25519_FIELD_PRIME);case "p-plus-one"->publicKey.point=new EdECPoint(false,TestJwk.ED25519_FIELD_PRIME.add(BigInteger.ONE));case "too-large-y"->publicKey.point=new EdECPoint(false,BigInteger.ONE.shiftLeft(300));case "negative-bit-length"->publicKey.point=new EdECPoint(false,new ShapedInteger(-1,new byte[]{1}));case "empty-encoding"->publicKey.point=new EdECPoint(false,new ShapedInteger(1,new byte[0]));case "overlong-encoding"->publicKey.point=new EdECPoint(false,new ShapedInteger(1,new byte[33]));case "nondecoding-y"->publicKey.point=new EdECPoint(false,BigInteger.TWO);case "zero-x-with-sign"->publicKey.point=new EdECPoint(true,BigInteger.ONE);case "throw-point"->publicKey.failure=1;case "throw-params"->publicKey.failure=2;case "lying-y"->publicKey.point=new EdECPoint(real.getPoint().isXOdd(),new LyingInteger());default->throw new AssertionError("Unknown structural fault");}
   IllegalArgumentException failure=assertThrows(IllegalArgumentException.class,()->construct(key().getPrivateKey(),publicKey));assertEquals("The Ed25519 signing key is invalid.",failure.getMessage());assertNull(failure.getCause());
  }));return tests;
 }
 @TestFactory @NonNull List<@NonNull DynamicTest> rejectsAllEightSmallOrderPublicPoints(){
  List<DynamicTest> tests=new ArrayList<>();for(String encoding:TestJwk.ed25519SmallOrderPublicKeys())tests.add(DynamicTest.dynamicTest("SIGN-03/small-order/"+encoding,()->{byte[] little=Base64.getUrlDecoder().decode(encoding);boolean odd=(little[31]&0x80)!=0;little[31]&=0x7f;byte[] reversed=new byte[32];for(int i=0;i<32;i++)reversed[i]=little[31-i];MutablePublic publicKey=new MutablePublic(new EdECPoint(odd,new BigInteger(1,reversed)),NamedParameterSpec.ED25519);assertThrows(IllegalArgumentException.class,()->construct(key().getPrivateKey(),publicKey));}));return tests;
 }
 @TestFactory @NonNull List<@NonNull DynamicTest> wrongPrivateAndPublicFamiliesAndNullsAreRejected(){
  List<DynamicTest> tests=new ArrayList<>();for(String algorithm:List.of("RSA","EC","X25519","X448","XDH","Ed448","unknown"))tests.add(DynamicTest.dynamicTest("SIGN-03/private-family/"+algorithm,()->assertThrows(IllegalArgumentException.class,()->construct(new RefusingPrivate(algorithm),key().getPublicKey()))));
  for(String algorithm:List.of("Ed448","X25519","X448","RSA","EC"))tests.add(DynamicTest.dynamicTest("SIGN-03/actual-key-family/"+algorithm,()->{KeyPair pair=KeyPairGenerator.getInstance(algorithm).generateKeyPair();assertThrows(IllegalArgumentException.class,()->construct(pair.getPrivate(),key().getPublicKey()));assertThrows(IllegalArgumentException.class,()->construct(key().getPrivateKey(),pair.getPublic()));}));
  tests.add(DynamicTest.dynamicTest("SIGN-03/nulls",()->{assertThrows(NullPointerException.class,()->construct(nullValue(),key().getPublicKey()));assertThrows(NullPointerException.class,()->construct(key().getPrivateKey(),nullValue()));}));return tests;
 }
 @TestFactory @NonNull List<@NonNull DynamicTest> inertConstructionKeepsOnlyIndependentPublicSnapshotsAndOpaquePrivateReference(){
  List<DynamicTest> tests=new ArrayList<>();for(String name:List.of("EdDSA","Ed25519","ed25519"))tests.add(DynamicTest.dynamicTest("SIGN-03/inert-snapshot/"+name,()->{
   EdECPublicKey real=(EdECPublicKey)key().getPublicKey();MutableInteger y=new MutableInteger(real.getPoint().getY());MutableParameters parameters=new MutableParameters();MutablePublic supplied=new MutablePublic(new EdECPoint(real.getPoint().isXOdd(),y),parameters);supplied.algorithm=name;JwsSigner inert=signer(new RefusingPrivate(name),supplied);assertEquals(JwsAlgorithm.ED25519,inert.getAlgorithm());JwsSigner usable=signer(key().getPrivateKey(),supplied);y.changed=true;parameters.changed=true;supplied.point=new EdECPoint(false,BigInteger.ONE);supplied.algorithm="RSA";EdECPublicKey snapshot=(EdECPublicKey)usable.getPublicKey();assertEquals(real.getPoint().getY(),snapshot.getPoint().getY());assertEquals(BigInteger.class,snapshot.getPoint().getY().getClass());assertEquals(real.getPoint().isXOdd(),snapshot.getPoint().isXOdd());assertEquals("Ed25519",snapshot.getParams().getName());assertEquals("Ed25519",snapshot.getAlgorithm());assertNull(snapshot.getFormat());assertNull(snapshot.getEncoded());assertNotSame(snapshot.getPoint(),snapshot.getPoint());assertNotSame(snapshot.getParams(),snapshot.getParams());assertEquals(EdECPoint.class,snapshot.getPoint().getClass());assertEquals(NamedParameterSpec.class,snapshot.getParams().getClass());assertEquals("Ed25519PublicKey{material=<redacted>}",snapshot.toString());assertTrue(verify(usable.toCompactSerialization("JWT",null,null,"{}".getBytes(StandardCharsets.UTF_8),BUDGET),real));
  }));return tests;
 }
 @TestFactory @NonNull List<@NonNull DynamicTest> inspectablePrivateAlgorithmParametersAreCheckedWithoutReadingPrivateBytes(){
  List<DynamicTest> tests=new ArrayList<>();for(String parameter:List.of("Ed25519","Ed448","ed25519","X25519","throw","null"))tests.add(DynamicTest.dynamicTest("SIGN-03/private-params/"+parameter,()->{InspectPrivate input=new InspectPrivate(parameter);if(parameter.equals("Ed25519"))assertEquals(JwsAlgorithm.ED25519,signer(input,key().getPublicKey()).getAlgorithm());else assertThrows(IllegalArgumentException.class,()->construct(input,key().getPublicKey()));assertEquals(1,input.reads);}));return tests;
 }
 @TestFactory @NonNull List<@NonNull DynamicTest> actualPairAgreementAndIssuerIsolationArePreserved(){
  return List.of(DynamicTest.dynamicTest("SIGN-03/pair-mismatch",()->{KeyPair wrong=KeyPairGenerator.getInstance("Ed25519").generateKeyPair();JwsSigner signer=signer(wrong.getPrivate(),key().getPublicKey());assertEquals(JwsSigningException.Reason.KEY_PAIR_MISMATCH,assertThrows(JwsSigningException.class,()->signer.toCompactSerialization("JWT",null,null,"{}".getBytes(StandardCharsets.UTF_8),BUDGET)).getReason());assertEquals(JwsSigningException.Reason.KEY_PAIR_MISMATCH,assertThrows(JwsSigningException.class,()->signer.warmUp(BUDGET)).getReason());}),DynamicTest.dynamicTest("SIGN-03/issuer-rsa-only",()->assertThrows(IllegalArgumentException.class,()->OAuthIssuerSigningKey.fromRsaKeyPair("ed",key().getPrivateKey(),key().getPublicKey()))));
 }
 @TestFactory @NonNull List<@NonNull DynamicTest> genericClientAssertionDelegationUsesExactAdvertisedEd25519Metadata(){
  List<DynamicTest> tests=new ArrayList<>();for(String policy:List.of("match","legacy-alias","empty","exclude"))tests.add(DynamicTest.dynamicTest("SIGN-03/assertion-metadata/"+policy,()->{
   JwsSigner signer=signer(key().getPrivateKey(),key().getPublicKey());AtomicInteger reads=new AtomicInteger();ClientAuthentication auth=ClientAuthentication.fromPrivateKeyJwt(budget->{reads.incrementAndGet();return ClientAssertionSigningKey.withSigner(signer).keyId("ed").build();});try(TestHttpsServer server=TestHttpsServer.start()){
    Set<String> allowed=switch(policy){case "match"->Set.of("Ed25519");case "legacy-alias"->Set.of("EdDSA");case "empty"->Set.of();default->Set.of("RS256");};AuthorizationServerMetadata metadata=AuthorizationServerMetadata.withIssuer(server.getBaseUri().toString()).authorizationEndpoint(server.uri("/authorize")).tokenEndpoint(server.uri("/token")).tokenEndpointAuthMethodsSupported(Set.of("private_key_jwt")).tokenEndpointAuthSigningAlgValuesSupported(allowed).build();OAuthClient client=OAuthClient.withAuthorizationServerMetadata(metadata).clientId("ed-client").clientAuthentication(auth).httpClient(TestTls.httpClient()).clock(Clock.fixed(JwtFixtures.NOW,ZoneOffset.UTC)).build();assertEquals(0,reads.get());if(policy.equals("match")){server.script("/token",TestHttpsServer.Script.fromResponse(TestHttpsServer.Response.fromJson(200,"{\"access_token\":\"TEST-ONLY-ed\",\"token_type\":\"Bearer\",\"expires_in\":300}")));assertInstanceOf(OAuthTokenRequestResult.Succeeded.class,client.requestClientCredentialsResult(TokenRequestOptions.builder().build()));assertEquals(1,reads.get());assertEquals(1,server.getRequests().size());Map<String,String> form=new HashMap<>();var request=server.getRequests("/token").get(0);assertTrue(request.getHeader("Authorization").isEmpty());for(String field:request.getBodyAsString().split("&",-1)){String[] pair=field.split("=",2);assertNull(form.put(URLDecoder.decode(pair[0],StandardCharsets.UTF_8),URLDecoder.decode(pair[1],StandardCharsets.UTF_8)));}assertEquals("ed-client",form.get("client_id"));assertEquals("urn:ietf:params:oauth:client-assertion-type:jwt-bearer",form.get("client_assertion_type"));assertFalse(form.containsKey("client_secret"));String assertion=requireNonNull(form.get("client_assertion"));assertTrue(verify(assertion,key().getPublicKey()));JsonObject header=(JsonObject)JsonCodec.parse(Base64.getUrlDecoder().decode(assertion.split("\\.",-1)[0]),JsonLimits.jose(4096));assertEquals(JsonString.fromValue("Ed25519"),header.getMembers().get("alg"));}
    else{assertEquals(OAuthException.Reason.CLIENT_ASSERTION_ENDPOINT_MISMATCH,assertThrows(OAuthConfigurationException.class,()->client.requestClientCredentialsResult(TokenRequestOptions.builder().build())).getReason());assertEquals(policy.equals("empty")?0:1,reads.get());assertTrue(server.getRequests().isEmpty());}
   }
  }));return tests;
 }
 @TestFactory @NonNull List<@NonNull DynamicTest> providerShapeFailureDeadlineOwnershipAndErrorCasesRunInOwnedChildJvms(){
  List<DynamicTest> tests=new ArrayList<>();for(String mode:List.of("opaque","opaque-wrong-curve","zero-length","short","trailing","oversized","r-at-p","r-nondecoding","r-zero-x-sign","s-at-l","mismatch","late-init","late-update","late-sign","late-verify","throwing","throwing-verifier","vm-error","verify-vm-error","interrupt"))tests.add(DynamicTest.dynamicTest("SIGN-03/provider/"+mode,()->{ChildJvm.Result result=ChildJvm.withMainClass(JwsSignerEd25519TestProvider.class).arguments(List.of(mode)).build().run();assertEquals(0,result.getExitCode(),()->result.getStandardOutput()+result.getStandardError());assertEquals("scenario="+mode+" passed\n",result.getStandardOutput());assertFalse(result.isTimedOut());}));return tests;
 }
 @TestFactory @NonNull List<@NonNull DynamicTest> ed25519UsesTheExistingRawGrammarByteAndBudgetBoundaries(){
  List<DynamicTest> tests=new ArrayList<>();for(String cell:List.of("valid","exact-byte-limit","duplicate","array","bom","invalid-utf8","trailing-json","unpaired","over-byte-limit","wrong-type","key-id","digest","zero-budget","negative-budget"))tests.add(DynamicTest.dynamicTest("SIGN-03/raw-policy/"+cell,()->{
   JwsSigner signer=signer(key().getPrivateKey(),key().getPublicKey());String json=switch(cell){case "exact-byte-limit"->"{}"+" ".repeat(32766);case "over-byte-limit"->"{}"+" ".repeat(32767);case "duplicate"->"{\"x\":1,\"x\":2}";case "array"->"[]";case "bom"->"\uFEFF{}";case "trailing-json"->"{}x";case "unpaired"->"{\"x\":\"\\uD800\"}";default->"{}";};byte[] input=cell.equals("invalid-utf8")?new byte[]{(byte)0xc3,0x28}:json.getBytes(StandardCharsets.UTF_8),before=input.clone();String type=cell.equals("wrong-type")?"jwt":"JWT";@Nullable String kid=cell.equals("key-id")?"k".repeat(257):null;byte @Nullable [] digest=cell.equals("digest")?new byte[31]:null;Duration budget=cell.equals("zero-budget")?Duration.ZERO:cell.equals("negative-budget")?Duration.ofNanos(-1):BUDGET;
   if(cell.equals("valid")||cell.equals("exact-byte-limit")){String compact=signer.toCompactSerialization(type,kid,digest,input,budget);assertArrayEquals(input,Base64.getUrlDecoder().decode(compact.split("\\.",-1)[1]));assertTrue(verify(compact,key().getPublicKey()));}
   else if(cell.endsWith("budget"))assertEquals(JwsSigningException.Reason.BUDGET_EXHAUSTED,assertThrows(JwsSigningException.class,()->signer.toCompactSerialization(type,kid,digest,input,budget)).getReason());
   else assertThrows(IllegalArgumentException.class,()->signer.toCompactSerialization(type,kid,digest,input,budget));assertArrayEquals(before,input);
  }));return tests;
 }

 static @NonNull JwsSigner construct(@NonNull PrivateKey privateKey,@NonNull PublicKey publicKey){var method=assertDoesNotThrow(()->JwsSigner.class.getMethod("fromEd25519KeyPair",PrivateKey.class,PublicKey.class),"Selected Ed25519 signing factory must be available.");assertEquals(JwsSigner.class,method.getReturnType());try{return (JwsSigner)method.invoke(null,privateKey,publicKey);}catch(InvocationTargetException wrapped){Throwable cause=wrapped.getCause();if(cause instanceof RuntimeException runtime)throw runtime;if(cause instanceof Error error)throw error;throw new AssertionError("Unexpected checked Ed25519 factory failure");}catch(ReflectiveOperationException failure){throw new AssertionError("Ed25519 factory linkage failure");}}
 private static @NonNull JwsSigner signer(@NonNull PrivateKey privateKey,@NonNull PublicKey publicKey){return assertDoesNotThrow(()->construct(privateKey,publicKey),"Valid Ed25519 pair constructs without provider work.");}
 static TestJwk.@NonNull Fixture key(){return TestJwk.Fixture.ED25519;}
 static boolean verify(@NonNull String compact,@NonNull PublicKey publicKey)throws Exception{String[] pieces=compact.split("\\.",-1);Signature verifier=Signature.getInstance("Ed25519");verifier.initVerify(publicKey);verifier.update((pieces[0]+"."+pieces[1]).getBytes(StandardCharsets.US_ASCII));return verifier.verify(Base64.getUrlDecoder().decode(pieces[2]));}
 private static final class RefusingPrivate implements PrivateKey {private static final long serialVersionUID=1L;private final @NonNull String algorithm;private RefusingPrivate(@NonNull String algorithm){this.algorithm=algorithm;}@Override public @NonNull String getAlgorithm(){return this.algorithm;}@Override public @Nullable String getFormat(){throw new AssertionError("Private format inspected");}@Override public byte @Nullable [] getEncoded(){throw new AssertionError("Private encoded");}}
 private static final class InspectPrivate implements EdECPrivateKey {private static final long serialVersionUID=1L;private final @NonNull String parameter;private int reads;private InspectPrivate(@NonNull String parameter){this.parameter=parameter;}@Override public @NonNull String getAlgorithm(){return "EdDSA";}@Override public @NonNull NamedParameterSpec getParams(){this.reads++;if(this.parameter.equals("throw"))throw new IllegalStateException("TEST-ONLY-private-params");return this.parameter.equals("null")?nullValue():new NamedParameterSpec(this.parameter);}@Override public @NonNull Optional<byte @NonNull []> getBytes(){throw new AssertionError("Private bytes inspected");}@Override public @Nullable String getFormat(){throw new AssertionError("Private format inspected");}@Override public byte @Nullable [] getEncoded(){throw new AssertionError("Private encoded");}}
 private static final class MutablePublic implements EdECPublicKey {private static final long serialVersionUID=1L;@SuppressWarnings("serial")private @Nullable EdECPoint point;@SuppressWarnings("serial")private @Nullable NamedParameterSpec parameters;private @NonNull String algorithm="EdDSA";private int failure;private MutablePublic(@NonNull EdECPoint point,@NonNull NamedParameterSpec parameters){this.point=point;this.parameters=parameters;}@Override public @NonNull EdECPoint getPoint(){if(this.failure==1)throw new IllegalStateException("TEST-ONLY-public-point");return this.point==null?nullValue():this.point;}@Override public @NonNull NamedParameterSpec getParams(){if(this.failure==2)throw new IllegalStateException("TEST-ONLY-public-params");return this.parameters==null?nullValue():this.parameters;}@Override public @NonNull String getAlgorithm(){return this.algorithm;}@Override public @Nullable String getFormat(){throw new AssertionError("Public format inspected");}@Override public byte @Nullable [] getEncoded(){throw new AssertionError("Public encoded");}}
 private static final class MutableParameters extends NamedParameterSpec {private boolean changed;private MutableParameters(){super("Ed25519");}@Override public @NonNull String getName(){return this.changed?"Ed448":"Ed25519";}}
 private static final class MutableInteger extends BigInteger {private static final long serialVersionUID=1L;private boolean changed;private MutableInteger(@NonNull BigInteger value){super(value.toByteArray());}@Override public byte @NonNull [] toByteArray(){return this.changed?new byte[]{1}:super.toByteArray();}}
 private static final class ShapedInteger extends BigInteger {private static final long serialVersionUID=1L;private final int bits;private final byte @NonNull [] bytes;private ShapedInteger(int bits,byte @NonNull [] bytes){super("1");this.bits=bits;this.bytes=bytes.clone();}@Override public int bitLength(){return this.bits;}@Override public byte @NonNull [] toByteArray(){return this.bytes.clone();}}
 private static final class LyingInteger extends BigInteger {private static final long serialVersionUID=1L;private LyingInteger(){super("2");}@Override public int compareTo(@NonNull BigInteger other){return 0;}@Override public int signum(){return 1;}}
 @SuppressWarnings({"NullAway","TypeParameterUnusedInFormals"}) private static <T> @NonNull T nullValue(){return null;}
}
