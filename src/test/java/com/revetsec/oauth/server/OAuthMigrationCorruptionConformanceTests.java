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

package com.revetsec.oauth.server;
import com.revetsec.*;
import com.revetsec.internal.crypto.*;
import org.jspecify.annotations.NonNull;
import org.junit.jupiter.api.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
import static com.revetsec.internal.crypto.MigrationCodecTestSupport.*;
import static org.junit.jupiter.api.Assertions.*;

/** MIG-04 authenticated malformed outer1 admin/outer2 native records, including every status-specific schema. */
final class OAuthMigrationCorruptionConformanceTests {
 @Test void corpusAndAllApplicablePositiveControls()throws Exception{verifyCorpus();for(Spec s:specs("ISSUER"))open(s,record(s,s.bytes(),"payload"));}
 @TestFactory @NonNull List<@NonNull DynamicTest> normalAuthenticatedCorruptions(){return corruptionTests(true);}
 @TestFactory @NonNull List<@NonNull DynamicTest> closedMigrationAuthenticatedCorruptions(){return corruptionTests(false);}
 private @NonNull List<@NonNull DynamicTest> corruptionTests(boolean normal){List<DynamicTest> tests=new ArrayList<>();for(Case c:cases("ISSUER"))if((c.spec().format()==2)==normal)tests.add(DynamicTest.dynamicTest(c.name(),()->assertThrows(IllegalArgumentException.class,()->open(c.spec(),record(c.spec(),c.body(),c.op())))));return tests;}
 @TestFactory @NonNull List<@NonNull DynamicTest> authenticatedLegacyHasNoNormalFallback(){List<DynamicTest> tests=new ArrayList<>();for(Spec s:specs("ISSUER"))if(s.format()==1)tests.add(DynamicTest.dynamicTest("MIG-04/no-fallback/"+s.name(),()->{var old=record(s,s.bytes(),"payload");open(s,old);assertThrows(IllegalArgumentException.class,()->target(s).open(old,CLOCK));}));return tests;}
 private static @NonNull OAuthStoreRecordCodecV2 target(@NonNull Spec s){return new OAuthStoreRecordCodecV2(s.get("issuer"),sealer(),16384,OAuthServerIngressLimits.fromDefaults(),1024);}
 private static void open(@NonNull Spec s,@NonNull OAuthStoreEntry r)throws Exception{
  var target=target(s);if(s.format()==2){assertNotNull(target.open(r,CLOCK));return;}
  var intent=ClosedMigrationIntent.fromExternalIntent(s.get("migrationId"),StoreAdmission.fromIdentifiers(s.get("authority"),s.get("recovery")),Set.of(ClosedMigrationIntent.Format.ISSUER_SCHEMA2));var migration=new OAuthStoreMigrationCodec(target,16384,intent);
  String rootPayload=new String(HexFormat.of().parseHex(s.get("rootPlain")),StandardCharsets.UTF_8);String rootVersion=s.get("version"),rootKey=s.get("rootKey");
  String root="{\"schema\":1,\"issuer\":\""+s.get("issuer")+"\",\"key\":\""+rootKey+"\",\"version\":\""+rootVersion+"\",\"retainUntil\":"+OAuthStoreFormat.PERMANENT.getEpochSecond()+",\"payload\":"+rootPayload+"}";
  var entry=OAuthStoreEntry.fromStoredForm(OAuthStoreKey.fromStoredForm(rootKey),rootVersion,OAuthStoreFormat.PERMANENT,seal(SealedStateType.AS_RECORD,"revetsec/as-record/v1:"+rootKey,OAuthStoreFormat.PERMANENT.getEpochSecond(),root.getBytes(StandardCharsets.UTF_8),false));
  if(r.getKey().getKind()==OAuthStoreKey.Kind.ISSUER_STATE)migration.convert(r,migration.openRoot(r));else migration.convert(r,migration.openRoot(entry));
 }
 private static @NonNull OAuthStoreEntry record(@NonNull Spec s,byte @NonNull [] raw,@NonNull String op)throws Exception{
  String key=s.get("key"),context="revetsec/as-record/v"+s.format()+":"+key;long retention=Long.parseLong(s.get("retain"));
  String sealed=seal(op.equals("wrong-type")?SealedStateType.APP:SealedStateType.AS_RECORD,op.equals("wrong-context")?context+"x":context,retention,raw,op.equals("outer-spare-bits"));if(op.startsWith("outer-"))sealed=alter(sealed,op);
  if(op.equals("wrong-key"))key=s.get("rootKey").replace(":ISSUER_STATE:",":SUBJECT_STATE:");
  return OAuthStoreEntry.fromStoredForm(OAuthStoreKey.fromStoredForm(key),s.get("version"),java.time.Instant.ofEpochSecond(retention),sealed);
 }
}
