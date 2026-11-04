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
import com.revetsec.*;
import com.revetsec.internal.crypto.*;
import org.jspecify.annotations.NonNull;
import org.junit.jupiter.api.*;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.*;
import static com.revetsec.internal.crypto.MigrationCodecTestSupport.*;
import static org.junit.jupiter.api.Assertions.*;

/** MIG-04 TTR1/TTR2 admin and normal TTR3 exact rejection matrix. */
final class TotpMigrationCorruptionConformanceTests {
 @Test void corpusAndAllApplicablePositiveControls()throws Exception{verifyCorpus();for(Spec s:specs("TOTP"))open(s,record(s,s.bytes(),"payload"));}
 @TestFactory @NonNull List<@NonNull DynamicTest> normalAuthenticatedCorruptions(){return corruptionTests(true);}
 @TestFactory @NonNull List<@NonNull DynamicTest> closedMigrationAuthenticatedCorruptions(){return corruptionTests(false);}
 private @NonNull List<@NonNull DynamicTest> corruptionTests(boolean normal){List<DynamicTest> tests=new ArrayList<>();for(Case c:cases("TOTP"))if((c.spec().format()==3)==normal)tests.add(DynamicTest.dynamicTest(c.name(),()->assertThrows(IOException.class,()->open(c.spec(),record(c.spec(),c.body(),c.op())))));return tests;}
 @TestFactory @NonNull List<@NonNull DynamicTest> authenticatedLegacyHasNoNormalFallback(){List<DynamicTest> tests=new ArrayList<>();for(Spec s:specs("TOTP"))if(s.format()<3)tests.add(DynamicTest.dynamicTest("MIG-04/no-fallback/"+s.name(),()->{var r=record(s,s.bytes(),"payload");open(s,r);assertThrows(IOException.class,()->new TotpRecordsV3(sealer()).open(r));}));return tests;}
 private static void open(@NonNull Spec s,@NonNull TotpStoreRecord r)throws Exception{
  if(s.format()==3){try(var decoded=new TotpRecordsV3(sealer()).open(r)){assertNotNull(decoded);}}
  else{var migration=new TotpMigrationV3(sealer());var intent=ClosedMigrationIntent.fromExternalIntent(s.get("migrationId"),StoreAdmission.fromIdentifiers(s.get("authority"),s.get("version")),Set.of(ClosedMigrationIntent.Format.TOTP_TTR3));var root=record(s,HexFormat.of().parseHex(s.get("rootPlain")),"root");if(r.getKey().getKind()==TotpStoreKey.Kind.NAMESPACE_STATE)migration.migrateNamespace(r,intent);else migration.migrateAccount(r,root,intent);}
 }
 private static @NonNull TotpStoreRecord record(@NonNull Spec s,byte @NonNull [] raw,@NonNull String op)throws Exception{
  boolean root=op.equals("root");var key=TotpStoreKey.fromStoredForm(root?s.get("rootKey"):s.get("key"));String context="revetsec/totp/durable/v"+(s.format()==3?"2:":"1:")+encode(TotpPrimitives.digest("revetsec/totp/address/v1",key.getStorageKey()));
  String text=encode(raw);if(op.startsWith("inner-")&&!op.equals("inner-invalid-utf8")){text=alter(text,op);}
  byte[] plaintext=op.equals("inner-invalid-utf8")?new byte[]{(byte)255}:text.getBytes(StandardCharsets.US_ASCII);
  String sealed=seal(op.equals("wrong-type")?SealedStateType.APP:SealedStateType.TOTP_RECORD,op.equals("wrong-context")?context+"x":context,Long.MAX_VALUE,plaintext,op.equals("outer-spare-bits"));if(op.startsWith("outer-"))sealed=alter(sealed,op);
  if(op.equals("wrong-key"))key=TotpStoreKey.forAccount("other","epoch","account");
  return TotpStoreRecord.fromStoredForm(key,op.equals("carrier-version")?"A".repeat(43):s.get("version"),sealed.getBytes(StandardCharsets.US_ASCII));
 }

}
