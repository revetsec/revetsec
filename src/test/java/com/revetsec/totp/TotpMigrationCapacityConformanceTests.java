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
import com.revetsec.internal.encoding.Base64Url;
import org.jspecify.annotations.NonNull;
import org.junit.jupiter.api.*;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.*;
import static org.junit.jupiter.api.Assertions.*;

/** MIG-05: logical limits, raw framing and opaque carrier capacities are distinct contracts. */
final class TotpMigrationCapacityConformanceTests {
 private static final @NonNull Instant TIME=Instant.ofEpochSecond(253402300799L,999999999);
 @TestFactory @NonNull List<@NonNull DynamicTest> durableRawAndCarrierBoundaries(){List<DynamicTest> tests=new ArrayList<>();
  for(int keyLength:List.of(1,64))for(int bytes:List.of(31999,32000,32001))tests.add(DynamicTest.dynamicTest("MIG-05/TOTP/raw/"+keyLength+"/"+bytes,()->{
   var sealer=sealer(keyLength);var key=TotpStoreKey.forNamespace("capacity","epoch");byte[] raw=pattern(bytes,31);String text=Base64Url.encode(raw);assertEquals((bytes*4+2)/3,text.length());String sealed=SealedStateAccess.get().sealDurable(sealer,text,context(key,true));assertEquals(((54+keyLength+text.length())*4+2)/3,sealed.length());assertEquals(text,SealedStateAccess.get().unsealDurable(sealer,sealed,context(key,true)));assertEquals(3800,SealedStateAccess.get().getMaximumSealedLength(sealer));if(bytes==32000 && keyLength==64){assertEquals(42667,text.length());assertEquals(57047,sealed.length());}
   // Arbitrary raw bytes are not an admissible account at either side of the framing bound.
   var row=TotpStoreRecord.fromStoredForm(key,id(1),sealed.getBytes(StandardCharsets.US_ASCII));assertThrows(IOException.class,()->new TotpRecordsV3(sealer).open(row));
  }));
  for(int keyLength:List.of(1,64))for(int chars:List.of(47999,48000,48001))tests.add(DynamicTest.dynamicTest("MIG-05/TOTP/durable-text/"+keyLength+"/"+chars,()->{var s=sealer(keyLength);String text="A".repeat(chars),context=context(TotpStoreKey.forNamespace("capacity","epoch"),true);if(chars<=48000){String sealed=SealedStateAccess.get().sealDurable(s,text,context);assertEquals(((54+keyLength+chars)*4+2)/3,sealed.length());assertEquals(text,SealedStateAccess.get().unsealDurable(s,sealed,context));}else assertThrows(IllegalArgumentException.class,()->SealedStateAccess.get().sealDurable(s,text,context));}));
  for(int length:List.of(65535,65536,65537))tests.add(DynamicTest.dynamicTest("MIG-05/TOTP/carrier/"+length,()->{byte[] raw=pattern(length,3);var key=TotpStoreKey.forNamespace("capacity","epoch");if(length<=65536){var row=TotpStoreRecord.fromStoredForm(key,id(1),raw);assertArrayEquals(raw,row.getSealedBytes());}else assertThrows(IllegalArgumentException.class,()->TotpStoreRecord.fromStoredForm(key,id(1),raw));}));return tests;
 }
 @TestFactory @NonNull List<@NonNull DynamicTest> legacyRawWriterCeilingDoesNotGrantLogicalAdmission(){List<DynamicTest> tests=new ArrayList<>();for(int keyLength:List.of(1,64))for(int target:List.of(31999,32000,32001))tests.add(DynamicTest.dynamicTest("MIG-05/TOTP/legacy-raw-writer/"+keyLength+"/"+target,()->{
  var s=sealer(keyLength);var codec=new TotpRecords(s);int count=530;String account="a";var initial=new TotpRecords.Account(account,id(1),TIME);for(int n=0;n<count;n++)initial.totpCharges.add(new TotpRecords.Charge(id(n+20),TIME));var key=TotpStoreKey.forAccount("capacity","epoch",account);int measured=plain(s,codec.seal(key,new TotpRecords.Namespace(TIME),initial),false).length;int padding=target-measured;assertTrue(padding>=0 && padding<1024);account="a".repeat(1+padding);var state=new TotpRecords.Account(account,id(1),TIME);state.totpCharges.addAll(initial.totpCharges);var actualKey=TotpStoreKey.forAccount("capacity","epoch",account);
  try{if(target<=32000){var row=codec.seal(actualKey,new TotpRecords.Namespace(TIME),state);assertEquals(target,plain(s,row,false).length);assertThrows(IOException.class,()->codec.open(row));}else assertThrows(IllegalArgumentException.class,()->codec.seal(actualKey,new TotpRecords.Namespace(TIME),state));assertEquals(count,state.totpCharges.size());assertEquals(account,state.accountId);}finally{state.erase();initial.erase();}
 }));return tests;}
 @TestFactory @NonNull List<@NonNull DynamicTest> exactLegalTextAndCountBoundaries(){List<DynamicTest> tests=new ArrayList<>();
  for(int format:List.of(1,2,3))for(int keyLength:List.of(1,64))for(String width:List.of("ascii","utf8"))for(int length:List.of(1023,1024,1025))tests.add(DynamicTest.dynamicTest("MIG-05/TOTP/account-text/"+format+"/"+keyLength+"/"+width+"/"+length,()->{String name=width.equals("ascii")?"a".repeat(length):"é".repeat(length/2)+(length%2==0?"":"a");assertEquals(length,name.getBytes(StandardCharsets.UTF_8).length);if(length>1024)assertThrows(IllegalArgumentException.class,()->TotpStoreKey.forAccount("n".repeat(128),"e".repeat(128),name));else roundTrip(format,keyLength,name,10,5,10);}));
  for(int format:List.of(1,2,3))for(int keyLength:List.of(1,64))for(String field:List.of("recovery","short","daily"))if(format!=1 || !field.equals("daily"))for(int delta:List.of(-1,0,1))tests.add(DynamicTest.dynamicTest("MIG-05/TOTP/count/"+format+"/"+keyLength+"/"+field+"/"+delta,()->roundTrip(format,keyLength,"a".repeat(1024),field.equals("recovery")?10+delta:10,field.equals("short")?5+delta:5,field.equals("daily")?10+delta:10)));
  for(int n:List.of(127,128,129))for(boolean namespace:List.of(false,true))tests.add(DynamicTest.dynamicTest("MIG-05/TOTP/scope/"+namespace+"/"+n,()->{if(n<=128){var key=TotpStoreKey.forNamespace(namespace?"n".repeat(n):"n",namespace?"e":"e".repeat(n));assertEquals(key,TotpStoreKey.fromStoredForm(key.getStorageKey()));}else assertThrows(IllegalArgumentException.class,()->TotpStoreKey.forNamespace(namespace?"n".repeat(n):"n",namespace?"e":"e".repeat(n)));}));return tests;
 }
 private static void roundTrip(int format,int keyLength,@NonNull String name,int hashes,int shortCount,int daily)throws Exception{
  var s=sealer(keyLength);var key=TotpStoreKey.forAccount("n".repeat(128),"e".repeat(128),name);var root=TotpStoreKey.forNamespace("n".repeat(128),"e".repeat(128));var state=state(name,hashes,shortCount,daily);boolean fits=hashes<=10 && shortCount<=5 && daily<=10;
  try{
   var legacy=new TotpRecords(s);var row=legacy.seal(key,new TotpRecords.Namespace(TIME),state);byte[] raw=plain(s,row,false);if(format==1){raw=Arrays.copyOf(raw,raw.length-4-59*daily);ByteBuffer.wrap(raw).putInt(0x54545231);}else if(format==3)ByteBuffer.wrap(raw).putInt(0x54545233);
   assertEquals(expectedRaw(key,name,hashes,shortCount,format==1?-1:daily),raw.length);var input=TotpStoreRecord.fromStoredForm(key,row.getVersion(),SealedStateAccess.get().sealDurable(s,Base64Url.encode(raw),context(key,format==3)).getBytes(StandardCharsets.US_ASCII));
   if(!fits){if(format==3){assertThrows(IllegalArgumentException.class,()->new TotpRecordsV3(s).sealAccount(key,state));assertThrows(IOException.class,()->new TotpRecordsV3(s).open(input));}else assertThrows(IOException.class,()->legacy.open(input));}
   else{
    TotpStoreRecord output=input;if(format<3){byte[] rootRaw=plain(s,legacy.seal(root,new TotpRecords.Namespace(TIME),null),false);if(format==1)ByteBuffer.wrap(rootRaw).putInt(0x54545231);var oldRoot=TotpStoreRecord.fromStoredForm(root,id(7),SealedStateAccess.get().sealDurable(s,Base64Url.encode(withHeaderVersion(rootRaw,root,id(7))),context(root,false)).getBytes(StandardCharsets.US_ASCII));output=new TotpMigrationV3(s).migrateAccount(input,oldRoot,intent());}
    else output=new TotpRecordsV3(s).sealAccount(key,state);
    try(var decoded=new TotpRecordsV3(s).open(output)){var account=Objects.requireNonNull(decoded.account);assertEquals(name,account.accountId);assertEquals(hashes,account.recoveryHashes.size());assertEquals(shortCount,account.charges.size());assertEquals(format==1?shortCount:daily,account.totpCharges.size());assertEquals(Long.MAX_VALUE,Objects.requireNonNull(account.active).usedStep);assertArrayEquals(pattern(20,3),Objects.requireNonNull(account.active).secret);assertArrayEquals(pattern(32,5),Objects.requireNonNull(account.pending).browserHash);assertEquals(TIME,account.observedAt);}
   }
   assertEquals(hashes,state.recoveryHashes.size());assertEquals(shortCount,state.charges.size());assertEquals(daily,state.totpCharges.size());assertArrayEquals(pattern(20,3),Objects.requireNonNull(state.active).secret);
  }finally{state.erase();}
 }
 private static int expectedRaw(@NonNull TotpStoreKey key,@NonNull String account,int hashes,int charges,int daily){return 55+key.getStorageKey().getBytes(StandardCharsets.UTF_8).length+65+account.getBytes(StandardCharsets.UTF_8).length+91+213+47+4+36*hashes+4+59*charges+(daily<0?0:4+59*daily);}
 private static TotpRecords.@NonNull Account state(@NonNull String account,int hashes,int charges,int daily){var s=new TotpRecords.Account(account,id(1),TIME);s.active=new TotpRecords.Active(id(2),pattern(20,3),TIME,Long.MAX_VALUE);s.pending=new TotpRecords.Pending(id(3),id(4),pattern(20,4),pattern(32,5),TIME,id(2));s.batchId=id(5);for(int n=0;n<hashes;n++)s.recoveryHashes.add(pattern(32,n));for(int n=0;n<charges;n++)s.charges.add(new TotpRecords.Charge(id(n+100),TIME));for(int n=0;n<daily;n++)s.totpCharges.add(new TotpRecords.Charge(id(n+200),TIME));return s;}
 private static @NonNull ClosedMigrationIntent intent(){return ClosedMigrationIntent.fromExternalIntent(id(7),StoreAdmission.fromIdentifiers(id(8),id(9)),Set.of(ClosedMigrationIntent.Format.TOTP_TTR3));}
 private static byte @NonNull [] withHeaderVersion(byte @NonNull [] raw,@NonNull TotpStoreKey key,@NonNull String version){byte[] b=raw.clone();System.arraycopy(version.getBytes(StandardCharsets.US_ASCII),0,b,12+key.getStorageKey().length(),43);return b;}
 private static byte @NonNull [] plain(@NonNull StateSealer s,@NonNull TotpStoreRecord row,boolean next)throws Exception{return Base64Url.decode(SealedStateAccess.get().unsealDurable(s,new String(row.getSealedBytes(),StandardCharsets.US_ASCII),context(row.getKey(),next)));}
 private static @NonNull String context(@NonNull TotpStoreKey key,boolean next){return "revetsec/totp/durable/v"+(next?"2:":"1:")+Base64Url.encode(TotpPrimitives.digest("revetsec/totp/address/v1",key.getStorageKey()));}
 private static @NonNull StateSealer sealer(int keyLength){return StateSealer.withActiveKey(SealingKey.fromBase64("k".repeat(keyLength),"AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA=")).build();}
 private static @NonNull String id(int n){return Base64Url.encode(ByteBuffer.allocate(32).putInt(n).array());}
 private static byte @NonNull [] pattern(int length,int value){byte[] b=new byte[length];Arrays.fill(b,(byte)value);return b;}
 @TestFactory @NonNull List<@NonNull DynamicTest> cap06PromotionHistoryRootAndKeyGrowth(){
  List<DynamicTest> tests=new ArrayList<>();
  for(int format:List.of(1,2))for(int scope:List.of(1,128))for(String width:List.of("ascii","utf8"))for(boolean full:List.of(false,true))for(int targetKeyLength:List.of(1,64))
   tests.add(DynamicTest.dynamicTest("CAP-06/"+format+"/"+scope+"/"+width+"/"+full+"/"+targetKeyLength,()->{
    String name=width.equals("ascii")?"a".repeat(1024):"é".repeat(512);var root=TotpStoreKey.forNamespace("n".repeat(scope),"e".repeat(scope));var key=TotpStoreKey.forAccount("n".repeat(scope),"e".repeat(scope),name);
    var oldSealer=sealer(1);var legacy=new TotpRecords(oldSealer);var state=full?state(name,10,5,10):new TotpRecords.Account(name,id(1),TIME);
    try{
     var oldRoot=legacy.seal(root,new TotpRecords.Namespace(TIME),null);var oldAccount=legacy.seal(key,new TotpRecords.Namespace(TIME),state);byte[] rootRaw=plain(oldSealer,oldRoot,false),accountRaw=plain(oldSealer,oldAccount,false);byte[] canonical=accountRaw.clone();
     if(format==1){accountRaw=Arrays.copyOf(accountRaw,accountRaw.length-4-59*(full?10:0));ByteBuffer.wrap(accountRaw).putInt(0x54545231);ByteBuffer.wrap(rootRaw).putInt(0x54545231);oldRoot=cap06Legacy(oldSealer,oldRoot,rootRaw);oldAccount=cap06Legacy(oldSealer,oldAccount,accountRaw);}
     byte[] sourceRoot=oldRoot.getSealedBytes(),sourceAccount=oldAccount.getSealedBytes();
     var active=SealingKey.fromBase64("r".repeat(targetKeyLength),"ISIjJCUmJygpKissLS4vMDEyMzQ1Njc4OTo7PD0+P0A=");var targetSealer=StateSealer.withActiveKey(active).verificationKeys(List.of(SealingKey.fromBase64("k","AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA="))).build();
     var migration=new TotpMigrationV3(targetSealer);var migratedRoot=migration.migrateNamespace(oldRoot,intent());var migrated=migration.migrateAccount(oldAccount,oldRoot,intent());byte[] newRoot=plain(targetSealer,migratedRoot,true),newAccount=plain(targetSealer,migrated,true);
     assertEquals(47,newRoot.length-rootRaw.length);assertEquals(format==1?4+59*(full?5:0):0,newAccount.length-accountRaw.length);assertTrue(newRoot.length<=544);assertTrue(newAccount.length<=3182);
     // Complete independent binary oracle: format one duplicates the exact short-list
     // bytes into its new daily list; format two preserves the original daily suffix.
     byte[] expected=canonical;
     if(format==1){int shortBytes=59*(full?5:0);int end=accountRaw.length;expected=Arrays.copyOf(accountRaw,end+4+shortBytes);ByteBuffer.wrap(expected,end,4).putInt(full?5:0);System.arraycopy(accountRaw,end-shortBytes,expected,end+4,shortBytes);}
     ByteBuffer.wrap(expected).putInt(0x54545233);expected=withHeaderVersion(expected,key,migrated.getVersion());assertArrayEquals(expected,newAccount);
     var buffer=new java.io.ByteArrayOutputStream();buffer.write(rootRaw,0,rootRaw.length-12);var out=new java.io.DataOutputStream(buffer);byte[] authority=intent().getTargetAdmission().getAuthorityId().getBytes(StandardCharsets.US_ASCII);out.writeInt(authority.length);out.write(authority);out.write(rootRaw,rootRaw.length-12,12);out.flush();var expectedRoot=buffer.toByteArray();ByteBuffer.wrap(expectedRoot).putInt(0x54545233);assertArrayEquals(withHeaderVersion(expectedRoot,root,migratedRoot.getVersion()),newRoot);
     for(var row:List.of(migratedRoot,migrated)){
      int raw=plain(targetSealer,row,true).length,wire=(4*(54+targetKeyLength+(4*raw+2)/3)+2)/3,sql=(4*wire+2)/3;assertEquals(wire,row.getSealedBytes().length);assertEquals(sql,Base64Url.encode(row.getSealedBytes()).length());assertTrue(wire<=65536);assertTrue(sql<=87382);
      int k1=(4*(55+(4*raw+2)/3)+2)/3,k64=(4*(118+(4*raw+2)/3)+2)/3;assertEquals(84,k64-k1);assertTrue(wire<=k64);
     }
     try(var decoded=new TotpRecordsV3(targetSealer).open(migrated)){var a=Objects.requireNonNull(decoded.account);assertEquals(TIME,a.observedAt);assertEquals(full?5:0,a.charges.size());assertEquals(full?(format==1?5:10):0,a.totpCharges.size());}
     assertArrayEquals(sourceRoot,oldRoot.getSealedBytes());assertArrayEquals(sourceAccount,oldAccount.getSealedBytes());assertNotEquals(oldRoot.getVersion(),migratedRoot.getVersion());assertNotEquals(oldAccount.getVersion(),migrated.getVersion());assertEquals(full?5:0,state.charges.size());assertEquals(full?10:0,state.totpCharges.size());
    }finally{state.erase();}
   }));return tests;
 }
 private static @NonNull TotpStoreRecord cap06Legacy(@NonNull StateSealer sealer,@NonNull TotpStoreRecord source,byte @NonNull [] raw){return TotpStoreRecord.fromStoredForm(source.getKey(),source.getVersion(),SealedStateAccess.get().sealDurable(sealer,Base64Url.encode(raw),context(source.getKey(),false)).getBytes(StandardCharsets.US_ASCII));}

}
