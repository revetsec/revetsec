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
import org.jspecify.annotations.Nullable;
import org.jspecify.annotations.NonNull;
import com.revetsec.StateSealer;
import com.revetsec.json.*;
import example.migration.CodecSupport;
import java.time.Instant;
import java.io.*;
import java.nio.charset.StandardCharsets;
import com.revetsec.internal.crypto.SealedStateAccess;
import com.revetsec.internal.crypto.TotpPrimitives;
import java.util.*;
import static example.migration.CodecSupport.*;

/** Synthetic source-bound fixtures written by the exact frozen legacy core, never target codec code. */
public final class FrozenTotpWriter {
 private FrozenTotpWriter(){}
 public static void main(@NonNull String @NonNull [] args)throws Exception{CodecSupport.fixtureMain(args,FrozenTotpWriter::fixtures);}
 private static @NonNull JsonArray fixtures(@NonNull JsonObject config)throws Exception{
  var codec=new TotpRecords(sealer(config));@NonNull String scope=text(config,"totpScope");@NonNull List<@NonNull JsonValue> rows=new ArrayList<>();@NonNull Instant minimum=Instant.ofEpochSecond(number(config,"minimumSeconds",1700000000),number(config,"minimumNanos",999999999));
  for(int epoch=1;epoch<=2;epoch++){
   @NonNull String recovery=epoch==1?"old-one":"old-two";var root=TotpStoreKey.forNamespace("migration",recovery);rows.add(row(scope,codec.seal(root,new TotpRecords.Namespace(minimum),null)));
   for(int index=0;index<3;index++){
    @NonNull String name="account-"+epoch+"-"+index;var account=new TotpRecords.Account(name,identifier(20+index),minimum.minusNanos(index));
    if(index<2){account.active=new TotpRecords.Active(identifier(30+index),pattern(20,7),minimum.minusSeconds(600),56789012L+index);account.batchId=identifier(40+index);account.recoveryHashes.add(pattern(32,9));account.recoveryHashes.add(pattern(32,10));account.pending=new TotpRecords.Pending(identifier(50+index),identifier(60+index),pattern(20,11),pattern(32,12),minimum.plusSeconds(300),account.active.factorId);}
    account.charges.add(new TotpRecords.Charge(identifier(70+index),minimum.minusSeconds(10)));account.totpCharges.add(new TotpRecords.Charge(identifier(80+index),minimum.minusSeconds(20)));
    try{rows.add(row(scope,codec.seal(TotpStoreKey.forAccount("migration",recovery,name),new TotpRecords.Namespace(minimum),account)));}finally{account.erase();}
   }
  }
  rows.add(row(scope,ttr1(config)));
  if(number(config,"totpCapacityCorpus",0)==1)rows.addAll(capacityRows(config));
  return JsonArray.fromElements(rows);
 }
 private static @NonNull List<@NonNull JsonValue> capacityRows(@NonNull JsonObject config)throws Exception{
  var result=new ArrayList<@NonNull JsonValue>();var sealer=sealer(config);var codec=new TotpRecords(sealer);Instant minimum=Instant.ofEpochSecond(number(config,"minimumSeconds"),number(config,"minimumNanos"));
  for(int format:List.of(1,2))for(boolean full:List.of(false,true))for(boolean utf8:List.of(false,true)){
   String prefix="cap06-"+format+"-"+full+"-"+utf8+"-";int left=1024-prefix.length();String name=prefix+(utf8?"é".repeat(left/2)+(left%2==0?"":"a"):"a".repeat(left));
   var key=TotpStoreKey.forAccount("migration","old-one",name);var account=new TotpRecords.Account(name,identifier(100),minimum.minusNanos(1));
   if(full){account.active=new TotpRecords.Active(identifier(101),pattern(20,7),minimum.minusSeconds(600),Long.MAX_VALUE);account.pending=new TotpRecords.Pending(identifier(102),identifier(103),pattern(20,8),pattern(32,9),minimum.plusSeconds(300),account.active.factorId);account.batchId=identifier(104);for(int i=0;i<10;i++)account.recoveryHashes.add(pattern(32,20+i));for(int i=0;i<5;i++)account.charges.add(new TotpRecords.Charge(identifier(110+i),minimum.minusSeconds(i+1)));for(int i=0;i<10;i++)account.totpCharges.add(new TotpRecords.Charge(identifier(120+i),minimum.minusSeconds(i+1)));}
   try{
    var source=codec.seal(key,new TotpRecords.Namespace(minimum),account);
    if(format==1){byte[] digest=TotpPrimitives.digest("revetsec/totp/address/v1",key.getStorageKey());String context="revetsec/totp/durable/v1:"+b64(digest);byte[] plain=bytes(SealedStateAccess.get().unsealDurable(sealer,new String(source.getSealedBytes(),StandardCharsets.US_ASCII),context));byte[] shortened=Arrays.copyOf(plain,plain.length-4-59*(full?10:0));java.nio.ByteBuffer.wrap(shortened).putInt(0x54545231);try{source=TotpStoreRecord.fromStoredForm(key,source.getVersion(),SealedStateAccess.get().sealDurable(sealer,b64(shortened),context).getBytes(StandardCharsets.US_ASCII));}finally{Arrays.fill(digest,(byte)0);Arrays.fill(plain,(byte)0);Arrays.fill(shortened,(byte)0);}}
    // Independently require the frozen reader to admit the old frame and promotion.
    try(var opened=codec.open(source)){var old=Objects.requireNonNull(opened.account);if(old.charges.size()!=(full?5:0)||old.totpCharges.size()!=(full?(format==1?5:10):0))throw new IllegalArgumentException("Legacy capacity fixture mismatch");}
    result.add(row(text(config,"totpScope"),source));
   }finally{account.erase();}
  }return result;
 }
 private static @NonNull TotpStoreRecord ttr1(@NonNull JsonObject config)throws Exception{
  var key=TotpStoreKey.forAccount("migration","old-one","ttr1-promoted");@NonNull String version=identifier(91);@NonNull Instant minimum=Instant.ofEpochSecond(number(config,"minimumSeconds",1700000000),number(config,"minimumNanos",999999999));
  @NonNull ByteArrayOutputStream buffer=new ByteArrayOutputStream();try(@NonNull DataOutputStream out=new DataOutputStream(buffer)){
   out.writeInt(0x54545231);textValue(out,key.getStorageKey());textValue(out,version);textValue(out,"ttr1-promoted");textValue(out,identifier(92));out.writeLong(minimum.getEpochSecond());out.writeInt(minimum.getNano());out.writeBoolean(false);out.writeBoolean(false);textValue(out,"");out.writeInt(0);out.writeInt(1);textValue(out,identifier(93));out.writeLong(minimum.minusSeconds(2).getEpochSecond());out.writeInt(minimum.getNano());
  }
  byte @NonNull [] plain=buffer.toByteArray(),digest=TotpPrimitives.digest("revetsec/totp/address/v1",key.getStorageKey());try{@NonNull String sealed=SealedStateAccess.get().sealDurable(sealer(config),b64(plain),"revetsec/totp/durable/v1:"+b64(digest));return TotpStoreRecord.fromStoredForm(key,version,sealed.getBytes(StandardCharsets.US_ASCII));}finally{Arrays.fill(plain,(byte)0);Arrays.fill(digest,(byte)0);buffer.reset();}
 }
 private static void textValue(@NonNull DataOutputStream out,@NonNull String value)throws IOException{byte @NonNull [] b=value.getBytes(StandardCharsets.UTF_8);out.writeInt(b.length);out.write(b);Arrays.fill(b,(byte)0);}
 private static @NonNull JsonObject row(@NonNull String scope,@NonNull TotpStoreRecord value){@NonNull String key=value.getKey().getStorageKey();return JsonObject.builder().put("family","TOTP").put("scope",scope).put("handle",hash("TOTP\0"+scope+'\0'+key)).put("key",key).put("version",value.getVersion()).put("ciphertext",b64(value.getSealedBytes())).put("retention",instant(Instant.ofEpochSecond(Instant.MAX.getEpochSecond()))).build();}
 private static byte @NonNull [] pattern(int n,int shift){byte @NonNull [] b=new byte[n];for(int i=0;i<n;i++)b[i]=(byte)(i+shift);return b;}
}

