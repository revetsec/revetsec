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

package example.migration;

import org.jspecify.annotations.Nullable;
import org.jspecify.annotations.NonNull;
import com.revetsec.SealingKey;
import com.revetsec.StateSealer;
import com.revetsec.json.*;
import com.revetsec.internal.json.JsonCodec;
import com.revetsec.internal.json.JsonLimits;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.*;
import java.time.*;
import java.util.*;

/** Private administrative transport. No plaintext is emitted to files or ordinary output. */
public final class CodecSupport {
 private CodecSupport() { }
 public interface Processor { @NonNull JsonArray run(@NonNull JsonObject input) throws Exception; }
 public static void main(@NonNull String @NonNull [] args, @NonNull Processor processor) throws Exception { run(args,processor,"decisions"); }
 public static void fixtureMain(@NonNull String @NonNull [] args, @NonNull Processor processor) throws Exception { run(args,processor,"rows"); }
 private static void run(@NonNull String @NonNull [] args, @NonNull Processor processor,@NonNull String label) throws Exception {
  if(args.length!=2) throw new IllegalArgumentException("Expected protected input/output paths");
  @NonNull Path in=Path.of(args[0]),out=Path.of(args[1]);
  if(!Files.getPosixFilePermissions(in).equals(PosixFilePermissions.fromString("rw-------"))) throw new IllegalArgumentException("Input is not private");
  if(Files.size(in)>4_194_304) throw new IllegalArgumentException("Input too large");
  byte @NonNull [] encoded=Files.readAllBytes(in);@NonNull JsonObject input;
  try {input=(JsonObject)JsonCodec.parse(encoded,JsonLimits.protocolDocument(4_194_304));}finally{Arrays.fill(encoded,(byte)0);}
  @NonNull String origin=HexFormat.of().formatHex(bytes(hash(Files.readAllBytes(Path.of(StateSealer.class.getProtectionDomain().getCodeSource().getLocation().toURI())))));
  if(!origin.equals(text(input,"expectedCoreSha256")))throw new IllegalArgumentException("Artifact origin mismatch");
  @NonNull JsonArray decisions=processor.run(input);
  write(out,JsonObject.builder().put(label,decisions).put("coreOriginSha256",origin).build());
  System.out.println("CODEC_OK rows="+decisions.getElements().size());
 }
 public static void write(@NonNull Path out,@NonNull JsonObject object)throws IOException{
  @NonNull Path parent=out.toAbsolutePath().getParent();Files.createDirectories(parent);@NonNull Path tmp=Files.createTempFile(parent,"protected-codec-",".tmp",PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------")));
  try {byte @NonNull [] bytes=object.toJson().getBytes(StandardCharsets.UTF_8);try{Files.write(tmp,bytes);}finally{Arrays.fill(bytes,(byte)0);}Files.move(tmp,out,StandardCopyOption.ATOMIC_MOVE,StandardCopyOption.REPLACE_EXISTING);}finally{Files.deleteIfExists(tmp);}
 }
 public static @NonNull String text(@NonNull JsonObject o,@NonNull String n){return ((JsonString)o.find(n).orElseThrow()).getValue();}
 public static long number(@NonNull JsonObject o,@NonNull String n){return ((JsonNumber)o.find(n).orElseThrow()).getValue().longValueExact();}
 public static long number(@NonNull JsonObject o,@NonNull String n,long fallback){return o.find(n).isEmpty()?fallback:number(o,n);}
 public static @NonNull List<@NonNull JsonObject> rows(@NonNull JsonObject o,@NonNull String name){return ((JsonArray)o.find(name).orElseThrow()).getElements().stream().map(x->(JsonObject)x).toList();}
 public static @NonNull JsonObject instant(@NonNull Instant v){return JsonObject.builder().put("epochSecond",v.getEpochSecond()).put("nano",(long)v.getNano()).build();}
 public static @NonNull Instant instant(@NonNull JsonObject o){long nano=number(o,"nano");if(nano<0||nano>999999999)throw new IllegalArgumentException("Invalid instant");return Instant.ofEpochSecond(number(o,"epochSecond"),nano);}
 public static byte @NonNull [] bytes(@NonNull String v){byte @NonNull [] a=Base64.getUrlDecoder().decode(v);if(!b64(a).equals(v))throw new IllegalArgumentException("Noncanonical encoding");return a;}
 public static @NonNull String b64(byte @NonNull [] a){return Base64.getUrlEncoder().withoutPadding().encodeToString(a);}
 public static @NonNull String hash(byte @NonNull [] a){try{return b64(MessageDigest.getInstance("SHA-256").digest(a));}catch(NoSuchAlgorithmException e){throw new IllegalStateException(e);}}
 public static @NonNull String hash(@NonNull String a){return hash(a.getBytes(StandardCharsets.UTF_8));}
 public static @NonNull String rootCommitment(@NonNull JsonObject row){return hash(text(row,"key")+'\0'+text(row,"version")+'\0'+text(row,"ciphertext"));}
 public static @NonNull JsonObject row(@NonNull JsonObject previous,byte @NonNull [] version,byte @NonNull [] ciphertext,@NonNull Instant retention){return JsonObject.builder().put("family",text(previous,"family")).put("scope",text(previous,"scope")).put("handle",text(previous,"handle")).put("key",text(previous,"key")).put("version",b64(version)).put("ciphertext",b64(ciphertext)).put("retention",retention==null?JsonNull.defaultInstance():instant(retention)).build();}
 public static @NonNull StateSealer sealer(@NonNull JsonObject config){
  @NonNull String active=text(config,"activeKeyId");@NonNull JsonObject keys=(JsonObject)config.find("keys").orElseThrow();@NonNull List<@NonNull SealingKey> others=new ArrayList<>();@Nullable SealingKey selected=null;
  for(var e:keys.getMembers().entrySet()){@NonNull SealingKey key=SealingKey.fromBase64(e.getKey(),((JsonString)e.getValue()).getValue());if(e.getKey().equals(active))selected=key;else others.add(key);}
  if(selected==null)throw new IllegalArgumentException("Missing active key");return StateSealer.withActiveKey(selected).verificationKeys(others).maximumSealedLength((int)number(config,"sealerMaximumSealedLength",16384)).build();
 }
 public static @NonNull Set<@NonNull String> keyIds(@NonNull JsonObject config){return ((JsonObject)config.find("keys").orElseThrow()).getMembers().keySet();}
 public static @NonNull String wireKey(byte @NonNull [] sealed){
  if(sealed.length<56||sealed[0]!=1)throw new IllegalArgumentException("Invalid wire");int n=Byte.toUnsignedInt(sealed[1]);if(n<1||n>64||sealed.length<54+n)throw new IllegalArgumentException("Invalid key");@NonNull String key=new String(sealed,2,n,StandardCharsets.US_ASCII);if(!key.matches("[A-Za-z0-9._~\\-]{1,64}"))throw new IllegalArgumentException("Invalid key");return key;
 }
 public static @NonNull String asciiKey(byte @NonNull [] sealed){byte @NonNull [] wire=bytes(new String(sealed,StandardCharsets.US_ASCII));try{return wireKey(wire);}finally{Arrays.fill(wire,(byte)0);}}
 public static int reserve(byte @NonNull [] sealed){byte @NonNull [] wire=bytes(new String(sealed,StandardCharsets.US_ASCII));try{int n=wireKey(wire).length();return (4*(wire.length-n+64)+2)/3;}finally{Arrays.fill(wire,(byte)0);}}
 public static @NonNull JsonObject decision(@NonNull JsonObject source,@Nullable JsonObject target,@NonNull String classification,@Nullable String before,@Nullable String after,@Nullable Instant floor,@Nullable Instant retention,boolean permanent,@NonNull String kind,@NonNull String sourceFormat,@NonNull String targetFormat,long reservation,long actual,long sql,@Nullable String opening,@Nullable String active,@Nullable String root,@NonNull List<@NonNull String> openingKeys){
  if(!openingKeys.equals(new ArrayList<>(new TreeSet<>(openingKeys))))throw new IllegalArgumentException("Noncanonical key inventory");
  return JsonObject.builder().put("classification",classification).put("source",source).put("target",target==null?JsonNull.defaultInstance():target).put("sourceSemanticCommitment",before==null?JsonNull.defaultInstance():JsonString.fromValue(before)).put("targetSemanticCommitment",after==null?JsonNull.defaultInstance():JsonString.fromValue(after)).put("floor",floor==null?JsonNull.defaultInstance():instant(floor)).put("retention",retention==null?JsonNull.defaultInstance():instant(retention)).put("permanent",permanent).put("kind",kind).put("sourceFormat",sourceFormat).put("targetFormat",targetFormat).put("reservationBytes",reservation).put("actualBytes",actual).put("sqlBytes",sql).put("openingKeyId",opening==null?JsonNull.defaultInstance():JsonString.fromValue(opening)).put("openingKeyIds",JsonArray.fromElements(openingKeys.stream().map(JsonString::fromValue).toList())).put("activeKeyId",active==null?JsonNull.defaultInstance():JsonString.fromValue(active)).put("rootCommitment",root==null?JsonNull.defaultInstance():JsonString.fromValue(root)).build();
 }
 public static @NonNull JsonObject refusal(@NonNull JsonObject row,@NonNull String classification,@NonNull String targetFormat){return refusal(row,classification,targetFormat,List.of());}
 public static @NonNull JsonObject refusal(@NonNull JsonObject row,@NonNull String classification,@NonNull String targetFormat,@NonNull List<@NonNull String> openingKeys){return decision(row,null,classification,null,null,null,null,false,"UNKNOWN","UNKNOWN",targetFormat,0,0,0,openingKeys.isEmpty()?null:openingKeys.get(0),null,null,openingKeys);}
 public static @NonNull List<@NonNull String> requiredKeys(@NonNull Collection<@NonNull String> first,@NonNull Collection<@NonNull String> second){var all=new TreeSet<@NonNull String>(first);all.addAll(second);return List.copyOf(all);}
 public static @NonNull String identifier(int value){byte @NonNull [] v=new byte[32];v[0]=(byte)value;return b64(v);}
 public static @NonNull String testKey(int v){byte @NonNull [] k=new byte[32];for(int i=0;i<32;i++)k[i]=(byte)(i+v);return Base64.getEncoder().encodeToString(k);}
}

