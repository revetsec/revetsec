/* Copyright 2026 Revetware LLC. Licensed under the Apache License, Version 2.0. */
package com.revetsec.oauth.server;
import com.revetsec.SealingKey;
import com.revetsec.StateSealer;
import com.revetsec.internal.encoding.Base64Url;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.HexFormat;
import java.util.Properties;
/** Private native-codec transport fixture. Never grants service or deployment admission. */
public final class CapacityRowFixture {
 private CapacityRowFixture(){}
 public static void main(String[] args)throws Exception{
  var input=new Properties();try(var in=Files.newInputStream(Path.of(args[0]))){input.load(in);}
  for(int i=0;i<Integer.parseInt(input.getProperty("count"));i++){
   String v="v."+i+'.';
   if(!"golden".equals(input.getProperty(v+"group")) || !"GRANT".equals(input.getProperty(v+"kind")) || !"12170".equals(input.getProperty(v+"completeBytes")))continue;
   String issuer=text(input.getProperty(v+"issuerHex")),payload=text(input.getProperty(v+"payloadHex"));
   var sealer=StateSealer.withActiveKey(SealingKey.fromBase64("k".repeat(64),"AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA=")).maximumSealedLength(16384).clock(Clock.fixed(Instant.EPOCH,ZoneOffset.UTC)).build();
   var codec=new OAuthStoreRecordCodecV2(issuer,sealer,16384,new OAuthServerIngressLimits(65536,65536,65536,4096,4096,8,16,128,128),1024);
   var key=OAuthStoreKey.fromStoredForm(input.getProperty(v+"key"));var retain=Instant.ofEpochSecond(Long.parseLong(input.getProperty(v+"retention")));
   var row=codec.sealVersion(key,Base64Url.encode(ByteBuffer.allocate(32).putInt(70).array()),retain,Instant.ofEpochSecond(Long.parseLong(input.getProperty(v+"floorSeconds")),Integer.parseInt(input.getProperty(v+"floorNanos"))),payload);
   if(row.toSealedForm().length()!=16384 || !codec.open(row,Clock.fixed(Instant.EPOCH,ZoneOffset.UTC)).payload().toJson().equals(payload))throw new AssertionError("native-capacity-row");
   var output=new Properties();output.setProperty("key",row.getKey().getStorageKey());output.setProperty("version",row.getVersion());output.setProperty("retain",Long.toString(row.getRetainUntil().getEpochSecond()));output.setProperty("sealed",row.toSealedForm());try(var out=Files.newOutputStream(Path.of(args[1]))){output.store(out,"Synthetic native exact16384 transport fixture");}return;
  }throw new AssertionError("Missing boundary seed");
 }
 private static String text(String hex){return new String(HexFormat.of().parseHex(hex),StandardCharsets.UTF_8);}
}
