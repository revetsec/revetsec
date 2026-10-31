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
import org.jspecify.annotations.Nullable;
import org.jspecify.annotations.NonNull;
import com.revetsec.json.*;
import example.migration.CodecSupport;
import java.time.Instant;
import com.revetsec.internal.crypto.SealedStateAccess;
import com.revetsec.internal.crypto.SealedStateType;
import java.nio.charset.StandardCharsets;
import java.util.*;
import static example.migration.CodecSupport.*;
/** Synthetic legacy codec writer compiled only against the preserved baseline JAR. */
public final class FrozenIssuerWriter {
 private FrozenIssuerWriter(){}
 public static void main(@NonNull String @NonNull [] args)throws Exception{CodecSupport.fixtureMain(args,FrozenIssuerWriter::fixtures);}
 private static @NonNull JsonArray fixtures(@NonNull JsonObject config){
  var old=new OAuthStoreRecordCodec(text(config,"issuer"),sealer(config),16384);@NonNull Instant minimum=Instant.ofEpochSecond(number(config,"minimumSeconds",1700000000),number(config,"minimumNanos",999999999));@NonNull String scope=text(config,"issuerScope");@NonNull List<@NonNull JsonValue> rows=new ArrayList<>();
  rows.add(row(scope,old.seal(old.issuerKey(),OAuthStoreFormat.PERMANENT,OAuthStoreFence.initialIssuer(identifier(1),minimum).toPayload())));
  rows.add(row(scope,old.seal(old.subjectKey("álîçè"),OAuthStoreFormat.PERMANENT,OAuthStoreFence.initialSubject(identifier(2)).toPayload())));
  int index=20;for(var kind:List.of(OAuthStoreKey.Kind.INTERACTION,OAuthStoreKey.Kind.CODE,OAuthStoreKey.Kind.GRANT,OAuthStoreKey.Kind.ACCESS_TOKEN,OAuthStoreKey.Kind.REFRESH_TOKEN))for(@NonNull String status:statuses(kind)){
   @NonNull String id=identifier(index++);@NonNull JsonObject payload=authorization(kind,status,minimum.minusSeconds(2000),id);var limits=new OAuthServerIngressLimits(65536,65536,65536,4096,4096,1024,64,128,128);var record=OAuthAuthorizationRecord.decode(kind,id,payload,limits,1024);rows.add(row(scope,old.seal(old.key(kind,id),record.retention(),payload.toJson())));
  }
  if(config.find("oversizedInteraction").isPresent()){
   @NonNull String id=identifier(101);var kind=OAuthStoreKey.Kind.INTERACTION;var payload=authorization(kind,"PENDING",minimum,id);@NonNull List<@NonNull JsonValue> scopes=new ArrayList<>();for(int i=0;i<80;i++)scopes.add(JsonString.fromValue(String.format(java.util.Locale.ROOT,"%03d",i)+"s".repeat(125)));
   var members=new LinkedHashMap<String,JsonValue>(payload.getMembers());members.put("scopes",JsonArray.fromElements(scopes));members.put("state",JsonString.fromValue(""));var key=old.key(kind,id);long expiry=minimum.plusSeconds(100).getEpochSecond();
   @NonNull String envelope="{\"schema\":1,\"issuer\":"+JsonString.fromValue(text(config,"issuer")).toJson()+",\"key\":"+JsonString.fromValue(key.getStorageKey()).toJson()+",\"version\":\""+identifier(0)+"\",\"retainUntil\":"+expiry+",\"payload\":"+JsonObject.fromMembers(members).toJson()+"}";
   int state=12233-envelope.getBytes(StandardCharsets.UTF_8).length;if(state<0||state>4096)throw new IllegalArgumentException("Unsupported synthetic fixture");members.put("state",JsonString.fromValue("x".repeat(state)));var large=old.seal(key,Instant.ofEpochSecond(expiry),JsonObject.fromMembers(members).toJson());if(large.toSealedForm().length()!=16384)throw new IllegalArgumentException("Wrong synthetic boundary");rows.add(row(scope,large));
  }
  if(config.find("noncanonicalLegacy").isPresent()){
   @NonNull String id=identifier(102),version=identifier(103);var key=old.key(OAuthStoreKey.Kind.CODE,id);var payload=authorization(OAuthStoreKey.Kind.CODE,"USED",minimum,id);var record=OAuthAuthorizationRecord.decode(OAuthStoreKey.Kind.CODE,id,payload,new OAuthServerIngressLimits(65536,65536,65536,4096,4096,1024,64,128,128),1024);
   @NonNull String raw=" { \"payload\" : "+payload.toJson().replace("\"issuerEpoch\":999","\"issuerEpoch\":9.99e2")+", \"retainUntil\" : "+record.retention().getEpochSecond()+", \"version\" : \""+version+"\", \"key\" : "+JsonString.fromValue(key.getStorageKey()).toJson()+", \"issuer\" : "+JsonString.fromValue(text(config,"issuer")).toJson()+", \"schema\" : 1e0 } ";
   @NonNull String sealed=SealedStateAccess.get().seal(sealer(config),SealedStateType.AS_RECORD,raw,"revetsec/as-record/v1:"+key.getStorageKey(),record.retention());rows.add(row(scope,OAuthStoreEntry.fromStoredForm(key,version,record.retention(),sealed)));
  }
  return JsonArray.fromElements(rows);
 }
 private static @NonNull JsonObject row(@NonNull String scope,@NonNull OAuthStoreEntry value){@NonNull String key=value.getKey().getStorageKey();return JsonObject.builder().put("family","ISSUER").put("scope",scope).put("handle",hash("ISSUER\0"+scope+'\0'+key)).put("key",key).put("version",value.getVersion()).put("ciphertext",b64(value.toSealedForm().getBytes(StandardCharsets.US_ASCII))).put("retention",instant(value.getRetainUntil())).build();}
	private static @NonNull List<@NonNull String> statuses(OAuthStoreKey.@NonNull Kind kind) {
		return switch (kind) {
			case INTERACTION -> List.of("PENDING", "COMPLETED");
			case CODE -> List.of("UNUSED", "USED", "CANCELLED");
			case GRANT -> List.of("PENDING", "DENIED", "ACTIVE", "REVOKED");
			case ACCESS_TOKEN -> List.of("ISSUED");
			case REFRESH_TOKEN -> List.of("ACTIVE", "USED");
			default -> throw new AssertionError("Not an authorization kind");
		};
	}
	private static @NonNull JsonObject authorization(OAuthStoreKey.@NonNull Kind kind, @NonNull String status, @NonNull Instant base,@NonNull String id) {
		JsonObject.Builder b = JsonObject.builder().put("schema", 1L).put("id", id).put("status", status)
				.put("expires", base.plusSeconds(100).getEpochSecond()).put("issuerIncarnation", id).put("issuerEpoch", 999L);
		if (kind == OAuthStoreKey.Kind.INTERACTION) return b.put("browserHash", id).put("clientHash", id)
				.put("clientId", "client").put("redirect", "https://client.example/cb").put("resource", "https://resource.example/mcp")
				.put("scopes", JsonArray.fromElements(List.of(JsonString.fromValue("read")))).put("challenge", id).put("state", JsonNull.defaultInstance()).build();
		b.put("subjectIncarnation", id).put("subjectEpoch", 999L);
		if (kind == OAuthStoreKey.Kind.CODE) {
			b.put("grantId", id).put("challenge", id).put("redirect", "https://client.example/cb");
			if (status.equals("USED")) b.put("horizon", base.plusSeconds(1000).getEpochSecond());
		} else if (kind == OAuthStoreKey.Kind.GRANT) {
			b.put("codeId", id).put("subject", "álîçè").put("clientId", "client").put("clientHash", id)
					.put("resource", "https://resource.example/mcp").put("scopes", JsonArray.fromElements(List.of(JsonString.fromValue("read"))))
					.put("refresh", true);
			if (status.equals("ACTIVE") || status.equals("REVOKED")) b.put("horizon", base.plusSeconds(1000).getEpochSecond())
					.put("maximumAccessSeconds", 30L).put("maximumAccessNanos", 123456789L).put("refreshId", id);
		} else if (kind == OAuthStoreKey.Kind.ACCESS_TOKEN) {
			b.put("grantId", id).put("subject", "álîçè").put("clientId", "client").put("resource", "https://resource.example/mcp")
					.put("scopes", JsonArray.fromElements(List.of(JsonString.fromValue("read"))))
					.put("issued", base.plusSeconds(1).getEpochSecond()).put("retain", base.plusSeconds(1000).getEpochSecond());
		} else b.put("grantId", id).put("horizon", base.plusSeconds(1000).getEpochSecond());
		return b.build();
	}
}

