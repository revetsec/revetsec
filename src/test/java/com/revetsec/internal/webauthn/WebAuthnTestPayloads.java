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

package com.revetsec.internal.webauthn;

import com.revetsec.SealingKey;
import com.revetsec.StateSealer;
import com.revetsec.internal.crypto.SealedStateAccess;
import com.revetsec.internal.crypto.SealedStateType;
import com.revetsec.internal.encoding.Base64Url;
import com.revetsec.webauthn.WebAuthnStoreKey;
import org.jspecify.annotations.NonNull;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Arrays;
import java.util.Base64;

/** Deliberately authenticated opaque WAR2 fixtures exercise inner-parser rejection after envelope admission. */
final class WebAuthnTestPayloads {
	private WebAuthnTestPayloads() { }
	static byte @NonNull [] seal(@NonNull WebAuthnStoreKey key,byte @NonNull [] inner,
			@NonNull Instant expires,@NonNull Instant observation){
		byte[] material=new byte[32];for(int n=0;n<material.length;n++)material[n]=(byte)(n+1);
		StateSealer sealer=StateSealer.withActiveKey(SealingKey.fromBase64("k",Base64.getEncoder().encodeToString(material)))
				.clock(Clock.fixed(observation,ZoneOffset.UTC)).build();
		Arrays.fill(material,(byte)0);
		byte[] payload=key.getKind()==WebAuthnStoreKey.Kind.NAMESPACE_CLOCK?inner.clone():
				ByteBuffer.allocate(12+inner.length).putLong(observation.getEpochSecond()).putInt(observation.getNano()).put(inner).array();
		try{return new WebAuthnRecordCodecV2(sealer).seal(key,payload,expires);}
		finally{Arrays.fill(payload,(byte)0);}
	}
	/** The removed, never-released WAR1 framing: authentic one-chunk envelope under its old magic and context domain. */
	static byte @NonNull [] removedWar1(@NonNull StateSealer sealer,@NonNull WebAuthnStoreKey key,byte @NonNull [] plaintext){
		return frame(sealer,key,plaintext,"WAR1","revetsec/wa-record/v1:");
	}
	/** Authentic one-chunk envelope under an explicit magic and context domain, independent of the production writer. */
	static byte @NonNull [] frame(@NonNull StateSealer sealer,@NonNull WebAuthnStoreKey key,byte @NonNull [] plaintext,
			@NonNull String magic,@NonNull String domain){
		byte[] recordId=new byte[16];for(int n=0;n<recordId.length;n++)recordId[n]=(byte)(n+9);
		String digest;
		try{digest=Base64Url.encode(MessageDigest.getInstance("SHA-256").digest(key.getStorageKey().getBytes(StandardCharsets.US_ASCII)));}
		catch(NoSuchAlgorithmException failure){throw new IllegalStateException(failure);}
		String context=domain+digest+':'+Base64Url.encode(recordId)+':'+1+':'+plaintext.length+':'+0;
		String sealed=SealedStateAccess.get().seal(sealer,SealedStateType.WEBAUTHN_RECORD,Base64Url.encode(plaintext),context,
				WebAuthnRecordPayloadV2.PERMANENT);
		return ByteBuffer.allocate(26+sealed.length()).put(magic.getBytes(StandardCharsets.US_ASCII)).putShort((short)1)
				.putShort((short)plaintext.length).put(recordId).putShort((short)sealed.length())
				.put(sealed.getBytes(StandardCharsets.US_ASCII)).array();
	}
}
