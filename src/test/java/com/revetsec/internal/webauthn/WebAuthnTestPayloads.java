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
import com.revetsec.webauthn.WebAuthnStoreKey;
import org.jspecify.annotations.NonNull;
import java.nio.ByteBuffer;
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
}
