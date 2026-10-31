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
package example.pending;

import com.revetsec.StoreAdmission;
import com.revetsec.StoreTimeObservation;
import org.jspecify.annotations.NonNull;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.time.Duration;
import java.util.Base64;

/** Scripted source only. No UTC/rate/ownership qualification follows from these fixture values. */
final class WebAuthnFixtureAuthority {
	private WebAuthnFixtureAuthority() {}
	static @NonNull String identity(@NonNull String value) {
		try{return Base64.getUrlEncoder().withoutPadding().encodeToString(MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8)));}
		catch(Exception failure){throw new IllegalStateException("Fixture hash unavailable",failure);}
	}
	static @NonNull String physical(@NonNull String namespace){return identity("webauthn-physical/"+namespace);}
	static @NonNull StoreAdmission admission(@NonNull String namespace){return StoreAdmission.fromIdentifiers(identity("webauthn-authority/"+namespace),identity("webauthn-recovery/"+namespace));}
	static @NonNull String clockGeneration(@NonNull String namespace){return identity("webauthn-clock/"+namespace);}
	static PostgresqlWebAuthnStore.@NonNull Authority fromEnvironment(@NonNull String namespace) {
		// Independent explicit channel; never read the worker's REVETSEC_TEST_WA_WORKER_NOW or Clock.
		String seconds=System.getenv().getOrDefault("REVETSEC_TEST_WA_AUTHORITY_NOW","1700000010");
		Instant instant=Instant.ofEpochSecond(Long.parseLong(seconds));
		return (scope,budget)->{
			if(!physical(namespace).equals(scope) || budget.isZero() || budget.isNegative())throw new IllegalStateException("Fixture authority admission unavailable");
			return StoreTimeObservation.Healthy.fromObservation(admission(namespace),clockGeneration(namespace),instant,Duration.ZERO);
		};
	}
}
