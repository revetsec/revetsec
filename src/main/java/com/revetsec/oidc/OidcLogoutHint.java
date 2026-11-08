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

package com.revetsec.oidc;

import com.revetsec.StateSealer;
import com.revetsec.internal.crypto.SealedStateAccess;
import com.revetsec.internal.crypto.SealedStateType;
import com.revetsec.internal.crypto.SealerV1;
import com.revetsec.internal.Limits;
import com.revetsec.internal.crypto.UnsealException;
import com.revetsec.internal.jose.RegisteredClaims;
import com.revetsec.json.JsonObject;
import com.google.errorprone.annotations.CheckReturnValue;
import org.jspecify.annotations.NonNull;
import javax.annotation.concurrent.Immutable;
import java.time.Duration;
import java.util.Set;
import static java.util.Objects.requireNonNull;

/**
 * An explicitly retained logout credential bound to the original OIDC continuity reference. It is not an identity
 * proof. The compact ID token is emitted only inside explicit trusted-storage serialization or a prepared logout
 * request. Parsing checks structure and continuity, without signature validation or rejecting an expired ID token.
 * Immutable strings and parser/provider-owned copies cannot be erased; owned temporary byte arrays are cleared.
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 * @since 1.0.0
 */
@Immutable
public final class OidcLogoutHint {
	private final @NonNull OidcSessionReference reference;
	private final @NonNull String compact;
	private final @NonNull String referenceForm;
	private final int referenceBytes;
	OidcLogoutHint(@NonNull OidcSessionReference reference, @NonNull String compact) {
		this.reference = requireNonNull(reference); this.compact = requireNonNull(compact);
		try {
			OidcLogoutSupport.continuity(reference, OidcLogoutSupport.token(compact));
			this.referenceForm = reference.toSerializedForm(); this.referenceBytes = OidcLogoutSupport.text(this.referenceForm, OidcLogoutSupport.REFERENCE_LIMIT);
			JsonObject stored = OidcLogoutSupport.object(this.referenceForm, OidcLogoutSupport.REFERENCE_LIMIT);
			OidcLogoutSupport.client(OidcLogoutSupport.field(stored, "client_id", OidcLogoutSupport.FIELD_LIMIT));
			if (!(stored.getMembers().get("claims") instanceof JsonObject claims)) throw OidcLogoutSupport.invalid();
			OidcLogoutSupport.field(claims, "iss", OidcLogoutSupport.FIELD_LIMIT);
		} catch (IllegalArgumentException | OidcValidationException invalid) { throw OidcLogoutSupport.failure(OidcLogoutException.Reason.HINT_MISMATCH); }
	}
	@NonNull OidcSessionReference reference() { return this.reference; }
	@NonNull String compact() { return this.compact; }

	/**
	 * Emits a credential-bearing versioned JSON envelope for trusted application storage. Never log this value.
	 * @return bounded serialized hint; parsing it creates no identity
	 * @throws OidcLogoutException if the selected representation cannot fit
	 * @since 1.0.0
	 */
	public @NonNull String toSerializedForm() {
		String referenceForm = this.referenceForm;
		String prefix = "{\"v\":1,\"reference\":"; String middle = ",\"id_token\":\""; String suffix = "\"}";
		long bytes = (long) this.referenceBytes + this.compact.length() + prefix.length() + middle.length() + suffix.length();
		if (bytes > OidcLogoutSupport.HINT_LIMIT) throw OidcLogoutSupport.failure(OidcLogoutException.Reason.INPUT_LIMIT);
		return prefix + referenceForm + middle + this.compact + suffix;
	}
	/**
	 * Seals under a dedicated logout-hint type and the sealer's configured clock/lifetime profile. Valid large hints
	 * can exceed the unchanged sealer size ceiling; no truncation or chunking is performed.
	 * @param sealer application-owned sealer
	 * @param context fixed application context
	 * @param lifetime explicit sealing lifetime
	 * @return typed sealed credential for trusted storage
	 * @throws NullPointerException if a required argument is null
	 * @throws OidcLogoutException if size/configuration, interruption or the provider prevents sealing
	 * @since 1.0.0
	 */
	public @NonNull String toSealedForm(@NonNull StateSealer sealer, @NonNull String context, @NonNull Duration lifetime) {
		requireNonNull(sealer); requireNonNull(context); requireNonNull(lifetime); OidcLogoutSupport.interrupted();
		String plaintext = toSerializedForm();
		try {
			SealerV1.requireContext(context); Limits.SEAL_LIFETIME.require(lifetime);
			int length = OidcLogoutSupport.text(plaintext, OidcLogoutSupport.HINT_LIMIT);
			if (SealerV1.sealedLength(SealedStateAccess.get().getActiveKeyId(sealer).length(), length) > SealedStateAccess.get().getMaximumSealedLength(sealer))
				throw OidcLogoutSupport.invalid();
		} catch (IllegalArgumentException invalid) { throw OidcLogoutSupport.failure(OidcLogoutException.Reason.STORAGE_PROFILE_UNSUPPORTED); }
		try {
			String sealed = SealedStateAccess.get().sealForLifetime(sealer, SealedStateType.OIDC_LOGOUT_HINT, plaintext, context, lifetime);
			OidcLogoutSupport.interrupted(); return sealed;
		} catch (OidcLogoutException failure) { throw failure; }
		catch (VirtualMachineError fatal) { throw fatal; }
		catch (RuntimeException | Error failure) { OidcLogoutSupport.interrupted(); throw OidcLogoutSupport.failure(OidcLogoutException.Reason.PROVIDER_UNAVAILABLE); }
	}
	/**
	 * Restores a structurally consistent credential from trusted application storage. No identity is authenticated.
	 * @param serializedForm credential-bearing storage form; never log it
	 * @return parsed credential or one value-free rejection
	 * @throws NullPointerException if serializedForm is null
	 * @since 1.0.0
	 */
	@CheckReturnValue
	public static @NonNull OidcLogoutHintParseResult fromSerializedFormResult(@NonNull String serializedForm) {
		requireNonNull(serializedForm); OidcLogoutSupport.interrupted();
		try {
			JsonObject envelope = OidcLogoutSupport.object(serializedForm, OidcLogoutSupport.HINT_LIMIT); OidcLogoutSupport.version(envelope);
			if (!envelope.getMembers().keySet().equals(Set.of("v", "reference", "id_token")) || !(envelope.getMembers().get("reference") instanceof JsonObject original)) throw OidcLogoutSupport.invalid();
			OidcSessionReferenceParseResult parsed = OidcSessionReference.fromSerializedFormResult(original.toJson());
			if (!(parsed instanceof OidcSessionReferenceParseResult.Succeeded success)) throw OidcLogoutSupport.invalid();
			OidcLogoutHint hint = new OidcLogoutHint(success.getReference(), OidcLogoutSupport.field(envelope, "id_token", OidcLogoutSupport.TOKEN_LIMIT));
			OidcLogoutSupport.interrupted(); return OidcLogoutHintParseResult.fromHint(hint);
		} catch (OidcLogoutException invalid) {
			if (invalid.getReason() != OidcLogoutException.Reason.HINT_MISMATCH && invalid.getReason() != OidcLogoutException.Reason.INPUT_LIMIT) throw invalid;
			return OidcLogoutHintParseResult.fromRejection();
		} catch (IllegalArgumentException | OidcValidationException invalid) { return OidcLogoutHintParseResult.fromRejection(); }
	}
	/**
	 * Opens only a typed logout hint using the sealer's configured clock. Invalid/tampered/cross-purpose/expired
	 * sealed state releases no hint. Provider and interruption failures remain distinct fixed exceptions.
	 * @param sealedForm received typed sealed credential
	 * @param sealer application-owned sealer
	 * @param context original application context
	 * @return restored credential or value-free rejection, never authenticated identity
	 * @throws NullPointerException if a required argument is null
	 * @throws OidcLogoutException if the provider or interruption prevents opening
	 * @since 1.0.0
	 */
	@CheckReturnValue
	public static @NonNull OidcLogoutHintParseResult fromSealedFormResult(@NonNull String sealedForm, @NonNull StateSealer sealer, @NonNull String context) {
		requireNonNull(sealedForm); requireNonNull(sealer); requireNonNull(context); OidcLogoutSupport.interrupted();
		try { SealerV1.requireContext(context); } catch (IllegalArgumentException invalid) { throw OidcLogoutSupport.failure(OidcLogoutException.Reason.STORAGE_PROFILE_UNSUPPORTED); }
		try {
			String opened = SealedStateAccess.get().unsealUsingConfiguredClock(sealer, SealedStateType.OIDC_LOGOUT_HINT, sealedForm, context);
			OidcLogoutSupport.interrupted(); return fromSerializedFormResult(opened);
		} catch (UnsealException invalid) { return OidcLogoutHintParseResult.fromRejection(); }
		catch (OidcLogoutException failure) { throw failure; }
		catch (VirtualMachineError fatal) { throw fatal; }
		catch (RuntimeException | Error failure) { OidcLogoutSupport.interrupted(); throw OidcLogoutSupport.failure(OidcLogoutException.Reason.PROVIDER_UNAVAILABLE); }
	}
	/** Redacts every credential and continuity field.
	 * @return redacted description
	 * @since 1.0.0
	 */
	@Override public @NonNull String toString() { return "OidcLogoutHint{credential=<redacted>, reference=<redacted>}"; }
}
