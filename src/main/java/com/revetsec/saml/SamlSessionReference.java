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
package com.revetsec.saml;

import com.revetsec.StateSealer;
import com.revetsec.internal.crypto.SealedStateAccess;
import com.revetsec.internal.crypto.SealedStateType;
import com.revetsec.internal.crypto.UnsealException;
import com.revetsec.internal.encoding.Base64Url;
import com.revetsec.internal.encoding.EncodingException;
import com.revetsec.internal.encoding.StrictUtf8;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import javax.annotation.concurrent.Immutable;
import java.time.Clock;
import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.Arrays;
import java.util.Optional;

import static java.util.Objects.requireNonNull;

/**
 * Identity and session fields from a checked assertion for later front-channel logout matching.
 * The application stores this reference alongside its own application session.
 *
 * @since 1.0.0
 */
@Immutable
public final class SamlSessionReference {
    private static final int MAXIMUM_BYTES = 32 * 1024;
    private final @NonNull String connectionId;
    private final @NonNull String identityProviderEntityId;
    private final @NonNull SamlNameId nameId;
    private final @Nullable String sessionIndex;
    private final @Nullable Instant sessionNotOnOrAfter;

    SamlSessionReference(@NonNull String connectionId, @NonNull String identityProviderEntityId,
            @NonNull SamlNameId nameId, @Nullable String sessionIndex,
            @Nullable Instant sessionNotOnOrAfter) {
        this.connectionId = connectionId;
        this.identityProviderEntityId = identityProviderEntityId;
        this.nameId = nameId;
        this.sessionIndex = sessionIndex;
        this.sessionNotOnOrAfter = sessionNotOnOrAfter;
    }

    /**
     * Returns the application-defined IdP namespace.
     *
     * @return connection ID
     * @since 1.0.0
     */
    public @NonNull String getIdentityProviderConnectionId() { return connectionId; }
    /**
     * Returns the checked IdP entity ID.
     *
     * @return entity ID
     * @since 1.0.0
     */
    public @NonNull String getIdentityProviderEntityId() { return identityProviderEntityId; }
    /**
     * Returns the checked NameID and qualifiers used for logout matching.
     *
     * @return NameID
     * @since 1.0.0
     */
    public @NonNull SamlNameId getNameId() { return nameId; }
    /**
     * Returns the session index when the IdP supplied one.
     *
     * @return optional session index
     * @since 1.0.0
     */
    public @NonNull Optional<@NonNull String> getSessionIndex() { return Optional.ofNullable(sessionIndex); }
    /**
     * Returns the IdP's session expiry when supplied.
     *
     * @return optional expiry
     * @since 1.0.0
     */
    public @NonNull Optional<@NonNull Instant> getSessionNotOnOrAfter() {
        return Optional.ofNullable(sessionNotOnOrAfter);
    }

    /**
     * Serializes the checked logout continuity fields for trusted application storage.
     * This contains personal data and is not itself proof of identity or authenticity.
     *
     * @return bounded versioned storage form
     * @since 1.0.0
     */
    public @NonNull String toSerializedForm() {
        try {
            String serialized = "1." + part(connectionId) + '.' + part(identityProviderEntityId)
                    + '.' + part(nameId.getValue()) + '.' + optionalPart(nameId.rawFormat())
                    + '.' + optionalPart(nameId.rawNameQualifier())
                    + '.' + optionalPart(nameId.rawSpNameQualifier())
                    + '.' + optionalPart(nameId.rawSpProvidedId())
                    + '.' + optionalPart(sessionIndex)
                    + '.' + optionalPart(sessionNotOnOrAfter == null ? null
                            : sessionNotOnOrAfter.toString());
            if (serialized.length() > MAXIMUM_BYTES) throw invalid();
            return serialized;
        } catch (EncodingException exception) { throw invalid(); }
    }

    /**
     * Restores a bounded reference from trusted application storage. It validates
     * structure, but cannot authenticate the original SAML assertion. Browser-side
     * storage must use {@link #fromSealedForm(String, StateSealer, String, Clock)}.
     *
     * @param serializedForm versioned storage form
     * @return logout continuity reference, not an authenticated identity
     * @since 1.0.0
     */
    public static @NonNull SamlSessionReference fromSerializedForm(@NonNull String serializedForm) {
        requireNonNull(serializedForm);
        try {
            if (serializedForm.length() > MAXIMUM_BYTES) throw invalid();
            String[] fields = serializedForm.split("\\.", -1);
            if (fields.length != 10 || !fields[0].equals("1")) throw invalid();
            String connection = required(fields[1], 256);
            String idp = required(fields[2], 2048);
            String value = required(fields[3], 4096);
            SamlNameId restoredName = new SamlNameId(value,
                    optional(fields[4], 2048), optional(fields[5], 2048),
                    optional(fields[6], 2048), optional(fields[7], 2048));
            String index = optional(fields[8], 2048);
            String end = optional(fields[9], 64);
            Instant expiry = end == null ? null : Instant.parse(end);
            return new SamlSessionReference(connection, idp, restoredName, index, expiry);
        } catch (EncodingException | DateTimeParseException | IllegalArgumentException invalid) {
            throw invalid();
        }
    }

    private static @NonNull String part(@NonNull String value) throws EncodingException {
        byte[] bytes = StrictUtf8.encode(value);
        try { return Base64Url.encode(bytes); }
        finally { Arrays.fill(bytes, (byte) 0); }
    }

    private static @NonNull String optionalPart(@Nullable String value) throws EncodingException {
        return value == null ? "-" : part("x" + value);
    }

    private static @NonNull String required(@NonNull String encoded, int maximum)
            throws EncodingException {
        String value = decoded(encoded);
        if (value.isEmpty() || value.length() > maximum) throw invalid();
        return value;
    }

    private static @Nullable String optional(@NonNull String encoded, int maximum)
            throws EncodingException {
        if (encoded.equals("-")) return null;
        String value = decoded(encoded);
        if (!value.startsWith("x") || value.length() - 1 > maximum) throw invalid();
        return value.substring(1);
    }

    private static @NonNull String decoded(@NonNull String encoded) throws EncodingException {
        if (encoded.isEmpty() || encoded.length() > MAXIMUM_BYTES) throw invalid();
        byte[] bytes = Base64Url.decode(encoded);
        try {
            if (bytes.length > MAXIMUM_BYTES) throw invalid();
            return StrictUtf8.decode(bytes);
        } finally { Arrays.fill(bytes, (byte) 0); }
    }

    /**
     * Seals the reference under a SAML-specific type and application context.
     * The application chooses an expiry no later than its own session lifetime.
     *
     * @param sealer active and verification keys
     * @param context application-selected session context
     * @param expiresAt absolute seal expiry
     * @return sealed storage form
     * @since 1.0.0
     */
    public @NonNull String toSealedForm(@NonNull StateSealer sealer, @NonNull String context,
            @NonNull Instant expiresAt) {
        return SealedStateAccess.get().seal(requireNonNull(sealer), SealedStateType.SAML_SESSION,
                toSerializedForm(), requireNonNull(context), requireNonNull(expiresAt));
    }

    /**
     * Opens a SAML session reference under the same application context.
     * Opening does not create or authenticate an identity.
     *
     * @param sealedForm sealed storage form
     * @param sealer active and verification keys
     * @param context original application context
     * @param clock time source for expiry
     * @return logout continuity reference
     * @since 1.0.0
     */
    public static @NonNull SamlSessionReference fromSealedForm(@NonNull String sealedForm,
            @NonNull StateSealer sealer, @NonNull String context, @NonNull Clock clock) {
        try {
            return fromSerializedForm(SealedStateAccess.get().unseal(requireNonNull(sealer),
                    SealedStateType.SAML_SESSION, requireNonNull(sealedForm), requireNonNull(context),
                    requireNonNull(clock)));
        } catch (UnsealException exception) {
            throw invalid();
        }
    }

    private static @NonNull IllegalArgumentException invalid() {
        return new IllegalArgumentException("Invalid SAML session reference.");
    }
    /**
     * Redacts the session identifiers.
     *
     * @return redacted description
     * @since 1.0.0
     */
    @Override public @NonNull String toString() { return "SamlSessionReference{<redacted>}"; }
}
