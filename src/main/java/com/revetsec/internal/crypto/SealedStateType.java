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

package com.revetsec.internal.crypto;

import org.jspecify.annotations.NonNull;

import javax.annotation.concurrent.Immutable;
import java.nio.charset.StandardCharsets;

/**
 * What a sealed value holds: the type label that StateSealer v1 binds into both the message key and the additional
 * authenticated data (M1 plan, "StateSealer v1"; G6-8 and G6-10).
 * <p>
 * A value sealed under one type never opens under another, even with the same key and context, so pending OAuth
 * state, pending SAML state, OIDC session references and application data can never be replayed as one another.
 * Only {@link #APP} is reachable through the public {@code StateSealer} API; the protocol packages reach the others
 * through {@link SealedStateAccess}.
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 */
@Immutable
public enum SealedStateType {
	/**
	 * Pending OAuth 2.0 or OpenID Connect authorization state: {@code revetsec/pending-authorization/v1}.
	 */
	PENDING_AUTHORIZATION("revetsec/pending-authorization/v1"),
	/**
	 * Pending SAML authentication state: {@code revetsec/pending-saml/v1}.
	 */
	PENDING_SAML("revetsec/pending-saml/v1"),
	/**
	 * Pending SAML front-channel logout state, separate from pending login.
	 */
	PENDING_SAML_LOGOUT("revetsec/pending-saml-logout/v1"),
	/**
	 * An OpenID Connect session reference: {@code revetsec/oidc-session/v1}.
	 */
	OIDC_SESSION("revetsec/oidc-session/v1"),
	/**
	 * Application data sealed through the public {@code StateSealer} API: {@code revetsec/app/v1}.
	 */
	APP("revetsec/app/v1"),
 /** Authenticated issuer persistence records: revetsec/as-record/v1. */
 AS_RECORD("revetsec/as-record/v1"),
 /** Optional authenticated client metadata cache, distinct from application/issuer persistence. */
 AS_CLIENT_METADATA_CACHE("revetsec/as-client-metadata-cache/v1"),
 /** Authenticated WebAuthn authoritative-store records, separate from application and issuer state. */
 WEBAUTHN_RECORD("revetsec/webauthn-record/v1");

	@NonNull
	private final String label;

	SealedStateType(@NonNull String label) {
		this.label = label;
	}

	/**
	 * Returns the type label, an ASCII string.
	 *
	 * @return the type label
	 */
	@NonNull
	public String getLabel() {
		return this.label;
	}

	/**
	 * Returns the type label's ASCII bytes, as the key derivation and the additional authenticated data use them.
	 */
	byte @NonNull [] getLabelBytes() {
		return this.label.getBytes(StandardCharsets.US_ASCII);
	}
}
