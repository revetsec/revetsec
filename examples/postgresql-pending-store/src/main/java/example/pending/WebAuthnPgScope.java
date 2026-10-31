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

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.Objects;

/** Private physical namespace identity; never a logical auth address or UTC source. */
final class WebAuthnPgScope {
	private final String family;
	private final String namespace;
	private WebAuthnPgScope(@NonNull String family, @NonNull String namespace) {
		this.family = family;
		this.namespace = namespace;
	}
	public static @NonNull WebAuthnPgScope from(@NonNull String family, @NonNull String namespace) {
		Objects.requireNonNull(family);
		Objects.requireNonNull(namespace);
		if (!family.equals("ISSUER") && !family.equals("TOTP") && !family.equals("WEBAUTHN"))
			throw new IllegalArgumentException("Unsupported private scope family");
		byte[] encoded = utf8(namespace);
		if (encoded.length < 1 || encoded.length > 256 || namespace.indexOf('\0') >= 0)
			throw new IllegalArgumentException("Invalid private physical namespace");
		return new WebAuthnPgScope(family, namespace);
	}
	static byte @NonNull [] utf8(@NonNull String value) {
		try {
			ByteBuffer buffer = StandardCharsets.UTF_8.newEncoder().onMalformedInput(CodingErrorAction.REPORT)
					.onUnmappableCharacter(CodingErrorAction.REPORT).encode(CharBuffer.wrap(value));
			byte[] bytes = new byte[buffer.remaining()];
			buffer.get(bytes);
			return bytes;
		} catch (CharacterCodingException failure) {
			throw new IllegalArgumentException("Invalid UTF-8 physical namespace", failure);
		}
	}
	public @NonNull String getFamily() { return this.family; }
	public @NonNull String getNamespace() { return this.namespace; }
	@Override public boolean equals(@Nullable Object other) {
		return other instanceof WebAuthnPgScope scope && this.family.equals(scope.family) && this.namespace.equals(scope.namespace);
	}
	@Override public int hashCode() { return Objects.hash(this.family, this.namespace); }
	@Override public @NonNull String toString() { return "WebAuthnPgScope[private namespace]"; }
}
