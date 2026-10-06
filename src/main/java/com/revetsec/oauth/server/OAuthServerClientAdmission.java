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

import com.revetsec.internal.encoding.EncodingException;
import com.revetsec.internal.encoding.StandardBase64;
import com.revetsec.internal.encoding.StrictUtf8;
import com.revetsec.internal.http.Deadline;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Arrays;
import java.util.Optional;
import static java.util.Objects.requireNonNull;
import static com.revetsec.oauth.server.OAuthServerAdmissionFailure.Reason.*;

/** Registry-only lookup/authentication. OAuthServerClientSelection owns eligible metadata fallback. */
final class OAuthServerClientAdmission {
	private OAuthServerClientAdmission() {}
	static @NonNull OAuthServerClientRegistration registered(@NonNull String id,
			@NonNull OAuthServerClientRepository repository, @NonNull Deadline deadline, @NonNull OAuthServerIngressLimits limits) {
		return findRegistered(id, repository, deadline, limits).orElseThrow(() -> failure(INVALID_CLIENT));
	}
	static @NonNull Optional<@NonNull OAuthServerClientRegistration> findRegistered(@NonNull String id,
			@NonNull OAuthServerClientRepository repository, @NonNull Deadline deadline, @NonNull OAuthServerIngressLimits limits) {
		requireNonNull(repository); requireNonNull(deadline); requireNonNull(limits);
		try { OAuthServerConfiguration.text(id, limits.clientIdLength); }
		catch (IllegalArgumentException failure) { throw failure(INVALID_CLIENT); }
		Optional<OAuthServerClientRegistration> found;
		try { found = repository.findRegisteredClient(id, remaining(deadline)); }
		catch (VirtualMachineError fatal) { throw fatal; }
		catch (Throwable exception) { throw infrastructure(exception); }
		remaining(deadline);
		if (found == null) throw failure(INFRASTRUCTURE);
		if (found.isEmpty()) return Optional.empty();
		OAuthServerClientRegistration client = found.orElseThrow();
		if (!id.equals(client.getClientId())) throw failure(INFRASTRUCTURE);
		if (client.getRedirectUris().size() > limits.redirects || client.getAllowedScopesByResource().size() > limits.resources
				|| client.getIntrospectionResources().size() > limits.resources) throw failure(INFRASTRUCTURE);
		for (var scopes : client.getAllowedScopesByResource().values()) {
			if (scopes.size() > limits.scopes) throw failure(INFRASTRUCTURE);
			for (String scope : scopes) if (scope.length() > limits.scopeLength) throw failure(INFRASTRUCTURE);
		}
		return Optional.of(client);
	}
	static @NonNull OAuthServerClientRegistration authenticate(@NonNull OAuthServerRequest request,
			@NonNull OAuthServerClientRepository repository, @NonNull Deadline deadline, @NonNull OAuthServerIngressLimits limits) {
		requireNonNull(request);
		if (request.endpoint() == OAuthServerRequest.Endpoint.AUTHORIZATION) throw OAuthServerRequest.invalid();
		String header = request.authorization();
		if (header == null) {
			String id = request.value("client_id"); if (id == null || id.isEmpty()) throw failure(INVALID_CLIENT);
			OAuthServerClientRegistration client = registered(id, repository, deadline, limits);
			if (client.getAuthentication().isConfidential() || request.endpoint() == OAuthServerRequest.Endpoint.INTROSPECTION)
				throw failure(INVALID_CLIENT);
			return client;
		}
		// A body client_id is another credential channel in this profile, even when it matches Basic.
		if (request.value("client_id") != null) throw failure(INVALID_CLIENT);
		byte[] decoded = basic(header);
		byte @Nullable [] secret = null;
		try {
			int colon = 0; while (colon < decoded.length && decoded[colon] != ':') colon++;
			if (colon == decoded.length || colon > limits.clientIdLength) throw failure(INVALID_CLIENT);
			byte[] idBytes = component(decoded, 0, colon);
			String id;
			try { id = StrictUtf8.decode(idBytes); } finally { Arrays.fill(idBytes, (byte) 0); }
			secret = component(decoded, colon + 1, decoded.length);
			OAuthServerClientRegistration client = registered(id, repository, deadline, limits);
			OAuthClientSecretVerifier verifier = client.getAuthentication().verifier();
			if (verifier == null) throw failure(INVALID_CLIENT);
			Boolean accepted;
			try { accepted = verifier.verifiesClientSecret(id, secret, remaining(deadline)); }
			catch (VirtualMachineError fatal) { throw fatal; }
			catch (Throwable exception) { throw infrastructure(exception); }
			remaining(deadline);
			if (accepted == null) throw failure(INFRASTRUCTURE);
			if (!accepted) throw failure(INVALID_CLIENT);
			return client;
		} catch (EncodingException exception) { throw failure(INVALID_CLIENT); }
		finally { Arrays.fill(decoded, (byte) 0); if (secret != null) Arrays.fill(secret, (byte) 0); }
	}
	private static byte @NonNull [] basic(@NonNull String header) {
		// Basic is case-insensitive; exactly one SP and canonical padded Base64, no OWS/comma combination.
		if (header.length() <= 6 || !header.regionMatches(true, 0, "Basic ", 0, 6)) throw failure(INVALID_CLIENT);
		try { return StandardBase64.decode(header.substring(6)); }
		catch (EncodingException exception) { throw failure(INVALID_CLIENT); }
	}
	private static byte @NonNull [] component(byte @NonNull [] raw, int start, int end) {
		byte[] result = new byte[end - start]; int used = 0;
		try {
			for (int i = start; i < end; i++) {
				int c = raw[i] & 255;
				if (c > 127) throw failure(INVALID_CLIENT);
				if (c == '%') {
					if (i + 2 >= end) throw failure(INVALID_CLIENT);
					int high = hex(raw[++i] & 255), low = hex(raw[++i] & 255);
					if (high < 0 || low < 0) throw failure(INVALID_CLIENT);
					result[used++] = (byte) ((high << 4) | low);
				} else result[used++] = (byte) (c == '+' ? ' ' : c);
			}
			// Validate without ever constructing an immutable String containing the decoded secret.
			char[] characters = new char[used];
			try {
				var decoder = StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT)
						.onUnmappableCharacter(CodingErrorAction.REPORT);
				CharBuffer output = CharBuffer.wrap(characters);
				if (!decoder.decode(ByteBuffer.wrap(result, 0, used), output, true).isUnderflow()
						|| !decoder.flush(output).isUnderflow()) throw failure(INVALID_CLIENT);
			} finally { Arrays.fill(characters, '\0'); }
			return Arrays.copyOf(result, used);
		} finally { Arrays.fill(result, (byte) 0); }
	}
	private static int hex(int c) {
		if (c >= '0' && c <= '9') return c - '0';
		if (c >= 'a' && c <= 'f') return c - 'a' + 10;
		return c >= 'A' && c <= 'F' ? c - 'A' + 10 : -1;
	}
	private static @NonNull OAuthServerAdmissionFailure infrastructure(@NonNull Throwable exception) {
		if (exception instanceof InterruptedException) Thread.currentThread().interrupt();
		return failure(INFRASTRUCTURE);
	}
	static @NonNull Duration remaining(@NonNull Deadline deadline) {
		if (Thread.currentThread().isInterrupted()) throw failure(INFRASTRUCTURE);
		Duration remaining = deadline.remaining(); if (remaining.isNegative() || remaining.isZero()) throw failure(INFRASTRUCTURE);
		return remaining;
	}
	static @NonNull OAuthServerAdmissionFailure failure(OAuthServerAdmissionFailure.@NonNull Reason reason) {
		return new OAuthServerAdmissionFailure(reason);
	}
}
