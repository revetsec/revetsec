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

import com.revetsec.internal.encoding.Base64Url;
import com.revetsec.internal.encoding.EncodingException;
import com.revetsec.internal.http.Deadline;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import java.net.URI;
import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import static java.util.Objects.requireNonNull;
import static com.revetsec.oauth.server.OAuthServerClientAdmission.failure;
import static com.revetsec.oauth.server.OAuthServerAdmissionFailure.Reason.*;

/** Exact registered redirect/resource/scope selection; produces no Location, interaction or credential. */
final class OAuthServerAuthorizationAdmission {
	private final @NonNull OAuthServerClientRegistration client;
	private final @NonNull String redirect, resource, challenge;
	private final @Nullable String state;
	private final @NonNull Set<@NonNull String> scopes;
	private OAuthServerAuthorizationAdmission(@NonNull OAuthServerClientRegistration client, @NonNull String redirect,
			@NonNull String resource, @NonNull String challenge, @Nullable String state, @NonNull Set<@NonNull String> scopes) {
		this.client = client; this.redirect = redirect; this.resource = resource; this.challenge = challenge;
		this.state = state; this.scopes = Set.copyOf(scopes);
	}
	static @NonNull OAuthServerAuthorizationAdmission admit(@NonNull OAuthServerRequest request,
			@NonNull OAuthServerClientRepository repository, @NonNull Deadline deadline,
			@NonNull Map<@NonNull String, @NonNull Set<@NonNull String>> serverResources,
			@NonNull OAuthServerIngressLimits limits, boolean nativeLoopback, boolean localhostInterop) {
		requireNonNull(request); requireNonNull(serverResources);
		serverResources = checkedServerResources(serverResources, limits);
		if (request.endpoint() != OAuthServerRequest.Endpoint.AUTHORIZATION) throw OAuthServerRequest.invalid();
		OAuthServerClientRegistration client = OAuthServerClientAdmission.registered(request.required("client_id"), repository, deadline, limits);
		if (!client.isAuthorizationCodePermitted()) throw failure(UNAUTHORIZED_CLIENT);
		String redirect = request.required("redirect_uri");
		if (!matchesRedirect(client, redirect, nativeLoopback, localhostInterop)) throw OAuthServerRequest.invalid();
		if (!request.required("response_type").equals("code")) throw failure(UNSUPPORTED_RESPONSE_TYPE);
		String mode = request.value("response_mode"); if (mode != null && !mode.equals("query")) throw OAuthServerRequest.invalid();
		String challenge = request.required("code_challenge");
		if (!request.required("code_challenge_method").equals("S256") || !challenge(challenge)) throw OAuthServerRequest.invalid();
		String resource = request.required("resource");
		Set<String> scopes = selectScopes(resource, request.value("scope"), client, serverResources, limits);
		return new OAuthServerAuthorizationAdmission(client, redirect, resource, challenge, request.value("state"), scopes);
	}
	private static @NonNull Map<@NonNull String, @NonNull Set<@NonNull String>> checkedServerResources(
			@NonNull Map<@NonNull String, @NonNull Set<@NonNull String>> resources, @NonNull OAuthServerIngressLimits limits) {
		Map<String, Set<String>> checked = OAuthServerConfiguration.resources(resources, limits.resources);
		for (Set<String> scopes : checked.values()) {
			if (scopes.size() > limits.scopes) throw OAuthServerConfiguration.invalid();
			for (String scope : scopes) if (scope.length() > limits.scopeLength) throw OAuthServerConfiguration.invalid();
		}
		return checked;
	}
	static boolean matchesRedirect(@NonNull OAuthServerClientRegistration client, @NonNull String supplied,
			boolean nativeLoopback, boolean localhostInterop) {
		URI candidate;
		try { candidate = URI.create(supplied); OAuthServerConfiguration.redirects(List.of(candidate)); }
		catch (IllegalArgumentException exception) { return false; }
		for (URI registered : client.getRedirectUris()) {
			if (registered.getScheme().equalsIgnoreCase("https")) {
				if (registered.toString().equals(supplied)) return true;
			} else if (registered.getHost().equals("localhost")) {
				if (localhostInterop && registered.toString().equals(supplied)) return true;
			} else if (nativeLoopback && candidate.getScheme().equalsIgnoreCase("http")
					&& (candidate.getHost().equals("127.0.0.1") || candidate.getHost().equals("[::1]"))
					&& withoutPort(registered).equals(withoutPort(candidate))) return true;
		}
		return false;
	}
	private static @NonNull String withoutPort(@NonNull URI value) {
		String authority = requireNonNull(value.getRawAuthority());
		int end = authority.startsWith("[") ? authority.indexOf(']') + 1 : authority.indexOf(':');
		if (end < 0 || end == authority.length()) return value.toString();
		int start = value.getScheme().length() + 3;
		return value.toString().substring(0, start + end) + value.toString().substring(start + authority.length());
	}
	static @NonNull Set<@NonNull String> selectScopes(@NonNull String resource, @Nullable String requested,
			@NonNull OAuthServerClientRegistration client,
			@NonNull Map<@NonNull String, @NonNull Set<@NonNull String>> serverResources, @NonNull OAuthServerIngressLimits limits) {
		Set<String> server = serverResources.get(resource), allowed = client.getAllowedScopesByResource().get(resource);
		if (server == null || allowed == null) throw failure(INVALID_TARGET);
		// Server configuration is a trusted immutable snapshot checked before these helpers are wired into an engine.
		Set<String> intersection = new LinkedHashSet<>(allowed); intersection.retainAll(server);
		if (requested == null) { if (intersection.isEmpty()) throw failure(INVALID_SCOPE); return Set.copyOf(intersection); }
		Set<String> selected = new LinkedHashSet<>(); int count = 0;
		for (int start = 0; start <= requested.length();) {
			int end = requested.indexOf(' ', start); if (end < 0) end = requested.length();
			if (end == start || end - start > limits.scopeLength || ++count > limits.scopes) throw failure(INVALID_SCOPE);
			String scope = requested.substring(start, end);
			try { OAuthServerConfiguration.scope(scope); } catch (IllegalArgumentException exception) { throw failure(INVALID_SCOPE); }
			if (!intersection.contains(scope)) throw failure(INVALID_SCOPE);
			selected.add(scope); if (end == requested.length()) break; start = end + 1;
		}
		return Set.copyOf(selected);
	}
	static boolean challenge(@NonNull String value) {
		if (value.length() != 43) return false;
		try { byte[] bytes = Base64Url.decode(value); try { return bytes.length == 32; } finally { Arrays.fill(bytes, (byte) 0); } }
		catch (EncodingException exception) { return false; }
	}
	static void requireTokenGrant(@NonNull OAuthServerRequest request) {
		if (request.endpoint() != OAuthServerRequest.Endpoint.TOKEN) throw OAuthServerRequest.invalid();
		String grant = request.required("grant_type");
		if (grant.equals("authorization_code")) {
			request.required("code"); String verifier = request.required("code_verifier");
			if (verifier.length() < 43 || verifier.length() > 128) throw OAuthServerRequest.invalid();
			for (int i = 0; i < verifier.length(); i++) {
				char c = verifier.charAt(i);
				if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
						|| "-._~".indexOf(c) >= 0)) throw OAuthServerRequest.invalid();
			}
		} else if (grant.equals("refresh_token")) request.required("refresh_token");
		else throw failure(UNSUPPORTED_GRANT_TYPE);
		request.required("resource");
	}
	@NonNull OAuthServerClientRegistration client() { return this.client; }
	@NonNull String redirect() { return this.redirect; }
	@NonNull String resource() { return this.resource; }
	@NonNull String challenge() { return this.challenge; }
	@Nullable String state() { return this.state; }
	@NonNull Set<@NonNull String> scopes() { return this.scopes; }
	@Override public @NonNull String toString() { return "OAuthServerAuthorizationAdmission{<redacted>}"; }
}
