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

import com.revetsec.SealingKey;
import com.revetsec.StateSealer;
import com.revetsec.oauth.BearerToken;
import com.revetsec.oauth.server.OAuthAuthorizationDecision;
import com.revetsec.oauth.server.OAuthAuthorizationResult;
import com.revetsec.oauth.server.OAuthAuthorizationServer;
import com.revetsec.oauth.server.OAuthIssuerAccessTokenResult;
import com.revetsec.oauth.server.OAuthIssuerKeyProvider;
import com.revetsec.oauth.server.OAuthIssuerKeySnapshot;
import com.revetsec.oauth.server.OAuthIssuerSigningKey;
import com.revetsec.oauth.server.OAuthAuthorizationServerStore;
import com.revetsec.oauth.server.OAuthServerClientAuthentication;
import com.revetsec.oauth.server.OAuthServerClientRegistration;
import com.revetsec.oauth.server.OAuthServerException;
import com.revetsec.oauth.server.OAuthServerStoreException;
import com.revetsec.oauth.server.OAuthStoreCommitStatus;
import com.revetsec.oauth.server.OAuthStoreEntry;
import com.revetsec.oauth.server.OAuthStoreKey;
import com.revetsec.oauth.server.OAuthStoreTransaction;
import com.revetsec.oauth.server.OAuthTokenResult;
import org.jspecify.annotations.NonNull;

import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.concurrent.atomic.AtomicInteger;

/** Local synthetic issuer workflow in independent JVMs. Secrets live only in the runner's tempdir. */
public final class IssuerStoreProbe {
	private static final @NonNull String ISSUER = "https://issuer.example";
	private static final @NonNull String RESOURCE = "https://resource.example/mcp";
	private static final @NonNull String REDIRECT = "https://client.example/cb";
	private static final @NonNull String BROWSER = "A".repeat(43);
	private static final @NonNull String VERIFIER = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
	private IssuerStoreProbe() { }

	private static @NonNull Path secretDirectory() {
		return Path.of(java.util.Objects.requireNonNull(System.getenv("REVETSEC_TEST_ISSUER_SECRET_DIR")));
	}

	private static void keygen() throws Exception {
		KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
		generator.initialize(3072);
		KeyPair pair = generator.generateKeyPair();
		Path directory = secretDirectory();
		Files.write(directory.resolve("private.der"), pair.getPrivate().getEncoded());
		Files.write(directory.resolve("public.der"), pair.getPublic().getEncoded());
		KeyPair next = generator.generateKeyPair();
		Files.write(directory.resolve("private-next.der"), next.getPrivate().getEncoded());
		Files.write(directory.resolve("public-next.der"), next.getPublic().getEncoded());
		Files.writeString(directory.resolve("key-generation.txt"), "g1", StandardCharsets.US_ASCII);
		byte[] sealing = new byte[32];
		new SecureRandom().nextBytes(sealing);
		Files.writeString(directory.resolve("sealer.txt"),
				Base64.getEncoder().encodeToString(sealing), StandardCharsets.US_ASCII);
		java.util.Arrays.fill(sealing, (byte) 0);
		byte[] partition = new byte[32];
		new SecureRandom().nextBytes(partition);
		Files.write(directory.resolve("partition.key"), partition);
		java.util.Arrays.fill(partition, (byte) 0);
		System.out.println("KEYS_READY");
	}

	private static @NonNull OAuthAuthorizationServer server(@NonNull OAuthAuthorizationServerStore store)
			throws Exception {
		return server(store, Duration.ofSeconds(10));
	}

	private static @NonNull OAuthAuthorizationServer server(@NonNull OAuthAuthorizationServerStore store,
			@NonNull Duration totalDeadline) throws Exception {
		Path directory = secretDirectory();
		KeyFactory factory = KeyFactory.getInstance("RSA");
		var privateKey = factory.generatePrivate(new PKCS8EncodedKeySpec(Files.readAllBytes(directory.resolve("private.der"))));
		var publicKey = factory.generatePublic(new X509EncodedKeySpec(Files.readAllBytes(directory.resolve("public.der"))));
		var keys = OAuthIssuerKeySnapshot.withActiveKey(
				OAuthIssuerSigningKey.fromKeyPair("fixture", privateKey, publicKey))
				.generation("g1").publishedAt(Instant.parse("2026-10-06T11:00:00Z")).build();
		var resources = Map.of(RESOURCE, Set.of("read"));
		var client = OAuthServerClientRegistration.withClientId("client").configurationVersion("v1")
				.redirectUris(List.of(URI.create(REDIRECT))).allowedScopesByResource(resources)
				.refreshTokenPermitted(true).build();
		var resource = OAuthServerClientRegistration.withClientId("resource").configurationVersion("v1")
				.authorizationCodePermitted(false).introspectionResources(Set.of(RESOURCE))
				.authentication(OAuthServerClientAuthentication.fromClientSecretVerifier(
						(id, secret, budget) -> java.util.Arrays.equals(secret,
								"fixture-secret".getBytes(StandardCharsets.UTF_8)))).build();
		SealingKey sealingKey = SealingKey.fromBase64("fixture", Files.readString(directory.resolve("sealer.txt")));
		return OAuthAuthorizationServer.withIssuer(ISSUER).authorizationEndpoint(URI.create(ISSUER + "/authorize"))
				.tokenEndpoint(URI.create(ISSUER + "/token")).jsonWebKeySetEndpoint(URI.create(ISSUER + "/jwks"))
				.revocationEndpoint(URI.create(ISSUER + "/revoke"))
				.introspectionEndpoint(URI.create(ISSUER + "/introspect"))
				.clientRepository((id, budget) -> Optional.ofNullable(
						id.equals("client") ? client : id.equals("resource") ? resource : null))
				.store(store)
				.signingKeys(OAuthIssuerKeyProvider.fromSnapshot(keys)).resources(resources)
				.stateSealer(StateSealer.withActiveKey(sealingKey).build())
				.grantPolicy((context, budget) -> decision()).refreshTokensEnabled(true)
				.clock(Clock.fixed(Instant.ofEpochSecond(Long.parseLong(
						java.util.Objects.requireNonNull(System.getenv("REVETSEC_TEST_ISSUER_TIME")))), ZoneOffset.UTC))
				.requestTimeout(totalDeadline.compareTo(Duration.ofSeconds(5)) < 0
						? Duration.ofSeconds(1) : Duration.ofSeconds(5))
				.totalDeadline(totalDeadline).build();
	}

	private static @NonNull OAuthAuthorizationDecision decision() {
		return OAuthAuthorizationDecision.withSubject("subject")
				.authorizedScopesByResource(Map.of(RESOURCE, Set.of("read")))
				.refreshTokenPermitted(true).build();
	}

	private static @NonNull String form(@NonNull Map<@NonNull String, @NonNull String> values) {
		return values.entrySet().stream().map(item -> URLEncoder.encode(item.getKey(), StandardCharsets.UTF_8)
				+ "=" + URLEncoder.encode(item.getValue(), StandardCharsets.UTF_8))
				.reduce((left, right) -> left + "&" + right).orElse("");
	}

	private static @NonNull String issue(@NonNull OAuthAuthorizationServer server) {
		String query = form(Map.of("client_id", "client", "response_type", "code", "redirect_uri", REDIRECT,
				"resource", RESOURCE, "code_challenge", "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
				"code_challenge_method", "S256", "state", "fixture"));
		var interaction = ((OAuthAuthorizationResult.InteractionRequired) server.beginAuthorizationResult(
				"GET", query, new byte[0], Map.of(), BROWSER)).getInteraction();
		var completed = (OAuthAuthorizationResult.Completed) server.completeAuthorizationResult(
				interaction.getInteractionValue(), BROWSER, decision());
		String location = completed.getResponse().getLocationWithCredentials().orElseThrow().toString();
		int start = location.indexOf("code=");
		int end = location.indexOf("&state=", start);
		if (start < 0 || end <= start) throw new IllegalStateException("Missing synthetic code.");
		return location.substring(start + 5, end);
	}

	private static @NonNull OAuthTokenResult redeemResult(@NonNull OAuthAuthorizationServer server,
			@NonNull String code) {
		byte[] body = form(Map.of("grant_type", "authorization_code", "client_id", "client", "code", code,
				"code_verifier", VERIFIER, "resource", RESOURCE, "redirect_uri", REDIRECT))
				.getBytes(StandardCharsets.UTF_8);
		return server.tokenResult("POST", null, body,
				Map.of("Content-Type", List.of("application/x-www-form-urlencoded")));
	}

	private static @NonNull OAuthTokenResult refreshResult(@NonNull OAuthAuthorizationServer server,
			@NonNull String refreshToken) {
		byte[] body = form(Map.of("grant_type", "refresh_token", "client_id", "client",
				"refresh_token", refreshToken, "resource", RESOURCE)).getBytes(StandardCharsets.UTF_8);
		return server.tokenResult("POST", null, body,
				Map.of("Content-Type", List.of("application/x-www-form-urlencoded")));
	}

	private static @NonNull String tokenField(@NonNull String json, @NonNull String name) {
		Matcher match = Pattern.compile("\"" + name + "\"\\s*:\\s*\"([A-Za-z0-9_.-]+)\"").matcher(json);
		if (!match.find()) throw new IllegalStateException("Missing synthetic token field.");
		String token = match.group(1);
		if (match.find()) throw new IllegalStateException("Duplicate synthetic token field.");
		return token;
	}

	private static @NonNull String redeem(@NonNull OAuthAuthorizationServer server, @NonNull String code) {
		OAuthTokenResult result = redeemResult(server, code);
		if (result instanceof OAuthTokenResult.Rejected) return "REJECTED";
		String json = new String(((OAuthTokenResult.Succeeded) result).getResponse()
				.toHttpBodyWithCredentials(), StandardCharsets.UTF_8);
		return "TOKEN:" + tokenField(json, "access_token");
	}

	private static @NonNull String tokenPair(@NonNull OAuthTokenResult result) {
		if (result instanceof OAuthTokenResult.Rejected) return "REJECTED";
		String json = new String(((OAuthTokenResult.Succeeded) result).getResponse()
				.toHttpBodyWithCredentials(), StandardCharsets.UTF_8);
		return "PAIR:" + tokenField(json, "access_token") + "\t" + tokenField(json, "refresh_token");
	}

	private static @NonNull OAuthAuthorizationServerStore uncertainCommitStore() {
		PostgresqlIssuerStore reads = new PostgresqlIssuerStore(
				"fixture_issuer", PendingStoreProbe::connection, 256);
		PostgresqlIssuerStore commits = new PostgresqlIssuerStore(
				"fixture_issuer", PendingStoreProbe::commitAcknowledgementLost, 256);
		return new OAuthAuthorizationServerStore() {
			@Override public @NonNull Optional<@NonNull OAuthStoreEntry> read(@NonNull OAuthStoreKey key,
					@NonNull Duration remainingBudget) {
				return reads.read(key, remainingBudget);
			}
			@Override public @NonNull OAuthStoreCommitStatus commit(@NonNull OAuthStoreTransaction transaction,
					@NonNull Duration remainingBudget) {
				return commits.commit(transaction, remainingBudget);
			}
		};
	}

	public static void main(@NonNull String @NonNull [] args) throws Exception {
		if (args[0].equals("keygen")) { keygen(); return; }
		if (args[0].equals("active-short-budget") || args[0].equals("revoke-short-budget")) {
			OAuthAuthorizationServer bounded = server(new PostgresqlIssuerStore("fixture_issuer",
					PendingStoreProbe::connection, 256), Duration.ofSeconds(1));
			try {
				if (args[0].equals("active-short-budget")) {
					var status = bounded.validateAccessTokenResult(
							BearerToken.fromAuthorizationHeaderValues(List.of("Bearer " + args[1])).orElseThrow(), RESOURCE);
					System.out.println(status instanceof OAuthIssuerAccessTokenResult.Succeeded ? "ACTIVE" : "INACTIVE");
				} else {
					bounded.revokeAllGrants();
					System.out.println("REVOKED");
				}
			} catch (OAuthServerStoreException failure) {
				if (failure.getReason() != OAuthServerException.Reason.STORE_UNAVAILABLE) throw failure;
				System.out.println("STORE_UNAVAILABLE");
			}
			return;
		}
		if (args[0].equals("unknown-init")) {
			AtomicInteger opened = new AtomicInteger();
			PostgresqlIssuerStore uncertain = new PostgresqlIssuerStore("fixture_issuer_unknown",
					remaining -> opened.incrementAndGet() == 2
							? PendingStoreProbe.commitAcknowledgementLost(remaining)
							: PendingStoreProbe.connection(remaining), 256);
			System.out.println(server(uncertain).initializeFreshIssuer());
			return;
		}
		if (args[0].equals("reconcile-unknown")) {
			System.out.println(server(new PostgresqlIssuerStore("fixture_issuer_unknown",
					PendingStoreProbe::connection, 256)).initializeFreshIssuer());
			return;
		}
		if (args[0].equals("unknown-subject-revoke")) {
			try {
				server(uncertainCommitStore()).revokeSubject("subject");
				throw new IllegalStateException("An uncertain subject revocation reported success.");
			} catch (OAuthServerStoreException failure) {
				if (failure.getReason() != OAuthServerException.Reason.COMMIT_OUTCOME_UNKNOWN) throw failure;
				System.out.println("UNKNOWN_REVOCATION_REPORTED");
			}
			return;
		}
		if (args[0].equals("unknown-refresh") || args[0].equals("unknown-redeem")) {
			try {
				OAuthAuthorizationServer uncertain = server(uncertainCommitStore());
				OAuthTokenResult result = args[0].equals("unknown-refresh")
						? refreshResult(uncertain, args[1]) : redeemResult(uncertain, args[1]);
				throw new IllegalStateException(result instanceof OAuthTokenResult.Succeeded
						? "An uncertain token grant released credentials." : "An uncertain token grant was rejected.");
			} catch (OAuthServerStoreException failure) {
				if (failure.getReason() != OAuthServerException.Reason.COMMIT_OUTCOME_UNKNOWN) throw failure;
				System.out.println("UNKNOWN_NO_CREDENTIALS");
			}
			return;
		}
		OAuthAuthorizationServer server = server(new PostgresqlIssuerStore(
				args[0].startsWith("fence-") ? "fixture_issuer_fence" : "fixture_issuer",
				PendingStoreProbe::connection,
				args[0].equals("active-small-cap") || args[0].equals("issue-small-cap") ? 1 : 256));
		switch (args[0]) {
			case "init", "fence-init" -> {
				if (server.initializeFreshIssuer() != OAuthStoreCommitStatus.COMMITTED)
					throw new IllegalStateException("Issuer initialization was not confirmed.");
				server.establishNewSubject("subject");
				System.out.println("INITIALIZED");
			}
			case "issue", "fence-issue" -> System.out.println(issue(server));
			case "issue-small-cap" -> {
				try {
					issue(server);
					throw new IllegalStateException("Issuer capacity refusal released a code.");
				} catch (OAuthServerStoreException failure) {
					if (failure.getReason() != OAuthServerException.Reason.STORE_UNAVAILABLE) throw failure;
					System.out.println("CAPACITY_REFUSED");
				}
			}
			case "redeem", "fence-redeem" -> System.out.println(redeem(server, args[1]));
			case "redeem-pair" -> System.out.println(tokenPair(redeemResult(server, args[1])));
			case "refresh" -> System.out.println(tokenPair(refreshResult(server, args[1])));
			case "race" -> {
				System.out.println("READY");
				System.out.flush();
				if (System.in.read() == -1) throw new IllegalStateException("Race signal missing.");
				System.out.println(redeem(server, args[1]));
			}
			case "refresh-race" -> {
				System.out.println("READY");
				System.out.flush();
				if (System.in.read() == -1) throw new IllegalStateException("Race signal missing.");
				System.out.println(tokenPair(refreshResult(server, args[1])));
			}
			case "active", "active-small-cap", "fence-active" -> {
				var status = server.validateAccessTokenResult(
						BearerToken.fromAuthorizationHeaderValues(List.of("Bearer " + args[1])).orElseThrow(), RESOURCE);
				System.out.println(status instanceof OAuthIssuerAccessTokenResult.Succeeded ? "ACTIVE"
						: "INACTIVE:" + ((OAuthIssuerAccessTokenResult.Rejected) status).getReason());
			}
			case "revoke" -> { server.revokeAllGrants(); System.out.println("REVOKED"); }
			case "subject-revoke" -> { server.revokeSubject("subject"); System.out.println("SUBJECT_REVOKED"); }
			default -> throw new IllegalArgumentException("Unknown issuer probe mode.");
		}
	}
}
