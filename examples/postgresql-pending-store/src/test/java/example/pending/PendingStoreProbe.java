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

import com.revetsec.oauth.AuthorizationCompletionResult;
import com.revetsec.oauth.AuthorizationRedirect;
import com.revetsec.oauth.AuthorizationResponse;
import com.revetsec.oauth.AuthorizationServerMetadata;
import com.revetsec.oauth.ClientAuthentication;
import com.revetsec.oauth.OAuthClient;
import com.revetsec.oauth.PendingAuthorizationSource;
import com.revetsec.oauth.PendingAuthorizationStore;
import com.revetsec.oauth.PendingAuthorizationStoreException;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Duration;
import java.time.Instant;
import java.util.Properties;

/** Executable cross-JVM probe. The runner keeps emitted state in memory and does not archive it. */
public final class PendingStoreProbe {
	private static final @NonNull String NAMESPACE = "fixture";
	private static final @NonNull URI CALLBACK = URI.create("https://consumer.example/callback");
	private PendingStoreProbe() { }

	private static @NonNull Connection connection(@NonNull Duration remaining) throws java.sql.SQLException {
		int seconds = Math.max(1, (int) Math.min(30, (remaining.toMillis() + 999) / 1_000));
		Properties properties = new Properties();
		properties.setProperty("user", System.getenv("REVETSEC_TEST_DB_USER"));
		properties.setProperty("password", System.getenv("REVETSEC_TEST_DB_PASSWORD"));
		properties.setProperty("connectTimeout", Integer.toString(seconds));
		properties.setProperty("socketTimeout", Integer.toString(seconds));
		properties.setProperty("gssEncMode", "disable");
		return DriverManager.getConnection(System.getenv("REVETSEC_TEST_DB_URL"), properties);
	}

	private static @NonNull PostgresqlPendingAuthorizationStore store() {
		return new PostgresqlPendingAuthorizationStore(NAMESPACE, PendingStoreProbe::connection,
				1_024, 8 * 1_024, 4L * 1_024 * 1_024);
	}

	private static @NonNull PostgresqlPendingAuthorizationStore uncertainStore() {
		return new PostgresqlPendingAuthorizationStore(NAMESPACE, PendingStoreProbe::commitAcknowledgementLost,
				1_024, 8 * 1_024, 4L * 1_024 * 1_024);
	}

	private static @NonNull Connection commitAcknowledgementLost(@NonNull Duration remaining) throws SQLException {
		Connection physical = connection(remaining);
		return (Connection) Proxy.newProxyInstance(Connection.class.getClassLoader(),
				new Class<?>[] { Connection.class }, new java.lang.reflect.InvocationHandler() {
					@Override public @Nullable Object invoke(@NonNull Object proxy, @NonNull Method method,
							@Nullable Object @Nullable [] arguments) throws Throwable {
						try {
							Object result = method.invoke(physical, arguments);
							if (method.getName().equals("commit")) throw new SQLException("Test-only lost COMMIT acknowledgement.");
							return result;
						} catch (InvocationTargetException failure) {
							throw failure.getCause();
						}
					}
				});
	}

	private static @NonNull OAuthClient client(@NonNull Duration deadline) {
		AuthorizationServerMetadata metadata = AuthorizationServerMetadata.withIssuer("https://issuer.example")
				.authorizationEndpoint(URI.create("https://issuer.example/authorize"))
				.tokenEndpoint(URI.create("https://issuer.example/token")).build();
		return OAuthClient.withAuthorizationServerMetadata(metadata).clientId("distributed-probe")
				.clientAuthentication(ClientAuthentication.noneInstance()).redirectUri(CALLBACK)
				.requestTimeout(Duration.ofSeconds(1)).totalDeadline(deadline).build();
	}

	private static @NonNull OAuthClient codeClient(@NonNull String issuer) {
		URI base = URI.create(issuer);
		AuthorizationServerMetadata metadata = AuthorizationServerMetadata.withIssuer(issuer)
				.authorizationEndpoint(base.resolve("/authorize"))
				.tokenEndpoint(base.resolve("/token")).build();
		return OAuthClient.withAuthorizationServerMetadata(metadata).clientId("distributed-probe")
				.clientAuthentication(ClientAuthentication.noneInstance()).redirectUri(CALLBACK)
				.allowInsecureLoopback(true).requestTimeout(Duration.ofSeconds(1))
				.totalDeadline(Duration.ofSeconds(3)).build();
	}

	private static @NonNull String queryValue(@NonNull AuthorizationRedirect redirect, @NonNull String name) {
		for (String part : redirect.getAuthorizationUri().getRawQuery().split("&")) {
			String[] pair = part.split("=", 2);
			if (pair[0].equals(name)) return URLDecoder.decode(pair[1], StandardCharsets.UTF_8);
		}
		throw new IllegalStateException("Authorization parameter missing.");
	}

	private static @NonNull String state(@NonNull AuthorizationRedirect redirect) {
		return queryValue(redirect, "state");
	}

	private static @NonNull String callback(@NonNull String state, @NonNull String binding,
			@NonNull Duration deadline) {
		AuthorizationResponse response = AuthorizationResponse.fromQueryString("state=" + state + "&error=access_denied");
		AuthorizationCompletionResult result = client(deadline).completeAuthorizationResult(response,
				PendingAuthorizationSource.fromStore(store(), binding), CALLBACK);
		if (result instanceof AuthorizationCompletionResult.Denied) return "DENIED";
		if (result instanceof AuthorizationCompletionResult.Rejected rejected) return "REJECTED:" + rejected.getReason();
		if (result instanceof AuthorizationCompletionResult.Failed failed) return "FAILED:" + failed.getReason();
		throw new IllegalStateException("Unexpected callback result.");
	}

	private static @NonNull String codeCallback(@NonNull String state, @NonNull String binding,
			@NonNull String issuer) {
		return codeCallback(state, binding, issuer, store());
	}

	private static @NonNull String codeCallback(@NonNull String state, @NonNull String binding,
			@NonNull String issuer, @NonNull PendingAuthorizationStore pendingStore) {
		AuthorizationResponse response = AuthorizationResponse.fromQueryString("state=" + state + "&code=test-only-code");
		AuthorizationCompletionResult result = codeClient(issuer).completeAuthorizationResult(response,
				PendingAuthorizationSource.fromStore(pendingStore, binding), CALLBACK);
		if (result instanceof AuthorizationCompletionResult.Succeeded succeeded) {
			if (!succeeded.getTokens().getAccessToken().getValue().equals("test-only-token"))
				throw new IllegalStateException("Unexpected synthetic access token.");
			return "SUCCEEDED";
		}
		if (result instanceof AuthorizationCompletionResult.Rejected rejected) return "REJECTED:" + rejected.getReason();
		if (result instanceof AuthorizationCompletionResult.Failed failed) return "FAILED:" + failed.getReason();
		throw new IllegalStateException("Unexpected code callback result.");
	}

	private static void hold() throws Exception {
		try (Connection connection = connection(Duration.ofSeconds(5))) {
			connection.setAutoCommit(false);
			try (PreparedStatement statement = connection.prepareStatement(
					"SELECT observed_seconds FROM pending_authorization_clock WHERE namespace=? FOR UPDATE")) {
				statement.setString(1, NAMESPACE);
				try (ResultSet result = statement.executeQuery()) {
					if (!result.next()) throw new IllegalStateException("Clock fence missing.");
				}
			}
			System.out.println("READY");
			System.out.flush();
			Thread.sleep(2_500);
			connection.rollback();
		}
	}

	public static void main(@NonNull String @NonNull [] args) throws Exception {
		PostgresqlPendingAuthorizationStore store = store();
		switch (args[0]) {
			case "issue" -> {
				AuthorizationRedirect redirect = client(Duration.ofSeconds(3)).beginAuthorization();
				redirect.getPendingAuthorization().saveTo(store, args[1], Duration.ofSeconds(3));
				System.out.println(state(redirect));
			}
			case "callback" -> System.out.println(callback(args[1], args[2], Duration.ofSeconds(3)));
			case "callback-short" -> System.out.println(callback(args[1], args[2], Duration.ofSeconds(1)));
			case "callback-race" -> {
				System.out.println("READY");
				System.out.flush();
				if (System.in.read() == -1) throw new IllegalStateException("Race signal missing.");
				System.out.println(callback(args[1], args[2], Duration.ofSeconds(3)));
			}
			case "issue-code" -> {
				AuthorizationRedirect redirect = codeClient(args[2]).beginAuthorization();
				redirect.getPendingAuthorization().saveTo(store, args[1], Duration.ofSeconds(3));
				if (!queryValue(redirect, "code_challenge_method").equals("S256"))
					throw new IllegalStateException("Unexpected PKCE method.");
				System.out.println(state(redirect) + "\t" + queryValue(redirect, "code_challenge"));
			}
			case "issue-code-unknown" -> {
				AuthorizationRedirect redirect = codeClient(args[2]).beginAuthorization();
				boolean failedClosed = false;
				try { redirect.getPendingAuthorization().saveTo(uncertainStore(), args[1], Duration.ofSeconds(3)); }
				catch (PendingAuthorizationStoreException expected) { failedClosed = true; }
				if (!failedClosed) throw new IllegalStateException("Unknown save commit released a redirect.");
				if (store.consume(args[1], state(redirect), Duration.ofSeconds(3)).isEmpty())
					throw new IllegalStateException("Injected save COMMIT did not happen.");
				System.out.println("UNCERTAIN_SAVE_NO_REDIRECT");
			}
			case "callback-code" -> System.out.println(codeCallback(args[1], args[2], args[3]));
			case "callback-code-unknown" -> System.out.println(codeCallback(args[1], args[2], args[3], uncertainStore()));
			case "callback-code-race" -> {
				System.out.println("READY");
				System.out.flush();
				if (System.in.read() == -1) throw new IllegalStateException("Race signal missing.");
				System.out.println(codeCallback(args[1], args[2], args[3]));
			}
			case "hold" -> hold();
			case "duplicate" -> {
				String key = "duplicate-" + System.nanoTime();
				Instant expiry = Instant.now().plusSeconds(60);
				store.save("browser", key, "first", expiry, Duration.ofSeconds(3));
				boolean rejected = false;
				try { store.save("browser", key, "second", expiry, Duration.ofSeconds(3)); }
				catch (IllegalArgumentException expected) { rejected = true; }
				if (!rejected || !store.consume("browser", key, Duration.ofSeconds(3)).orElseThrow().equals("first"))
					throw new IllegalStateException("Duplicate was accepted or replaced the first record.");
				System.out.println("DUPLICATE_REJECTED");
			}
			case "expiry" -> {
				String key = "expiry-" + System.nanoTime();
				store.save("browser", key, "record", Instant.now().plusMillis(250), Duration.ofSeconds(3));
				Thread.sleep(400);
				if (store.consume("browser", key, Duration.ofSeconds(3)).isPresent())
					throw new IllegalStateException("Expired record returned.");
				System.out.println("EXPIRED_ABSENT");
			}
			case "zero-budget" -> {
				String key = "budget-" + System.nanoTime();
				store.save("browser", key, "record", Instant.now().plusSeconds(60), Duration.ofSeconds(3));
				try {
					store.consume("browser", key, Duration.ZERO);
					throw new IllegalStateException("Zero-budget consume succeeded.");
				} catch (IllegalStateException expected) {
					if (!store.consume("browser", key, Duration.ofSeconds(3)).orElseThrow().equals("record"))
						throw new IllegalStateException("Zero-budget consume changed the record.");
					System.out.println("ZERO_BUDGET_NO_MUTATION");
				}
			}
			case "long-budget" -> {
				String key = "long-budget-" + System.nanoTime();
				store.save("browser", key, "record", Instant.now().plusSeconds(60), Duration.ofMinutes(2));
				if (!store.consume("browser", key, Duration.ofMinutes(2)).orElseThrow().equals("record"))
					throw new IllegalStateException("Long-budget call failed.");
				System.out.println("LONG_BUDGET_BOUNDED");
			}
			case "unknown-consume" -> {
				String key = "unknown-" + System.nanoTime();
				store.save("browser", key, "record", Instant.now().plusSeconds(60), Duration.ofSeconds(3));
				boolean failedClosed = false;
				try { uncertainStore().consume("browser", key, Duration.ofSeconds(3)); }
				catch (IllegalStateException expected) { failedClosed = true; }
				if (!failedClosed) throw new IllegalStateException("Unknown commit released a record.");
				if (store.consume("browser", key, Duration.ofSeconds(3)).isPresent())
					throw new IllegalStateException("Injected COMMIT did not happen.");
				System.out.println("UNKNOWN_COMMIT_NO_RELEASE");
			}
			case "capacity" -> {
				PostgresqlPendingAuthorizationStore tiny = new PostgresqlPendingAuthorizationStore(NAMESPACE,
						PendingStoreProbe::connection, 1, 8 * 1_024, 64 * 1_024);
				String first = "capacity-a-" + System.nanoTime();
				store.save("browser", first, "record", Instant.now().plusSeconds(60), Duration.ofSeconds(3));
				String second = "capacity-b-" + System.nanoTime();
				boolean refused = false;
				try { tiny.save("browser", second, "record", Instant.now().plusSeconds(60), Duration.ofSeconds(3)); }
				catch (IllegalStateException expected) { refused = true; }
				if (!refused || !store.consume("browser", first, Duration.ofSeconds(3)).orElseThrow().equals("record")
						|| store.consume("browser", second, Duration.ofSeconds(3)).isPresent())
					throw new IllegalStateException("Capacity refusal was not atomic.");
				System.out.println("CAPACITY_NO_EVICTION");
			}
			case "future-fence" -> {
				PostgresqlPendingAuthorizationStore clockStore = new PostgresqlPendingAuthorizationStore(
						"fixture_clock", PendingStoreProbe::connection, 1_024, 8 * 1_024, 4L * 1_024 * 1_024);
				String key = "clock-" + System.nanoTime();
				clockStore.save("browser", key, "record", Instant.now().plusSeconds(60), Duration.ofSeconds(3));
				try (Connection connection = connection(Duration.ofSeconds(3));
						PreparedStatement statement = connection.prepareStatement("UPDATE pending_authorization_clock "
								+ "SET observed_seconds=?,observed_nanos=0 WHERE namespace=?")) {
					statement.setLong(1, Instant.now().plusSeconds(90).getEpochSecond());
					statement.setString(2, "fixture_clock");
					statement.executeUpdate();
				}
				if (clockStore.consume("browser", key, Duration.ofSeconds(3)).isPresent())
					throw new IllegalStateException("Clock rollback revived a record.");
				System.out.println("ROLLBACK_FENCED");
			}
			default -> throw new IllegalArgumentException("Unknown probe mode.");
		}
	}
}
