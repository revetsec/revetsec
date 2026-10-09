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

import com.revetsec.oauth.server.OAuthClientMetadataCacheEntry;
import com.revetsec.oauth.server.OAuthClientMetadataCacheException;
import com.revetsec.oauth.server.OAuthClientMetadataCacheKey;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.nio.ByteBuffer;
import java.sql.Connection;
import java.sql.SQLException;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.Optional;

/** Small independent-process storage probe; all data is synthetic. */
public final class ClientMetadataCacheProbe {
	private ClientMetadataCacheProbe() { }

	private static @NonNull String nonce(int value) {
		return Base64.getUrlEncoder().withoutPadding().encodeToString(
				ByteBuffer.allocate(32).putInt(value).array());
	}

	private static @NonNull OAuthClientMetadataCacheKey key(int value) {
		return OAuthClientMetadataCacheKey.fromStoredForm("revetsec:cimd-cache:1:" + nonce(1) + ":" + nonce(value));
	}

	private static @NonNull OAuthClientMetadataCacheEntry entry(int key, int version) {
		return OAuthClientMetadataCacheEntry.fromStoredForm(key(key), nonce(version),
				Instant.ofEpochSecond(2_000_000_000L), "synthetic-encrypted-envelope-" + version);
	}

	private static @NonNull PostgresqlClientMetadataCache cache() {
		return new PostgresqlClientMetadataCache("fixture_cache", PendingStoreProbe::connection, 2);
	}

	private static @NonNull Connection closeAcknowledgementLost(@NonNull Duration remaining) throws SQLException {
		Connection physical = PendingStoreProbe.connection(remaining);
		return (Connection) Proxy.newProxyInstance(Connection.class.getClassLoader(),
				new Class<?>[] { Connection.class }, new java.lang.reflect.InvocationHandler() {
					@Override public @Nullable Object invoke(@NonNull Object proxy, @NonNull Method method,
							@Nullable Object @Nullable [] arguments) throws Throwable {
						try {
							Object result = method.invoke(physical, arguments);
							if (method.getName().equals("close")) throw new SQLException("Test-only close acknowledgement loss.");
							return result;
						} catch (InvocationTargetException failure) {
							throw failure.getCause();
						}
					}
				});
	}

	private static @NonNull String read(int key) {
		Optional<OAuthClientMetadataCacheEntry> found = cache().read(key(key), Duration.ofSeconds(3));
		return found.map(value -> "HIT:" + value.getVersion() + ":" + value.toSealedForm()).orElse("MISS");
	}

	private static @NonNull String cas(int key, int expected, int replacement) {
		boolean changed = cache().compareAndSet(key(key), expected == 0 ? null : nonce(expected),
				replacement == 0 ? null : entry(key, replacement), Duration.ofSeconds(3));
		return changed ? "TRUE" : "FALSE";
	}

	public static void main(@NonNull String @NonNull [] args) throws Exception {
		try {
			switch (args[0]) {
				case "read" -> System.out.println(read(Integer.parseInt(args[1])));
				case "cas" -> System.out.println(cas(Integer.parseInt(args[1]),
						Integer.parseInt(args[2]), Integer.parseInt(args[3])));
				case "race" -> {
					System.out.println("READY");
					System.out.flush();
					if (System.in.read() == -1) throw new IllegalStateException("Race signal missing.");
					System.out.println(cas(Integer.parseInt(args[1]), Integer.parseInt(args[2]),
							Integer.parseInt(args[3])));
				}
				case "unknown" -> {
					PostgresqlClientMetadataCache uncertain = new PostgresqlClientMetadataCache("fixture_cache",
							PendingStoreProbe::commitAcknowledgementLost, 2);
					try {
						uncertain.compareAndSet(key(Integer.parseInt(args[1])), null,
								entry(Integer.parseInt(args[1]), Integer.parseInt(args[2])), Duration.ofSeconds(3));
						throw new IllegalStateException("Unknown cache COMMIT returned success.");
					} catch (OAuthClientMetadataCacheException expected) {
						System.out.println("UNKNOWN_WRITE_REPORTED");
					}
				}
				case "close-failure" -> System.out.println(new PostgresqlClientMetadataCache(
						"fixture_cache", ClientMetadataCacheProbe::closeAcknowledgementLost, 2)
						.read(key(Integer.parseInt(args[1])), Duration.ofSeconds(3)).isPresent()
						? "CONFIRMED_READ" : "MISS");
				default -> throw new IllegalArgumentException("Unknown cache probe mode.");
			}
		} catch (OAuthClientMetadataCacheException failure) {
			System.out.println("CACHE_FAILURE:" + failure.getReason());
		}
	}
}
