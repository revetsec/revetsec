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

package com.revetsec.testing;

import org.jspecify.annotations.NonNull;

import org.jspecify.annotations.Nullable;

import javax.annotation.concurrent.ThreadSafe;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;
import java.io.IOException;
import java.io.InputStream;
import java.net.http.HttpClient;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.time.Duration;

/**
 * TLS for in-process test servers and their clients, built from the TEST ONLY PKI in {@code src/test/resources/tls/}
 * (see its {@code README.md}): {@value #SERVER_KEY_STORE_RESOURCE} holds the server key and chain, and
 * {@value #TRUST_STORE_RESOURCE} holds the test CA. Both use the public password {@value #PKCS12_PASSWORD}.
 * <p>
 * HTTPS stays on in tests: clients verify the server against the test CA, with hostname verification, instead of
 * turning verification off. The server leaf names {@code localhost} and {@code 127.0.0.1}.
 * <p>
 * Every method loads the key stores afresh and returns a new object, so nothing here holds shared mutable state.
 * Failures to read the fixtures are programming errors and surface as {@link IllegalStateException}.
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 */
@ThreadSafe
public final class TestTls {
	/**
	 * Class-path resource holding the server key and its chain {@code [server, test-ca]}, alias
	 * {@value #SERVER_KEY_ALIAS}.
	 */
	public static final String SERVER_KEY_STORE_RESOURCE = "/tls/server.p12";

	/**
	 * Class-path resource holding only the test CA certificate, alias {@value #TRUST_ANCHOR_ALIAS}.
	 */
	public static final String TRUST_STORE_RESOURCE = "/tls/truststore.p12";

	/**
	 * The store and key password of every PKCS#12 fixture. It is public on purpose: the fixtures are TEST ONLY.
	 */
	public static final String PKCS12_PASSWORD = "changeit";

	/**
	 * Alias of the server's {@code PrivateKeyEntry} in {@value #SERVER_KEY_STORE_RESOURCE}.
	 */
	public static final String SERVER_KEY_ALIAS = "server";

	/**
	 * Alias of the test CA's {@code trustedCertEntry} in {@value #TRUST_STORE_RESOURCE}.
	 */
	public static final String TRUST_ANCHOR_ALIAS = "revetsec-test-ca";

	/**
	 * The connect timeout of {@link #httpClientBuilder()}, long enough for a loaded CI machine.
	 */
	public static final Duration CONNECT_TIMEOUT = Duration.ofSeconds(10);

	private TestTls() {
		// Static helpers only.
	}

	/**
	 * Loads {@value #SERVER_KEY_STORE_RESOURCE}.
	 *
	 * @return a new key store holding the server's key and chain
	 */
	public static @NonNull KeyStore serverKeyStore() {
		return loadPkcs12(SERVER_KEY_STORE_RESOURCE);
	}

	/**
	 * Loads {@value #TRUST_STORE_RESOURCE}.
	 *
	 * @return a new key store holding only the test CA certificate
	 */
	public static @NonNull KeyStore trustStore() {
		return loadPkcs12(TRUST_STORE_RESOURCE);
	}

	/**
	 * A server-side context that presents the test server certificate and requests no client certificate.
	 *
	 * @return a new, initialized {@code TLS} context
	 */
	public static @NonNull SSLContext serverSslContext() {
		try {
			KeyManagerFactory keyManagerFactory =
					KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
			keyManagerFactory.init(serverKeyStore(), PKCS12_PASSWORD.toCharArray());
			SSLContext sslContext = SSLContext.getInstance("TLS");
			sslContext.init(keyManagerFactory.getKeyManagers(), null, null);
			return sslContext;
		} catch (GeneralSecurityException e) {
			throw new IllegalStateException("Unable to build the TEST ONLY server TLS context", e);
		}
	}

	/**
	 * A client-side context that trusts only the test CA.
	 *
	 * @return a new, initialized {@code TLS} context
	 */
	public static @NonNull SSLContext clientSslContext() {
		try {
			TrustManagerFactory trustManagerFactory =
					TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
			trustManagerFactory.init(trustStore());
			SSLContext sslContext = SSLContext.getInstance("TLS");
			sslContext.init(null, trustManagerFactory.getTrustManagers(), null);
			return sslContext;
		} catch (GeneralSecurityException e) {
			throw new IllegalStateException("Unable to build the TEST ONLY client TLS context", e);
		}
	}

	/**
	 * A builder for a client of the in-process test servers: it trusts only the test CA, never follows redirects
	 * (the only setting Revetsec accepts on an injected client, G6-5), speaks HTTP/1.1 (the only version the JDK
	 * {@code HttpsServer} and {@link RawTlsServer} speak) and connects within {@link #CONNECT_TIMEOUT}. Tests may
	 * change any setting before building, for example to prove that Revetsec rejects a client that follows redirects.
	 *
	 * @return a new builder
	 */
	public static HttpClient.@NonNull Builder httpClientBuilder() {
		return HttpClient.newBuilder()
				.sslContext(clientSslContext())
				.followRedirects(HttpClient.Redirect.NEVER)
				.version(HttpClient.Version.HTTP_1_1)
				.connectTimeout(CONNECT_TIMEOUT);
	}

	/**
	 * A new client from {@link #httpClientBuilder()}. Each client owns its JDK selector thread, so a test that needs
	 * several requests should reuse one client.
	 *
	 * @return a new client that trusts only the test CA and never follows redirects
	 */
	public static @NonNull HttpClient httpClient() {
		return httpClientBuilder().build();
	}

	private static @NonNull KeyStore loadPkcs12(@NonNull String resource) {
		try (@Nullable InputStream inputStream = TestTls.class.getResourceAsStream(resource)) {
			if (inputStream == null)
				throw new IllegalStateException("Missing TEST ONLY TLS fixture " + resource);
			KeyStore keyStore = KeyStore.getInstance("PKCS12");
			keyStore.load(inputStream, PKCS12_PASSWORD.toCharArray());
			return keyStore;
		} catch (IOException | GeneralSecurityException e) {
			throw new IllegalStateException("Unable to load TEST ONLY TLS fixture " + resource, e);
		}
	}
}
