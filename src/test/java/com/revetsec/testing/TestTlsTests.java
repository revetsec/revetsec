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

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.Collections;
import java.util.List;
import java.util.Optional;

/**
 * Tests {@link TestTls}: the fixtures in {@code src/test/resources/tls/} load as documented in their README, and the
 * client verifies the test server instead of trusting everything (plan 14.1: HTTPS stays on in tests; G6-5: clients
 * never follow redirects).
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 */
final class TestTlsTests {
	@Test
	void theServerKeyStoreHoldsTheServerKeyAndItsTwoCertificateChain() throws Exception {
		KeyStore keyStore = TestTls.serverKeyStore();

		Assertions.assertEquals(List.of(TestTls.SERVER_KEY_ALIAS), Collections.list(keyStore.aliases()));
		Assertions.assertTrue(keyStore.isKeyEntry(TestTls.SERVER_KEY_ALIAS));
		Certificate[] chain = keyStore.getCertificateChain(TestTls.SERVER_KEY_ALIAS);
		Assertions.assertEquals(2, chain.length);
		X509Certificate leaf = (X509Certificate) chain[0];
		Assertions.assertTrue(leaf.getSubjectX500Principal().getName().contains("CN=localhost"),
				() -> leaf.getSubjectX500Principal().getName());
	}

	@Test
	void theTrustStoreHoldsOnlyTheTestCa() throws Exception {
		KeyStore trustStore = TestTls.trustStore();

		Assertions.assertEquals(List.of(TestTls.TRUST_ANCHOR_ALIAS), Collections.list(trustStore.aliases()));
		Assertions.assertTrue(trustStore.isCertificateEntry(TestTls.TRUST_ANCHOR_ALIAS));
		X509Certificate certificate = (X509Certificate) trustStore.getCertificate(TestTls.TRUST_ANCHOR_ALIAS);
		Assertions.assertTrue(certificate.getSubjectX500Principal().getName().contains("DO NOT TRUST"),
				() -> certificate.getSubjectX500Principal().getName());
	}

	@Test
	void theClientNeverFollowsRedirectsAndSpeaksHttp11() {
		HttpClient client = TestTls.httpClient();

		Assertions.assertEquals(HttpClient.Redirect.NEVER, client.followRedirects());
		Assertions.assertEquals(HttpClient.Version.HTTP_1_1, client.version());
		Assertions.assertEquals(Optional.of(TestTls.CONNECT_TIMEOUT), client.connectTimeout());
		Assertions.assertEquals("TLS", client.sslContext().getProtocol());
	}

	@Test
	void everyCallBuildsAFreshContext() {
		Assertions.assertNotSame(TestTls.serverSslContext(), TestTls.serverSslContext());
		Assertions.assertNotSame(TestTls.clientSslContext(), TestTls.clientSslContext());
	}

	@Test
	void theTestClientVerifiesTheTestServerByIpAddressAndByHostName() throws Exception {
		try (TestHttpsServer server = TestHttpsServer.start()) {
			server.script("/ok", TestHttpsServer.Script.fromResponse(TestHttpsServer.Response.fromStatus(204)));
			HttpClient client = TestTls.httpClient();

			HttpResponse<Void> byAddress = client.send(HttpRequest.newBuilder(server.uri("/ok")).build(),
					HttpResponse.BodyHandlers.discarding());
			HttpResponse<Void> byName = client.send(HttpRequest.newBuilder(
							java.net.URI.create("https://localhost:" + server.getPort() + "/ok")).build(),
					HttpResponse.BodyHandlers.discarding());

			Assertions.assertEquals(204, byAddress.statusCode());
			Assertions.assertEquals(204, byName.statusCode());
			Assertions.assertEquals(2, server.getHitCount("/ok"));
		}
	}

	@Test
	void aClientWithTheJdkDefaultTrustStoreRejectsTheTestServer() throws Exception {
		try (TestHttpsServer server = TestHttpsServer.start()) {
			HttpClient defaultTrust = HttpClient.newBuilder()
					.followRedirects(HttpClient.Redirect.NEVER)
					.connectTimeout(Duration.ofSeconds(10))
					.build();

			Assertions.assertThrows(IOException.class, () -> defaultTrust.send(
					HttpRequest.newBuilder(server.uri("/ok")).build(), HttpResponse.BodyHandlers.discarding()));
			Assertions.assertEquals(0, server.getHitCount("/ok"), "no request crosses a failed handshake");
		}
	}
}
