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


package com.revetsec.internal.http;

import com.revetsec.testing.TestTls;
import org.jspecify.annotations.NonNull;
import org.junit.jupiter.api.Test;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.X509ExtendedTrustManager;
import javax.net.ssl.TrustManagerFactory;
import java.net.Socket;
import java.security.cert.CertificateException;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Set;
import static org.junit.jupiter.api.Assertions.*;

/** Direct rejection checks; reflected access stays test-only and exposes no application TLS bypass. */
final class PinnedTlsContextTests {
 private static @NonNull X509ExtendedTrustManager manager() throws Exception {
  var factory=TrustManagerFactory.getInstance("PKIX");factory.init(TestTls.trustStore());
  var delegate=assertInstanceOf(X509ExtendedTrustManager.class,factory.getTrustManagers()[0]);
  var type=Class.forName("com.revetsec.internal.http.PinnedTlsContext$LocalTrust");
  var constructor=type.getDeclaredConstructor(X509ExtendedTrustManager.class,Set.class);constructor.setAccessible(true);
  return (X509ExtendedTrustManager)constructor.newInstance(delegate,Set.of(new TrustAnchor(delegate.getAcceptedIssuers()[0],null)));
 }
 private static @NonNull SSLEngine engine() {
  SSLEngine engine=TestTls.clientSslContext().createSSLEngine("localhost",443);engine.setUseClientMode(true);
  var parameters=engine.getSSLParameters();parameters.setEndpointIdentificationAlgorithm("HTTPS");engine.setSSLParameters(parameters);return engine;
 }
 @Test void nullAndNonHttpsEngineCannotDelegateTrust() throws Exception {
  var manager=manager();X509Certificate[] chain=manager.getAcceptedIssuers();
  assertThrows(CertificateException.class,()->manager.checkServerTrusted(chain,"RSA",(SSLEngine)null));
  SSLEngine engine=engine();var parameters=engine.getSSLParameters();parameters.setEndpointIdentificationAlgorithm(null);engine.setSSLParameters(parameters);
  assertThrows(CertificateException.class,()->manager.checkServerTrusted(chain,"RSA",engine));
 }
 @Test void legacySocketAndClientTrustPathsAlwaysReject() throws Exception {
  var manager=manager();X509Certificate[] chain=manager.getAcceptedIssuers();
  assertThrows(CertificateException.class,()->manager.checkClientTrusted(chain,"RSA"));
  assertThrows(CertificateException.class,()->manager.checkServerTrusted(chain,"RSA"));
  assertThrows(CertificateException.class,()->manager.checkClientTrusted(chain,"RSA",(Socket)null));
  assertThrows(CertificateException.class,()->manager.checkServerTrusted(chain,"RSA",(Socket)null));
  assertThrows(CertificateException.class,()->manager.checkClientTrusted(chain,"RSA",engine()));
 }
 @Test void emptyExcessiveAndNullCertificateElementsRejectBeforeValidation() throws Exception {
  var manager=manager();SSLEngine engine=engine();
  assertThrows(CertificateException.class,()->manager.checkServerTrusted(new X509Certificate[0],"RSA",engine));
  X509Certificate[] excessive=new X509Certificate[11];Arrays.fill(excessive,manager.getAcceptedIssuers()[0]);
  assertThrows(CertificateException.class,()->manager.checkServerTrusted(excessive,"RSA",engine));
  assertThrows(CertificateException.class,()->manager.checkServerTrusted(new X509Certificate[]{null},"RSA",engine));
 }
 @Test void issuerListReflectsConfiguredTrustAndUsesDefensiveArrays() throws Exception {
  var manager=manager();X509Certificate[] original=manager.getAcceptedIssuers();assertTrue(original.length>0);
  X509Certificate root=original[0];original[0]=null;assertEquals(root,manager.getAcceptedIssuers()[0]);
 }
}
