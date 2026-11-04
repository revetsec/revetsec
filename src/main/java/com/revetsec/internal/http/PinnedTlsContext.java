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

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import javax.annotation.concurrent.ThreadSafe;
import javax.net.ssl.CertPathTrustManagerParameters;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509ExtendedTrustManager;
import java.net.Socket;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.Provider;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertPathValidator;
import java.security.cert.PKIXBuilderParameters;
import java.security.cert.PKIXParameters;
import java.security.cert.PKIXCertPathValidatorResult;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.LinkedHashSet;
import java.util.Set;
import static java.util.Objects.requireNonNull;

/**
 * Per-exchange local trust context. No global property changes or client keys. Bounded paths are constructed
 * from the peer certificate bag and configured trust anchors, keeping the first certificate as the leaf. Each
 * path must validate locally with revocation disabled before the ordinary extended TLS trust manager receives
 * its complete anchored chain. The inspected JDK SunJSSE/SUN implementations then take direct validation,
 * never network-capable path building. At most 128 candidate prefixes are checked for a bag of ten certificates.
 * Unknown providers fail closed: their secondary-egress behavior is not inferred from a standard algorithm name.
 * Provider execution and local trust-store configuration are trusted runtime work, cooperatively bounded by callers.
 */
@ThreadSafe
final class PinnedTlsContext {
 private PinnedTlsContext() {}

 static @NonNull SSLContext fromDefaults() throws HttpExchangeException {
  return fromTrustStore(null);
 }

 static @NonNull SSLContext fromTrustStore(@Nullable KeyStore trustStore) throws HttpExchangeException {
  try {
   TrustManagerFactory factory = TrustManagerFactory.getInstance("PKIX");
   supported(factory.getProvider(), "SunJSSE");
   supported(CertPathValidator.getInstance("PKIX").getProvider(), "SUN");
   supported(CertificateFactory.getInstance("X.509").getProvider(), "SUN");
   factory.init(trustStore);
   X509ExtendedTrustManager original = manager(factory);
   Set<TrustAnchor> anchors = new HashSet<>();
   for (X509Certificate cert : original.getAcceptedIssuers()) anchors.add(new TrustAnchor(cert, null));
   PKIXBuilderParameters parameters = new PKIXBuilderParameters(anchors, null);
   parameters.setRevocationEnabled(false);
   factory.init(new CertPathTrustManagerParameters(parameters));
   X509ExtendedTrustManager delegate = manager(factory);
   SSLContext context = SSLContext.getInstance("TLS");
   supported(context.getProvider(), "SunJSSE");
   context.init(null, new TrustManager[]{new LocalTrust(delegate, Set.copyOf(anchors))}, null);
   return context;
  } catch (GeneralSecurityException | RuntimeException failure) {
   throw new HttpExchangeException(HttpExchangeException.Kind.PINNED_TLS_UNAVAILABLE);
  }
 }

 private static void supported(@NonNull Provider provider, @NonNull String name) throws CertificateException {
  if (!name.equals(provider.getName()) || !"java.base".equals(provider.getClass().getModule().getName()))
   throw rejected();
 }

 private static @NonNull X509ExtendedTrustManager manager(@NonNull TrustManagerFactory factory)
   throws CertificateException {
  TrustManager[] managers = factory.getTrustManagers();
  if (managers.length != 1 || !(managers[0] instanceof X509ExtendedTrustManager extended)
    || !"sun.security.ssl.X509TrustManagerImpl".equals(extended.getClass().getName())
    || !"java.base".equals(extended.getClass().getModule().getName())) throw rejected();
  return extended;
 }

 private static @NonNull CertificateException rejected() {
  return new CertificateException("The local TLS certificate checks failed.");
 }

 @ThreadSafe
 private static final class LocalTrust extends X509ExtendedTrustManager {
  private final @NonNull X509ExtendedTrustManager delegate;
  private final @NonNull Set<@NonNull TrustAnchor> anchors;
  private LocalTrust(@NonNull X509ExtendedTrustManager delegate, @NonNull Set<@NonNull TrustAnchor> anchors) {
   this.delegate = delegate; this.anchors = anchors;
  }
  @Override public void checkServerTrusted(@NonNull X509Certificate @NonNull [] chain, @NonNull String authType,
    @Nullable SSLEngine engine) throws CertificateException {
   if (engine == null || !"HTTPS".equals(engine.getSSLParameters().getEndpointIdentificationAlgorithm()))
    throw rejected();
   checkLocalServer(chain, authType, engine);
  }
  private void checkLocalServer(@NonNull X509Certificate @NonNull [] supplied, @NonNull String authType,
    @NonNull SSLEngine engine) throws CertificateException {
   try {
    requireNonNull(supplied);
    if (supplied.length == 0 || supplied.length > 10) throw rejected();
    // Check the entire bag, including material after an anchor. Never mutate the peer's array.
    Set<X509Certificate> unique = new LinkedHashSet<>();
    for (X509Certificate cert : supplied) {
     if (cert == null || cert.getEncoded().length > 32768) throw rejected();
     unique.add(cert);
    }
    X509Certificate leaf = supplied[0];
    // JSSE can shortcut an explicitly trusted leaf; even that leaf must be current.
    leaf.checkValidity();
    if (this.anchors.stream().anyMatch(anchor -> leaf.equals(anchor.getTrustedCert()))) {
     this.delegate.checkServerTrusted(new X509Certificate[]{leaf}, authType, engine);
     return;
    }
    PKIXParameters parameters = new PKIXParameters(this.anchors);
    parameters.setRevocationEnabled(false);
    CertPathValidator validator = CertPathValidator.getInstance("PKIX");
    supported(validator.getProvider(), "SUN");
    CertificateFactory certificates = CertificateFactory.getInstance("X.509");
    supported(certificates.getProvider(), "SUN");
    LocalPaths search = new LocalPaths(List.copyOf(unique), parameters, validator, certificates);
    if (!search.check(new ArrayList<>(List.of(leaf)), authType, engine)) throw rejected();
   } catch (GeneralSecurityException | RuntimeException failure) {
    throw rejected();
   }
  }

  /** Operation-local search. No CertStores, builders, revocation checkers or certificate-URL access. */
  private final class LocalPaths {
   private final @NonNull List<@NonNull X509Certificate> candidates;
   private final @NonNull PKIXParameters parameters;
   private final @NonNull CertPathValidator validator;
   private final @NonNull CertificateFactory certificates;
   private int remaining = 128;
   private LocalPaths(@NonNull List<@NonNull X509Certificate> candidates, @NonNull PKIXParameters parameters,
     @NonNull CertPathValidator validator, @NonNull CertificateFactory certificates) {
    this.candidates = candidates; this.parameters = parameters;
    this.validator = validator; this.certificates = certificates;
   }
   private boolean check(@NonNull List<@NonNull X509Certificate> path, @NonNull String authType,
     @NonNull SSLEngine engine) throws CertificateException {
    if (this.remaining-- == 0) throw rejected();
    try {
     PKIXCertPathValidatorResult result = (PKIXCertPathValidatorResult)
       this.validator.validate(this.certificates.generateCertPath(path), this.parameters);
     List<X509Certificate> anchored = new ArrayList<>(path);
     anchored.add(requireNonNull(result.getTrustAnchor().getTrustedCert()));
     // This complete, ordered path forces the inspected delegate's direct-validation branch. It still
     // checks hostname, TLS algorithms and server usage. A rejected alternative may be backtracked.
     LocalTrust.this.delegate.checkServerTrusted(anchored.toArray(new X509Certificate[0]), authType, engine);
     return true;
    } catch (GeneralSecurityException invalidPath) {
     // Only the finite local bag may extend a rejected prefix; never ask a builder to retrieve an issuer.
    }
    X509Certificate last = path.get(path.size() - 1);
    for (X509Certificate candidate : this.candidates) {
     if (!path.contains(candidate) && last.getIssuerX500Principal().equals(candidate.getSubjectX500Principal())) {
      path.add(candidate);
      if (check(path, authType, engine)) return true;
      path.remove(path.size() - 1);
     }
    }
    return false;
   }
  }
  @Override public void checkClientTrusted(@NonNull X509Certificate @NonNull [] chain, @NonNull String authType)
    throws CertificateException { throw rejected(); }
  @Override public void checkServerTrusted(@NonNull X509Certificate @NonNull [] chain, @NonNull String authType)
    throws CertificateException { throw rejected(); }
  @Override public void checkClientTrusted(@NonNull X509Certificate @NonNull [] chain, @NonNull String authType,
    @Nullable Socket socket) throws CertificateException { throw rejected(); }
  @Override public void checkServerTrusted(@NonNull X509Certificate @NonNull [] chain, @NonNull String authType,
    @Nullable Socket socket) throws CertificateException { throw rejected(); }
  @Override public void checkClientTrusted(@NonNull X509Certificate @NonNull [] chain, @NonNull String authType,
    @Nullable SSLEngine engine) throws CertificateException { throw rejected(); }
  @Override public @NonNull X509Certificate @NonNull [] getAcceptedIssuers() { return this.delegate.getAcceptedIssuers(); }
 }
}
