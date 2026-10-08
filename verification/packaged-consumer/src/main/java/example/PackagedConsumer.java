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

package example;

import org.jspecify.annotations.NonNull;

import com.revetsec.oauth.server.OAuthServerResponse;
import com.revetsec.oauth.server.OAuthAuthorizationServer;
import com.revetsec.oauth.server.OAuthServerInteraction;
import com.revetsec.oauth.server.OAuthAuthorizationResult;
import com.revetsec.oauth.server.OAuthTokenResult;
import com.revetsec.oauth.server.OAuthRevocationResult;
import com.revetsec.oauth.server.OAuthIntrospectionResult;
import com.revetsec.oauth.server.OAuthIssuerAccessTokenResult;
import com.revetsec.oauth.server.OAuthServerException;
import com.revetsec.oauth.server.OAuthServerValidationException;
import com.revetsec.oauth.server.OAuthServerStoreException;
import com.revetsec.oauth.server.OAuthServerTransportException;
import com.revetsec.oauth.server.OAuthServerConfigurationException;
import com.revetsec.oauth.server.OAuthServerSigningException;
import com.revetsec.oauth.server.OAuthServerObserver;

import com.revetsec.oauth.server.OAuthIssuerSigningKey;
import com.revetsec.oauth.server.OAuthIssuerKeySnapshot;
import com.revetsec.oauth.server.OAuthIssuerKeyProvider;
import com.revetsec.oauth.server.OAuthClientMetadataPolicy;
import com.revetsec.oauth.server.InMemoryOAuthClientMetadataCache;
import com.revetsec.oauth.server.OAuthClientMetadataCache;
import com.revetsec.oauth.server.OAuthClientMetadataCacheKey;
import com.revetsec.oauth.server.OAuthClientMetadataCacheEntry;
import com.revetsec.oauth.server.OAuthClientMetadataCacheException;
import com.revetsec.oauth.server.OAuthClientMetadataAddressResolver;
import com.revetsec.oauth.server.OAuthClientSecretVerifier;
import com.revetsec.oauth.server.OAuthServerClientRepository;
import com.revetsec.oauth.server.OAuthAuthorizationServerStore;
import com.revetsec.oauth.server.OAuthStoreKey;
import com.revetsec.oauth.server.OAuthStoreEntry;
import com.revetsec.oauth.server.OAuthStoreTransaction;
import com.revetsec.oauth.server.OAuthStoreCommitStatus;
import com.revetsec.oauth.server.OAuthServerClientRegistration;
import com.revetsec.oauth.server.OAuthServerClientAuthentication;
import com.revetsec.oauth.server.OAuthAuthorizationDecision;
import com.revetsec.oauth.server.OAuthGrantPolicy;
import com.revetsec.oauth.server.OAuthGrantContext;
import com.revetsec.oauth.AccessTokenValidator;
import com.revetsec.oauth.JwtAccessTokenValidator;
import com.revetsec.oauth.TokenIntrospectionClient;
import com.revetsec.oauth.VerifiedAccessToken;
import com.revetsec.oauth.AccessTokenCompatibilityMode;
import com.revetsec.oauth.AccessTokenObserver;
import com.revetsec.oauth.AccessTokenValidationResult;
import com.revetsec.oidc.OidcAuthenticationResult;
import com.revetsec.oauth.AuthorizationCompletionResult;
import com.revetsec.oauth.BearerTokenResult;
import com.revetsec.jose.JwtValidationResult;
import com.revetsec.StateUnsealResult;
import com.revetsec.ErrorCategory;
import com.revetsec.InvalidSealedStateException;
import com.revetsec.OutboundUriPolicy;
import com.revetsec.RevetsecException;
import com.revetsec.SealingKey;
import com.revetsec.StateSealer;
import com.revetsec.oauth.AccessToken;
import com.revetsec.oauth.BearerToken;
import com.revetsec.oauth.BearerError;
import com.revetsec.oauth.BearerChallenge;
import com.revetsec.oauth.ProtectedResourceMetadata;
import com.revetsec.oauth.AccessTokenValidationException;
import com.revetsec.oauth.AuthorizationErrorException;
import com.revetsec.oauth.AuthorizationRedirect;
import com.revetsec.oauth.AuthorizationRequestOptions;
import com.revetsec.oauth.AuthorizationResponse;
import com.revetsec.oauth.AuthorizationServerMetadata;
import com.revetsec.oauth.ClientAuthentication;
import com.revetsec.oauth.ClientAssertionAudience;
import com.revetsec.oauth.ClientAssertionKeyProvider;
import com.revetsec.oauth.ClientAssertionSigningKey;
import com.revetsec.oauth.OAuthConfigurationException;
import com.revetsec.oauth.ClientCredentialsTokenSource;
import com.revetsec.oauth.ClientSecretBasicEncoding;
import com.revetsec.oauth.InMemoryPendingAuthorizationStore;
import com.revetsec.oauth.IssuerParameterPolicy;
import com.revetsec.oauth.OAuthClient;
import com.revetsec.oauth.OAuthEndpoint;
import com.revetsec.oauth.OAuthErrorResponseException;
import com.revetsec.oauth.OAuthException;
import com.revetsec.oauth.OAuthObserver;
import com.revetsec.oauth.OAuthResponseException;
import com.revetsec.oauth.OAuthTransportException;
import com.revetsec.oauth.OAuthValidationException;
import com.revetsec.oauth.PendingAuthorization;
import com.revetsec.oauth.PendingAuthorizationSource;
import com.revetsec.oauth.PendingAuthorizationStore;
import com.revetsec.oauth.PendingAuthorizationStoreException;
import com.revetsec.oauth.RefreshToken;
import com.revetsec.oauth.TokenRequestOptions;
import com.revetsec.oauth.TokenResponse;
import com.revetsec.oauth.TokenTypeHint;
import com.revetsec.oidc.IdToken;
import com.revetsec.oidc.OidcAuthentication;
import com.revetsec.oidc.OidcAuthenticationOptions;
import com.revetsec.oidc.OidcClient;
import com.revetsec.oidc.OidcCompatibilityMode;
import com.revetsec.oidc.OidcException;
import com.revetsec.oidc.OidcObserver;
import com.revetsec.oidc.OidcIssuerPolicy;
import com.revetsec.oidc.OidcProviderMetadata;
import com.revetsec.oidc.OidcSessionReference;
import com.revetsec.oidc.OidcUserInfo;
import com.revetsec.oidc.OidcValidationException;
import com.revetsec.oidc.OidcRefreshResult;
import com.revetsec.json.JsonArray;
import com.revetsec.json.JsonBoolean;
import com.revetsec.json.JsonNull;
import com.revetsec.json.JsonNumber;
import com.revetsec.json.JsonObject;
import com.revetsec.json.JsonString;
import com.revetsec.json.JsonValue;
import com.revetsec.jose.JoseException;
import com.revetsec.jose.JoseObserver;
import com.revetsec.jose.JsonWebKey;
import com.revetsec.jose.JsonWebKeySet;
import com.revetsec.jose.JsonWebKeySetUnavailableException;
import com.revetsec.jose.JsonWebKeySkipReason;
import com.revetsec.jose.JsonWebKeySource;
import com.revetsec.jose.JwsAlgorithm;
import com.revetsec.jose.JwsSigner;
import com.revetsec.jose.JwsSigningException;
import com.revetsec.jose.Jwt;
import com.revetsec.jose.JwtClaims;
import com.revetsec.jose.JwtValidationException;
import com.revetsec.jose.JwtValidator;
import com.revetsec.jose.MalformedJoseInputException;
import com.revetsec.jose.RemoteJsonWebKeySource;
import com.revetsec.jose.StaticJsonWebKeySource;
import com.revetsec.jose.UnsupportedJoseFeatureException;

import java.lang.module.ModuleDescriptor;
import java.lang.module.ModuleFinder;
import java.lang.module.ModuleReference;
import java.math.BigDecimal;
import java.math.BigInteger;
import java.net.JarURLConnection;
import java.net.URI;
import java.net.URL;
import java.net.URLConnection;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.TreeSet;
import java.util.jar.JarFile;
import java.util.jar.Manifest;

/**
 * A minimal application that consumes the packaged Revetsec JAR. The Maven consumer ({@code pom.xml}) and the Gradle
 * consumer ({@code build.gradle}) both compile and run it.
 * <p>
 * It checks what any consumer can observe: the root package is on the class path and comes from a JAR, that JAR
 * declares {@code Automatic-Module-Name: com.revetsec}, and the module system resolves it under that name.
 * <p>
 * It also calls the public API of the exported packages that hold types, {@code com.revetsec},
 * {@code com.revetsec.json}, {@code com.revetsec.jose}, {@code com.revetsec.oauth} and {@code com.revetsec.oidc}, and uses every public type in
 * them, nested builders and enums included. The JOSE calls validate a JWT the consumer signs itself with a fresh RSA key, against a key set it
 * writes, refuse forged, unsigned, malformed and unsupported tokens, and build a remote key source without any I/O.
 * The checked-in source has explicit JSpecify signatures. The verifier removes only those type annotations and
 * imports from its temporary consumer copy, preserving executable Java and literals. Both consumers compile that
 * copy with every lint warning an error and with nothing but the Revetsec JAR on the class path,
 * so a build proves that the published signatures resolve without Revetsec's provided-scope annotation JARs
 * (JSpecify, the jsr305 concurrency markers and Error Prone's annotations), and a run proves the calls work without
 * them. It prints {@code public-api=...} only after every call behaved as documented;
 * {@code verify-packaged-consumer.py} requires that line from both consumers.
 * <p>
 * The first argument, if present, is the path of the JAR the caller expects the root package to come from.
 */
public final class PackagedConsumer {
	private static final String MODULE_NAME = "com.revetsec";
	private static final String ROOT_PACKAGE_INFO_CLASS = "com.revetsec.package-info";
	private static final String ROOT_PACKAGE_INFO_RESOURCE = "com/revetsec/package-info.class";
	private static final String SEALING_CONTEXT = "packaged-consumer";
	private static final String ISSUER = "https://login.example.com/tenant-1";
	private static final String AUDIENCE = "packaged-consumer";
	private static final String KEY_ID = "consumer-key-1";
	// A fixed clock, so the tokens' lifetimes do not depend on when the consumer runs.
	private static final Instant NOW = Instant.ofEpochSecond(1_800_000_000L);
	private static final Base64.Encoder BASE64URL = Base64.getUrlEncoder().withoutPadding();

	private PackagedConsumer() {
		// Entry point only.
	}

	public static void main(@NonNull String @NonNull [] arguments) throws Exception {
  require(OAuthServerResponse.class.getConstructors().length == 0, "server response restricted construction");
  require(OAuthServerResponse.class.getDeclaredMethod("getStatusCode").getReturnType() == Integer.class
    && OAuthServerResponse.class.getDeclaredMethod("getHeaders").getReturnType() == Map.class
    && OAuthServerResponse.class.getDeclaredMethod("getLocationWithCredentials").getReturnType() == Optional.class
    && OAuthServerResponse.class.getDeclaredMethod("toHttpBodyWithCredentials").getReturnType() == byte[].class,
    "server response annotation-free exported method signatures");
  OAuthClientMetadataAddressResolver metadataResolver = (hostname, remainingBudget) -> List.of();
  OAuthClientMetadataPolicy.Builder metadataBuilder = OAuthClientMetadataPolicy.withAddressResolver(metadataResolver);
  OAuthClientMetadataPolicy metadataPolicy = metadataBuilder.allowedOrigins(Set.of(URI.create("https://consumer.example.com")))
   .allowedOrigins(null).maximumDocumentBytes(1024).maximumDocumentBytes(null).maximumCacheEntries(1).maximumCacheEntries(null)
   .maximumFreshness(Duration.ZERO).maximumFreshness(null).maximumConcurrentFetches(1).maximumConcurrentFetches(null)
   .maximumResolvedAddresses(1).maximumResolvedAddresses(null).addressResolver(metadataResolver).build();
  if (!metadataPolicy.getEnabled() || metadataPolicy.getAllowedOrigins().isPresent()
   || metadataPolicy.getAddressResolver().orElseThrow() != metadataResolver || metadataPolicy.getMaximumDocumentBytes() != 5120
   || metadataPolicy.getMaximumCacheEntries() != 128 || !metadataPolicy.getMaximumFreshness().equals(Duration.ofSeconds(300))
   || metadataPolicy.getMaximumConcurrentFetches() != 8 || metadataPolicy.getMaximumResolvedAddresses() != 16
   || OAuthClientMetadataPolicy.disabledInstance().getEnabled() || !OAuthClientMetadataPolicy.fromAddressResolver(metadataResolver).getEnabled())
   throw new AssertionError("CIMD policy contract");

  InMemoryOAuthClientMetadataCache localCache = InMemoryOAuthClientMetadataCache.fromMaximumEntries(2);
  OAuthClientMetadataCache cache = localCache;
  String cacheDigest = Base64.getUrlEncoder().withoutPadding().encodeToString(new byte[32]);
  OAuthClientMetadataCacheKey cacheKey = OAuthClientMetadataCacheKey.fromStoredForm("revetsec:cimd-cache:1:" + cacheDigest + ":" + cacheDigest);
  OAuthClientMetadataCacheEntry cacheEntry = OAuthClientMetadataCacheEntry.fromStoredForm(cacheKey, cacheDigest, NOW, "storage-only-test-carrier");
  require(localCache.getMaximumEntries() == 2 && InMemoryOAuthClientMetadataCache.fromDefaults().getMaximumEntries() == 128,
    "cache defaults and explicit local capacity");
  require(cache.read(cacheKey, Duration.ofSeconds(1)).isEmpty()
    && cache.compareAndSet(cacheKey, null, cacheEntry, Duration.ofSeconds(1))
    && cache.read(cacheKey, Duration.ofSeconds(1)).orElseThrow().getVersion().equals(cacheDigest)
    && cacheEntry.getKey().equals(cacheKey) && cacheEntry.getExpiresAt().equals(NOW)
    && cacheEntry.toSealedForm().equals("storage-only-test-carrier"), "opaque cache storage round trip");
  require(metadataBuilder.cache(cache).build().getCache().orElseThrow() == cache
    && metadataBuilder.cache(null).build().getCache().isEmpty(), "custom cache selection and deferred reset");
  require(cache.compareAndSet(cacheKey, cacheDigest, null, Duration.ofSeconds(1))
    && cache.read(cacheKey, Duration.ofSeconds(1)).isEmpty(), "exact-version cache deletion");
  OAuthClientMetadataCacheException cacheFailure = OAuthClientMetadataCacheException.fromReason(OAuthClientMetadataCacheException.Reason.UNAVAILABLE);
  require(cacheFailure.getReason() == OAuthClientMetadataCacheException.Reason.UNAVAILABLE
    && cacheFailure.getCategory() == ErrorCategory.TRANSPORT && cacheFailure.isTransient()
    && cacheFailure.getCause() == null, "fixed cache provider failure");


  for(Class<?> issuerContract:List.of(OAuthServerInteraction.class,OAuthAuthorizationResult.class,OAuthTokenResult.class,
    OAuthRevocationResult.class,OAuthIntrospectionResult.class,OAuthIssuerAccessTokenResult.class,OAuthServerException.class,
    OAuthServerValidationException.class,OAuthServerStoreException.class,OAuthServerTransportException.class,
    OAuthServerConfigurationException.class,OAuthServerSigningException.class)) {
   for(var constructor:issuerContract.getDeclaredConstructors()) require(!java.lang.reflect.Modifier.isPublic(constructor.getModifiers())
     && !java.lang.reflect.Modifier.isProtected(constructor.getModifiers()),"restricted issuer construction");
   for(var method:issuerContract.getDeclaredMethods()) require(!(java.lang.reflect.Modifier.isPublic(method.getModifiers())
     && java.lang.reflect.Modifier.isStatic(method.getModifiers())),"restricted issuer factories");
  }
  OAuthServerObserver issuerObserver=OAuthServerObserver.disabledInstance();
  require(issuerObserver==OAuthServerObserver.disabledInstance(),"shared disabled issuer observer");
  issuerObserver.willHandleEndpoint(OAuthServerObserver.Endpoint.TOKEN);
  issuerObserver.didHandleEndpoint(OAuthServerObserver.Endpoint.TOKEN,200,Duration.ZERO);
  issuerObserver.didRejectEndpoint(OAuthServerObserver.Endpoint.TOKEN,OAuthServerException.Reason.INVALID_GRANT,400,Duration.ZERO);
  require(OAuthIssuerAccessTokenResult.class.isSealed() && OAuthServerException.class.isSealed(),"sealed issuer contracts");


		ClassLoader classLoader = PackagedConsumer.class.getClassLoader();
		URL resource = classLoader.getResource(ROOT_PACKAGE_INFO_RESOURCE);

		if (resource == null)
			throw new IllegalStateException(ROOT_PACKAGE_INFO_RESOURCE + " is not on the class path");

		URLConnection connection = resource.openConnection();

		if (!(connection instanceof JarURLConnection))
			throw new IllegalStateException(ROOT_PACKAGE_INFO_RESOURCE + " must come from a JAR, found " + resource);

		connection.setUseCaches(false);
		Path jar = Path.of(((JarURLConnection) connection).getJarFileURL().toURI()).toRealPath();

		if (arguments.length > 0) {
			Path expectedJar = Path.of(arguments[0]).toRealPath();

			if (!expectedJar.equals(jar))
				throw new IllegalStateException("Root package came from " + jar + ", expected " + expectedJar);
		}

		String automaticModuleName;

		try (JarFile jarFile = new JarFile(jar.toFile())) {
			Manifest manifest = jarFile.getManifest();
			automaticModuleName = manifest == null ? null : manifest.getMainAttributes().getValue("Automatic-Module-Name");
		}

		if (!MODULE_NAME.equals(automaticModuleName))
			throw new IllegalStateException("Automatic-Module-Name is " + automaticModuleName + ", expected " + MODULE_NAME);

		ModuleReference moduleReference = ModuleFinder.of(jar).find(MODULE_NAME)
				.orElseThrow(() -> new IllegalStateException("The module system does not resolve " + MODULE_NAME + " from " + jar));
		ModuleDescriptor descriptor = moduleReference.descriptor();

		if (!descriptor.isAutomatic())
			throw new IllegalStateException(MODULE_NAME + " must be an automatic module; the plan uses Automatic-Module-Name");

		// Load, without initializing, the root package-info class to prove this runtime accepts the class file.
		Class<?> packageInfo = Class.forName(ROOT_PACKAGE_INFO_CLASS, false, classLoader);

		List<String> calledApi = new ArrayList<>();
		String json = exerciseJsonModel(calledApi);
		exerciseResultTypes();
		exerciseStateSealer(json, calledApi);
		exerciseOutboundUriPolicy(calledApi);
		exerciseJose(calledApi);
		exerciseOAuth(calledApi);
		exerciseOidc(calledApi);
		exerciseIssuerApplicationContracts();
		exerciseIssuerStorageCarriers();
		exerciseIssuerKeys();
		calledApi.add("com.revetsec.oauth.server");

		System.out.println("jar=" + jar);
		System.out.println("automatic-module-name=" + automaticModuleName);
		System.out.println("root-package-info=" + packageInfo.getName());
		System.out.println("packages=" + String.join(",", new TreeSet<>(descriptor.packages())));
		System.out.println("runtime=" + Runtime.version());
		System.out.println("error-categories=" + Arrays.toString(ErrorCategory.values()));
		System.out.println("public-api=" + String.join(",", calledApi));
	}

	/**
	 * Exercises issuer keys and the public authorization-server builder without application storage I/O.
	 */
	private static void exerciseIssuerKeys() throws Exception {
		KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
		generator.initialize(2048);
		KeyPair pair = generator.generateKeyPair();
		OAuthIssuerSigningKey key = OAuthIssuerSigningKey.fromKeyPair(KEY_ID, pair.getPrivate(), pair.getPublic());
		OAuthIssuerKeySnapshot.Builder builder = OAuthIssuerKeySnapshot.withActiveKey(key);
		OAuthIssuerKeySnapshot snapshot = builder.generation("consumer-generation").publishedAt(NOW.minusSeconds(120))
				.verificationKeys(Map.of(KEY_ID, pair.getPublic())).verificationKeys(null)
				.retirementNotBefore(Map.of(KEY_ID, NOW.plusSeconds(600))).retirementNotBefore(null).build();
		OAuthIssuerKeyProvider provider = OAuthIssuerKeyProvider.fromSnapshot(snapshot);
		require(provider.getSnapshot(Duration.ofSeconds(1)) == snapshot && snapshot.getActiveKey() == key,
				"fixed issuer key provider and immutable active holder");
		require(key.getKeyId().equals(KEY_ID) && key.getPublicKey() != null
				&& snapshot.getVerificationKeys().keySet().equals(Set.of(KEY_ID))
				&& snapshot.getGeneration().equals("consumer-generation") && snapshot.getPublishedAt().equals(NOW.minusSeconds(120))
				&& snapshot.getRetirementNotBefore().isEmpty(), "issuer snapshot projections and null resets");
		require(!key.toString().contains(KEY_ID) && !snapshot.toString().contains(KEY_ID), "issuer key redaction");
  byte[] sealBytes=new byte[32];for(int i=0;i<sealBytes.length;i++)sealBytes[i]=(byte)(i+1);
  OAuthAuthorizationServer server=OAuthAuthorizationServer.withIssuer(ISSUER)
   .authorizationEndpoint(URI.create(ISSUER+"/authorize")).tokenEndpoint(URI.create(ISSUER+"/token")).jsonWebKeySetEndpoint(URI.create(ISSUER+"/jwks"))
   .clientRepository((id,budget)->Optional.empty()).store(new OAuthAuthorizationServerStore(){
    @Override public @NonNull Optional<@NonNull OAuthStoreEntry> read(@NonNull OAuthStoreKey address,@NonNull Duration budget){throw new AssertionError("build touched store");}
    @Override public @NonNull OAuthStoreCommitStatus commit(@NonNull OAuthStoreTransaction transaction,@NonNull Duration budget){throw new AssertionError("build touched store");}
   }).signingKeys(provider).stateSealer(StateSealer.withActiveKey(SealingKey.fromBase64("consumer-issuer",Base64.getEncoder().encodeToString(sealBytes))).build())
   .resources(Map.of("https://resource.example/mcp",Set.of("read"))).grantPolicy((context,budget)->OAuthAuthorizationDecision.deniedInstance()).clock(Clock.fixed(NOW,ZoneOffset.UTC)).build();
  require(server.getIssuer().equals(ISSUER) && server.getTokenEndpoint().toString().equals(ISSUER+"/token") && server.getAuthorizationEndpoint()!=null
   && server.getJsonWebKeySetEndpoint()!=null && server.getRevocationEndpoint().isEmpty() && server.getIntrospectionEndpoint().isEmpty(),"public issuer builder/getters without I/O");
  require(server.metadataResponse("GET").getStatusCode()==200 && server.jsonWebKeySetResponse("HEAD").getStatusCode()==200,"public metadata/JWKS endpoints");
  require(server.tokenResult("GET",null,new byte[0],Map.of()) instanceof OAuthTokenResult.Rejected,"public bounded method result");

	}

	private static void exerciseIssuerApplicationContracts() {
		String resource = "https://resource.example/mcp";
		OAuthClientSecretVerifier verifier = (id, bytes, budget) -> id.equals("resource-client") && bytes.length == 1 && bytes[0] == 42;
		OAuthServerClientAuthentication authentication = OAuthServerClientAuthentication.fromClientSecretVerifier(verifier);
		OAuthServerClientRegistration.Builder clientBuilder = OAuthServerClientRegistration.withClientId("resource-client")
				.authorizationCodePermitted(false).authentication(authentication).introspectionResources(Set.of(resource)).configurationVersion("v1");
		OAuthServerClientRegistration client = clientBuilder.build();
		OAuthServerClientRepository repository = (id, budget) -> id.equals(client.getClientId()) ? Optional.of(client) : Optional.empty();
		OAuthAuthorizationDecision.Builder decisionBuilder = OAuthAuthorizationDecision.withSubject("app-subject")
				.authorizedScopesByResource(Map.of(resource, Set.of("read")));
		OAuthAuthorizationDecision decision = decisionBuilder.build();
		OAuthGrantPolicy policy = (context, budget) -> decisionForGrant(context);
		if (!verifier.verifiesClientSecret("resource-client", new byte[]{42}, Duration.ofSeconds(1))
				|| repository.findRegisteredClient("resource-client", Duration.ofSeconds(1)).orElseThrow() != client
				|| decision.isDenied() || decision.isRefreshTokenPermitted() || !OAuthAuthorizationDecision.deniedInstance().isDenied()
				|| client.isAuthorizationCodePermitted() || !client.getRedirectUris().isEmpty()
				|| OAuthServerClientAuthentication.publicClientInstance() == authentication || policy == null)
			throw new IllegalStateException("Issuer application contracts did not retain configuration.");
	}
	private static void exerciseIssuerStorageCarriers() {
  String nonce = "A".repeat(43);
  OAuthStoreKey key = OAuthStoreKey.fromStoredForm("revetsec:as:1:" + nonce + ":CODE:" + nonce);
  OAuthStoreEntry entry = OAuthStoreEntry.fromStoredForm(key, nonce, Instant.ofEpochSecond(2_000_000_000L), "opaque");
  OAuthAuthorizationServerStore store = new OAuthAuthorizationServerStore() {
   @Override public @NonNull Optional<@NonNull OAuthStoreEntry> read(@NonNull OAuthStoreKey address, @NonNull Duration budget) {
    return address.equals(key) ? Optional.of(entry) : Optional.empty();
   }
   @Override public @NonNull OAuthStoreCommitStatus commit(@NonNull OAuthStoreTransaction transaction, @NonNull Duration budget) {
    for (OAuthStoreTransaction.Condition condition : transaction.getConditions()) {
     condition.getKey().getStorageKey(); condition.getExpectedVersion();
    }
    for (OAuthStoreTransaction.Mutation mutation : transaction.getMutations()) {
     mutation.getKey(); mutation.getKind(); mutation.getEntry();
    }
    return OAuthStoreCommitStatus.UNKNOWN;
   }
  };
  if (store.read(key, Duration.ofSeconds(1)).orElseThrow() != entry || entry.getKey().getKind() != OAuthStoreKey.Kind.CODE
    || !entry.getVersion().equals(nonce) || entry.getRetainUntil().getEpochSecond() != 2_000_000_000L
    || !entry.toSealedForm().equals("opaque") || OAuthStoreTransaction.Mutation.Kind.values().length != 2
    || OAuthStoreCommitStatus.values().length != 3) throw new IllegalStateException("Storage carrier linkage failed.");
 }
	private static @NonNull OAuthAuthorizationDecision decisionForGrant(@NonNull OAuthGrantContext context) {
		return OAuthAuthorizationDecision.withSubject(context.getSubject())
				.authorizedScopesByResource(context.getAuthorizedScopesByResource())
				.refreshTokenPermitted(context.isRefreshTokenPermitted()).build();
	}

	private static @NonNull String exerciseJsonModel(@NonNull List<@NonNull String> calledApi) {
		JsonObject.Builder builder = JsonObject.builder();
		JsonObject object = builder
				.put("iss", "https://issuer.example")
				.put("exp", 1_800_000_000L)
				.put("ratio", new BigDecimal("0.50"))
				.put("active", Boolean.TRUE)
				.put("aud", JsonArray.fromElements(List.of(JsonString.fromValue("a"), JsonString.fromValue("b"))))
				.put("scale", JsonNumber.fromValue(1L))
				.putNull("nonce")
				.build();
		String json = object.toJson();
		String expected = "{\"iss\":\"https://issuer.example\",\"exp\":1800000000,\"ratio\":0.50,\"active\":true,"
				+ "\"aud\":[\"a\",\"b\"],\"scale\":1,\"nonce\":null}";

		require(expected.equals(json), "JsonObject.toJson() wrote " + json);
		require(object.findString("iss").equals(Optional.of("https://issuer.example")), "findString(iss)");
		require(object.findLong("exp").equals(Optional.of(1_800_000_000L)), "findLong(exp)");
		require(object.findBoolean("active").equals(Optional.of(Boolean.TRUE)), "findBoolean(active)");
		require(object.findStringList("aud").equals(Optional.of(List.of("a", "b"))), "findStringList(aud)");
		require(object.find("missing").isEmpty(), "find(missing)");
		require(JsonNull.defaultInstance().equals(object.getMembers().get("nonce")), "JsonNull.defaultInstance()");
		require(JsonNumber.fromValue(new BigDecimal("1.0")).equals(JsonNumber.fromValue(1L)), "JsonNumber equality");
		require(JsonBoolean.fromValue(Boolean.FALSE).equals(JsonBoolean.falseInstance()), "JsonBoolean.fromValue(false)");
		require(JsonObject.emptyInstance().toJson().equals("{}") && JsonArray.emptyInstance().toJson().equals("[]"),
				"empty instances");

		JsonValue ratio = object.getMembers().get("ratio");
		require(ratio instanceof JsonNumber && ((JsonNumber) ratio).getLongValueExact().isEmpty(), "0.50 is not a long");
		require(!object.toString().contains("issuer.example"), "JsonObject.toString() must be redacted");

		calledApi.add("com.revetsec.json");
		return json;
	}

	/**
	 * Seals and opens a value with a fresh random key, and checks that a value sealed for one context fails to open
	 * for another with {@link InvalidSealedStateException}.
	 */
	private static void exerciseResultTypes() {
		Class<?>[] types = {StateUnsealResult.class, StateUnsealResult.Succeeded.class, StateUnsealResult.Rejected.class,
				JwtValidationResult.class, JwtValidationResult.Succeeded.class, JwtValidationResult.Rejected.class,
				BearerTokenResult.class, BearerTokenResult.Absent.class, BearerTokenResult.Present.class, BearerTokenResult.Malformed.class,
				AuthorizationCompletionResult.class, AuthorizationCompletionResult.Succeeded.class, AuthorizationCompletionResult.Denied.class,
				AuthorizationCompletionResult.Rejected.class, AuthorizationCompletionResult.Failed.class,
				OidcAuthenticationResult.class, OidcAuthenticationResult.Succeeded.class,
				OidcAuthenticationResult.Denied.class, OidcAuthenticationResult.RejectedAuthorization.class,
				OidcAuthenticationResult.RejectedIdToken.class, OidcAuthenticationResult.Failed.class};
		require(types.length == 21, "all result declarations compile without annotation JARs");
	}

	private static @NonNull PendingAuthorizationStore unavailablePendingStore() {
		return new PendingAuthorizationStore() {
			@Override
			public void save(@NonNull String browserBinding, @NonNull String state, @NonNull String opaqueRecord,
					@NonNull Instant expiresAt, @NonNull Duration remaining) {
				throw new IllegalStateException("test store unavailable");
			}

			@Override
			public @NonNull Optional<@NonNull String> consume(@NonNull String browserBinding, @NonNull String state,
					@NonNull Duration remaining) {
				throw new IllegalStateException("test store unavailable");
			}
		};
	}

	private static void exerciseStateSealer(@NonNull String plaintext, @NonNull List<@NonNull String> calledApi) {
		byte[] keyBytes = new byte[32];
		new SecureRandom().nextBytes(keyBytes);
		SealingKey key = SealingKey.fromBase64("consumer-1", Base64.getEncoder().encodeToString(keyBytes));
		StateSealer.Builder builder = StateSealer.withActiveKey(key);
		StateSealer sealer = builder.clock(Clock.systemUTC()).maximumSealedLength(4_096).build();
		String sealed = sealer.seal(plaintext, SEALING_CONTEXT, Duration.ofMinutes(5));

		require(sealer.unseal(sealed, SEALING_CONTEXT).equals(plaintext), "StateSealer round trip");
		StateUnsealResult opened = sealer.unsealResult(sealed, SEALING_CONTEXT);
		require(opened instanceof StateUnsealResult.Succeeded && ((StateUnsealResult.Succeeded) opened).getValue().equals(plaintext),
				"result opening authenticates plaintext");
		require(sealer.unsealResult(sealed, "another-context") instanceof StateUnsealResult.Rejected,
				"result opening rejects another context");
		require(key.getKeyId().equals("consumer-1")
				&& !key.toString().contains(Base64.getEncoder().encodeToString(keyBytes)),
				"SealingKey must render its key ID but never its key");

		RevetsecException failure = null;

		try {
			sealer.unseal(sealed, "another-context");
		} catch (InvalidSealedStateException e) {
			failure = e;
		}

		require(failure != null, "a value sealed for one context must not open for another");
		require(failure.getCategory() == ErrorCategory.VALIDATION_FAILURE && !failure.isTransient(),
				"InvalidSealedStateException is a non-transient VALIDATION_FAILURE");

		calledApi.add("StateSealer");
	}

	/**
	 * Asks both outbound URI policies about DNS names, a private address and a literal cloud metadata address.
	 */
	private static void exerciseOutboundUriPolicy(@NonNull List<@NonNull String> calledApi) {
		OutboundUriPolicy policy = OutboundUriPolicy.defaultInstance();

		require(policy.permits(URI.create("https://issuer.example/.well-known/openid-configuration")),
				"the default policy permits an https DNS name");
		require(!policy.permits(URI.create("https://169.254.169.254/latest/meta-data/")),
				"the default policy rejects the link-local metadata address");
		require(policy.permits(URI.create("https://10.0.0.1/jwks")), "the default policy permits a private address");

		OutboundUriPolicy publicAddressesOnly = OutboundUriPolicy.publicAddressesOnlyInstance();

		require(publicAddressesOnly.permits(URI.create("https://login.example.com/.well-known/openid-configuration")),
				"the public-addresses-only policy permits a public DNS name");
		require(!publicAddressesOnly.permits(URI.create("https://10.0.0.1/jwks"))
						&& !publicAddressesOnly.permits(URI.create("https://issuer.example/jwks"))
						&& !publicAddressesOnly.permits(URI.create("https://169.254.169.254/latest/meta-data/")),
				"the public-addresses-only policy rejects private addresses, special-use names and metadata addresses");

		calledApi.add("OutboundUriPolicy");
	}

	/**
	 * Validates a JWT that this method signs with a fresh RSA key, against a JSON Web Key Set it writes; checks that
	 * forged, unsigned, malformed and unsupported tokens fail with their documented exception and reason, and that the
	 * observer sees each outcome; and builds a remote key source and a validator over it, which do no I/O.
	 */
	private static void exerciseJose(@NonNull List<@NonNull String> calledApi) throws Exception {
		require(JwsAlgorithm.findByWireValue("RS256").equals(Optional.of(JwsAlgorithm.RS256))
						&& JwsAlgorithm.findByWireValue("rs256").isEmpty() && JwsAlgorithm.findByWireValue("none").isEmpty()
						&& JwsAlgorithm.EDDSA.getWireValue().equals("EdDSA"),
				"JwsAlgorithm lookup is exact and has no none");

		KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
		generator.initialize(2_048);
		KeyPair keyPair = generator.generateKeyPair();
		RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
		String modulus = BASE64URL.encodeToString(unsignedBytes(publicKey.getModulus()));
		String exponent = BASE64URL.encodeToString(unsignedBytes(publicKey.getPublicExponent()));
		String signingKey = "{\"kty\":\"RSA\",\"kid\":\"" + KEY_ID + "\",\"use\":\"sig\",\"alg\":\"RS256\",\"n\":\""
				+ modulus + "\",\"e\":\"" + exponent + "\"}";
		// The same key published for encryption: a key set skips it, and never uses its public half to verify.
		String encryptionKey = "{\"kty\":\"RSA\",\"kid\":\"consumer-key-2\",\"use\":\"enc\",\"n\":\"" + modulus
				+ "\",\"e\":\"" + exponent + "\"}";
		JsonWebKeySet keySet = JsonWebKeySet.fromJson("{\"keys\":[" + signingKey + "," + encryptionKey + "]}");

		require(keySet.getKeys().size() == 1, "the encryption key is skipped");
		require(keySet.equals(JsonWebKeySet.fromJson("{\"keys\":[" + signingKey + "]}")), "key sets compare by value");

		JsonWebKey key = keySet.getKeys().get(0);
		String thumbprintInput = "{\"e\":\"" + exponent + "\",\"kty\":\"RSA\",\"n\":\"" + modulus + "\"}";
		String thumbprint = BASE64URL.encodeToString(MessageDigest.getInstance("SHA-256")
				.digest(thumbprintInput.getBytes(StandardCharsets.UTF_8)));

		require(key.getKeyType().equals("RSA") && key.getKeyId().equals(Optional.of(KEY_ID))
						&& key.getAlgorithm().equals(Optional.of(JwsAlgorithm.RS256)) && key.getUse().equals(Optional.of("sig"))
						&& key.getCurve().isEmpty() && key.getThumbprintSha256().equals(thumbprint),
				"JsonWebKey exposes its public facts and its RFC 7638 thumbprint");
		require(!key.toString().contains(modulus), "JsonWebKey.toString() must not show the modulus");

		JsonWebKeySource source = StaticJsonWebKeySource.fromJsonWebKeySet(keySet);
		require(source instanceof StaticJsonWebKeySource
						&& ((StaticJsonWebKeySource) source).getJsonWebKeySet().equals(keySet),
				"StaticJsonWebKeySource holds the key set");

		boolean refusedEmptySource = false;

		try {
			StaticJsonWebKeySource.fromJsonWebKeySet(JsonWebKeySet.fromJson("{\"keys\":[" + encryptionKey + "]}"));
		} catch (IllegalArgumentException e) {
			refusedEmptySource = true;
		}

		require(refusedEmptySource, "a static source with no usable key is refused");

		RecordingJoseObserver observer = new RecordingJoseObserver();
		JwtValidator.Builder builder = JwtValidator.withIssuer(ISSUER);
		JwtValidator validator = builder
				.jsonWebKeySource(source)
				.expectedAudiences(Set.of(AUDIENCE))
				.clock(Clock.fixed(NOW, ZoneOffset.UTC))
				.observer(observer)
				.build();

		String header = "{\"alg\":\"RS256\",\"typ\":\"JWT\",\"kid\":\"" + KEY_ID + "\"}";
		String claims = "{\"iss\":\"" + ISSUER + "\",\"sub\":\"user-1\",\"aud\":\"" + AUDIENCE + "\",\"iat\":"
				+ NOW.getEpochSecond() + ",\"exp\":" + (NOW.getEpochSecond() + 300) + ",\"scope\":\"openid\"}";
		String token = signRs256(header, claims, keyPair);
		exerciseSigner(keyPair, claims);

        String accessClaims=claims.substring(0,claims.length()-1)+",\"client_id\":\"app\",\"jti\":\"id\"}";
        String accessCompact=signRs256(header.replace("JWT","at+jwt"),accessClaims,keyPair);
        JwtAccessTokenValidator.Builder accessBuilder=JwtAccessTokenValidator.withIssuer(ISSUER).expectedAudiences(Set.of(AUDIENCE)).jsonWebKeySource(source).clock(Clock.fixed(NOW,ZoneOffset.UTC)).observer(AccessTokenObserver.disabledInstance());
        AccessTokenValidator access=accessBuilder.build();((JwtAccessTokenValidator)access).warmUp();
        AccessTokenValidationResult accessResult=access.validateResult(BearerToken.fromAuthorizationHeaderValues(List.of("Bearer "+accessCompact)).orElseThrow());
        require(accessResult instanceof AccessTokenValidationResult.Succeeded,"packaged access-token validation");VerifiedAccessToken proof=((AccessTokenValidationResult.Succeeded)accessResult).getAccessToken();
        require(proof.getIssuer().equals(ISSUER)&&proof.getSubject().equals(Optional.of("user-1"))&&proof.getClientId().equals(Optional.of("app"))&&proof.getScopes().equals(Set.of("openid"))&&proof.getAudiences().equals(List.of(AUDIENCE))&&proof.getExpiresAt().isPresent()&&proof.getClaims().findString("jti").equals(Optional.of("id")),"checked access-token getters");
        AccessTokenValidationResult bad=access.validateResult(BearerToken.fromAuthorizationHeaderValues(List.of("Bearer malformed")).orElseThrow());require(bad instanceof AccessTokenValidationResult.Rejected&&((AccessTokenValidationResult.Rejected)bad).getReason()==AccessTokenValidationException.Reason.JWT_REJECTED&&((AccessTokenValidationResult.Rejected)bad).getJoseReason().isPresent()&&((AccessTokenValidationResult.Rejected)bad).getBearerError()==BearerError.INVALID_TOKEN,"packaged access-token rejection");
        OAuthClient confidential=OAuthClient.withAuthorizationServerMetadata(AuthorizationServerMetadata.withIssuer(ISSUER).authorizationEndpoint(URI.create(ISSUER+"/authorize")).tokenEndpoint(URI.create(ISSUER+"/token")).introspectionEndpoint(URI.create(ISSUER+"/inspect")).jwksUri(URI.create(ISSUER+"/keys")).introspectionEndpointAuthMethodsSupported(Set.of("client_secret_basic")).build()).clientId("app").clientAuthentication(ClientAuthentication.fromClientSecretBasic("TEST-ONLY-secret")).build();
        TokenIntrospectionClient.Builder introspectionBuilder=TokenIntrospectionClient.withOAuthClient(confidential).expectedAudiences(Set.of(AUDIENCE));TokenIntrospectionClient introspection=introspectionBuilder.build();introspection.warmUp();
        for(Class<?> type:List.of(AccessTokenValidator.class,JwtAccessTokenValidator.class,JwtAccessTokenValidator.Builder.class,TokenIntrospectionClient.class,TokenIntrospectionClient.Builder.class,VerifiedAccessToken.class,AccessTokenObserver.class,AccessTokenCompatibilityMode.class,AccessTokenValidationResult.class,AccessTokenValidationResult.Succeeded.class,AccessTokenValidationResult.Rejected.class))require(type.getName().startsWith("com.revetsec.oauth."),"packaged resource type "+type.getName());
		Jwt jwt = validator.validate(token);
		JwtClaims jwtClaims = jwt.getClaims();

		require(jwt.getAlgorithm() == JwsAlgorithm.RS256 && jwt.getKeyId().equals(Optional.of(KEY_ID))
						&& jwt.getType().equals(Optional.of("JWT")) && jwt.toCompactSerialization().equals(token),
				"Jwt exposes its header facts and the token as received");
		require(jwtClaims.getIssuer().equals(Optional.of(ISSUER)) && jwtClaims.getSubject().equals(Optional.of("user-1"))
						&& jwtClaims.getAudiences().equals(List.of(AUDIENCE))
						&& jwtClaims.getExpiresAt().equals(Optional.of(NOW.plusSeconds(300)))
						&& jwtClaims.getClaim("scope").equals(Optional.of(JsonString.fromValue("openid"))),
				"JwtClaims exposes the validated claims");
		require(!jwt.toString().contains(token.substring(0, 20)) && !jwtClaims.toString().contains("user-1"),
				"Jwt and JwtClaims render neither the token nor a claim");
		require(observer.validated.equals(List.of(JwsAlgorithm.RS256)), "the observer saw the validation");


		// The signed payload swapped for another subject's: the signature no longer matches.
		String forgedClaims = claims.replace("\"sub\":\"user-1\"", "\"sub\":\"admin\"");
		String[] segments = token.split("\\.");
		String forged = segments[0] + "." + base64Url(forgedClaims) + "." + segments[2];
		JoseException forgery = refusal(validator, forged);
		require(forgery instanceof JwtValidationException
						&& forgery.getReason() == JoseException.Reason.SIGNATURE_MISMATCH
						&& forgery.getCategory() == ErrorCategory.VALIDATION_FAILURE,
				"a forged token fails with SIGNATURE_MISMATCH");

		JoseException unsigned = refusal(validator, base64Url("{\"alg\":\"none\"}") + "." + base64Url(claims) + ".");
		require(unsigned instanceof JwtValidationException
						&& unsigned.getReason() == JoseException.Reason.ALGORITHM_NOT_ALLOWED,
				"an unsigned token fails with ALGORITHM_NOT_ALLOWED");

		JoseException malformed = refusal(validator, "not-a-token");
		require(malformed instanceof MalformedJoseInputException
						&& malformed.getReason() == JoseException.Reason.TOKEN_SYNTAX
						&& malformed.getCategory() == ErrorCategory.MALFORMED_INPUT,
				"a malformed token fails with TOKEN_SYNTAX");

		JoseException encrypted = refusal(validator, "a.b.c.d.e");
		require(encrypted instanceof UnsupportedJoseFeatureException
						&& encrypted.getReason() == JoseException.Reason.ENCRYPTED_TOKEN
						&& encrypted.getCategory() == ErrorCategory.UNSUPPORTED,
				"an encrypted token fails with ENCRYPTED_TOKEN");

		JwtValidator otherIssuer = JwtValidator.withIssuer("https://login.example.com/tenant-2")
				.jsonWebKeySource(source)
				.acceptAnyAudience(Boolean.TRUE)
				.clock(Clock.fixed(NOW, ZoneOffset.UTC))
				.observer(JoseObserver.disabledInstance())
				.build();
		require(refusal(otherIssuer, token).getReason() == JoseException.Reason.ISSUER_MISMATCH,
				"a token from another issuer fails with ISSUER_MISMATCH");

		require(observer.failures.equals(List.of(forgery, unsigned, malformed, encrypted)),
				"the observer saw each refusal, as the very instance thrown");

		JwtValidationResult checked = validator.validateResult(token);
		require(checked instanceof JwtValidationResult.Succeeded && ((JwtValidationResult.Succeeded) checked).getJwt().toCompactSerialization().equals(token),
				"result validation exposes only a validated JWT");
		JwtValidationResult rejected = validator.validateResult("bad.jwt");
		require(rejected instanceof JwtValidationResult.Rejected && ((JwtValidationResult.Rejected) rejected).getReason() == JoseException.Reason.TOKEN_SYNTAX,
				"result validation rejects malformed input");

		boolean refusedKeySet = false;

		try {
			JsonWebKeySet.fromJson("{\"keys\":{}}");
		} catch (MalformedJoseInputException e) {
			refusedKeySet = e.getReason() == JoseException.Reason.KEY_SET;
		}

		require(refusedKeySet, "a key set document without a keys array fails with KEY_SET");

		// A remote source and a validator over it do no I/O until a key is needed, so nothing here touches the network.
		URI jwksUri = URI.create("https://login.example.com/tenant-1/discovery/v2.0/keys?appid=packaged-consumer");
		RemoteJsonWebKeySource.Builder remoteBuilder = RemoteJsonWebKeySource.withUri(jwksUri);
		RemoteJsonWebKeySource remoteSource = remoteBuilder
				.outboundUriPolicy(OutboundUriPolicy.publicAddressesOnlyInstance())
				.requestTimeout(Duration.ofSeconds(5))
				.unknownKeyRefreshCooldown(Duration.ofSeconds(30))
				.maximumStaleness(Duration.ofHours(1))
				.observer(observer)
				.build();
		JwtValidator remoteValidator = JwtValidator.withIssuer(ISSUER)
				.jsonWebKeySource(remoteSource)
				.expectedAudiences(Set.of(AUDIENCE))
				.build();

		require(remoteSource.getUri().equals(jwksUri) && !remoteSource.toString().contains("appid")
						&& !remoteValidator.toString().contains("appid"),
				"RemoteJsonWebKeySource keeps its URI and renders it without the query");
		require(refusesToBuild(URI.create("https://169.254.169.254/keys"))
						&& refusesToBuild(URI.create("http://login.example.com/keys"))
						&& refusesToBuild(URI.create("https://login.example.com/keys#fragment")),
				"RemoteJsonWebKeySource refuses a metadata address, plain http and a fragment at build()");
		require(observer.unexpected.isEmpty(), "no key set was fetched or skipped: " + observer.unexpected);

		calledApi.add("com.revetsec.jose");
	}

	/** Builds a static OAuth client and begins a PKCE flow without contacting an authorization server. */
	private static void exerciseOAuth(@NonNull List<@NonNull String> calledApi) {
		exerciseResourceServerProtocols();
		AuthorizationServerMetadata.Builder metadataBuilder = AuthorizationServerMetadata.withIssuer(ISSUER);
		AuthorizationServerMetadata metadata = metadataBuilder
				.authorizationEndpoint(URI.create(ISSUER + "/authorize"))
				.tokenEndpoint(URI.create(ISSUER + "/token")).build();
		ClientAuthentication authentication = ClientAuthentication.fromClientSecretBasic("consumer-secret",
				ClientSecretBasicEncoding.FORM_URLENCODED);
		OAuthClient.Builder clientBuilder = OAuthClient.withAuthorizationServerMetadata(metadata);
		OAuthClient client = clientBuilder.clientId("packaged-consumer").clientAuthentication(authentication)
				.redirectUri(URI.create("https://consumer.example/callback"))
				.issuerParameterPolicy(IssuerParameterPolicy.METADATA_DRIVEN).observer(OAuthObserver.disabledInstance())
				.build();
		AuthorizationRequestOptions.Builder requestBuilder = AuthorizationRequestOptions.builder();
		AuthorizationRequestOptions options = requestBuilder.scopes(Set.of("read"))
				.responseMode(AuthorizationRequestOptions.ResponseMode.QUERY).build();
		AuthorizationRedirect redirect = client.beginAuthorization(options);
		PendingAuthorization pending = redirect.getPendingAuthorization();
		require(redirect.getAuthorizationUri().getRawQuery().contains("code_challenge_method=S256")
				&& pending.getIssuer().equals(ISSUER) && pending.getRequestedScopes().equals(Set.of("read"))
				&& !redirect.toString().contains("code_challenge"), "OAuth begin uses PKCE and redacts pending state");
		AuthorizationResponse response = AuthorizationResponse.fromQueryString("code=example&state=opaque");
		require(response.getCode().equals(Optional.of("example")), "OAuth callback parser exposes the code");
		TokenRequestOptions.Builder tokenBuilder = TokenRequestOptions.builder();
		TokenRequestOptions tokenOptions = tokenBuilder.scopes(Set.of("read")).build();
		require(tokenOptions.getScopes().equals(Optional.of(Set.of("read"))), "OAuth token scope override");
		ClientCredentialsTokenSource.Builder sourceBuilder = ClientCredentialsTokenSource.withClient(client);
		ClientCredentialsTokenSource source = sourceBuilder.build();
		InMemoryPendingAuthorizationStore.Builder storeBuilder = InMemoryPendingAuthorizationStore.builder();
		PendingAuthorizationStore store = storeBuilder.build();
		AuthorizationCompletionResult outcome = client.completeAuthorizationResult(response,
				PendingAuthorizationSource.fromStore(store, "consumer-browser"), URI.create("https://consumer.example/callback"));
		require(outcome instanceof AuthorizationCompletionResult.Rejected
				&& ((AuthorizationCompletionResult.Rejected) outcome).getReason() == OAuthException.Reason.PENDING_AUTHORIZATION_NOT_FOUND,
				"callback result rejects missing state without network I/O");
		AuthorizationCompletionResult unavailable = client.completeAuthorizationResult(response,
				PendingAuthorizationSource.fromStore(unavailablePendingStore(), "consumer-browser"),
				URI.create("https://consumer.example/callback"));
		require(unavailable instanceof AuthorizationCompletionResult.Failed
				&& ((AuthorizationCompletionResult.Failed) unavailable).getReason() == OAuthException.Reason.PENDING_AUTHORIZATION_STORE_UNAVAILABLE,
				"callback result reports pending-store failure without network I/O");
		require(source != null && store != null, "OAuth client-side sources build without I/O");

		// Compiling against every exported type also checks signatures that this offline smoke cannot instantiate.
		Class<?>[] exported = {AccessToken.class, AuthorizationErrorException.class, AuthorizationRedirect.class,
				AuthorizationRequestOptions.class, AuthorizationRequestOptions.ResponseMode.class,
				AuthorizationRequestOptions.Builder.class, AuthorizationResponse.class, AuthorizationServerMetadata.class,
				AuthorizationServerMetadata.Builder.class, ClientAuthentication.class, ClientAuthentication.PrivateKeyJwtBuilder.class,
				ClientAssertionAudience.class, ClientAssertionKeyProvider.class, ClientAssertionSigningKey.class,
				ClientAssertionSigningKey.Builder.class, OAuthConfigurationException.class,
				ClientCredentialsTokenSource.class, ClientCredentialsTokenSource.Builder.class,
				ClientSecretBasicEncoding.class, InMemoryPendingAuthorizationStore.class,
				InMemoryPendingAuthorizationStore.Builder.class, IssuerParameterPolicy.class, OAuthClient.class,
				OAuthClient.Builder.class, OAuthEndpoint.class, OAuthErrorResponseException.class,
				OAuthException.class, OAuthException.Reason.class, OAuthObserver.class, OAuthResponseException.class,
				BearerToken.class, BearerTokenResult.class, BearerTokenResult.Absent.class, BearerTokenResult.Present.class, BearerTokenResult.Malformed.class,
				AuthorizationCompletionResult.class, AuthorizationCompletionResult.Succeeded.class, AuthorizationCompletionResult.Denied.class,
				AuthorizationCompletionResult.Rejected.class, AuthorizationCompletionResult.Failed.class,
				BearerError.class, BearerChallenge.class, BearerChallenge.Builder.class,
				ProtectedResourceMetadata.class, ProtectedResourceMetadata.Builder.class,
				AccessTokenValidationException.class, AccessTokenValidationException.Reason.class,
				OAuthTransportException.class, OAuthValidationException.class, PendingAuthorization.class,
				PendingAuthorizationSource.class, PendingAuthorizationStore.class, PendingAuthorizationStoreException.class,
				RefreshToken.class, TokenRequestOptions.class, TokenRequestOptions.Builder.class, TokenResponse.class,
				TokenTypeHint.class};
		require(exported.length == 58, "all OAuth exported types compile from the packaged JAR");
		calledApi.add("com.revetsec.oauth");
	}

	/** Exercises the pure resource protocol surface and raw callback envelope without annotation JARs or I/O. */
	private static void exerciseResourceServerProtocols() {
		require(BearerToken.fromAuthorizationHeaderValuesResult(List.of()) instanceof BearerTokenResult.Absent,
				"result parsing distinguishes absence");
		BearerTokenResult parsed = BearerToken.fromAuthorizationHeaderValuesResult(List.of("Bearer TEST-ONLY-credential"), 8192);
		require(parsed instanceof BearerTokenResult.Present && ((BearerTokenResult.Present) parsed).getToken() != null,
				"result parsing returns an unverified bearer");
		require(BearerToken.fromAuthorizationHeaderValuesResult(List.of("Bearer a", "Bearer a")) instanceof BearerTokenResult.Malformed,
				"result parsing rejects duplicate headers");
		BearerToken credential = BearerToken.fromAuthorizationHeaderValues(List.of("bEaReR a._~+/=="), 8192).orElseThrow();
		require(!credential.toString().contains("a._~+/=="), "parsed bearer diagnostic is redacted");
		require(BearerToken.fromAuthorizationHeaderValues(List.of()).isEmpty(), "missing bearer remains absent");
		try {
			BearerToken.fromAuthorizationHeaderValues(List.of("Bearer a", "Bearer a"));
			throw new IllegalStateException("Repeated credential was accepted.");
		} catch (AccessTokenValidationException error) {
			require(error.getReason() == AccessTokenValidationException.Reason.MALFORMED_REQUEST
					&& error.getBearerError() == BearerError.INVALID_REQUEST
					&& error.getBearerError().getStatusCode() == 400 && error.getJoseReason().isEmpty()
					&& error.getCause() == null && !error.isTransient(), "fixed malformed bearer verdict");
		}
		URI resource = URI.create("https://rs.example/mcp/?q=%2F");
		ProtectedResourceMetadata.Builder metadataBuilder = ProtectedResourceMetadata.withResource(resource);
		ProtectedResourceMetadata metadata = metadataBuilder.authorizationServers(List.of("https://as.example"))
				.scopesSupported(List.of("read", "write", "read")).allowInsecureLoopback(null).build();
		require(metadata.getResource().toString().equals(resource.toString())
				&& metadata.getWellKnownUri().toString().equals("https://rs.example/.well-known/oauth-protected-resource/mcp?q=%2F")
				&& metadata.getAuthorizationServers().equals(List.of("https://as.example"))
				&& metadata.getScopesSupported().equals(List.of("read", "write"))
				&& metadata.toJson().contains("\"bearer_methods_supported\":[\"header\"]"), "protected-resource metadata");
		BearerChallenge.Builder challengeBuilder = BearerChallenge.builder();
		BearerChallenge challenge = challengeBuilder.realm("api").error(null).errorDescription(null)
				.scopes(List.of("read")).resourceMetadata(metadata.getWellKnownUri()).maximumHeaderLength(null)
				.allowInsecureLoopback(null).build();
		require(challenge.getHeaderValue().startsWith("Bearer realm=\"api\", scope=\"read\"")
				&& !challenge.getHeaderValue().contains("error="), "initial bearer challenge omits error");
		require(BearerError.INVALID_TOKEN.getStatusCode() == 401 && BearerError.INVALID_TOKEN.getWireValue().equals("invalid_token")
				&& BearerError.INSUFFICIENT_SCOPE.getStatusCode() == 403, "bearer error mappings");
		AuthorizationResponse response = AuthorizationResponse.fromFormBody("state=abc&code=a%2Bb".getBytes(StandardCharsets.UTF_8),
				List.of("application/x-www-form-urlencoded; charset=utf-8"), "tracking=1");
		require(response.getCode().equals(Optional.of("a+b")), "raw callback Content-Type envelope");
	}

	/** Exercises OIDC configuration, pending requests and reference storage without contacting a provider. */
	private static void exerciseOidc(@NonNull List<@NonNull String> calledApi) throws Exception {
		OidcProviderMetadata.Builder metadataBuilder = OidcProviderMetadata.withIssuer(ISSUER);
		OidcProviderMetadata metadata = metadataBuilder.authorizationEndpoint(URI.create(ISSUER + "/authorize"))
				.tokenEndpoint(URI.create(ISSUER + "/token")).jwksUri(URI.create(ISSUER + "/keys"))
				.userInfoEndpoint(URI.create(ISSUER + "/userinfo")).userInfoSigningAlgValuesSupported(Set.of("RS256")).build();
		OidcObserver observer = OidcObserver.disabledInstance();
		OidcClient.Builder clientBuilder = OidcClient.withProviderMetadata(metadata);
		OidcClient client = clientBuilder.clientId(AUDIENCE).redirectUri(URI.create("https://consumer.example/callback"))
				.clock(Clock.fixed(NOW, ZoneOffset.UTC)).issuerPolicy(OidcIssuerPolicy.exactInstance()).issuerPolicy(null)
				.compatibility(Set.of()).observer(observer).userInfoSignedResponseAlgorithm(JwsAlgorithm.RS256).build();
		require(metadata.getAdvertisedIssuer().equals(ISSUER), "explicit OIDC advertised issuer");
		OidcIssuerPolicy entra = OidcIssuerPolicy.fromMicrosoftEntraMultiTenant(tenant -> { throw new AssertionError("build or parser called tenant policy"); });
		String common = "https://login.microsoftonline.com/common/v2.0";
		String template = "https://login.microsoftonline.com/{tenantid}/v2.0";
		String discovery = JsonObject.builder().put("issuer", template)
				.put("authorization_endpoint", common + "/authorize").put("token_endpoint", common + "/token")
				.put("jwks_uri", common + "/keys").put("response_types_supported", JsonArray.fromElements(List.of(JsonString.fromValue("code"))))
				.put("subject_types_supported", JsonArray.fromElements(List.of(JsonString.fromValue("public"))))
				.put("id_token_signing_alg_values_supported", JsonArray.fromElements(List.of(JsonString.fromValue("RS256")))).build().toJson();
		OidcProviderMetadata selected = OidcProviderMetadata.fromJson(common, discovery, entra);
		require(selected.getIssuer().equals(common) && selected.getAdvertisedIssuer().equals(template), "Entra configured and advertised issuers remain distinct");
		OidcClient selectedClient = OidcClient.withProviderMetadata(selected).issuerPolicy(entra).clientId(AUDIENCE)
				.redirectUri(URI.create("https://consumer.example/callback")).build();
		require(selectedClient.toString().contains("<redacted>") && entra.toString().contains("<redacted>"), "Entra configuration builds locally and redacts predicate");
		observer.didEnableMicrosoftEntraMultiTenant(); observer.didUseMicrosoftEntraMultiTenant();
		OidcAuthenticationOptions.Builder optionsBuilder = OidcAuthenticationOptions.builder();
		OidcAuthenticationOptions options = optionsBuilder.scopes(Set.of("email")).maxAge(Duration.ZERO)
				.responseMode(AuthorizationRequestOptions.ResponseMode.FORM_POST).build();
		AuthorizationRedirect redirect = client.beginAuthentication(options);
		require(redirect.getPendingAuthorization().getRequestedScopes().equals(Set.of("openid", "email"))
				&& redirect.getAuthorizationUri().getRawQuery().contains("response_mode=form_post")
				&& redirect.getAuthorizationUri().getRawQuery().contains("max_age=0"), "OIDC begin binds options and adds openid");
		require(metadata.getUserInfoSigningAlgValuesSupported().equals(Optional.of(Set.of("RS256"))), "OIDC UserInfo capabilities");

		JsonObject original = JsonObject.builder().put("iss", ISSUER).put("sub", "consumer-session")
				.put("aud", AUDIENCE).put("iat", NOW.getEpochSecond()).put("sid", "consumer-sid").build();
		String nonceDigest = BASE64URL.encodeToString(MessageDigest.getInstance("SHA-256").digest("TEST-ONLY-nonce".getBytes(StandardCharsets.UTF_8)));
		String storage = JsonObject.builder().put("v", 1L).put("client_id", AUDIENCE).put("claims", original)
				.put("nonce_digest", nonceDigest).build().toJson();
		OidcSessionReference reference = OidcSessionReference.fromSerializedForm(storage);
		byte[] keyBytes = new byte[32]; new SecureRandom().nextBytes(keyBytes);
		StateSealer sealer = StateSealer.withActiveKey(SealingKey.fromBase64("oidc-consumer", Base64.getEncoder().encodeToString(keyBytes)))
				.clock(Clock.fixed(NOW, ZoneOffset.UTC)).build(); Arrays.fill(keyBytes, (byte) 0);
		String sealed = reference.toSealedForm(sealer, "consumer-oidc-session", Duration.ofHours(1));
		OidcSessionReference opened = OidcSessionReference.fromSealedForm(sealed, sealer, "consumer-oidc-session");
		require(opened.getSessionId().equals(Optional.of("consumer-sid")) && opened.toSerializedForm().equals(storage)
				&& !opened.toString().contains("consumer-session"), "OIDC reference storage round trip and redaction");
		boolean rejected = false;
		try { OidcSessionReference.fromSerializedForm("{}"); }
		catch (OidcValidationException exception) {
			OidcException root = exception; OidcValidationException.Reason reason = exception.getReason();
			rejected = reason == OidcValidationException.Reason.SESSION_REFERENCE_INVALID && root.getCategory() == ErrorCategory.VALIDATION_FAILURE;
		}
		require(rejected, "OIDC reference parser rejects invalid storage with a fixed reason");
		OidcAuthenticationResult outcome = client.completeAuthenticationResult(AuthorizationResponse.fromQueryString("state=missing&code=example"),
				PendingAuthorizationSource.fromStore(InMemoryPendingAuthorizationStore.builder().clock(Clock.fixed(NOW, ZoneOffset.UTC)).build(), "consumer-browser"),
				URI.create("https://consumer.example/callback"));
		require(outcome instanceof OidcAuthenticationResult.RejectedAuthorization
				&& ((OidcAuthenticationResult.RejectedAuthorization) outcome).getReason() == OAuthException.Reason.PENDING_AUTHORIZATION_NOT_FOUND,
				"OIDC result rejects missing state before any token or identity release");
		OidcAuthenticationResult unavailable = client.completeAuthenticationResult(
				AuthorizationResponse.fromQueryString("state=missing&code=example"),
				PendingAuthorizationSource.fromStore(unavailablePendingStore(), "consumer-browser"),
				URI.create("https://consumer.example/callback"));
		require(unavailable instanceof OidcAuthenticationResult.Failed
				&& ((OidcAuthenticationResult.Failed) unavailable).getReason() == OAuthException.Reason.PENDING_AUTHORIZATION_STORE_UNAVAILABLE,
				"OIDC result reports pending-store failure before token or identity release");
		// Results require provider responses; class references still check their packaged annotation-free signatures.
		Class<?>[] exported = {OidcIssuerPolicy.class, IdToken.class, OidcAuthentication.class, OidcAuthenticationOptions.class,
				OidcAuthenticationOptions.Builder.class, OidcClient.class, OidcClient.Builder.class, OidcException.class,
				OidcObserver.class, OidcProviderMetadata.class, OidcProviderMetadata.Builder.class, OidcSessionReference.class,
				OidcUserInfo.class, OidcValidationException.class, OidcValidationException.Reason.class, OidcRefreshResult.class, OidcCompatibilityMode.class,
				OidcAuthenticationResult.class, OidcAuthenticationResult.Succeeded.class, OidcAuthenticationResult.Denied.class,
				OidcAuthenticationResult.RejectedAuthorization.class, OidcAuthenticationResult.RejectedIdToken.class,
				OidcAuthenticationResult.Failed.class};
		require(exported.length == 23, "all OIDC exported types compile from the packaged JAR");
		calledApi.add("com.revetsec.oidc");
	}

	private static @NonNull JoseException refusal(@NonNull JwtValidator validator, @NonNull String token) {
		try {
			validator.validate(token);
		} catch (JoseException e) {
			require(e.getCause() == null && !e.isTransient() && !e.getMessage().contains(token),
					"a JOSE refusal has no cause, is not transient and does not show the token");
			return e;
		}

		throw new IllegalStateException("Public API check failed: a token that must be refused was accepted");
	}

	private static boolean refusesToBuild(@NonNull URI jwksUri) {
		try {
			RemoteJsonWebKeySource.withUri(jwksUri).build();
		} catch (IllegalArgumentException e) {
			return true;
		}

		return false;
	}

	/** Exercises all signer algorithms through the public JAR with an independent JCA verifier. */
	private static void exerciseSigner(@NonNull KeyPair keyPair, @NonNull String claims) throws Exception {
		for (JwsAlgorithm algorithm : List.of(JwsAlgorithm.PS256, JwsAlgorithm.RS256, JwsAlgorithm.RS384)) {
			JwsSigner signer = JwsSigner.fromRsaKeyPair(keyPair.getPrivate(), keyPair.getPublic(), algorithm);
			require(signer.getAlgorithm() == algorithm
					&& ((RSAPublicKey) signer.getPublicKey()).getModulus().equals(((RSAPublicKey) keyPair.getPublic()).getModulus()),
					"signer exposes only its selected algorithm and checked public projection");
			signer.warmUp(Duration.ofSeconds(10));
			String compact = signer.toCompactSerialization("JWT", KEY_ID, null,
					claims.getBytes(StandardCharsets.UTF_8), Duration.ofSeconds(10));
			String[] parts = compact.split("\\.");
			require(parts.length == 3 && new String(Base64.getUrlDecoder().decode(parts[1]), StandardCharsets.UTF_8).equals(claims),
					"signer preserves exact accepted claims bytes");
			String name = algorithm == JwsAlgorithm.PS256 ? "RSASSA-PSS"
					: algorithm == JwsAlgorithm.RS256 ? "SHA256withRSA" : "SHA384withRSA";
			Signature verifier = Signature.getInstance(name);
			verifier.initVerify(keyPair.getPublic());
			if (algorithm == JwsAlgorithm.PS256)
				verifier.setParameter(new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1));
			verifier.update((parts[0] + "." + parts[1]).getBytes(StandardCharsets.US_ASCII));
			require(verifier.verify(Base64.getUrlDecoder().decode(parts[2])), "independent signer verification");
			require(!signer.toString().contains(compact), "signer rendering excludes its credential");
			try {
				signer.warmUp(Duration.ZERO);
				throw new AssertionError("zero signing budget accepted");
			} catch (JwsSigningException failure) {
				require(failure.getReason() == JwsSigningException.Reason.BUDGET_EXHAUSTED
						&& failure.getCategory() == ErrorCategory.TRANSPORT && failure.isTransient()
						&& failure.getCause() == null, "fixed signer budget failure");
			}
		}
		require(JwsSigningException.Reason.values().length == 3, "signer reason inventory");
		JwsSigner signer = JwsSigner.fromRsaKeyPair(keyPair.getPrivate(), keyPair.getPublic(), JwsAlgorithm.PS256);
		ClientAssertionSigningKey.Builder keyBuilder = ClientAssertionSigningKey.withSigner(signer);
		byte[] digest = new byte[32]; digest[0] = 7;
		ClientAssertionSigningKey key = keyBuilder.keyId(KEY_ID).certificateSha256Thumbprint(digest).build();
		digest[0] = 8;
		require(key.getKeyId().equals(Optional.of(KEY_ID)) && key.getCertificateSha256Thumbprint().orElseThrow()[0] == 7, "assertion key snapshot getters");
		key.getCertificateSha256Thumbprint().orElseThrow()[0] = 9;
		require(key.getCertificateSha256Thumbprint().orElseThrow()[0] == 7, "assertion key getter copies");
		ClientAssertionKeyProvider provider = ClientAssertionKeyProvider.fromKey(key);
		require(provider.getSigningKey(Duration.ofSeconds(1)) == key, "fixed assertion key provider");
		ClientAuthentication.PrivateKeyJwtBuilder authenticationBuilder = ClientAuthentication.withPrivateKeyJwt(provider);
		ClientAuthentication authentication = authenticationBuilder.audience(ClientAssertionAudience.TOKEN_ENDPOINT).audience(null)
				.assertionLifetime(Duration.ofSeconds(1)).assertionLifetime(null).build();
		require(ClientAuthentication.fromPrivateKeyJwt(provider) != null && !authentication.toString().contains(KEY_ID), "assertion factories and redaction");
		AuthorizationServerMetadata role = AuthorizationServerMetadata.withIssuer(ISSUER).authorizationEndpoint(URI.create(ISSUER+"/a"))
				.tokenEndpoint(URI.create(ISSUER+"/t")).tokenEndpointAuthMethodsSupported(Set.of("private_key_jwt"))
				.tokenEndpointAuthSigningAlgValuesSupported(Set.of("PS256")).revocationEndpointAuthMethodsSupported(Set.of("private_key_jwt"))
				.revocationEndpointAuthSigningAlgValuesSupported(Set.of("RS384")).introspectionEndpointAuthSigningAlgValuesSupported(Set.of()).build();
		require(role.getTokenEndpointAuthSigningAlgValuesSupported().equals(Optional.of(Set.of("PS256")))
				&& role.getRevocationEndpointAuthMethodsSupported().equals(Optional.of(Set.of("private_key_jwt")))
				&& role.getRevocationEndpointAuthSigningAlgValuesSupported().equals(Optional.of(Set.of("RS384")))
				&& role.getIntrospectionEndpointAuthSigningAlgValuesSupported().equals(Optional.of(Set.of())), "assertion role metadata projections");
		OAuthClient.withAuthorizationServerMetadata(role).clientId("consumer").clientAuthentication(authentication).build();
	}

	private static @NonNull String signRs256(@NonNull String header, @NonNull String claims, @NonNull KeyPair keyPair) throws Exception {
		String signingInput = base64Url(header) + "." + base64Url(claims);
		Signature signature = Signature.getInstance("SHA256withRSA");
		signature.initSign(keyPair.getPrivate());
		signature.update(signingInput.getBytes(StandardCharsets.US_ASCII));
		return signingInput + "." + BASE64URL.encodeToString(signature.sign());
	}

	private static @NonNull String base64Url(@NonNull String text) {
		return BASE64URL.encodeToString(text.getBytes(StandardCharsets.UTF_8));
	}

	/**
	 * The big-endian octets of a positive integer with no leading zero octet (RFC 7518 section 6.3.1's
	 * Base64urlUInt).
	 */
	private static byte @NonNull [] unsignedBytes(@NonNull BigInteger value) {
		byte[] bytes = value.toByteArray();
		return bytes.length > 1 && bytes[0] == 0 ? Arrays.copyOfRange(bytes, 1, bytes.length) : bytes;
	}

	/**
	 * Records the events a consumer's observer receives. Key-set events must not occur here: every source the consumer
	 * validates with is static, and the remote one is never used.
	 */
	private static final class RecordingJoseObserver implements JoseObserver {
		private final List<JwsAlgorithm> validated = new ArrayList<>();
		private final List<RevetsecException> failures = new ArrayList<>();
		private final List<String> unexpected = new ArrayList<>();

		@Override
		public void didValidateJwt(@NonNull JwsAlgorithm algorithm, @NonNull Duration elapsed) {
			this.validated.add(algorithm);
		}

		@Override
		public void didFailToValidateJwt(@NonNull RevetsecException exception, @NonNull Duration elapsed) {
			this.failures.add(exception);

			if (exception instanceof JsonWebKeySetUnavailableException)
				this.unexpected.add("a static source made the key set unavailable");
		}

		@Override
		public void willFetchJsonWebKeySet(@NonNull URI jwksUri) {
			this.unexpected.add("willFetchJsonWebKeySet");
		}

		@Override
		public void didFailToFetchJsonWebKeySet(@NonNull URI jwksUri, @NonNull JsonWebKeySetUnavailableException exception,
																						@NonNull Boolean servingStaleKeys, @NonNull Duration elapsed) {
			this.unexpected.add("didFailToFetchJsonWebKeySet");
		}

		@Override
		public void didSkipJsonWebKey(@NonNull URI jwksUri, @NonNull Integer keyIndex, @NonNull JsonWebKeySkipReason reason) {
			this.unexpected.add("didSkipJsonWebKey " + reason);
		}
	}

 private static byte @NonNull [] issuerBodyWithCredentials(@NonNull OAuthServerResponse response) {
  require(response.getStatusCode() >= 100 && !response.getHeaders().containsKey("Location"), "server response ordinary fields");
  Optional<URI> location = response.getLocationWithCredentials();
  require(location.isEmpty() || location.orElseThrow().isAbsolute(), "server response redirect signature");
  require(response.toString().equals("OAuthServerResponse{<redacted>}"), "server response diagnostic boundary");
  return response.toHttpBodyWithCredentials();
 }

	private static void require(boolean condition, @NonNull String what) {
		if (!condition)
			throw new IllegalStateException("Public API check failed: " + what);
	}

 // Compile the restricted result accessors against the packaged JAR; public engine production follows separately.
 private static void issuerOutcomes(@NonNull OAuthAuthorizationResult authorization,@NonNull OAuthTokenResult token,
   @NonNull OAuthRevocationResult revocation,@NonNull OAuthIntrospectionResult introspection,@NonNull OAuthIssuerAccessTokenResult validation) {
  if(authorization instanceof OAuthAuthorizationResult.InteractionRequired required) {
   OAuthServerInteraction interaction=required.getInteraction();require(!interaction.getInteractionValue().isEmpty()
    && !interaction.getClientId().isEmpty() && interaction.getClientName()!=null && interaction.getRedirectUri().isAbsolute()
    && !interaction.getRequestedScopesByResource().isEmpty() && interaction.getExpiresAt()!=null,"restricted pending view");
  } else if(authorization instanceof OAuthAuthorizationResult.Completed completed) require(completed.getResponse()!=null,"completed response");
  else if(authorization instanceof OAuthAuthorizationResult.Denied denied) require(denied.getResponse()!=null,"denial response");
  else if(authorization instanceof OAuthAuthorizationResult.Rejected rejected) require(rejected.getReason()!=null&&rejected.getResponse()!=null,"authorization rejection");
  if(token instanceof OAuthTokenResult.Succeeded ok) require(ok.getResponse()!=null,"token response");
  else if(token instanceof OAuthTokenResult.Rejected bad) require(bad.getReason()!=null&&bad.getResponse()!=null,"token rejection");
  if(revocation instanceof OAuthRevocationResult.Succeeded ok) require(ok.getResponse()!=null,"revocation response");
  else if(revocation instanceof OAuthRevocationResult.Rejected bad) require(bad.getReason()!=null&&bad.getResponse()!=null,"revocation rejection");
  if(introspection instanceof OAuthIntrospectionResult.Succeeded ok) require(ok.getResponse()!=null,"introspection response");
  else if(introspection instanceof OAuthIntrospectionResult.Rejected bad) require(bad.getReason()!=null&&bad.getResponse()!=null,"introspection rejection");
  if(validation instanceof OAuthIssuerAccessTokenResult.Succeeded ok) require(ok.getAccessToken()!=null,"issuer proof");
  else if(validation instanceof OAuthIssuerAccessTokenResult.Rejected bad) require(bad.getReason()!=null&&bad.getAccessTokenReason()!=null
    && bad.getJoseReason()!=null&&bad.getBearerError()!=null,"issuer rejection without proof");
 }
}
