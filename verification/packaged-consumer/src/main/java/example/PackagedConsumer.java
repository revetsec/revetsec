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

import com.revetsec.ErrorCategory;
import com.revetsec.InvalidSealedStateException;
import com.revetsec.OutboundUriPolicy;
import com.revetsec.RevetsecException;
import com.revetsec.SealingKey;
import com.revetsec.StateSealer;
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
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
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
 * {@code com.revetsec.json} and {@code com.revetsec.jose}, and uses every public type in them, nested builders and
 * enums included. The JOSE calls validate a JWT the consumer signs itself with a fresh RSA key, against a key set it
 * writes, refuse forged, unsigned, malformed and unsupported tokens, and build a remote key source without any I/O.
 * Both consumers compile it with every lint warning an error and with nothing but the Revetsec JAR on the class path,
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

	public static void main(String[] arguments) throws Exception {
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
		exerciseStateSealer(json, calledApi);
		exerciseOutboundUriPolicy(calledApi);
		exerciseJose(calledApi);

		System.out.println("jar=" + jar);
		System.out.println("automatic-module-name=" + automaticModuleName);
		System.out.println("root-package-info=" + packageInfo.getName());
		System.out.println("packages=" + String.join(",", new TreeSet<>(descriptor.packages())));
		System.out.println("runtime=" + Runtime.version());
		System.out.println("error-categories=" + Arrays.toString(ErrorCategory.values()));
		System.out.println("public-api=" + String.join(",", calledApi));
	}

	/**
	 * Builds, reads and writes JSON values through {@code com.revetsec.json}; returns the object's JSON text.
	 */
	private static String exerciseJsonModel(List<String> calledApi) {
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
	private static void exerciseStateSealer(String plaintext, List<String> calledApi) {
		byte[] keyBytes = new byte[32];
		new SecureRandom().nextBytes(keyBytes);
		SealingKey key = SealingKey.fromBase64("consumer-1", Base64.getEncoder().encodeToString(keyBytes));
		StateSealer.Builder builder = StateSealer.withActiveKey(key);
		StateSealer sealer = builder.clock(Clock.systemUTC()).maximumSealedLength(4_096).build();
		String sealed = sealer.seal(plaintext, SEALING_CONTEXT, Duration.ofMinutes(5));

		require(sealer.unseal(sealed, SEALING_CONTEXT).equals(plaintext), "StateSealer round trip");
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
	private static void exerciseOutboundUriPolicy(List<String> calledApi) {
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
	private static void exerciseJose(List<String> calledApi) throws Exception {
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

	private static JoseException refusal(JwtValidator validator, String token) {
		try {
			validator.validate(token);
		} catch (JoseException e) {
			require(e.getCause() == null && !e.isTransient() && !e.getMessage().contains(token),
					"a JOSE refusal has no cause, is not transient and does not show the token");
			return e;
		}

		throw new IllegalStateException("Public API check failed: a token that must be refused was accepted");
	}

	private static boolean refusesToBuild(URI jwksUri) {
		try {
			RemoteJsonWebKeySource.withUri(jwksUri).build();
		} catch (IllegalArgumentException e) {
			return true;
		}

		return false;
	}

	private static String signRs256(String header, String claims, KeyPair keyPair) throws Exception {
		String signingInput = base64Url(header) + "." + base64Url(claims);
		Signature signature = Signature.getInstance("SHA256withRSA");
		signature.initSign(keyPair.getPrivate());
		signature.update(signingInput.getBytes(StandardCharsets.US_ASCII));
		return signingInput + "." + BASE64URL.encodeToString(signature.sign());
	}

	private static String base64Url(String text) {
		return BASE64URL.encodeToString(text.getBytes(StandardCharsets.UTF_8));
	}

	/**
	 * The big-endian octets of a positive integer with no leading zero octet (RFC 7518 section 6.3.1's
	 * Base64urlUInt).
	 */
	private static byte[] unsignedBytes(BigInteger value) {
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
		public void didValidateJwt(JwsAlgorithm algorithm, Duration elapsed) {
			this.validated.add(algorithm);
		}

		@Override
		public void didFailToValidateJwt(RevetsecException exception, Duration elapsed) {
			this.failures.add(exception);

			if (exception instanceof JsonWebKeySetUnavailableException)
				this.unexpected.add("a static source made the key set unavailable");
		}

		@Override
		public void willFetchJsonWebKeySet(URI jwksUri) {
			this.unexpected.add("willFetchJsonWebKeySet");
		}

		@Override
		public void didFailToFetchJsonWebKeySet(URI jwksUri, JsonWebKeySetUnavailableException exception,
																						Boolean servingStaleKeys, Duration elapsed) {
			this.unexpected.add("didFailToFetchJsonWebKeySet");
		}

		@Override
		public void didSkipJsonWebKey(URI jwksUri, Integer keyIndex, JsonWebKeySkipReason reason) {
			this.unexpected.add("didSkipJsonWebKey " + reason);
		}
	}

	private static void require(boolean condition, String what) {
		if (!condition)
			throw new IllegalStateException("Public API check failed: " + what);
	}
}
