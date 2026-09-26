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

import java.lang.module.ModuleDescriptor;
import java.lang.module.ModuleFinder;
import java.lang.module.ModuleReference;
import java.math.BigDecimal;
import java.net.JarURLConnection;
import java.net.URI;
import java.net.URL;
import java.net.URLConnection;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Optional;
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
 * It also calls the public API of both exported packages, {@code com.revetsec} and {@code com.revetsec.json},
 * nested builders included. Both consumers compile it with every lint warning an error and with nothing but the
 * Revetsec JAR on the class path, so a build proves that the published signatures resolve without Revetsec's
 * provided-scope annotation JARs (JSpecify, the jsr305 concurrency markers and Error Prone's annotations), and a run
 * proves the calls work without them. It prints {@code public-api=...} only after every call behaved as documented;
 * {@code verify-packaged-consumer.py} requires that line from both consumers.
 * <p>
 * The first argument, if present, is the path of the JAR the caller expects the root package to come from.
 */
public final class PackagedConsumer {
	private static final String MODULE_NAME = "com.revetsec";
	private static final String ROOT_PACKAGE_INFO_CLASS = "com.revetsec.package-info";
	private static final String ROOT_PACKAGE_INFO_RESOURCE = "com/revetsec/package-info.class";
	private static final String SEALING_CONTEXT = "packaged-consumer";

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
	 * Asks the default outbound URI policy about a DNS name and a literal cloud metadata address.
	 */
	private static void exerciseOutboundUriPolicy(List<String> calledApi) {
		OutboundUriPolicy policy = OutboundUriPolicy.defaultInstance();

		require(policy.permits(URI.create("https://issuer.example/.well-known/openid-configuration")),
				"the default policy permits an https DNS name");
		require(!policy.permits(URI.create("https://169.254.169.254/latest/meta-data/")),
				"the default policy rejects the link-local metadata address");

		calledApi.add("OutboundUriPolicy");
	}

	private static void require(boolean condition, String what) {
		if (!condition)
			throw new IllegalStateException("Public API check failed: " + what);
	}
}
