# verification

Tooling that checks Revetsec's packaged artifact the way a consumer receives it. It checks invariant INV-L1 from [docs/threat-model.md](../docs/threat-model.md): the JAR has zero compile or runtime dependencies and needs no JDK modules other than `java.base`, `java.net.http`, `java.xml`, `java.xml.crypto` and `java.logging`. CI runs it in the `packaged-consumer` job. Nothing here is published, and the root pom never builds it.

| Path | Checks |
|---|---|
| `verify-published-pom.py` | A POM exactly as installed or downloaded: zero compile, runtime or system dependencies, including inside profiles; literal coordinates; jar packaging; no `<parent>`; no `<repositories>`; no DOCTYPE. A scope written as a property fails, because it cannot be checked statically. |
| `packaged-consumer/src/` | A minimal application that both consumer builds compile and run. It checks what any consumer can observe: the root package loads from the JAR, and `Automatic-Module-Name: com.revetsec` resolves as an automatic module. It also calls the public API of `com.revetsec`, `com.revetsec.json` and `com.revetsec.jose`, using every exported public type, nested builder and nested enum: a `JsonObject` built, read and written; a `StateSealer` sealing, opening and refusing a value for the wrong context; both `OutboundUriPolicy` presets; a `JwtValidator` over a `StaticJsonWebKeySource` that validates a JWT the consumer signs with a fresh RSA key, refuses forged, unsigned, malformed and unsupported tokens with their documented exceptions and reasons, and reports each outcome to a `JoseObserver`; a `RemoteJsonWebKeySource` and a validator over it, built without any I/O; and OIDC metadata/client/options, an offline authentication redirect, session-reference plain/sealed storage round trips and fixed parser errors. Class references cover all exported OAuth/OIDC result and exception types that require provider responses. It prints `public-api=...` last, only after every call behaved as documented. Both consumers compile it with every lint warning an error and nothing but the Revetsec JAR on the class path, so each build proves that the published signatures resolve without Revetsec's provided-scope annotation JARs. |
| `packaged-consumer/pom.xml` | The Maven consumer: `com.revetsec:revetsec` at default scope, compiled warning-free, with its resolved runtime class path written to a file. |
| `packaged-consumer/build.gradle`, `packaged-consumer/settings.gradle` | The Gradle consumer: `com.revetsec:revetsec` as an `implementation` dependency, resolved from the same local repository read as a file repository (its only repository, serving only `com.revetsec`), compiled warning-free. Its `resolutionReport` task writes every component, unresolved dependency and file in `runtimeClasspath` and `compileClasspath`, plus the Gradle version and the JDK that ran it. |
| `packaged-consumer/verify-packaged-consumer.py` | The whole check. The installed POM and JAR must be byte-identical to the build; the POM must pass the script above; the JAR must hold classes only under `com/revetsec/`, with `META-INF/LICENSE` and `META-INF/NOTICE`. The Maven consumer's resolved runtime class path must be exactly the Revetsec JAR. The Gradle distribution must have the pinned SHA-256, checked before anything is extracted from it. In the Gradle consumer, `runtimeClasspath` and `compileClasspath` must each be exactly the installed Revetsec JAR, and the Revetsec component must have no dependency. Both consumers must run, and each run's output must end with the `public-api=` line naming every group of calls. `jdeps` must list only the INV-L1 modules. The only classes it may report as not found are the provided-scope annotations (JSpecify, jsr305 concurrency markers, Error Prone), and those may appear only as annotations, never as class references the JVM resolves. Finally, the installed JAR and POM must be unchanged. |
| `test_*.py` | Seeded-violation self-tests for both scripts. The packaged-consumer self-tests also require `PackagedConsumer.java` to use every public type in the exported packages' sources, and to print the `public-api=` line. |

## Running locally

Download the pinned Gradle distribution, install core, then run the check with the same JDK and local repository:

```sh
export JAVA_HOME=/path/to/jdk-17-or-later
work=$(mktemp -d)
curl --proto '=https' --tlsv1.2 --fail --location --silent --show-error --output "$work/gradle-9.8.0-bin.zip" https://services.gradle.org/distributions/gradle-9.8.0-bin.zip
mvn -B -ntp -Dmaven.javadoc.skip=true -DskipTests install
python3 verification/packaged-consumer/verify-packaged-consumer.py --gradle-distribution "$work/gradle-9.8.0-bin.zip"
```

[CONTRIBUTING.md](../CONTRIBUTING.md#packaged-consumer) has the CI variant, which installs into an empty repository.

Useful options:

- `--repository DIR` names the local repository core was installed into. The default is `~/.m2/repository`.
- `--maven-arg=-Dmaven.repo.local.tail=$HOME/.m2/repository` reuses already-downloaded plugins when `--repository` is an isolated directory. It applies to the Maven consumer only; the Gradle consumer needs nothing but the installed JAR and POM.
- `--gradle-distribution ZIP` (required) is the downloaded Gradle archive. The script refuses it unless its SHA-256 is the pinned `GRADLE_DISTRIBUTION_SHA256`.
- `--output DIR` writes `packaged-consumer-result.json`, the evidence CI uploads.

Both consumers are copied to a temporary directory before they are built, so the checkout stays clean. Gradle runs offline, without a daemon or build cache, with a fresh Gradle user home in that directory, and fails on any deprecation warning.

To check a POM downloaded from Central:

```sh
python3 verification/verify-published-pom.py revetsec-1.0.0.pom --expect com.revetsec:revetsec:1.0.0
```

Self-tests:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s verification -p 'test_*.py'
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s verification/packaged-consumer -p 'test_*.py'
```

## The Gradle pin

`verify-packaged-consumer.py` pins Gradle 9.8.0 by the SHA-256 Gradle publishes next to the archive (`GRADLE_VERSION`, `GRADLE_DISTRIBUTION_SHA256`). It runs on every JDK from 17 to 27, so the same distribution serves the whole matrix; it was checked on Corretto 17, 21, 25, 26 and 27. There is no Gradle wrapper, so no wrapper JAR is committed. Dependabot does not update the pin. To move it, change the two constants, the download URL in `.github/workflows/ci.yml`, and the commands and every "Gradle <version>" in this file and in CONTRIBUTING.md together; `test_verify_packaged_consumer.py` fails while they disagree.

## In CI

The `packaged-consumer` job in `.github/workflows/ci.yml` runs the self-tests, downloads the Gradle archive, installs core into an isolated repository under `$RUNNER_TEMP`, and runs the check on Corretto 17 and 27, so each of those JDKs also runs Gradle. It uploads the result JSON as a 30-day artifact.

## Limits

- `jdeps` sees only class-file references. A class loaded by name through reflection is invisible to it; `SourcePolicyTests` and review cover that.
- The Gradle consumer reads the installed POM through Gradle's own POM mapping, as Gradle does for any module that publishes no Gradle Module Metadata (`.module` file). Core publishes none; if it ever did, this check would have to consume that file too.
- One Gradle version is checked: the pinned one.
- The consumer compile checks only the types `PackagedConsumer` uses, which is why a self-test requires it to use every exported public type. That matters for annotations: javac warns on JDK 17, 21, 25 and 26 (not on 27), and a consumer that compiles with warnings as errors fails, when a class it compiles against carries a provided-scope annotation with an element, such as jsr305's `@GuardedBy("lock")`, on any member, private ones included, and the annotation JAR is absent. Revetsec uses `@GuardedBy` only in internal packages, and the source policy's `provided-annotation-with-element` rule keeps such annotations out of every file in an exported package.

## Explicit executable signatures

`ExecutableNullabilityContractTests` attributes authored core test and Java verification/spike signatures with the
actual test classpath. The integration profile includes the IT/scripted-IdP sources; ordinary runs mirror Maven's
compile exclusions. `InternalNullabilityContractTests` retains the calibrated production/array/wildcard/record checks.
`FuzzNullabilityContractTests` checks every fuzz Java helper and target in both ordinary and main-sources-only replays.
Reference parameters and returns require exactly one explicit JSpecify meaning at every nested type position.
Intentional malformed Java fixtures and fixture strings retain their rejection calibrations.

The packaged consumer's canonical source also declares its signatures. Its temporary Maven/Gradle source copy erases
only JSpecify type-use tokens and imports, preserving Java bodies, comments and literal contents. Both actual consumer
builds still compile against the Revetsec JAR alone and run without annotation JARs; the rendering has calibrated
literal-preservation tests.

`render-java-source.py` uses that same literal-preserving renderer for the standalone Keycloak and scripted-IdP
spike launchers. Their temporary copies remain JDK-only; canonical authored signatures remain explicitly annotated.
The large core/fuzz signature guard child JVMs have a384MiB heap ceiling and two active processors.

The packaged consumer also exercises all three `JwsSigner` algorithms, exact payload bytes, checked public-key getters, explicit noncredential warm-up and fixed budget failure. Its independent JCA verification runs against the built JAR without annotation dependencies.

The packaged consumer exercises the assertion signing-key/provider/authentication builders, identifier/digest copying and role metadata getters without annotation dependencies. Actual assertion POST behavior and independent JCA verification run in `ClientAssertionTests`; full private-key provider qualification remains pending.

The packaged consumer also calls `OidcIssuerPolicy` factories, the nullable/reset issuer-policy setter, selected metadata parser, advertised-issuer accessor and default observer hooks without annotation JARs. The parser/build callback is a rejecting sentinel, proving these local operations do not call it. Real local TLS Entra identity/UserInfo/refresh paths are covered by `OidcIssuerPolicyTests`; hosted acceptance is unproven.
