## How To Contribute

#### Basics

Pull requests and bug reports are welcomed. For enhancement pull requests, please ask first to save time! It's possible the proposed enhancement is outside the scope or design goals of the project.

Revetsec is pre-release and its public API is still being designed, so please open an issue before starting any change that touches public API.

Report suspected security vulnerabilities privately as described in [SECURITY.md](SECURITY.md), not in an issue or pull request.

No contributor license agreement is required at this time.

Workflow runs for pull requests from forks need a maintainer's approval. Before approving one, a maintainer reviews every change under `.github/` and `.clusterfuzzlite/` in that pull request, because those files control what the run executes.

#### Local Build

You need JDK 17 or newer (17.0.3 at minimum) and Maven 3.9 or newer. The library targets Java 17 whichever JDK runs the build.

```shell
$ export JAVA_HOME=/absolute/path/to/jdk-17
$ export PATH="$JAVA_HOME/bin:$PATH"
$ mvn -B -ntp -Dmaven.javadoc.skip=true verify
```

This compiles, runs every test (including the contract tests) and packages the JAR. Use `install` instead of `verify` to put `1.0.0-SNAPSHOT` into your local Maven repository, for example to build an adapter repository against it.

`-Dmaven.javadoc.skip=true` skips the Javadoc JAR, which the build otherwise generates with a separate JDK 26, the version the pom's offline Java API links are for. CI checks the Javadoc in its own job. To run that check locally, point `REVETSEC_JAVADOC_HOME` at a JDK 26 and leave the flag off:

```shell
$ export REVETSEC_JAVADOC_HOME=/absolute/path/to/jdk-26
$ mvn -B -ntp -Dmaven.javadoc.failOnWarnings=true -DskipTests verify
```

Maven and the compiler still run on `JAVA_HOME`; only the `javadoc` tool comes from `REVETSEC_JAVADOC_HOME`. The pom turns on every doclint group except `html`, and `failOnWarnings` makes each warning fail the build. So every public type and member needs a comment, every parameter and type parameter an `@param`, every non-void method an `@return`, every checked exception in a `throws` clause an `@throws`, and every serialized field of an exception a doc comment. CI installs Corretto 26.0.2 with a pinned SHA-256 (`.github/scripts/install-pinned-corretto-linux-x64.sh`); locally, any JDK 26 build works.

#### Gate Commands

CI runs these gating checks on every pull request (the scripted-IdP image only when its inputs change). Run the ones your change affects before opening one.

| Check | JDK | Command |
| --- | --- | --- |
| Build and tests | 17, 21, 25, 27 | `mvn -B -ntp -Dmaven.javadoc.skip=true clean verify` |
| Turkish locale | 21 | `REVETSEC_EXPECTED_LOCALE=tr-TR JAVA_TOOL_OPTIONS="-Duser.language=tr -Duser.country=TR" mvn -B -ntp -Dmaven.javadoc.skip=true clean verify` |
| Arabic locale | 21 | `REVETSEC_EXPECTED_LOCALE=ar-EG JAVA_TOOL_OPTIONS="-Duser.language=ar -Duser.country=EG" mvn -B -ntp -Dmaven.javadoc.skip=true clean verify` |
| Error Prone and NullAway | 21 | `mvn -B -ntp -Dmaven.javadoc.skip=true -Pstatic-analysis clean verify` |
| SpotBugs | 21 | `mvn -B -ntp -Dmaven.javadoc.skip=true -Pspotbugs clean verify` |
| Keycloak OAuth integration | 17, Docker | `mvn -B -ntp -Dmaven.javadoc.skip=true -Pintegration clean verify` |
| Fuzz corpus replay: every fuzz target's seeds, in Jazzer's regression mode | 21 | `mvn -B -ntp -f fuzz/pom.xml clean verify` |
| Javadoc | 17 for Maven, 26 for `javadoc` | `REVETSEC_JAVADOC_HOME=/absolute/path/to/jdk-26 mvn -B -ntp -Dmaven.javadoc.failOnWarnings=true -DskipTests clean verify` |
| Packaged consumer: Maven | 17, 27 | the commands under [Packaged consumer](#packaged-consumer) |
| Packaged consumer: Gradle 9.8.0 | 17, 27 | the same commands; one run of the script checks both consumers |
| Scripted IdP image, only when `interop/scripted-idp/` or `ci.yml` changes | none (Docker, x86-64 and arm64) | the commands under [Scripted IdP image](#scripted-idp-image) |

Run them with `clean`, as the table does. CI always starts from a fresh checkout, and Error Prone and NullAway report only while they compile, so a local `verify` after an earlier build can pass without analyzing anything.

In the locale rows, `REVETSEC_EXPECTED_LOCALE` makes `LocaleCanaryTests` check that the forked test JVM really runs in that locale. Without it the canary is skipped, and the build can pass without the locale ever taking effect.

The coverage floors are not a pull-request check: they are checked when a milestone is integrated. To check them yourself, on JDK 17, 21 or 27:

```shell
$ mvn -B -ntp -Dmaven.javadoc.skip=true -Pcoverage clean verify
```

The `coverage` profile fails the build when the whole JAR, or a package in the critical set (`internal.json`, `internal.crypto`, `internal.encoding`, `internal.http`, `internal.jose`, `jose` and `oauth` so far), falls below its floor. The pom lists each floor with the measurement it came from. Code that runs only in a child JVM, which some tests start, is not counted.

Mutation testing is not a pull-request check either. PIT mutates the protocol packages as they land, so far `jose`, `internal.jose`, `oauth` and the signature and key classes of `internal.crypto` (the pom's `mutation` profile lists its targets). Its report is evidence for milestone reviews, and at each release candidate every surviving mutant must be killed or explained in writing. To run it:

```shell
$ mvn -B -ntp -Dmaven.javadoc.skip=true -Pmutation clean verify
```

The build's contract tests enforce the conventions in [NAMING_CONVENTIONS.md](NAMING_CONVENTIONS.md), the allowed dependencies between packages, a list of banned source constructs, and the wording of the documentation. `ClaimsLintTests` rejects unsupported claims in any Markdown file. If it flags wording you wrote, rephrase it. An entry in `claims-allowlist.txt` is for wording that has evidence behind it, and each entry states that evidence.

##### Packaged Consumer

This installs core into an empty local repository, then checks the installed POM and JAR, builds two separate consumer projects against them, one with Maven and one with Gradle, and runs `jdeps`. Each consumer must resolve exactly the Revetsec JAR from that repository, with no dependency of its own, and must compile and run a program that calls the public API. [verification/README.md](verification/README.md) describes each check and the script's options.

The Gradle consumer builds with Gradle 9.8.0, which runs on every JDK from 17 to 27. The script checks the distribution's pinned SHA-256 before it extracts anything, so download the archive from the pinned URL:

```shell
$ export PYTHONDONTWRITEBYTECODE=1
$ python3 -m unittest discover -s verification -p 'test_*.py'
$ python3 -m unittest discover -s verification/packaged-consumer -p 'test_*.py'
$ work=$(mktemp -d)
$ curl --proto '=https' --tlsv1.2 --fail --location --silent --show-error --output "$work/gradle-9.8.0-bin.zip" https://services.gradle.org/distributions/gradle-9.8.0-bin.zip
$ mvn -B -ntp -Dmaven.repo.local="$work/consumer-repository" -Dmaven.javadoc.skip=true -DskipTests clean install
$ python3 verification/packaged-consumer/verify-packaged-consumer.py --repository "$work/consumer-repository" --java-home "$JAVA_HOME" --gradle-distribution "$work/gradle-9.8.0-bin.zip" --output "$work/packaged-consumer-result"
```

##### Scripted IdP Image

This builds the SAML test IdP's image and re-runs its selftest with no network. The image stays in your local Docker. Never push it to a registry.

```shell
$ docker build -t revetsec-scripted-idp:ci interop/scripted-idp
$ out=$(mktemp -d) && chmod 0777 "$out"
$ docker run --rm --network none --volume "$out:/out" revetsec-scripted-idp:ci selftest --out /out
```

The container runs as uid 65534, so the output directory must be writable by any user.

##### Other Workflows

`.github/workflows/` is the source of truth for all of the above. CodeQL (`codeql.yml`) and ClusterFuzzLite's time-boxed fuzzing (`cflite_pr.yml`, 20 minutes shared by every fuzz target) also run on pull requests, but only in GitHub Actions. Once the corpus storage repository is set up (the owner setup in the header of `cflite_batch.yml`), ClusterFuzzLite also fuzzes every target nightly and prunes the stored corpus (`cflite_batch.yml` and `cflite_cron.yml`). [fuzz/README.md](fuzz/README.md) describes the targets and how to fuzz one locally. The nightly legs on other JDK builds and on an early-access JDK are advisory. The tooling directories (`fuzz/`, `verification/` and `interop/`) have their own builds, and the root build does not build them.

#### Code Conventions

- Java 17 language level; tabs for indentation.
- Every Java source file starts with the Apache License 2.0 header that names `Copyright 2026 Revetware LLC.`, as in the existing sources.
- Public API follows [NAMING_CONVENTIONS.md](NAMING_CONVENTIONS.md). There are no public records. Every public element carries JSpecify nullness annotations, every exported type carries exactly one of `@ThreadSafe`, `@NotThreadSafe` or `@Immutable`, and every public member has `@since`.
- No compile or runtime dependencies. Build-time dependencies are `provided` or `test` scope.
- Test classes are named `*Tests`. Tests use a fixed `Clock`, hand-written fakes instead of a mocking library, and no `Thread.sleep`.
- Build a `@TestFactory`'s dynamic tests in a fixed order, from a `List`, a `LinkedHashMap`, an `EnumMap` or sorted entries, not by iterating a `Map.of`, `Set.of`, `HashMap` or `HashSet`, whose order can differ from one JVM to the next. A dynamic test's ID is its position, and PIT reruns a test by its ID in a fresh JVM, so an order that changes can make it report a mutant as surviving that the tests kill.

#### Publishing

Publishing is a project-owner operation, not the last step of an ordinary contributor build. Do not run `mvn deploy`. Releases are signed and published to Maven Central by the project owner. Snapshot builds are not published.
