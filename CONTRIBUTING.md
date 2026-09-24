## How To Contribute

#### Basics

Pull requests and bug reports are welcomed. For enhancement pull requests, please ask first to save time! It's possible the proposed enhancement is outside the scope or design goals of the project.

RevetSec is pre-release and its public API is still being designed, so please open an issue before starting any change that touches public API.

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

Pass `-Dmaven.javadoc.skip=true` to every build for now. There are no public types to document yet; Javadoc generation starts with the first public API, and this file will then describe its setup.

#### Gate Commands

CI runs these gating checks on every pull request (the scripted-IdP image only when its inputs change). Run the ones your change affects before opening one.

| Check | JDK | Command |
| --- | --- | --- |
| Build and tests | 17, 21, 25, 27 | `mvn -B -ntp -Dmaven.javadoc.skip=true verify` |
| Turkish locale | 21 | `REVETSEC_EXPECTED_LOCALE=tr-TR JAVA_TOOL_OPTIONS="-Duser.language=tr -Duser.country=TR" mvn -B -ntp -Dmaven.javadoc.skip=true verify` |
| Arabic locale | 21 | `REVETSEC_EXPECTED_LOCALE=ar-EG JAVA_TOOL_OPTIONS="-Duser.language=ar -Duser.country=EG" mvn -B -ntp -Dmaven.javadoc.skip=true verify` |
| Error Prone and NullAway | 21 | `mvn -B -ntp -Dmaven.javadoc.skip=true -Pstatic-analysis verify` |
| SpotBugs | 21 | `mvn -B -ntp -Dmaven.javadoc.skip=true -Pspotbugs verify` |
| Fuzz corpus replay | 21 | `mvn -B -ntp -f fuzz/pom.xml verify` |
| Packaged consumer | 17, 27 | the commands under [Packaged consumer](#packaged-consumer) |
| Scripted IdP image, only when `interop/scripted-idp/` or `ci.yml` changes | none (Docker, x86-64 and arm64) | the commands under [Scripted IdP image](#scripted-idp-image) |

In the locale rows, `REVETSEC_EXPECTED_LOCALE` makes `LocaleCanaryTests` check that the forked test JVM really runs in that locale. Without it the canary is skipped, and the build can pass without the locale ever taking effect.

The build's contract tests enforce the conventions in [NAMING_CONVENTIONS.md](NAMING_CONVENTIONS.md), the allowed dependencies between packages, a list of banned source constructs, and the wording of the documentation. `ClaimsLintTests` rejects unsupported claims in any Markdown file. If it flags wording you wrote, rephrase it. An entry in `claims-allowlist.txt` is for wording that has evidence behind it, and each entry states that evidence.

##### Packaged Consumer

This installs core into an empty local repository, then checks the installed POM and JAR, builds a separate consumer project against them, and runs `jdeps`. [verification/README.md](verification/README.md) describes each check and the script's options.

```shell
$ export PYTHONDONTWRITEBYTECODE=1
$ python3 -m unittest discover -s verification -p 'test_*.py'
$ python3 -m unittest discover -s verification/packaged-consumer -p 'test_*.py'
$ work=$(mktemp -d)
$ mvn -B -ntp -Dmaven.repo.local="$work/consumer-repository" -Dmaven.javadoc.skip=true -DskipTests clean install
$ python3 verification/packaged-consumer/verify-packaged-consumer.py --repository "$work/consumer-repository" --java-home "$JAVA_HOME" --output "$work/packaged-consumer-result"
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

`.github/workflows/` is the source of truth for all of the above. CodeQL (`codeql.yml`) and ClusterFuzzLite's time-boxed fuzzing (`cflite_pr.yml`) also run on pull requests, but only in GitHub Actions. The nightly legs on other JDK builds and on an early-access JDK are advisory. The tooling directories (`fuzz/`, `verification/` and `interop/`) have their own builds, and the root build does not build them.

#### Code Conventions

- Java 17 language level; tabs for indentation.
- Every Java source file starts with the Apache License 2.0 header that names `Copyright 2026 Revetware LLC.`, as in the existing sources.
- Public API follows [NAMING_CONVENTIONS.md](NAMING_CONVENTIONS.md). There are no public records. Every public element carries JSpecify nullness annotations, every exported type carries exactly one of `@ThreadSafe`, `@NotThreadSafe` or `@Immutable`, and every public member has `@since`.
- No compile or runtime dependencies. Build-time dependencies are `provided` or `test` scope.
- Test classes are named `*Tests`. Tests use a fixed `Clock`, hand-written fakes instead of a mocking library, and no `Thread.sleep`.

#### Publishing

Publishing is a project-owner operation, not the last step of an ordinary contributor build. Do not run `mvn deploy`. Releases are signed and published to Maven Central by the project owner. Snapshot builds are not published.
