# RevetSec Fuzz Tests

This module holds RevetSec's [Jazzer](https://github.com/CodeIntelligenceTesting/jazzer) fuzz
targets. It has its own `pom.xml`, the root build never sees it, and it is never published: the
pom skips `install` and `deploy` and builds no jar. Fuzzing dependencies therefore stay out of the
published `com.revetsec:revetsec` artifact, which keeps zero runtime dependencies.

The module compiles RevetSec's sources directly, the same way Soklet's `fuzz/` does:

- `../src/main/java` as main sources;
- `../src/test/java` and `../src/test/resources` as test sources and resources, so targets can
  reuse test helpers, fixtures and (from M7) the SAML mutator. Two groups of files are left out:
  Failsafe integration tests (`**/*IT.java`) and the Testcontainers-backed scripted-IdP classes
  (`com/revetsec/saml/ScriptedIdp*`). Nothing here needs Docker or Testcontainers.

`build-helper-maven-plugin` cannot filter the test sources it adds, so the compiler's
`testExcludes` does the filtering. The excluded files stay on javac's source path. If an included
file ever references one of them, javac compiles it implicitly and the build fails on the missing
Testcontainers classes. That failure is deliberate.

Versions: Jazzer 0.30.0 (as in Soklet's `fuzz/`) and JUnit 6.1.3 through the JUnit BOM, on Java
17 or newer. The BOM aligns Jazzer's transitive JUnit Platform modules with the explicit API,
engine and launcher dependencies. Without it, older Platform classes stay on the test classpath
and a run can fail before any input executes.

## Status at M0

The only target is `com.revetsec.PlaceholderFuzzTests`. It exercises no RevetSec code: it checks
a JDK property, that UTF-8 decoding with replacement is a fixed point after one round. It exists
only because ClusterFuzzLite's build check fails when a build has no fuzz targets.
**It is deleted at M1**, when the first real targets land. Its passing says nothing about
RevetSec.

The planned targets are:

- the JSON codec;
- the JOSE compact parser;
- the JWKS parser;
- the discovery document parser;
- `AuthorizationResponse`;
- `StateSealer.unseal`;
- `SecureXmlParser`;
- `SamlDomWalker`;
- the SAML metadata parser;
- the Redirect-binding inflate;
- PEM;
- the SCIM filter lexer and parser;
- the PATCH path parser;
- the PATCH body.

The invariant for every target is that only documented exceptions are thrown and that work is
bounded. A structure-aware SAML target will mutate valid signed responses and assert that each
result is either a rejection or an identical acceptance.

## Writing a target

- Put the class in `fuzz/src/test/java`, in the package of the code it exercises.
- Name the class `*FuzzTests`. Surefire here runs only `**/*FuzzTests.java`, because the core
  test tree is compiled into this module but its tests (the contract tests included) belong to
  the root build. `.clusterfuzzlite/build.sh` looks for the same class names. For the same
  reason, no class in the core test tree may be named `*FuzzTests`.
- Each `@FuzzTest` method becomes one ClusterFuzzLite target, named
  `<SimpleClassName>_<method>`. Target names must be unique across packages.
- Put curated seeds in `src/test/resources/<package>/<SimpleClassName>Inputs/<method>/`.
- Carry the Apache-2.0 header and a jsr305 thread-safety marker, as Soklet's fuzz targets do.

## Running locally

Replay the checked-in seeds (Jazzer's regression mode). This is what CI's `fuzz-regression` job
runs:

```sh
mvn -B -ntp -f fuzz/pom.xml verify
```

Run a short coverage-guided session for one target:

```sh
JAZZER_FUZZ=1 mvn -B -ntp -f fuzz/pom.xml \
  -Dtest='PlaceholderFuzzTests#utf8ReplacementDecodingIsAFixedPointAfterOneRound' \
  -Djazzer.max_duration=30s \
  test
```

Jazzer's JUnit integration runs only one coverage-guided `@FuzzTest` per JVM, so select one
method per invocation. Jazzer must be able to attach its agent to the test JVM (the Surefire
`argLine` allows it). A denied attachment is a harness failure, not evidence about the code under
test.

Replay passes on JDK 17, 21, 25 and 27 (checked 2026-09-23). On JDK 27, Jazzer 0.30.0's bundled
ASM cannot read Java 27 class files (major version 71), so it logs `Failed to instrument` warnings
for the JDK classes it hooks, such as `java.util.regex`. Use JDK 17 to 25 for fuzzing sessions
until a Jazzer release supports 27.

If the core test tree doesn't compile (for example while a change to it is in flight), build
against the main sources alone:

```sh
mvn -B -ntp -f fuzz/pom.xml -Drevetsec.fuzz.mainSourcesOnly verify
```

## Corpus policy

Inputs checked in under `src/test/resources/**/<Class>Inputs/<method>/` are curated regression
seeds. They are reviewed, named for the behavior they cover, and small enough to replay on every
push and PR. When real corpora land (M1, starting with the JSON corpus ported from Soklet), they
carry SHA-256 manifests.

Generated fuzzing output is ignored by `fuzz/.gitignore`:

- `fuzz/target/`;
- `fuzz/.cifuzz-corpus/`, Jazzer's generated corpus;
- raw `crash-*`, `timeout-*`, `slow-unit-*` and `oom-*` files.

When a target finds a real crash, do not commit the raw file. Confirm the root cause and fix it,
then promote the reproducer into one or both of:

- a focused unit or regression test next to the affected code;
- a named seed that describes the behavior, such as `overlong-slash.bin`.

Seeds are synthetic protocol values only. They must never contain captured production requests,
tokens, assertions, secrets, credentials or personal data. Test keys come only from the test-only
material under `src/test/resources/fixtures/keys/`.

Passing replay, and fuzzing without findings, are bounded evidence and not proof of the absence
of bugs.

## ClusterFuzzLite

[ClusterFuzzLite](https://google.github.io/clusterfuzzlite/) runs the same targets in GitHub
Actions:

| Workflow | Trigger | What it does |
|---|---|---|
| `ci.yml`, job `fuzz-regression` | push, PR | Gating seed replay: `mvn -B -ntp -f fuzz/pom.xml verify` on JDK 21 |
| `cflite_pr.yml` | PR | Builds every target and fuzzes them for 300 seconds in total (`code-change` mode), starting from the batch corpus |
| `cflite_batch.yml` | nightly, manual | Batch fuzzing for 600 seconds in total, then corpus pruning. Without a storage repository, the corpus and any crashes are kept as workflow artifacts |

The budgets are small while the only target is the placeholder. They grow when real targets land.

The build integration lives in `.clusterfuzzlite/`:

- `project.yaml`: `language: jvm`. JVM projects support only the `address` and `undefined`
  sanitizers, and the workflows use `address` alone, because RevetSec has no native code.
- `Dockerfile`: `gcr.io/oss-fuzz-base/base-builder-jvm:v1`, pinned by digest, plus Maven 3.9.16
  from Maven Central with its SHA-512 checked. `Dockerfile.dockerignore` keeps build output out of
  the context.
- `build.sh`: compiles this module with Maven, then asks Jazzer to list the `@FuzzTest` methods
  of every `*FuzzTests` class. For each one it writes an executable wrapper
  `$OUT/<SimpleClassName>_<method>`, which runs the method through the base image's Jazzer driver
  (`--target_class`, `--target_method`), and packs the method's seeds as
  `$OUT/<SimpleClassName>_<method>_seed_corpus.zip`.

  At runtime the targets use the base image's Jazzer (driver, agent and JUnit integration), and
  Maven's copies of Jazzer are left out so that two Jazzer versions are never mixed. The build
  also removes the seed directories from the runtime classpath: ClusterFuzzLite supplies them
  through the zip, and its build check needs a `-runs=4` start-up run to execute exactly four
  inputs.

**JDK.** On 2026-09-23 both `base-builder-jvm` (digest `sha256:5eaa9b0d…`) and the runner image
`clusterfuzzlite-run-fuzzers:v1` (digest `sha256:4c1febe9…`) shipped Temurin 17.0.16+8 as
`$JAVA_HOME`. The ClusterFuzzLite docs still say OpenJDK 15, which is stale. No extra JDK is
installed; `build.sh` fails if the image's JDK is older than 17.

**Pins.** The ClusterFuzzLite actions are pinned to the commit behind their `v1` tag. They are
Docker actions whose image tags (`clusterfuzzlite-build-fuzzers:v1`,
`clusterfuzzlite-run-fuzzers:v1`) are set upstream and cannot be pinned from this repository.

### Reproducing the ClusterFuzzLite build locally

JVM fuzzing in OSS-Fuzz and ClusterFuzzLite is x86_64 only. On an arm64 machine, pass
`--platform linux/amd64` and Docker runs the images under emulation. From the repository root:

```sh
# 1. Build the builder image (the context is the repository root).
docker build --platform linux/amd64 -t revetsec-cflite -f .clusterfuzzlite/Dockerfile .

# 2. Run the build, as ClusterFuzzLite's `compile` step does.
mkdir -p /tmp/revetsec-cflite-out
docker run --rm --platform linux/amd64 \
  -e FUZZING_ENGINE=libfuzzer -e SANITIZER=address -e FUZZING_LANGUAGE=jvm -e ARCHITECTURE=x86_64 \
  -v /tmp/revetsec-cflite-out:/out revetsec-cflite compile

# 3. Run ClusterFuzzLite's build checks, then fuzz one target for 20 seconds, in the runner image.
docker run --rm --platform linux/amd64 \
  -e FUZZING_ENGINE=libfuzzer -e SANITIZER=address -e FUZZING_LANGUAGE=jvm -e ARCHITECTURE=x86_64 \
  -e OUT=/out -e RUN_FUZZER_MODE=batch -e FUZZER_ARGS='-rss_limit_mb=2560 -timeout=25' \
  -v /tmp/revetsec-cflite-out:/out --entrypoint /bin/bash \
  gcr.io/oss-fuzz-base/clusterfuzzlite-run-fuzzers:v1 -c '
    python3 /usr/local/bin/test_all.py &&
    mkdir -p /tmp/corpus &&
    run_fuzzer PlaceholderFuzzTests_utf8ReplacementDecodingIsAFixedPointAfterOneRound \
      -max_total_time=20 /tmp/corpus'
```

Measured on an arm64 Mac under emulation (2026-09-23):

- pulling `base-builder-jvm` took 1 min 53 s, and pulling `clusterfuzzlite-run-fuzzers:v1` took
  1 min 44 s;
- the image build took about 3 s once the base image was cached;
- the `compile` step took about 34 s, most of it Maven resolving dependencies;
- `test_all.py` passed in about 33 s;
- the 20-second run executed about 26 million inputs with no findings.
