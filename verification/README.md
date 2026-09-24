# verification

Tooling that checks RevetSec's packaged artifact the way a consumer receives it. It checks invariant INV-L1 from [docs/threat-model.md](../docs/threat-model.md): the JAR has zero compile or runtime dependencies and needs no JDK modules other than `java.base`, `java.net.http`, `java.xml`, `java.xml.crypto` and `java.logging`. CI runs it in the `packaged-consumer` job. Nothing here is published, and the root pom never builds it.

| Path | Checks |
|---|---|
| `verify-published-pom.py` | A POM exactly as installed or downloaded: zero compile, runtime or system dependencies, including inside profiles; literal coordinates; jar packaging; no `<parent>`; no `<repositories>`; no DOCTYPE. A scope written as a property fails, because it cannot be checked statically. |
| `packaged-consumer/pom.xml`, `packaged-consumer/src/` | A minimal Maven application depending on `com.revetsec:revetsec` at default scope. Until M1 the JAR holds only `package-info` classes, so it checks what a consumer can observe: the root package loads from the JAR, and `Automatic-Module-Name: com.revetsec` resolves as an automatic module. From M1 it also calls the public API. |
| `packaged-consumer/verify-packaged-consumer.py` | The whole check. The installed POM and JAR must be byte-identical to the build; the POM must pass the script above; the JAR must hold classes only under `com/revetsec/`, with `META-INF/LICENSE` and `META-INF/NOTICE`. The consumer's resolved runtime class path must be exactly the RevetSec JAR, and the consumer must run. `jdeps` must list only the INV-L1 modules. The only classes it may report as not found are the provided-scope annotations (JSpecify, jsr305 concurrency markers, Error Prone), and those may appear only as annotations, never as class references the JVM resolves. |
| `test_*.py` | Seeded-violation self-tests for both scripts. |

## Running locally

Install core, then run the check with the same JDK and local repository:

```sh
export JAVA_HOME=/path/to/jdk-17-or-later
mvn -B -ntp -Dmaven.javadoc.skip=true -DskipTests install
python3 verification/packaged-consumer/verify-packaged-consumer.py
```

Useful options:

- `--repository DIR` names the local repository core was installed into. The default is `~/.m2/repository`.
- `--maven-arg=-Dmaven.repo.local.tail=$HOME/.m2/repository` reuses already-downloaded plugins when `--repository` is an isolated directory.
- `--output DIR` writes `packaged-consumer-result.json`, the evidence CI uploads.

The consumer is copied to a temporary directory before it is built, so the checkout stays clean.

To check a POM downloaded from Central:

```sh
python3 verification/verify-published-pom.py revetsec-1.0.0.pom --expect com.revetsec:revetsec:1.0.0
```

Self-tests:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s verification -p 'test_*.py'
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s verification/packaged-consumer -p 'test_*.py'
```

## In CI

The `packaged-consumer` job in `.github/workflows/ci.yml` runs the self-tests, installs core into an isolated repository under `$RUNNER_TEMP`, and runs the check on Corretto 17 and 27. It uploads the result JSON as a 30-day artifact.

## Limits

- `jdeps` sees only class-file references. A class loaded by name through reflection is invisible to it; `SourcePolicyTests` and review cover that.
- A Gradle consumer joins at M1, when there is public API to call.
