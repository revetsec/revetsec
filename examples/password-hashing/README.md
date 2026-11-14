# Password hashing example

This Java 17 example creates a synthetic credential under an older Argon2id
profile, verifies it with a current profile, and upgrades it with an exact
credential-version compare-and-set. It uses one process-local work gate and an
ephemeral pepper key generated at startup. It prints no password or hash.

Install the current core artifact as described in the
[parent Maven instructions](../README.md#build-with-maven), then build and run
from the core repository root:

```sh
mvn -B -ntp -f examples/password-hashing/pom.xml verify
java -jar examples/password-hashing/target/password-hashing-1.0.0.jar
```

Maven puts the core runtime dependency in `target/lib`. Keep that directory
beside the executable JAR. No Python or HTTP adapter is needed.

The example's in-memory credential store and key are deliberately volatile.
Core CI compiles this source with the Java 17 language/API baseline and runs it
on each supported JDK after the core test suite.
Production applications need authoritative durable storage, distributed
per-account login admission, protected key retention/rotation, password policy,
MFA, and an application session transaction. Read the
[password hashing guide](../../docs/password-hashing.md) before adapting it.
