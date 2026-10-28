# Password hashing example

This Java 17 example creates a synthetic credential under an older Argon2id
profile, verifies it with a current profile, and upgrades it with an exact
credential-version compare-and-set. It uses one process-local work gate and an
ephemeral pepper key generated at startup. It prints no password or hash.

From the core repository root, build the unpublished core artifact and run the
source file:

```sh
mvn -B -ntp -Dmaven.javadoc.skip=true -DskipTests package
mkdir -p target/password-example
javac --release 17 -Xlint:all -Werror -cp target/classes -d target/password-example \
  examples/password-hashing/PasswordHashingExample.java
java -cp target/classes:target/password-example PasswordHashingExample
```

The example's in-memory credential store and key are deliberately volatile.
Core CI compiles this source with the Java 17 language/API baseline and runs it
on each supported JDK after the core test suite.
Production applications need authoritative durable storage, distributed
per-account login admission, protected key retention/rotation, password policy,
MFA, and an application session transaction. Read the
[password hashing guide](../../docs/password-hashing.md) before adapting it.
