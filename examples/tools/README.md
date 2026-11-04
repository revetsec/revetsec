# Demo access-key utility

This JDK-only runtime utility replaces ad hoc secret-generation scripts for the
passkey and self-issued demos. Build it with `mvn -f examples/tools/pom.xml package`
from the core repository root (or build the complete examples reactor), then run:

```sh
java -jar examples/tools/target/example-tools-1.0.0-SNAPSHOT.jar \
  /absolute/private/new-access-key
```

Use an existing private parent directory. Each path must be absolute and new;
the utility refuses to overwrite a file. It creates POSIX mode 0600 files with
32 random bytes encoded as 43 unpadded base64url characters. It prints no key.
It fails if POSIX permissions are unavailable. These are disposable application
demo keys, not human passwords or production key management.
