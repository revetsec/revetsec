# Key publication profile characterization

This Java 17 public-only probe keeps three distinct contracts explicit: generic RSA material can advertise all six RS*/PS* publication algorithms; compatible typed PSS keys can sign with fixed PSS parameters and verify with raw JCA; typed PSS publication and import refuse instead of erasing key restrictions. It uses only synthetic generated keys, sends no network request and prints no private key or compact credential.

Compile against an explicitly selected core JAR and the compile-only JSpecify annotation JAR, then run with only the selected core and consumer classes. The argument is the SHA-256 of that exact core. The probe checks its actual code origin before generating keys. Use a new private output directory for each toolchain; compilation with `--release 17 -proc:none -Xlint:all -Werror` and execution on JDK 17/21/27 are recorded in the current qualification packet.

```sh
javac --release 17 -proc:none -Xlint:all -Werror \
  -cp "$PROFILE_CORE:$PROFILE_JSPECIFY" -d "$PROFILE_CLASSES" \
  src/verification/keyprofile/KeyPublicationProfiles.java
java -cp "$PROFILE_CORE:$PROFILE_CLASSES" \
  verification.keyprofile.KeyPublicationProfiles "$PROFILE_CORE_SHA256"
```

These are behavior characterizations and a documented policy disposition, not a runtime defect repair or a generic PSS-container promise. The final combined candidate, applicable provider/hardware profiles and owner release acceptance remain separate. See the [publication guide](../../docs/jwks-publication.md) and [import guide](../../docs/key-imports.md).
