# Optional example verification

The public examples build with Maven and run with Java; see
[examples/README.md](../../examples/README.md#build-with-maven).
These Python coordinators are optional CI audits, not consumer build launchers:

| Tool | Additional checks |
| --- | --- |
| [verify_packaged_examples.py](verify_packaged_examples.py) | Exact core/adapter source pins, framework checksum, complete adapter tests, unchanged pinned upstream tests, packaged runtime dependencies and attributed nullability |
| [verify_self_issued.py](verify_self_issued.py) | Frozen authored core/adapter inventories, private Maven repository, redacted capture and annotation-free standalone runtime |
| [verify_rsa_oidc.py](verify_rsa_oidc.py) | Frozen authored core inventory, private TLS fixture, independent JCA provider capture and attributed nullability |

Each tool accepts `--help`. Supply a new absolute `--work` directory and explicit
Maven/JDK/source paths. The packaged verifier takes `--core-source`,
`--adapter-source` and either `--framework-source` or the checksum-pinned
`--framework-jar`; CI supplies the exact run commit using `--core-revision`.
Source-building the framework requires the exact compiler recorded in
[examples/pins.json](../../examples/pins.json). The authored-source verifiers
accept `--core-source` (and `--adapter-source`/`--framework-jar` for self-issued).
Optional `--repository-tail` is read-only; `--offline` needs cached dependencies.
Retain inventories, commands and redacted results with the tested artifacts.
Never upload generated private TLS material, keys, tokens or browser state.

The [adapter input guard](adapter_compatibility.py) checks the exact pinned POM,
production and test trees before and after the build. The current published adapter
runs its full 196-test upstream suite without source replacements. The former
shared-clock fixture overlay is retired; the [manifest](../../examples/compatibility/soklet-shared-clock/manifest.json)
records the current revision and required count. Dirty inputs, source drift or
missing/failing/skipped tests fail closed.

## Explicit nullability

The `NullabilityAudit.java` checker attributes actual Java types through javac
and checks every source-declared method, constructor and record-component
reference, including private, nested, generic, wildcard and array positions.
Each must carry exactly one JSpecify `NonNull` or `Nullable` meaning.
Primitive/void positions are exempt. NullMarked defaults and same-named shadow
annotations do not substitute for explicit JSpecify.

The checker runs after the actual build with its resolved test classpath and
Java 21 attribution for Soklet applications, or Java 17 for core-only recipes.
Missing annotations and attribution errors fail with JSON evidence. CI runs the
Soklet examples on JDK 21/27 and core-only RSA recipes on JDK 17/27. This checker
is verification tooling and does not enter application JARs.
