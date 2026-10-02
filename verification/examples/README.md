# Explicit example nullability

`NullabilityAudit.java` attributes actual Java types through javac and checks every source-declared method/constructor/record-component reference, including private, nested, generic, wildcard and array positions. Each must carry exactly one JSpecify `NonNull` or `Nullable` meaning. Primitive/void positions are exempt. NullMarked defaults and same-named shadow annotations do not substitute for explicit JSpecify.

[The example builder](../../examples/build.py) audits all main/test sources and the checker itself after each example's actual build, using its resolved test classpath and Java 17 attribution. Missing annotations and attribution errors produce JSON evidence and a failing exit. This runs in the `examples` CI job on Java 17 and 27. The checker is verification tooling and does not enter published or example JARs.
