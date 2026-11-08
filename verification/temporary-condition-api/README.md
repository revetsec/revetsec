# Temporary condition API consumer

Compile the public consumer with `--release 17 -proc:none -Xlint:all -Werror` against the selected actual core JAR and compile-only JSpecify. Supply that core JAR's SHA-256 as the sole runtime argument. The classpath and automatic-module-path runtimes contain only core plus consumer classes; annotations and JUnit are absent. A real key-import rejection exercises the getter through its public declaring type. Live temporary failures and effect knowledge are covered separately by actual TLS/source tests.

The negative old-name source compiles on the earlier99 component and specifically fails to find the removed method on the new component. This is an intentional pre-1.0 source break, not a failing-before runtime security defect. No alias, new public type, replay decision, effect field or serialized-field change is introduced.
