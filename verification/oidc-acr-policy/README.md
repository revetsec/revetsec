# Public OIDC ACR policy consumer

Compile `src/verification/oidcacr/OidcAcrPolicy.java` with Java 17 and the selected core JAR (JSpecify may be supplied only for compilation). Run with only core plus these consumer classes. No network, credentials, internal imports, annotations runtime or JUnit are required.

This checks ordered preferences, complete overrides/reset/copy behavior, preference versus acceptance configuration, strict version-2 reference parsing and immutable policy access through public APIs. Its manually supplied reference is structural comparison data, never identity. Genuine public login/refresh, sealed reference and logout integration are qualified separately by the OIDC source suites and final application/container join. Old version-1 references require authentication again.

The consumer requires the selected core JAR's SHA-256 as its sole argument and verifies the loaded code origin. Compile with `--release 17 -Xlint:all -Werror -proc:none`, using core plus compile-only annotations; run either on the classpath or with `--module-path` and `--add-modules com.revetsec`. Each runtime has only the core JAR and consumer classes. The qualification runner in the dated evidence packet records exact commands, artifacts and JDK paths.
