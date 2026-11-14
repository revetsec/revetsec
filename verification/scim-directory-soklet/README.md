# Restrictive Soklet SCIM qualification

This runner exercises the actual packaged Playground service-client directory on an
owned IPv4 loopback Soklet listener. The native fixture verifies the application,
core, adapter and framework CodeSource paths and SHA-256 values before binding.
Runtime uses those four JARs plus the fixture; JSpecify is compilation-only.
Use the normal application distribution with its matching lib directory, since
its manifest also declares those dependencies.

Build the example with its matching core/adapter/framework dependencies. Supply
each artifact path and its expected SHA-256 explicitly:

    python3 verification/scim-directory-soklet/run.py \
      --application-jar examples/playground/target/playground-1.0.0.jar \
      --application-sha256 EXPECTED_APPLICATION_SHA256 \
      --core-jar examples/playground/target/lib/revetsec-1.0.0.jar \
      --core-sha256 EXPECTED_CORE_SHA256 \
      --adapter-jar examples/playground/target/lib/revetsec-soklet-1.0.0.jar \
      --adapter-sha256 EXPECTED_ADAPTER_SHA256 \
      --framework-jar examples/playground/target/lib/soklet-4.0.0.jar \
      --framework-sha256 EXPECTED_FRAMEWORK_SHA256 \
      --annotations-jar /path/to/jspecify-1.0.1.jar \
      --java-home /path/to/jdk21 \
      --output /private/tmp/scim-directory-owned-run

The output directory must be new. The runner generates private ephemeral service
credentials, records fixed case/status observations, and terminates its owned JVM
in a finally block. It does not archive Authorization values or response bodies.
Repeat on Java 27 with another new output directory. Java 17 cannot run the pinned
Soklet 4.0 carrier.

The 44 native observations cover alpha/beta and alias routing, administrator/limited/
reader policy, denied privilege/query/cookie/header channels, password privacy,
conditional writes, same-tenant group references, authenticated HEAD and framework OPTIONS, duplicate media and
complete/chunked body caps. This is HTTP loopback under a fixed HTTPS Host contract.
TLS edge/browser, durable persistence and independent review are separate gates.

Run the parser-only pin/refusal controls with:

    python3 verification/scim-directory-soklet/test_artifact_selection.py

Its fifteen refusal variants and one positive parsing control start no JVM or socket.
The normal example test suite includes actual policy changes at each exposed phase,
snapshot conflicts, UNKNOWN-applied versus known-no-effect writes, KDF outside
protection, secret-array wiping, generation non-reuse and eight-operation admission.

The portable calibration runner accepts the same artifact/JDK/annotation flags as
the native runner, plus:

    --source-tree examples/playground \
    --repository /path/to/offline-maven-cache \
    --maven /path/to/mvn \
    --output /private/tmp/scim-directory-owned-plants

Invoke calibrate.py with all those flags. It copies five application sources and
two test sources into isolated Maven projects, changes one named guard (or the
two guards constituting one policy check), and runs the actual selected regression.
Nine plants cover tenant isolation, privilege fields, current principal, snapshot
CAS, exact If-Match, KDF under protection, UNKNOWN as no effect, privileged queries
and the original deadline. Every plant must reach an assertion failure with zero
test errors or skips. It never changes the supplied source tree or installs artifacts.
JSpecify 1.0.1, jsr305 3.0.2 and JUnit 6.1.3 must already exist in the offline cache.

The original administrative fixture's accepted privilege write is retained as a
selected-profile acceptance gap. It does not establish an unauthorized-access
defect in that explicitly administrative fixture. Existing interop receipts retain
their original source/schema/profile scope.
