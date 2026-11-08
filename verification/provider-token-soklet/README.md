# Optional Soklet provider-token component checks

First build the [normal Maven module](../../examples/provider-backend-tokens-soklet/README.md). This Python tool is an optional verification coordinator, not an application build launcher. It launches only its owned loopback Soklet/fake-JWKS JVM and removes it after the run. It records fixed checks and response hashes/cookie counts; generated fixture credentials and token bodies are not written to receipts.

```sh
python3 verification/provider-token-soklet/run.py \
  --java-home /absolute/jdk21 \
  --core-sha256 THE_EXACT_MATCHING_CORE_JAR_SHA256 \
  --framework-sha256 THE_SELECTED_EXAMPLES_PIN_SHA256 \
  --output /absolute/new-evidence-directory
```

`--examples-root` can select an already built isolated authored examples tree. Supply the SHA-256 of the actual Maven runtime copies: the common module's `target/lib/revetsec-1.0.0-SNAPSHOT.jar` and the Soklet module's `target/lib/soklet-4.0.0.jar`. The normal JAR manifests select those paths. Input mismatch refuses before creating output or starting services. Manifest runtime dependencies must be among the selected core/common/carrier/framework artifacts; annotation and JUnit libraries are absent. Source/artifact stability, cleanup, actual requests and precise profile gaps are recorded separately.

A successful tool exit means the component observations match their expectations. `qualifiedProfile` remains false. In particular, one observation demonstrates the pinned framework's loss of a bare trailing query delimiter; it is not a negative-guard pass. The deployed authenticated HTTPS edge must reject every query-bearing raw provider-route target before Soklet parsing. This tool supplies no real TLS/edge, browser, hosted-provider/device, distributed recovery or release qualification. The synthetic fixture/control routes and test signing keys must never be installed as application routes.
