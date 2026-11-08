# Unpublished component characterization

These four JMH 1.37 cases add no production runtime dependency and are outside the core Maven build. Select an immutable core JAR with its expected SHA-256 and matching source manifest. The script validates the seven cached tooling/annotation JAR pins, compiles with `--release 17`, checks actual JAR origins and controlled positive/negative inputs, and preserves commands, fixtures, generated classes, raw JMH JSON/text and host/JDK metadata in a new output directory.

| Method | Measured operation | Trial setup excluded |
| --- | --- | --- |
| `jsonParse` | Bounded UTF-8 `JsonCodec.parse`, protocol-document profile with 4096-byte ceiling | File loading and input construction |
| `jwsVerify` | RS256 JWS cryptographic verification, fixed RSA-2048 test key and prepared signing-input/signature bytes | PEM/certificate parsing, Base64, signing, JSON/claims/complete JWT validation |
| `xmlSignatureVerify` | Pinned-key RSA-SHA256 enveloped metadata signature verification | XML signing, serialization and secure parsing |
| `scimFilterParse` | Public bounded SCIM syntax parse | File loading, schema binding, policy, query execution and authorization |

XML verification reuses the original parsed DOM but the production verifier unmarshals a fresh `XMLSignature` and creates a fresh validation context on every call. The control verifies, changes signed data on the same DOM, requires rejection, restores it and requires fresh verification; a cached successful XMLDSig result must not pass that control. Both verification benchmark methods require successful verification on every measured call. Results/trees are returned to JMH's generated blackhole consumer.

The selected run is single-thread average time in microseconds, two forks, three one-second warmups and five one-second measurements per fork, a fixed 512 MiB heap and JMH GC allocation counters. Inputs are fixed synthetic component fixtures, including an existing public test-only private key. No live account, network request or credential is involved. JMH and supplied annotation dependencies are confined to the unpublished runner classpath.

```sh
python3 run.py \
  --core /absolute/frozen/core.jar \
  --expected-core-sha256 SHA256 \
  --source-manifest /absolute/frozen/PRODUCTION-SOURCE-MANIFEST.json \
  --repository /absolute/cached/maven/repository \
  --jdk /absolute/jdk/home \
  --output /absolute/new/results
```

Use `--check-only` for compilation, origin and input controls without timed forks. Run each selected JDK into its own fresh directory. This tool does not fetch dependencies or install artifacts. Performance measurements on a shared development host with concurrent work characterize only these exact component fixtures, artifact and run conditions. They establish no SLA, representative-host baseline, deployment throughput or final-release acceptance. A later combined artifact needs an explicit exact dependency/source join or a targeted rerun.
