# Bounded key import

This Java 17 example loads an application-owned PKCS#8 private DER file and a separately supplied SPKI public DER file, then explicitly checks that they form a pair. File reads stop at the fixed import ceiling. Private input bytes are erased after loading; JCA/provider-owned key copies remain under their ownership.

Build from the core repository root after installing a matching core artifact:

```sh
mvn -B -ntp -f examples/key-import/pom.xml verify
java -jar examples/key-import/target/revetsec-key-import-1.0.0.jar /path/to/private.pk8 /path/to/public.spki
```

Keep the packaged JAR and its sibling `lib` directory together. Maven runs the example's disposable test-only four-family and file-limit checks. Annotation libraries and JUnit are absent from its runtime dependencies. The application does not generate or export a key; test fixtures generate disposable keys only for verification.

`KeyImports` also accepts one matching PEM block, DER certificates and two-prime PKCS#1 RSA private DER. The selected keys are RSA under the existing strength policy, EC P-256/P-384 and Ed25519. The fixed ceilings are 65,536 DER bytes and 98,304 PEM characters, including a pre-decode DER ceiling for PEM.

Private PKCS#8 is version 0 without attributes or an outer public field. Ordinary EC inner public hints are checked structurally but do not establish pair agreement. Imports do not sign implicitly; the explicit pair check uses a fresh noncredential challenge and returns no signature. Its original monotonic budget depends on trusted synchronous providers cooperating with the deadline.

Certificate import establishes bounded parsing and the embedded key profile. Applications still own certificate trust, chain, hostname, validity and revocation decisions. Loading a certificate or key does not authorize any application use.
