# Playground POST-SLO and session cancellation checks

Build the normal unpublished `examples/playground` module first, using one matching core and Soklet adapter. The module targets Java21; run the actual application on21/27. The core library keeps its own Java17 baseline. This optional verifier is not the ordinary application build launcher.

`run.py` requires the exact core/helper/framework/application JAR SHA256 values before creating output or listeners. It uses the application's normal packaged JAR and manifest runtime copies, compiles a separate JUnit/annotation-free runtime fixture with warnings fatal, and verifies every actual loaded JAR origin. Fixture classes and static signing keys are excluded from the application JAR. It watches source, POM, fixture and key inputs, and removes each owned loopback JVM/private instance. Synthetic IdP requests are verified by JCA against the actual SP public key; SP replies are verified and correlated by a separate fixture oracle.

```sh
python3 -B verification/playground-post-slo/run.py \
  --examples-root /absolute/built/examples --java-home /absolute/jdk21 \
  --repository /absolute/maven/repository \
  --core-sha256 EXACT_CORE_SHA256 --adapter-sha256 EXACT_HELPER_SHA256 \
  --framework-sha256 EXACT_FRAMEWORK_SHA256 --application-sha256 EXACT_APPLICATION_SHA256 \
  --binding post --output /private/tmp/fresh-slo-evidence
```

Run both `--binding post` and `redirect`. The POST workload includes signed login/logout, local-first close, strict pending cookie/mode/correlation handling, raw duplicates/media/query-body confusion and body bounds, signed IdP full-session matching/replay, genuine late-login non-revival, post-validation cancellation with a real replay mark held, rotation-before-close, fresh bootstrap independence and subsequent protected control access. A closed object may remain a pending SLO browser marker but is never normal authentication authority. SAML permits non-protocol query fields; this is distinct from the provider/logout recipes' strict no-query profile.

`calibrate.py` first requires a green live socket control. It then compiles exact private source copies for trusted-mode bypass, missing final cancellation predicates, missing SessionIndex matching and the generic other-auth rotation guard. Only the expected socket assertion or one selected genuine-SSO/app-session unit failure counts; setup/compile/timeouts are failures, not detections. Live sources remain unchanged. The cross-auth unit case starts a real public OIDC pending flow but deliberately does not claim an OP token validation; it tests the application completion contract for a stale caller holding the old object.

```sh
python3 -B verification/playground-post-slo/calibrate.py \
  --examples-root /absolute/built/examples --repository /absolute/maven/repository \
  --java-home /absolute/jdk21 --maven /absolute/maven/bin/mvn \
  --core-sha256 EXACT_CORE_SHA256 --adapter-sha256 EXACT_HELPER_SHA256 \
  --framework-sha256 EXACT_FRAMEWORK_SHA256 --output /private/tmp/fresh-slo-calibration
```

The fixture has a private unlogged credential. Receipts contain fixed labels, counts and body/query fingerprints, never cookies, assertion XML, keys or credentials. Test controls are not deployment routes. The controlled clock and keys, plaintext loopback HTTP and manually supplied HTTPS Origin do not qualify real TLS, browser behavior, a separate hosted IdP, encrypted interoperability, UTC, shared storage or final release. Full manual M12/SAML tools and the selected deployment profile remain open. Preserve original failing-before receipts and historical artifact scopes separately.
