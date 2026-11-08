# Issuer RSA factory API consumer

The pre-1.0 issuer factory is `OAuthIssuerSigningKey.fromRsaKeyPair`. The issuer remains RS256-only; general JWS signing and client-assertion factories keep their own names and profiles. There is no old `fromKeyPair` alias on this holder.

Compile the positive source with `--release 17` and the selected core JAR plus compile-only annotations. Run it with only core and consumer classes, passing the selected core SHA-256 as its sole argument. It checks actual construction and the unchanged non-RSA refusal. The deliberately negative source must fail specifically on the removed old method; it compiles with the older API for calibration. Compilation failure is the intended source-API break, not evidence of a runtime security defect.

Current consumer and recipe sources use the current factory. Reproducing a dated historical artifact requires the exact source captured in its evidence packet, rather than newer mutable setup helpers. Core/adapter/source/pin/runtime and external qualification retain their own exact scopes.
