# Pinned Soklet adapter test guard

The current adapter pin is the published `06350ebec1e6002bb365c2226a06b37f9077c1a0` commit. It contains the shared-clock store test conversion, current SAML replay-cache factory calls and the metadata HEAD-body fix. The temporary issuer fixture replacement for `3bad3251bb9b3bd2baeecd5c55a41574c8ebb9b0` is retired and removed.

`manifest.json` now records the current revision and its complete **196-test** suite. `verification/examples/adapter_compatibility.py` compares the private copy's entire POM, production tree and test tree against that immutable Git revision. It writes no source files. The build must run all 196 tests with zero failures, errors or skips, and the postcondition verifies that neither production nor test inputs changed during the build. `ADAPTER-COMPATIBILITY.json` retains the exact selected source hashes and result counts.

Both examples CI and SCIM interop use the same adapter pin as `examples/pins.json`. The default core pin advances to published `4e46439b88f88dbf0717cc375e515a940a08f1cc`; CI continues to select its own exact run revision explicitly. No library input, test fixture or dependency is rewritten to accommodate another API generation. Historical qualification records retain the older overlay sources and their original scope.
