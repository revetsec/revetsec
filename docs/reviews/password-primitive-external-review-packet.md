# Password primitive external-review packet

**Status:** prepared for independent review; no external reviewer finding or
approval is recorded here. This packet concerns the selected 1.0.0 password
API's internal Argon2id v19/BLAKE2b translation. It does not qualify the
application's credential store, password policy, online admission, or production
workload sizing.

## Material and provenance

- Implementation: `src/main/java/com/revetsec/internal/password/Argon2id.java`
  and `Blake2b.java`, called by `src/main/java/com/revetsec/password/PasswordHasher.java`.
- Pinned reference: PHC Argon2 tag `20190702`, commit
  `62358ba2123abd17fccf2a108a301d4b52c01a7c`; source archive SHA-256
  `daf972a89577f8772602bf2eb38b6a3dd3d922bf5724d45e7f9589b5e830442c`.
  Exact test-only copies and their hashes are in
  `src/test/resources/vectors/argon2-reference-20190702/`. The source mapping is
  `JAVA-MAP.tsv` in that directory, checked by `Argon2VendoredSourceTests`.
- Translation record: [password primitive source and verification](../password-vendored-source.md),
  including each Java-specific safety deviation and the original C file hashes.
- Other evidence: `Argon2idVectorsTests` checks RFC 9106, a pinned C-reference
  corpus regenerated in a network-disabled Linux container, a 32-byte secret
  (the public pepper length), and a separate Bouncy Castle implementation.
  `Blake2bTests` checks digest-size and block-boundary vectors. These are
  differential checks, not a review of source correctness.

## Requested reviewer work

1. Compare the Java operation map with the pinned C source on the accepted,
   uninterrupted path: Argon2id's initial hash and parameter encoding, memory
   rounding, first blocks, data-independent address generation, lane/slice and
   reference-index selection, block mixing, and final tag reduction. Include
   non-multiple memory costs, multiple lanes, single-pass and multi-pass cases.
2. Inspect `Blake2b` parameter initialization, 64-bit unsigned arithmetic,
   counter and final-block handling, compression schedule, rotations, and
   `blake2b_long` output chaining, especially exact-block and digest-length
   boundaries. Confirm that Java's signed `long` operations preserve the
   reference bit patterns.
3. Check the public keyed path: a 32-byte pepper enters Argon2's secret `K`
   input, stored forms never expose key bytes, and changing or removing the
   selected key cannot yield a match or unpeppered fallback. Review the
   unkeyed/peppered stored-form grammar and the explicit legacy boundaries.
4. Check resource and failure behavior: all untrusted costs are bounded before
   KDF allocation; work-gate permits are always released; interruption cannot
   release a success; intermediate blocks, digests, password bytes and copied
   secret arrays are cleared on normal and exceptional exits where Java allows.
   Record limits of JVM heap erasure separately from implementation defects.
5. Try adversarial cases that existing vectors do not cover. Record the exact
   source revision, test vectors, commands, findings, severity and disposition.

The independent review should not infer safety solely from matching known
vectors. A useful finding report states whether any accepted calculation can
depart from the pinned C implementation, whether a malformed input can create
unbounded work or a false match, and which Java adaptations remain uncertain.

## Reproduction and acceptance

Use Java 17 or later for the focused test selection:

```sh
mvn -B -ntp -Dmaven.javadoc.skip=true \
  -Dtest=Argon2VendoredSourceTests,Argon2idVectorsTests,Blake2bTests,PasswordStoredFormTests,PasswordHasherTests,LegacyPasswordVerifierTests \
  test
```

The [workload probe](../../verification/password/README.md) can capture local
latency and capacity outcomes when run on production-class hosts. Source review and
workload sizing are separate gates. Before release, attach an independent
reviewer's report with an identified implementation revision; resolve or
explicitly accept each finding; rerun focused vectors and regression tests on
the resulting source; and record the deployment sizing evidence. Until then,
the external-review gate remains open.
