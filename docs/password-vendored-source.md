# Password primitive source and verification

The public password API has no compile or runtime dependency. Argon2id v19 is an internal Java translation of
the PHC [Argon2 reference implementation](https://github.com/P-H-C/phc-winner-argon2/tree/20190702), tag
`20190702`, commit `62358ba2123abd17fccf2a108a301d4b52c01a7c`. Its source archive SHA-256 is
`daf972a89577f8772602bf2eb38b6a3dd3d922bf5724d45e7f9589b5e830442c`. The reference authors' original
header is retained in the Java translation. The original is dual licensed CC0-1.0 or Apache-2.0; Revetsec selects
Apache-2.0. Exact source copies and their SHA-256 manifest are under
`src/test/resources/vectors/argon2-reference-20190702/`, where tests verify their identity. They do not enter the
runtime JAR. `JAVA-MAP.tsv` maps every declared Java method in the translation, including nested block/state
adaptations and same-package test entry points, to a named operation in these pinned files. The provenance test
compares that map with reflection and checks the source hashes and mapped C names.

| Original file | SHA-256 | Java mapping |
| --- | --- | --- |
| `src/argon2.c` | `72a93deebc5fd76bec0c6d300a2d92b500fb354b26babbddbc6d8b88681e663d` | `Argon2id.hash` operation ordering and memory rounding |
| `src/ref.c` | `4ec47b080c22f4ee416b9dbcfae70ee6007fcfba427f870d7b84395846fa1bc7` | `Argon2id.fill_block`, `next_addresses`, `fill_segment` |
| `src/core.c` | `0f53eb2370f8971f04fcf043b8083bf81d1530c48b2ead71c0b6c4e22a01aeec` | block helpers, `finalize`, `index_alpha`, `fill_memory_blocks_st`, `fill_first_blocks`, `initial_hash`, `initialize` in source order |
| `src/core.h` | `c9665623cb3d306f63b6a3effd87bcfab971c28253c77e111445e42c1523235e` | Argon2 block, segment, version and type constants |
| `src/blake2/blake2b.c` | `52519ccbc1e48f489ff444091f630d05dadcc8f1ee61c5b7361e3a9618299c9a` | unkeyed sequential `Blake2b.blake2b_*` methods, `G`, `ROUND` |
| `src/blake2/blake2-impl.h` | `8ac91f1f57d94235f8de0069b7809be1deb365c3b37adb8e30423cd364aff09a` | `load64`, `store32`, `store64` |
| `src/blake2/blamka-round-ref.h` | `bcfdcf785218cf897f05b144e80b659e611188fee3887d533bdcb7a6aa4c336b` | `Argon2id.fBlaMka`, `G`, `BLAKE2_ROUND_NOMSG` |
| `include/argon2.h` | `df20cb726a2fe6bccc736b81ea0d86219766a0d17f1794c19e048a34830ca1cc` | context/type/version constants |

The exercised Argon2id path follows the C functions' names, order, constants, branches and loop structure.
C block pointers become Java `Block` views over contiguous `long[]` memory; C structs become private Java
classes; C round macros become methods; and C stack scratch blocks are reused through the single-threaded
instance. BLAKE2b uses the C streaming state, parameter block, compression schedule and long-output chain.
Only the unkeyed sequential BLAKE2b path and single-threaded Argon2id v19 path are translated; unused keyed,
tree, Argon2i/Argon2d, custom allocator and worker-thread paths are omitted. The public password wrapper owns
work admission and policy bounds; the translated primitives also check hard bounds and interrupt state, and
clear intermediate arrays on a best-effort basis. The Java block-view objects add heap overhead
beyond Argon2's requested KiB; the caller's work gate must account for application heap headroom.
The pinned BLAKE2b IV and sigma arrays are private constants never exposed or written after initialization;
they have two reviewed `SourcePolicyTests.MUTABLE_STATIC_ALLOWLIST` rows to retain the C-shaped tables.

These Java adaptations express C pointers, structs, macros and stack lifetimes safely; they are recorded rather
than described as a near-verbatim source copy. External review of this translation remains a separate release task.

The safety deviations from the C source are confined to these locations. They reject invalid work or abort and
clear state; none changes the block or digest calculation for an accepted, uninterrupted invocation.

| Java file and location | Safety deviation |
| --- | --- |
| `Argon2id.java` `hash` (lines 169–178) | Requires non-null input arrays, caps lanes/memory/passes/tag and input byte lengths before allocation, and rejects an already interrupted caller. These hard bounds supplement the public wrapper's policy limits. |
| `Argon2id.java` `fill_memory_blocks_st` (lines 267–268) and `fill_segment` (lines 415–416) | Checks interruption at each lane and every 128 blocks; aborts without clearing the thread's interrupt flag. The outer `finally` then clears derived memory. |
| `Argon2id.java` `Instance.clear` (lines 149–152), `hash` (line 189), `finalize` (lines 227–228), `fill_first_blocks` (lines 284–294), `initial_hash` (lines 332–334), `initialize` (lines 346–349), and `fill_segment` (lines 442–444) | Wipes working blocks, memory and intermediate digests in `finally` paths, including exceptional exits. The borrowed caller arrays and returned tag remain caller-owned; JVM copies cannot be guaranteed erased. |
| `Blake2b.java` `blake2b_init` (lines 127–140), `blake2b_update` (lines 189–193), and `blake2b_final` (lines 214–216) | Checks digest length, input slice and state reuse; translates C error returns to exceptions. The parameter block is cleared after initialization. |
| `Blake2b.java` `State.clear` (lines 82–89), `blake2b_compress` (lines 159–163), `blake2b_final` (lines 225–228), and `blake2b_long` (lines 268–285) | Wipes chaining state, message/round scratch, temporary outputs and long-output intermediates on completion or failure. The returned digest remains caller-owned. |

The [RFC 9106 Argon2id vector](https://www.rfc-editor.org/rfc/rfc9106.html#section-5.3) exercises a secret and
associated data. A nine-case raw-tag corpus was first generated with the pinned source's `argon2` CLI,
compiled on arm64 macOS with Apple clang 21.0.0; it covers non-multiple memory costs, lane counts, passes,
Unicode UTF-8, tag lengths, and the 64 MiB/three-pass/four-lane profile. The original corpus is
`src/test/resources/vectors/argon2id-reference-20190702.tsv` (SHA-256
`0f23d8a1d80268fc6d02e8aaee8e1b54ea78ad712393470246bad2e2bd7daee5`). Regenerate each row by
passing the listed password bytes on stdin to:

```text
argon2 <ASCII salt> -id -v 13 -k <memoryKiB> -t <passes> -p <lanes> -l <tagBytes> -r
```

The same nine cases were regenerated and manifested from the pinned C source in a network-disabled Linux
container: `gcr.io/oss-fuzz-base/base-builder-jvm@sha256:5eaa9b0d62fe132cfd319061dffa85a7bb6a6795ff2cdd52872a4b3a2c816f4a`,
`linux/amd64`, GCC 9.4.0, `-std=c89 -O2 -DARGON2_NO_THREADS`, explicitly compiling `src/ref.c` rather
than `src/opt.c`. The checked-in `src/test/resources/vectors/argon2-container-corpus.c` harness calls
`argon2_ctx` on the original corpus inputs. The container output is
`src/test/resources/vectors/argon2id-reference-20190702-container.tsv` (SHA-256
`b76f2f621482628205e6cae911731f86bf10bb86276b5dd185667a9147ab3f0a`); its nine data rows match
the original corpus exactly. The input source's `ref.c` and `core.c` hashes matched the manifest inside
the container. The container was pinned by digest and invoked with `--network none`.

An independent Java differential test uses test-scope Bouncy Castle `bcprov-jdk18on:1.84` (JAR SHA-256
`64d6c5a6121fcd927152dd182cbed39afe0fda641a970d9bcc0c9cb1858b2731`) across parameter combinations
including secret and associated data. It is not a runtime dependency. BLAKE2b is separately checked against
RFC 7693/Python `hashlib.blake2b` digests at empty, short, exact-block and multi-block boundaries.
`Argon2idVectorsTests.matchesPinnedReferenceCVectorWithActualThirtyTwoBytePepper` also checks a known-answer
tag generated by the pinned C `argon2_ctx` path with a 32-byte secret, matching the public pepper-key length.

The bcrypt migration verifier embeds Spring Security's standalone
[`BCrypt.java`](https://github.com/spring-projects/spring-security/blob/6.5.11/crypto/src/main/java/org/springframework/security/crypto/bcrypt/BCrypt.java)
from version `6.5.11`, commit `73b077790fcb04ac3712033d3e939daf42264545`; original SHA-256
`c05d267ceef5faa04380006075b9067939e03d526a2d9f4987bbf22a7a6ff7be`. Only its package declaration
changes. Its ISC license header is retained and the original source hash is checked by
`BcryptVendoredSourceTests` after reversing that rewrite. The wrapper decides the accepted format, cost and
password-length policy before invoking it.

The [password SpotBugs disposition](reviews/password-spotbugs-2026-10-16.md)
records two calculation-preserving byte-write changes in the Java translation,
removal of unused per-instance constants, and method-scoped exceptions for the
unchanged pinned bcrypt source and fresh per-call salt generator. Local static
analysis is green; the independent primitive review remains a separate gate.
