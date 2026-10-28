# Password SpotBugs disposition — 2026-10-16

**Status:** source-bound closeout of seven JDK 21 SpotBugs/FindSecBugs findings in the uncommitted password implementation. This clears the local static-analysis gate. It is not an independent Argon2id/BLAKE2b review, production workload sizing, or a 1.0.0 release sign-off.

| Finding | Disposition |
| --- | --- |
| `ICAST_QUESTIONABLE_UNSIGNED_RIGHT_SHIFT` in `Argon2id.store32` and `Blake2b.store32` | Changed the four little-endian byte writes to arithmetic `>>`. Each shifted value is narrowed to `byte`, so only its low eight bits survive; `>>` and `>>>` produce the same emitted bytes for every input. Pinned C-reference, RFC, and independent differential vectors pass. |
| `SS_SHOULD_BE_STATIC` on `Argon2id.Instance.type` and `.version` | Removed two unused per-instance constant fields. The implementation uses the existing Argon2id v19 constants; no accepted calculation changes. |
| `BIT_IOR_OF_SIGNED_BYTE` in pinned Spring `BCrypt.streamtowords` | Kept the signed-byte operation unchanged. Spring computes both corrected and sign-extended words for its `$2a$` collision-safety behavior; masking this path could change accepted legacy verification. Revetsec does not accept `$2x$`. The [SpotBugs filter](../../config/spotbugs-exclude.xml) matches only this pattern, class and method. |
| `INT_BAD_COMPARISON_WITH_NONNEGATIVE_VALUE` in pinned Spring `BCrypt.char64` | Kept the upstream `char < 0` guard unchanged. Java `char` cannot be negative, while the other half of the check still rejects out-of-range values. The filter matches only this pattern, class and method. |
| `DMI_RANDOM_USED_ONLY_ONCE` in `PasswordHasher.hashResult` | Kept a fresh platform `SecureRandom` for each 16-byte salt, created only after work admission. This is a cryptographic generator; sharing one solely to satisfy a generic one-use warning would introduce shared provider state. The filter matches only this pattern, class and method. |

The pinned Spring bcrypt source and `PasswordHasher` are unchanged. `BcryptVendoredSourceTests` still checks the exact upstream source after the package rewrite; the two bcrypt exclusions do not hide findings in other methods or classes. The Argon2id/BLAKE2b changes preserve the reference calculation but remain within the planned independent primitive review.

## Verification

- Focused Java 17 password, bcrypt, Argon2id/BLAKE2b vector and provenance tests passed, including the pinned C corpus and the Bouncy Castle differential.
- Full Java 17 core `verify` passed 19,077 tests, zero failures, zero errors, one skip.
- Clean JDK 21 Error Prone/NullAway build passed. The JDK 21 `-Pspotbugs` check passed; `target/spotbugsXml.xml` contains zero `BugInstance` entries.

The remaining password release gates are an identified independent review of the internal Argon2id/BLAKE2b translation and sizing under the intended production hosts and traffic. This static-analysis result does not qualify either one.
