# SCIM M11 fuzz corpus

These are synthetic, hand-authored inputs created 2026-10-13. They are not captured provider traffic or hosted interoperability evidence. Grammar and operation semantics follow [RFC 7644 §§3.5.2–3.5.2.3](https://www.rfc-editor.org/rfc/rfc7644.html#section-3.5.2), and integer lexical negatives follow [RFC 7643 §2.3.4](https://www.rfc-editor.org/rfc/rfc7643.html#section-2.3.4). Named vendor shapes follow the owner-approved private SCIM plan and are explicitly tested against strict mode.

The wire target covers envelope/op/path/value shape, case folding, explicit nulls, typed numbers, same-element selectors, upsert shape, primary reassignment, membership metadata, remove/add order, remove-with-value empty negatives, late read-only failure, JSON duplicates/UTF-8/body size. Structured bytes generate member IDs for an add followed by a forbidden ID mutation, with a fixed original snapshot.

The complete corpus and exact checksums are in `scim-m11-seeds.sha256`. No credentials, personal records, passwords, account captures or production identifiers are persisted.
