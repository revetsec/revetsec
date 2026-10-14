# SCIM M12 evaluator fuzz corpus

These synthetic inputs were hand-authored on 2026-10-13. They follow [RFC 7644 §3.4.2.2](https://www.rfc-editor.org/rfc/rfc7644.html#section-3.4.2.2) and [RFC 7643 §2.5](https://www.rfc-editor.org/rfc/rfc7643.html#section-2.5), with the owner-approved default-null, empty-string and any-element `ne` profile stated in the SCIM evaluator guide and private plan. They contain no captured traffic, credentials or personal records.

One target checks arbitrary UTF-8 and raw UTF-16 filter trees under two receiving policies and limits, and always evaluates structured assigned/unassigned scalar and multivalue data against an independent boolean model. Named textual cases exercise correlated ValuePath versus flat subattributes, null comparisons, empty values, implicit `.value`, qualified paths, unknown/hidden paths, typed numbers/date offsets, partial date ordering, exact references, wrong types and receiving syntax/policy bounds. Binary matrix cases cover four scalar states and empty/single/nonempty arrays; every comparison keeps `ne` distinct from `not(eq)`.

The exact inventory and checksums are in `scim-m12-seeds.sha256`. These inputs establish local property testing, not hosted provider interoperability evidence.
