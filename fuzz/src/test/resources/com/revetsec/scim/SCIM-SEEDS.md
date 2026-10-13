# SCIM M9 syntax seed provenance

Authored 2026-10-13 for bounded syntax qualification. All values are synthetic.

The 17 `rfc7644-figure2-*.txt` files transcribe RFC 7644 §3.4.2.2 Figure 2 filter examples with HTTP parameter prefixes removed and line wrapping joined. The primary source is https://www.rfc-editor.org/rfc/rfc7644.html#section-3.4.2.2. RFC 7644's IETF Trust license and repository NOTICE apply. The earlier research note's count of 18 examples was incorrect.

All remaining files were authored from the approved syntax and limit contract: contextual keywords, operator precedence, same-element predicates, `$ref` (RFC 7643 erratum 8924, Held for Document Update), RFC 3986 absolute URI paths including IPv6/IPvFuture and empty hier-part, strict JSON literal syntax (RFC 8259), invalid nested ValuePath (RFC 7644 errata 4690/7322), and exact/over limit boundaries. They are not captured vendor traffic, generated parser output, credentials, or interoperability evidence.

Each target consumes the full file as UTF-8 text and separately pairs its bytes as raw big-endian UTF-16 units; an odd trailing byte becomes the high byte of the last unit. This second view preserves unpaired surrogates. Files named `*utf16be.bin` are explicitly authored raw UTF-16BE inputs. `control-character-raw.bin` contains a raw NUL inside a quoted literal, and the empty files cover zero-length input.

`scim-seeds.sha256` inventories the complete path set and bytes. `ScimSeedProvenanceTests` verifies both, and `FuzzSeedLayoutTests` checks method/directory coverage. The fuzz assertions check bounded total parsing, graph invariants, fixed errors and same-limits canonical round trips; independent acceptance/AST/precedence oracles are the core SCIM grammar tests. These property targets do not establish full specification conformance or SCIM service readiness.
