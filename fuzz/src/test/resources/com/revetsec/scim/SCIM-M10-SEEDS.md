# M10 fuzz seeds

All seeds in `ScimM10FuzzTestsInputs` are synthetic, authored protocol examples under Apache-2.0; none are captured account data. SHA-256 values are in `scim-m10-seeds.sha256`.

Raw query seeds exercise strict percent/UTF-8 decoding, physical multiplicity, bounded counts/cursors, approved and rejected filter paths and projection conflicts (RFC 7644 sections 3.4.2 and 3.9; RFC 9865 section 2). Raw body seeds distinguish SearchRequest and User documents, ignored read-only input, required fields, duplicates, optional compatibility coercion and RFC 7643 integer wire syntax, including numerically integral fraction/exponent tokens. Inputs one byte beyond the configured 16384-byte body and 4096-byte query boundaries are deliberate.

Model-control seeds drive bounded runtime data generation, output-byte/header limits, selection association and stripping of transient write-only passwords. The password marker is created only at runtime and does not appear in a seed body. Passing these properties is not an interoperability or backend authorization claim.
