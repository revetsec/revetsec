# Pinned external Javadoc indexes

These package and element indexes are inputs to Javadoc's `-linkoffline` option. The generated
hyperlinks still point to the public documentation, but the build never fetches those sites to
discover packages. `manifest.json` records, for each index, the upstream versioned archive (or Java
API index URL), its SHA-256, and the SHA-256 of the checked-in index. Indexes are stored as UTF-8
with LF line endings; where the upstream line endings differ, the original index checksum is recorded
separately.

The indexes and their checksums were copied from Soklet's pinned set, and the copied bytes were
checked against the recorded SHA-256 values.

To upgrade a dependency, extract the index from that exact version's Javadoc JAR on Maven Central,
update the link target in `pom.xml` and the local directory, and record the new provenance and
checksums. Never fetch a mutable "latest" index during release packaging.

Java API links target Java 26, the pinned Javadoc JDK. The library's compile and runtime floor stays
Java 17. The Javadoc JAR is built from M1 on; until then every build passes
`-Dmaven.javadoc.skip=true`.
