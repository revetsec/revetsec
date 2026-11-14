# Releasing Revetsec

Releases are project-owner operations. Contributors and automation must not publish, tag, or use signing credentials. The `release` Maven profile creates a complete signed Central bundle locally, but `central.skipUpload` defaults to `true`; Maven cannot upload the bundle unless the owner explicitly overrides that safeguard. The intended path is to inspect the local bundle and upload it manually in the Central Portal.

## Release boundary

A green build is necessary but is not release approval. Before starting a version transition, the owner must explicitly accept the final Q5 source/artifact/API/claims join, the M-R compatibility dossier, applicable external qualification, and the final security-claims audit. Preserve the exact accepted commit IDs and hosted run URLs in the release record.

Copy `release/RELEASE_RECORD.template.json` to the owner-controlled release-record location at the start of the release. Keep its disposition `TEMPLATE` while any field is pending. The template checker validates its shape without treating it as approval:

```sh
python3 verification/verify-release-record.py release/RELEASE_RECORD.template.json --template
```

For each of the five owner gates, copy `release/OWNER_ACCEPTANCE.template.json` to the evidence root and complete it only when the owner accepts that gate. Set its exact gate name, version, accepting-owner identity, acceptance time, all four final release commit IDs, and at least one supporting evidence path plus SHA-256. The five allowed gate names are `finalQ5`, `compatibility`, `externalQualification`, `securityClaims`, and `release`. Set `disposition` to `ACCEPTED`, hash the completed receipt, and record its relative path and hash in the corresponding `ownerAcceptance` entry. Historical reviews remain supporting evidence; they do not replace a final receipt bound to the exact four release commits. The final verifier hashes every local supporting file and rejects self-reference, duplicated evidence, a wrong gate/version, a post-release acceptance time, or any commit mismatch.

Only after every recorded owner gate, repository identity, signing-key identity, artifact hash, reproducibility join, hosted-evidence join, cryptographic attestation verification, Central receipt, consumer check, documentation publication and GitHub Release is complete may the copied record use disposition `RELEASED`. Run `verify-release-record.py` without `--template` and provide the root directory containing its relative evidence paths. It verifies the signing-key, claims-audit, reproducibility, hosted-evidence, attestation, Central, consumer, GitHub and documentation receipt bytes against their recorded hashes. The signing-key receipt must bind the canonical public-key URL and downloaded key bytes to the recorded primary fingerprint and at least one usable signing key. Each reproducibility receipt must bind the two separately built signed bundle identities to the same five payload hashes and that primary fingerprint. Each hosted-evidence receipt must bind the workflow-recorded tag, commit, run and attestation identities plus attested payload hashes to the approved signed bundle. Each attestation receipt must cryptographically bind all five payloads to the expected release-evidence workflow and bind the JAR's CycloneDX predicate to the exact SBOM. Each Central receipt must bind that bundle and those payloads to the five published signatures and canonical Central URLs. The documentation receipt must bind every deployed component API page to its signed Central Javadoc JAR and every deployed website file to the clean, commit-identified static export. Each GitHub receipt must bind a published non-prerelease release and successful exact-commit runs to the verified annotated tag. Receipt times must form the same sequence as this runbook: signing-key verification before signed-bundle checks; completed release-evidence workflow before its hosted join; hosted join and attestation/reproducibility before Central verification; Central before consumers; all consumers before documentation; documentation before GitHub Releases; and all public-state verification before final owner release acceptance and `releasedAt`. The final check also fails on an omitted or unaccepted gate, missing local evidence, incomplete artifact set, unsafe path, malformed hash, or mismatched signer, tag, run, attestation, consumer, GitHub or documentation evidence. The repository template intentionally fails final-record verification.

The first release comprises four components, each built from its own repository:

1. `com.revetsec:revetsec:1.0.0`
2. `com.revetsec:revetsec-soklet:1.0.0`
3. `com.revetsec:revetsec-servlet-jakarta:1.0.0`
4. `com.revetsec:revetsec-servlet-javax:1.0.0`

Publish core first. Publish adapters only after the exact required core release is available from Central. The two Servlet adapters are a paired release.

`revetsec-soklet` declares the published provided dependency `com.soklet:soklet:4.0.0` from Maven Central. There is no Soklet source-commit pin in the release source set. If the selected version changes, update the adapter POM and `externalDependencies` in the release-record template together; the four-repository preflight requires them to agree. The consumer verifier binds the published Soklet JAR and POM hashes from canonical Central into the final release record.

## Prepare release sources

Use clean, synchronized checkouts and an empty isolated Maven repository. Maven 3 is required; the Central publishing plugin does not support Maven 4. Use the pinned JDKs from CI: the component's compilation JDK plus the separately pinned Corretto 26 Javadoc executable.

For each repository:

1. Change the project version from `1.0.0-SNAPSHOT` to `1.0.0`.
2. In each adapter, change `revetsec.version` to `1.0.0`. Update every active example, verification tool, documentation snippet, and build input that consumes the release. Do not rewrite sealed historical evidence.
3. Add `<tag>v1.0.0</tag>` to `<scm>`. The release configuration test requires the tag for every non-SNAPSHOT POM.
4. Date and finalize `CHANGELOG.md` and create the accepted `release/SECURITY_CLAIMS_AUDIT.md`, separating approved, narrowed, and rejected public claims without overstating qualification.
5. Confirm that no active release input still uses the release's SNAPSHOT coordinate:

   ```sh
   python3 verification/verify-release-sources.py .. \
     --version 1.0.0 \
     --phase release
   ```

   Seeded negative tests and frozen historical migration evidence intentionally retain SNAPSHOT text and are excluded by the verifier.

6. Run the repository's normal full CI-equivalent matrix and the release configuration tests. The tests run automatically in hosted CI; locally:

   ```sh
   PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s verification -p 'test_release_configuration.py' -v
   ```

   Adapter repositories use `scripts` in place of `verification`.

   From the core repository, verify the four sibling repositories as one source set. This also checks the release-record template, dated changelogs and accepted claims-audit structure, and reports the published Soklet dependency whose exact Central artifacts require owner-recorded external qualification:

   ```sh
   python3 verification/verify-release-sources.py .. \
     --version 1.0.0 \
     --phase release
   ```

7. Have the owner commit and push the release source, wait for exact-head hosted CI, then create the signed `v1.0.0` tag. Build only from that exact tag. Agents do not commit or tag.

After the owner commits core, update every adapter workflow's `REVETSEC_CORE_SHA` to that exact pushed release commit, then commit the adapters. Repeat the source-set check with `--require-clean`; that mode requires all three adapter pins to equal the clean core release head. After all four annotated tags exist at their exact release heads, also add `--require-tag`. The local tag check confirms annotation and target identity; the hosted release-evidence workflow remains responsible for requiring GitHub-verified signatures.

The core and Soklet adapter use an intentionally acyclic pre-release pin pair: the adapter pins the last core code commit, while the later core commit pins the adapter. A release must be joined by the released Maven coordinates, not by introducing a circular source-build pin.

## Tag provenance evidence

Pushing a release tag starts `.github/workflows/release-evidence.yml`. The workflow accepts only a non-SNAPSHOT POM whose version and SCM tag exactly match the pushed tag, and it asks the GitHub Git Data API to confirm that the tag is annotated and its signature is verified. It has no Central or signing credentials. It builds with `gpg.skip=true` and `central.skipUpload=true`, creates an unsigned payload set, publishes GitHub build-provenance attestations for that set, binds the main JAR to its CycloneDX SBOM in a second attestation, and retains the payloads plus `SHA256SUMS` as workflow evidence.

The workflow is evidence, not publication and not a substitute for the signed local bundle. Download its `release-evidence-*` artifact after the hosted run succeeds. Once the approved signed local bundle exists, join the hosted evidence to that bundle with the fail-closed verifier:

```sh
python3 verification/verify-release-evidence.py \
  /downloaded/release-evidence \
  --bundle target/central-publishing/central-bundle.zip \
  --expect com.revetsec:revetsec:1.0.0 \
  --commit FULL_RELEASE_COMMIT_SHA \
  --keyring /temporary/path/revetsec-release-keyring.gpg \
  --expect-fingerprint FULL_RELEASE_SIGNING_FINGERPRINT \
  --output /release-records/revetsec-1.0.0-hosted-evidence.json
```

The verifier requires the exact five-payload-plus-`SHA256SUMS`-plus-`ATTESTATIONS.json` file set, validates the workflow's tag, commit, run and two distinct attestation identities plus all release payload structures, fully verifies the signed bundle, and requires byte-identical POM, main JAR, source JAR, Javadoc JAR, and SBOM content. Only those matching bytes let the workflow attestations apply to the payloads that are actually uploaded. A mismatch is a release stop.

Install GitHub CLI 2.102.0 or newer, authenticate it for public attestation lookup if required, then cryptographically verify every payload's SLSA provenance and the main JAR's CycloneDX predicate. Older versions are rejected because 2.102.0 fixed case-insensitive `--source-ref` verification; the verifier also pins the exact source commit digest. It fixes the repository, signer workflow, tag ref, commit, GitHub Actions OIDC issuer and hosted-runner policy, and requires verified timestamp evidence and exact SBOM content:

```sh
python3 verification/verify-release-attestations.py \
  --bundle target/central-publishing/central-bundle.zip \
  --hosted-evidence /release-records/revetsec-1.0.0-hosted-evidence.json \
  --expect com.revetsec:revetsec:1.0.0 \
  --commit FULL_RELEASE_COMMIT_SHA \
  --keyring /temporary/path/revetsec-release-keyring.gpg \
  --expect-fingerprint FULL_RELEASE_SIGNING_FINGERPRINT \
  --gh /path/to/gh \
  --output /release-records/revetsec-1.0.0-attestations.json
```

Record the attestation receipt's relative evidence path and SHA-256. Never use `--skip-signature-verification` for release evidence; it exists only for seeded self-tests.

## Build a local-only Central bundle

Run this only on the clean release host after the signing agent is intentionally primed. Do not place passphrases in the POM, Maven settings, command history, or files. GPG best-practice enforcement is enabled.

```sh
export JAVA_HOME=/path/to/the-component-build-jdk
export REVETSEC_JAVADOC_HOME=/path/to/pinned-corretto-26
mvn -B -ntp -Prelease clean deploy
```

Do not pass `-Dcentral.skipUpload=false` while creating the inspection bundle. A successful release build ends with a message that upload was skipped and leaves:

```text
target/central-publishing/central-bundle.zip
```

The bundle contains the POM, main JAR, source JAR, Javadoc JAR, CycloneDX 1.6 JSON SBOM, one detached signature for each payload, and MD5, SHA-1, SHA-256 and SHA-512 checksums. The SBOM intentionally describes the shipped runtime: it has the root library component and no dependency components because Revetsec artifacts have zero compile/runtime dependencies.

## Verify before upload

Publish the armored public release key at the canonical no-redirect URL, then verify its exact primary fingerprint, current validity, usable signing capability and downloaded bytes in a create-new receipt:

```sh
python3 verification/verify-release-signing-key.py \
  --expect-fingerprint FULL_RELEASE_SIGNING_FINGERPRINT \
  --output /release-records/revetsec-1.0.0-signing-key.json
```

Record the receipt's relative path and SHA-256 in `signing.receipt`. The canonical URL is fixed at `https://revetsec.com/security/release-key.asc`; an alternate host or redirect fails closed.

Export only that public release key to a temporary keyring, then use the fail-closed bundle inspector. It rejects unsafe paths, SNAPSHOT coordinates, incomplete Central metadata, a missing SCM tag, unexpected files, bad checksums, invalid signatures, a signer other than the expected primary fingerprint, malformed JARs, missing sources/Javadoc, and a non-reproducible or dependency-bearing SBOM.

```sh
gpg --export RELEASE_KEY_ID > /temporary/path/revetsec-release-keyring.gpg
python3 verification/verify-central-bundle.py \
  target/central-publishing/central-bundle.zip \
  --expect com.revetsec:revetsec:1.0.0 \
  --keyring /temporary/path/revetsec-release-keyring.gpg \
  --expect-fingerprint FULL_RELEASE_SIGNING_FINGERPRINT
```

The adapter bundles can be inspected with the core repository's copy of the script by changing `--expect` to the adapter coordinates. Never use `--skip-signature-verification` for a real release; that option exists only for the verifier's seeded self-tests.

Build twice in independent clean directories with the same pinned toolchains, then have the verifier inspect both bundles and compare their payloads:

```sh
python3 verification/verify-central-bundle.py \
  /first/target/central-publishing/central-bundle.zip \
  --compare-to /second/target/central-publishing/central-bundle.zip \
  --expect com.revetsec:revetsec:1.0.0 \
  --keyring /temporary/path/revetsec-release-keyring.gpg \
  --expect-fingerprint FULL_RELEASE_SIGNING_FINGERPRINT \
  --output /release-records/revetsec-1.0.0-reproducibility.json
```

The POM, main JAR, source JAR, Javadoc JAR, and SBOM must match byte for byte. The verifier fully validates both bundles before comparing those five SHA-256 values and creates a receipt containing both bundle hashes, the primary signing fingerprint, signature-verification results and matching payload hashes. `gpgv` must report that every detached signature chains to the explicitly pinned primary fingerprint; trusting whichever key happens to be in the supplied keyring is not sufficient. Copy both exact signed bundle ZIPs into distinct relative paths under the evidence root and record those paths and hashes in the component's `bundleEvidence.first` and `bundleEvidence.second` entries. Record the receipt's relative evidence path and SHA-256. Final verification reads and hashes the preserved ZIP bytes; a receipt or hash without the actual bundle is not sufficient. Bundle and detached-signature bytes need not match because their containers/signature creation times can differ.

## Publish and verify

For each component in release order:

1. Upload the already verified ZIP through the Central Portal.
2. Wait for Portal validation, inspect the exact coordinates and file list, and publish manually.
3. Verify that the canonical Maven Central HTTPS repository serves the exact five payloads and five signatures from the approved bundle. This command fully revalidates both the local bundle and the downloaded publication, verifies every signature, rejects redirects and noncanonical hosts, and writes a create-new receipt:

   ```sh
   python3 verification/verify-central-publication.py \
     target/central-publishing/central-bundle.zip \
     --expect com.revetsec:revetsec:1.0.0 \
     --keyring /temporary/path/revetsec-release-keyring.gpg \
     --expect-fingerprint FULL_RELEASE_SIGNING_FINGERPRINT \
     --output /release-records/revetsec-1.0.0-central.json
   ```

4. Resolve, compile and run both consumers from a fresh repository bound to the signed Central receipt. The verifier mirrors Maven exclusively to canonical Central, makes Gradle consume the same resolved files offline with the checksum-pinned distribution, requires the exact component/core/platform classpath, links representative public classes and writes a create-new receipt:

   ```sh
   python3 verification/verify-central-consumers.py \
     --component revetsec \
     --version 1.0.0 \
     --central-receipt /release-records/revetsec-1.0.0-central.json \
     --java-home /path/to/release-consumer-jdk \
     --maven /path/to/mvn \
     --gradle-distribution /path/to/gradle-9.8.2-bin.zip \
     --output /release-records/revetsec-1.0.0-consumers.json
   ```

   Repeat for each adapter with its component name. The Soklet adapter also requires `--soklet-version` naming the owner-approved literal release selected in its POM; the verifier refuses a different version. Its receipt retains the published adapter POM's exact provided dependencies and the canonical-Central hashes of the resolved Soklet JAR and POM. Copy those exact coordinates and hashes into the release record's single `externalDependencies` entry. Final verification requires the source template, published adapter POM, Maven and Gradle classpaths, resolved bytes, release record, and `externalQualification` owner acceptance to describe the same release. Record the Central deployment, publication and consumer receipts, tag, commit, hosted run, and separately named provenance/SBOM attestation links.

After all four components are verified, publish the API documentation and the approved `revetsec.com` static export. Run the documentation verifier from the core checkout with all four Central receipts. It refuses a dirty website checkout, binds its exact HEAD commit, downloads the exact Central Javadoc JARs, compares every component package page with `https://javadoc.revetsec.com`, and compares every exported website file with its canonical `https://revetsec.com` URL. The static host must serve extensionless HTML routes as described by the website repository. The receipt is create-new:

```sh
python3 verification/verify-release-documentation.py \
  --version 1.0.0 \
  --claims-audit /release-evidence/release/SECURITY_CLAIMS_AUDIT.md \
  --central-receipt /release-records/revetsec-1.0.0-central.json \
  --central-receipt /release-records/revetsec-soklet-1.0.0-central.json \
  --central-receipt /release-records/revetsec-servlet-jakarta-1.0.0-central.json \
  --central-receipt /release-records/revetsec-servlet-javax-1.0.0-central.json \
  --website-repository ../revetsec.com \
  --site-directory ../revetsec.com/dist \
  --output /release-records/revetsec-1.0.0-documentation.json
```

Record the documentation receipt's relative evidence path and SHA-256. Create each GitHub Release from the existing signed tag only after its artifacts and documentation are complete. Then verify the repository's public GitHub state. The command confirms the GitHub-verified annotated tag and direct commit target, successful exact-commit CI and release-evidence workflow identities, and a published non-draft, non-prerelease release:

```sh
python3 verification/verify-github-release.py \
  --repository revetsec \
  --version 1.0.0 \
  --commit FULL_RELEASE_COMMIT_SHA \
  --ci-run https://github.com/revetsec/revetsec/actions/runs/CI_RUN_ID \
  --release-evidence-run https://github.com/revetsec/revetsec/actions/runs/RELEASE_RUN_ID \
  --output /release-records/revetsec-1.0.0-github.json
```

Repeat for all three adapters and record each receipt's relative evidence path and SHA-256. `GITHUB_TOKEN` is optional for public repositories; if supplied, use a read-only token and do not place it on the command line. After all four components, both documentation surfaces and all four GitHub Releases are complete, create the final `release` owner-acceptance receipt bound to those exact release commits and supporting evidence. Set `releasedAt` after that acceptance, then validate the filled release record without `--template`:

```sh
python3 verification/verify-release-record.py \
  /release-records/RELEASE_RECORD.json \
  --evidence-root /release-evidence
```

Do not rewrite the verified record. Detach-sign its exact bytes with the recorded release key, then verify the signature, the complete transitive evidence graph and the signature chronology in one create-new seal receipt:

```sh
gpg --batch --armor --detach-sign \
  --local-user FULL_RELEASE_SIGNING_FINGERPRINT \
  --output /release-records/RELEASE_RECORD.json.asc \
  /release-records/RELEASE_RECORD.json

python3 verification/verify-release-record-seal.py \
  /release-records/RELEASE_RECORD.json \
  --signature /release-records/RELEASE_RECORD.json.asc \
  --evidence-root /release-evidence \
  --keyring /temporary/path/revetsec-release-keyring.gpg \
  --output /release-records/RELEASE_RECORD.seal.json
```

Preserve the exact record, detached signature and seal receipt with the release evidence. The seal verifier requires the signature to chain to the record's pinned primary fingerprint and to have been created at or after `releasedAt`.

After core is verified on Central, build and publish the adapters. Announce only after the documentation, GitHub Releases and final release record are verified, and include only the claims accepted in the release audit.

If Portal validation, signature verification, reproducibility, Central resolution, consumer execution, provenance, or documentation validation fails, stop. Do not repair a staged deployment in place or publish a different byte set under the same version; discard it, correct the source or release process, and start again with a new owner-approved candidate.
