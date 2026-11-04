# Issuer capacity profile qualification

This unpublished CAP-01 runner checks explicit 16,384-byte issuer/sealer configuration and actual PostgreSQL byte ceilings. It accepts existing JARs and the cached, digest-pinned PostgreSQL image; it never pulls an image. Every database is disposable, with a unique labelled container and volume, a loopback port, temporary credentials and verified cleanup. Run from an unchanged source tree into a new output directory:

```sh
python3 verification/capacity-profile/run.py \
  --java-home /absolute/jdk --core-jar /absolute/revetsec.jar \
  --pyranid-jar /absolute/pyranid.jar --driver-jar /absolute/postgresql.jar \
  --jspecify-jar /absolute/jspecify.jar --jsr305-jar /absolute/jsr305.jar \
  --output /absolute/new-receipt
```

`--profiles-only` compiles the complete selected closure and checks the two real fixture builders without starting PostgreSQL. The verification builder is checked in all five sealing modes. Core JUnit `OAuthStoreCapacityProfileTests` separately covers compatible/incompatible public cap combinations, unchanged defaults and construction without store/client callbacks.

The database mode applies the standalone example issuer schema, the combined example schema and the verification schema in separate fresh databases. It checks one byte, exactly 16,384 bytes, one byte over, empty text, and multibyte UTF-8 values. Raw text SQL trials establish constraints only; they are not authenticated records. A native typed, authenticated 16,384-byte GRANT fixture separately proves exact opaque transport through each compiled adapter. That expired synthetic row is installed administratively with its escrow charge, is only read through the adapter, and never claims service admission or successful migration.

Each adapter also runs genuine public issuer initialization and captures an engine-generated interaction transaction larger than the global 3,800-byte default. The printable state contains quotes/backslashes directly in the raw query (no form delimiter or percent escape); this deliberately respects the separate raw-field limit. A mismatched namespace entry capacity must refuse both read and commit before preparing any INSERT/UPDATE/DELETE. The correctly configured adapter then commits the same captured transaction and reads back its exact sealed bytes, providing a positive control for the write counter.

The receipt records source/JAR/classfile hashes and named outcomes, never keys, passwords, ciphertext or request payloads. Scripted healthy observations and local primary settings establish this component's behavior only. Approved UTC accuracy, witness ownership, Linux/device durability, worker continuity, retained-data migration, deployment activation and the complete C certificate remain separate. Passing this runner does not close CAP-01's full C lane or release HOLD.
