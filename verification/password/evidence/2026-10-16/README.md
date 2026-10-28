# Local password sizing smoke run, 2026-10-16

This is bounded, synthetic evidence that the probe executes the selected API
paths and reports admission behavior. **It is not a production sizing result or
a release latency target.** The machine was an arm64 Mac; Corretto 17.0.20.1
reported 18 available processors. The JVM ran with `-Xms128m -Xmx512m`. Each
command used one excluded warm-up wave and a fixed synthetic password. The
operating environment did not provide a reliable peak-RSS measurement, so
these runs establish latency and gate outcomes only. The Argon2 translation
uses additional heap beyond its requested KiB.

| Mode | Parameters | Measured calls | Completed | Gate refusals | p50 completed | p95 completed |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| Argon2id hash | 65,536 KiB, 3 passes, 4 lanes; gate 1, worker 1 | 8 | 8 | 0 | 105.681 ms | 114.657 ms |
| Argon2id verify | same | 8 | 8 | 0 | 113.340 ms | 121.216 ms |
| bcrypt verify | cost 14; gate 1, worker 1 | 5 | 5 | 0 | 827.937 ms | 848.201 ms |
| Argon2id overload | 19,456 KiB, 2 passes, 1 lane; gate 1, workers 4 | 32 | 8 | 24 | 22.756 ms | 27.167 ms |

The CSVs in this directory contain every measured call. `WORK_CAPACITY` means
the shared process-local gate declined it immediately; it was not queued.
These runs show why the configured bcrypt migration ceiling must be sized
separately from native Argon2id: even on this machine, cost 14 was much slower
than the measured native profile. No target latency or gate size should be
copied from this run to another process.

Commands, from the repository root after compiling
`verification/password/PasswordSizingProbe.java` as shown in its README:

```sh
java -Xms128m -Xmx512m -cp target/classes:target/password-sizing \
  PasswordSizingProbe argon2-hash 65536 3 4 1 1 8
java -Xms128m -Xmx512m -cp target/classes:target/password-sizing \
  PasswordSizingProbe argon2-verify 65536 3 4 1 1 8
java -Xms128m -Xmx512m -cp target/classes:target/password-sizing \
  PasswordSizingProbe bcrypt-verify 14 1 1 5
java -Xms128m -Xmx512m -cp target/classes:target/password-sizing \
  PasswordSizingProbe argon2-hash 19456 2 1 1 4 8
```

Each command's standard output was saved as the corresponding CSV file.
Summary values were printed to standard error. The first three profiles are
representative only of this local runtime, and the bcrypt sample uses the
cost-14 syntax of a valid test vector with a synthetic candidate; it still
runs the complete bounded bcrypt verifier. For release qualification, repeat
the probe with each production workload, migration cost, concurrency level,
JVM size, expected co-located process load, and OS memory/GC measurements.
