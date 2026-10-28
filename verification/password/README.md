# Password workload sizing probe

`PasswordSizingProbe` is a Java 17, synthetic load tool for choosing a deployment's
password work budget. It invokes the public API on caller threads and reports one
CSV row per measured call. It does not store credentials or establish a security
setting for another host. Run it on production-class hardware, with production
JVM heap/GC settings, in an isolated environment and with other expected process
load present. Record the CPU, physical memory, JVM version and flags, container
limits, active login traffic, and process RSS/GC data beside the CSV.

From the repository root, after compiling core:

```sh
mvn -B -ntp -Dmaven.javadoc.skip=true -DskipTests package
mkdir -p target/password-sizing
javac --release 17 -Xlint:all -Werror \
  -cp "target/classes:$HOME/.m2/repository/org/jspecify/jspecify/1.0.1/jspecify-1.0.1.jar:$HOME/.m2/repository/com/google/code/findbugs/jsr305/3.0.2/jsr305-3.0.2.jar" \
  -d target/password-sizing verification/password/PasswordSizingProbe.java
java -cp target/classes:target/password-sizing PasswordSizingProbe \
  argon2-verify 65536 3 4 4 4 20 > /tmp/argon2-verify.csv
java -cp target/classes:target/password-sizing PasswordSizingProbe \
  argon2-hash 65536 3 4 4 8 20 > /tmp/argon2-overload.csv
java -cp target/classes:target/password-sizing PasswordSizingProbe \
  bcrypt-verify 14 4 4 20 > /tmp/bcrypt-migration.csv
```

The Argon2 modes take `memoryKiB passes lanes gateCalls workers rounds`; the
bcrypt mode takes `logRounds gateCalls workers rounds`. Each run has one excluded
warm-up wave. `gateCalls` is the shared work-gate concurrency ceiling, and
`workers` is the number of calls released together. Argon2's gate memory budget
is `memoryKiB * gateCalls`. A row marked `WORK_CAPACITY` is an immediate local
admission failure, not a slow success. Summary p50/p95 values on stderr include
only completed calls. The CSV retains all rows so the operator can calculate
tail latency and throughput for each load level. The bcrypt probe uses a valid
synthetic Openwall vector with the selected cost; at a cost other than 5 it
expects a full-work non-match. No password or stored form is printed.

Run both a steady-state level (`workers` no greater than `gateCalls`) and an
overload level (`workers` greater than `gateCalls`). Measure new-hash creation,
native verification, and the **largest accepted** bcrypt migration cost. Repeat
on every deployment class. Choose limits based on observed p95/p99 latency,
process memory headroom, GC behavior, throughput, and the maximum number of
queued caller threads the app can tolerate. The Java translation uses extra heap
for block views and scratch beyond the requested Argon2 memory. Bcrypt cannot
stop an already-started calculation on interruption. Verify that app-owned
edge/per-account admission caps the incoming rate and that the login service
degrades safely when the process-local gate reports `WORK_CAPACITY`.

This probe is not a calibrated microbenchmark: JVM warm-up, allocation, GC, CPU
contention, and scheduling influence every sample. It makes actual API work and
gate outcomes reproducible; deployment qualification requires the same workload
measurements on the intended infrastructure. Keep recorded results out of the
source tree if they disclose private host capacity.
