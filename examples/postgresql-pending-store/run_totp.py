#!/usr/bin/env python3
# Copyright 2026 Revetware LLC. Apache-2.0. Unpublished application fixture.
"""Exercise admitted-time TOTP storage on an owned primary with scripted authority."""
from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import os
from pathlib import Path
import secrets
import select
import socket
import subprocess
import tempfile
import time

from run import ROOT

CORE = ROOT.parent.parent
IMAGE_DIGEST = "sha256:a02db8cac496f15b094798a38254f14d6e00741f709360e5e00bb6668ea31636"
IMAGE = "postgres:18.4@" + IMAGE_DIGEST
FIRST_EPOCH = "fixture-epoch-one"
SECOND_EPOCH = "fixture-epoch-two"
FLOW_NAMESPACE = "fixture_totp_flow"
BASE_TIME = 1_700_000_010
SOURCES = [
    ROOT / "src/main/java/example/pending/PostgresqlPyranidDataSource.java",
    ROOT / "src/main/java/example/pending/PostgresqlTotpStore.java",
    ROOT / "src/main/java/example/pending/TotpPgScope.java",
    ROOT / "src/main/java/example/pending/TotpPgLocks.java",
    ROOT / "src/main/java/example/pending/TotpPgCapacity.java",
    ROOT / "src/main/java/example/pending/TotpPgTransactions.java",
    ROOT / "src/test/java/example/pending/TotpFixtureAuthority.java",
    ROOT / "src/test/java/example/pending/TotpTemporalStoreProbe.java",
    ROOT / "src/test/java/example/pending/TotpStoreProbe.java",
    ROOT / "src/test/java/example/pending/TotpFlowProbe.java",
    ROOT / "src/test/java/example/pending/TotpFixtureRecoveryController.java",
    ROOT / "src/test/java/example/pending/TotpFixtureRecoveryGate.java",
    ROOT / "src/test/java/example/pending/TotpRecoveryControllerProbe.java",
    ROOT / "src/test/java/example/pending/TotpApplicationSessionStore.java",
    ROOT / "src/test/java/example/pending/TotpApplicationSessionProbe.java",
]
AUDITOR = CORE / "verification/examples/NullabilityAudit.java"
INPUTS = [*SOURCES, ROOT / "totp-schema.sql", ROOT / "totp-application-schema.sql",
          AUDITOR, Path(__file__), ROOT / "run.py"]


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def docker(*args: str, input_bytes: bytes | None = None, required: bool = True,
           timeout: int = 60) -> subprocess.CompletedProcess[bytes]:
    result = subprocess.run(["docker", *args], input=input_bytes, capture_output=True, timeout=timeout)
    if required and result.returncode:
        raise RuntimeError("owned-postgres-command-failed-" + args[0])
    return result


def totp_code(base32_secret: str, seconds: int) -> str:
    key = base64.b32decode(base32_secret + "=" * (-len(base32_secret) % 8), casefold=True)
    mac = hmac.new(key, (seconds // 30).to_bytes(8, "big"), hashlib.sha1).digest()
    offset = mac[-1] & 15
    number = int.from_bytes(mac[offset:offset + 4], "big") & 0x7fff_ffff
    return f"{number % 1_000_000:06d}"


def safe_step(base32_secret: str, earliest_seconds: int, maximum_shifts: int = 16) -> int:
    """Avoid a rare same-digit collision in a ±1-step acceptance window."""
    for shift in range(maximum_shifts):
        instant = earliest_seconds + shift * 30
        if len({totp_code(base32_secret, instant - 30),
                totp_code(base32_secret, instant),
                totp_code(base32_secret, instant + 30)}) == 3:
            return instant
    raise RuntimeError("bounded-totp-safe-step-not-found")


def read_line(child: subprocess.Popen[bytes], timeout: float) -> str:
    if child.stdout is None:
        raise RuntimeError("probe-stdout-unavailable")
    deadline = time.monotonic() + timeout
    data = bytearray()
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("probe-protocol-deadline")
        readable, _, _ = select.select([child.stdout], [], [], remaining)
        if not readable:
            raise TimeoutError("probe-protocol-deadline")
        character = os.read(child.stdout.fileno(), 1)
        if not character:
            raise RuntimeError("probe-ended-before-protocol-signal")
        if character == b"\n":
            return data.decode("ascii")
        if len(data) >= 256:
            raise RuntimeError("oversized-probe-protocol-signal")
        data.extend(character)


def write_line(child: subprocess.Popen[bytes], command: str) -> None:
    if child.stdin is None:
        raise RuntimeError("probe-stdin-unavailable")
    child.stdin.write((command + "\n").encode("ascii"))
    child.stdin.flush()


def finish(child: subprocess.Popen[bytes], timeout: float = 30) -> str:
    output, _ = child.communicate(timeout=timeout)
    if child.returncode:
        raise RuntimeError("probe-process-failed")
    return output.decode("ascii").strip()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("java-home", "core-jar", "pyranid-jar", "driver-jar", "jspecify-jar",
                 "jsr305-jar"):
        parser.add_argument("--" + name, required=True, type=Path)
    parser.add_argument("--output", type=Path,
                        help="Optional directory for a compact non-secret RESULT.json receipt")
    parser.add_argument("--workload-workers", type=int, default=4,
                        help="Separate JVMs sharing admission and assigned buckets (default: 4)")
    parser.add_argument("--workload-operations", type=int, default=8,
                        help="Read-and-insert operations per JVM (default: 8)")
    args = parser.parse_args()
    if not 1 <= args.workload_workers <= 8 or not 1 <= args.workload_operations <= 100:
        parser.error("Workload dimensions must be 1-8 workers and 1-100 operations per worker")
    jars = [args.core_jar, args.pyranid_jar, args.driver_jar, args.jspecify_jar, args.jsr305_jar]
    if not all(path.is_file() for path in jars) or not (args.java_home / "bin/javac").is_file():
        parser.error("All input JARs and the Java home must exist")
    if args.output is not None:
        args.output.mkdir(parents=True, exist_ok=True)
    receipt: dict[str, object] = {
        "success": False, "checks": [], "postgresImage": IMAGE,
        "ownedContainerRemoved": False, "ownedVolumeRemoved": False,
        "sourceInputs": {str(path.relative_to(CORE)): digest(path) for path in INPUTS},
        "artifacts": {path.name: digest(path) for path in jars},
        "profile": {
            "declaredFamilyAllowlist": ["TOTP"],
            "authoritySource": "SCRIPTED_INDEPENDENT_FIXTURE",
            "workerClockSource": "SEPARATE_SCRIPTED_TEST_INPUT",
            "witnessOwnerProcessJoined": False,
            "approvedUtcSourceQualified": False,
            "platformDurabilityQualified": False,
            "legacyWriterQuarantineExercised": False,
            "deploymentActivation": False,
        },
    }
    checks = receipt["checks"]
    assert isinstance(checks, list)

    def check(condition: bool, label: str) -> None:
        if not condition:
            raise RuntimeError("totp-qualification-failed-" + label)
        checks.append(label)

    name = "revetsec-totp-store-" + secrets.token_hex(6)
    volume = name + "-data"
    created_container = False
    created_volume = False
    children: list[subprocess.Popen[bytes]] = []
    try:
        repo_digests = json.loads(docker("image", "inspect", "--format",
                                         "{{json .RepoDigests}}", IMAGE).stdout.decode())
        check("postgres@" + IMAGE_DIGEST in repo_digests,
              "pinned-cached-multiarch-postgres-image")
        with tempfile.TemporaryDirectory(prefix="revetsec-totp-store-") as temporary:
            work = Path(temporary)
            classes = work / "classes"
            classes.mkdir()
            audit_classes = work / "audit-classes"
            audit_classes.mkdir()
            artifacts = work / "artifacts"
            artifacts.mkdir()
            private_jars: list[Path] = []
            for index, jar in enumerate(jars):
                private = artifacts / (str(index) + "-" + jar.name)
                private.write_bytes(jar.read_bytes())
                check(digest(private) == digest(jar), "private-artifact-copy-" + str(index))
                private_jars.append(private)
            classpath = os.pathsep.join([str(classes), *(str(jar) for jar in private_jars)])
            compile_result = subprocess.run([
                str(args.java_home / "bin/javac"), "--release", "17", "-parameters", "-proc:none",
                "-Xlint:all", "-Werror", "-cp", classpath, "-d", str(classes),
                *(str(source) for source in SOURCES),
            ], capture_output=True, text=True, timeout=60)
            if compile_result.returncode:
                raise RuntimeError("warning-fatal-totp-fixture-compile: " + compile_result.stderr[-4000:])
            check(True, "warning-fatal-java17-fixture-compile")

            compiled_auditor = subprocess.run([
                str(args.java_home / "bin/javac"), "--release", "17", "-proc:none",
                "-Xlint:all", "-Werror", "-cp", classpath, "-d", str(audit_classes), str(AUDITOR),
            ], capture_output=True, text=True, timeout=60)
            if compiled_auditor.returncode:
                raise RuntimeError("warning-fatal-nullability-auditor-compile")
            source_list = work / "sources.txt"
            source_list.write_text("\n".join(str(source) for source in SOURCES) + "\n")
            classpath_file = work / "classpath.txt"
            classpath_file.write_text(classpath + "\n")
            nullability_json = work / "nullability.json"
            audit = subprocess.run([
                str(args.java_home / "bin/java"), "-cp", os.pathsep.join([str(audit_classes), classpath]),
                "NullabilityAudit", str(source_list), str(classpath_file), str(nullability_json), "17",
            ], capture_output=True, text=True, timeout=60)
            check(audit.returncode == 0, "public-and-probe-nullability-audit")
            receipt["nullability"] = json.loads(nullability_json.read_text())

            with socket.socket() as reservation:
                reservation.bind(("127.0.0.1", 0))
                port = reservation.getsockname()[1]
            password = secrets.token_urlsafe(24)
            postgres_env_file = work / "postgres.env"
            postgres_env_file.write_text("POSTGRES_PASSWORD=" + password + "\nPOSTGRES_DB=totp_fixture\n")
            postgres_env_file.chmod(0o600)
            docker("volume", "create", "--label", "com.revetsec.owned-fixture=true", volume)
            created_volume = True
            docker("run", "--pull=never", "-d", "--name", name,
                   "--label", "com.revetsec.owned-fixture=true",
                   "--memory", "256m", "--cpus", "1", "--security-opt", "no-new-privileges",
                   "-p", "127.0.0.1:" + str(port) + ":5432", "--env-file", str(postgres_env_file),
                   "--mount", "type=volume,source=" + volume + ",target=/var/lib/postgresql", IMAGE)
            created_container = True

            def ready() -> None:
                deadline = time.monotonic() + 30
                while time.monotonic() < deadline:
                    response = docker("exec", name, "pg_isready", "-h", "127.0.0.1", "-U",
                                      "postgres", "-d", "totp_fixture", required=False, timeout=10)
                    if response.returncode == 0:
                        return
                    time.sleep(0.1)
                raise RuntimeError("bounded-owned-postgres-readiness")

            def flow_rows() -> bytes:
                return docker("exec", name, "psql", "-X", "-q", "-A", "-t", "-F", "|",
                              "-U", "postgres", "-d", "totp_fixture", "-c",
                              "SELECT storage_key,kind,version,sealed_form,sealed_size "
                              "FROM totp_store_entry WHERE namespace='" + FLOW_NAMESPACE
                              + "' ORDER BY storage_key").stdout

            def flow_storage_state() -> bytes:
                # Compare in memory only; never put addresses, versions or sealed state in receipts.
                return flow_rows() + docker("exec", name, "psql", "-X", "-q", "-A", "-t",
                    "-U", "postgres", "-d", "totp_fixture", "-c",
                    "SELECT bucket,allocation_generation,entry_limit,used_entries,byte_limit,used_bytes "
                    "FROM totp_store_escrow WHERE namespace=(SELECT physical_namespace "
                    "FROM totp_store_namespace WHERE namespace='" + FLOW_NAMESPACE + "') ORDER BY bucket").stdout

            def application_row_counts() -> bytes:
                return docker("exec", name, "psql", "-X", "-q", "-A", "-t", "-F", "|",
                              "-U", "postgres", "-d", "totp_fixture", "-c",
                              "SELECT (SELECT count(*) FROM totp_app_session),"
                              "(SELECT count(*) FROM totp_app_pending_login),"
                              "(SELECT count(*) FROM totp_app_approval),"
                              "(SELECT count(*) FROM totp_app_clock)").stdout.strip()

            ready()
            seed = ((ROOT / "totp-schema.sql").read_text()
                    + "\n" + (ROOT / "totp-application-schema.sql").read_text())
            def identity(value: str) -> str:
                return base64.urlsafe_b64encode(hashlib.sha256(value.encode()).digest()).decode().rstrip("=")

            def admission_lock_sql(namespace: str) -> str:
                physical = identity("totp-physical/" + namespace).encode()
                data = b"revetsec/pg-admission/v1\0" + (4).to_bytes(4, "big") + b"TOTP" + len(physical).to_bytes(4, "big") + physical
                raw = hashlib.sha256(data).digest()
                first = int.from_bytes(raw[:4], "big", signed=True)
                second = int.from_bytes(raw[4:8], "big", signed=True)
                return "SELECT pg_advisory_xact_lock(" + str(first) + "," + str(second) + "); "

            def address(namespace: str, epoch: str) -> str:
                encode = lambda value: base64.urlsafe_b64encode(value.encode()).decode().rstrip("=")
                return "totp1:" + encode(namespace) + ":" + encode(epoch) + ":NAMESPACE_STATE:imuTRYmFK91EEVQacqvPSOwL9Fiy6uV9Dlqs7_LkszQ"

            def quotas(capacity: int, bootstrap: list[int]) -> list[int]:
                remainder = capacity - sum(bootstrap)
                if remainder < 0:
                    raise RuntimeError("fixture-profile-cannot-reserve-bootstrap")
                return [bootstrap[i] + remainder // 256 + (1 if i < remainder % 256 else 0) for i in range(256)]

            for namespace in ("fixture-totp-basic", "fixture-totp-race", "fixture-totp-unknown",
                              "fixture-totp-byte-cap", "fixture-totp-load", "fixture-totp-temporal", FLOW_NAMESPACE):
                # Explicit new fixture profile:1024 synthetic entries,4096 flow/load entries.
                # This is not an online cap increase/default; old100-entry workloads strand quotas.
                entries = 4096 if namespace in ("fixture-totp-load", FLOW_NAMESPACE) else 1024
                byte_cap = 64 * 1024 * 1024 if namespace == FLOW_NAMESPACE else 2_000_000
                physical = identity("totp-physical/" + namespace)
                authority = identity("totp-authority/" + namespace)
                recovery = identity("totp-recovery/" + namespace)
                clock = identity("totp-clock/" + namespace)
                allocation = identity("totp-allocation/" + namespace)
                seed += ("\nINSERT INTO totp_store_namespace(namespace,physical_namespace,active_epoch,activation_state,authority_id,recovery_generation,clock_generation,maximum_utc_error_nanos,allocation_generation,format_version,maximum_entries,maximum_reserved_bytes) VALUES ('"
                         + namespace + "','" + physical + "','" + FIRST_EPOCH + "','NEW','" + authority + "','" + recovery + "','" + clock + "',0,'" + allocation + "',3," + str(entries) + "," + str(byte_cap) + ");\n"
                         "INSERT INTO totp_store_epoch(namespace,recovery_epoch,activated) VALUES ('" + namespace + "','" + FIRST_EPOCH + "',false);\n")
                planned_entries = [0] * 256
                planned_bytes = [0] * 256
                root_bucket = hashlib.sha256(address(namespace, FIRST_EPOCH).encode()).digest()[0]
                planned_entries[root_bucket] = 1
                # Scripted synthetic frame reserves158; genuine flow root bound1126 is conservative
                # fixture allocation only. Full exact prepared-root fit remains its separate gate.
                planned_bytes[root_bucket] = 1126 if namespace == FLOW_NAMESPACE else 158
                entry_quotas = quotas(entries, planned_entries)
                byte_quotas = quotas(byte_cap, planned_bytes)
                for bucket in range(256):
                    seed += ("INSERT INTO totp_store_escrow(family,namespace,bucket,allocation_generation,entry_limit,used_entries,byte_limit,used_bytes) VALUES ('TOTP','" + physical + "'," + str(bucket) + ",'" + allocation + "'," + str(entry_quotas[bucket]) + ",0," + str(byte_quotas[bucket]) + ",0);\n")
            docker("exec", "-i", name, "psql", "-X", "-q", "-v", "ON_ERROR_STOP=1",
                   "-U", "postgres", "-d", "totp_fixture", input_bytes=seed.encode())
            check(True, "schema-and-new-epoch-seeds")

            app_user = "totp_app_" + secrets.token_hex(5)
            app_password = secrets.token_urlsafe(24)
            role_sql = ("CREATE ROLE " + app_user + " LOGIN PASSWORD '" + app_password + "';\n"
                        "GRANT CONNECT ON DATABASE totp_fixture TO " + app_user + ";\n"
                        "GRANT USAGE ON SCHEMA public TO " + app_user + ";\n")
            docker("exec", "-i", name, "psql", "-X", "-q", "-v", "ON_ERROR_STOP=1",
                   "-U", "postgres", "-d", "totp_fixture", input_bytes=role_sql.encode())

            def grant_runtime_role() -> None:
                grant = ("GRANT SELECT,INSERT,UPDATE ON "
                         "totp_store_namespace,totp_store_epoch,totp_store_entry,totp_store_escrow,"
                         "totp_app_session,totp_app_pending_login,totp_app_approval,"
                         "totp_app_clock TO "
                         + app_user + ";\n")
                docker("exec", "-i", name, "psql", "-X", "-q", "-v", "ON_ERROR_STOP=1",
                       "-U", "postgres", "-d", "totp_fixture", input_bytes=grant.encode())

            def no_delete_or_truncate() -> bool:
                sql = ("SELECT count(*) FROM (VALUES ('totp_store_namespace'),"
                       "('totp_store_epoch'),('totp_store_entry'),('totp_store_escrow'),"
                       "('totp_app_session'),('totp_app_pending_login'),"
                       "('totp_app_approval'),('totp_app_clock')) AS tables(name) "
                       "WHERE has_table_privilege('" + app_user + "','public.'||name,'DELETE') "
                       "OR has_table_privilege('" + app_user
                       + "','public.'||name,'TRUNCATE')")
                result = docker("exec", name, "psql", "-X", "-q", "-A", "-t", "-U", "postgres",
                                "-d", "totp_fixture", "-c", sql)
                return result.stdout.strip() == b"0"

            grant_runtime_role()
            check(no_delete_or_truncate(), "runtime-role-cannot-delete-or-truncate")
            role_flags = docker("exec", name, "psql", "-X", "-q", "-A", "-t", "-U",
                "postgres", "-d", "totp_fixture", "-c",
                "SELECT rolsuper,rolcreaterole,rolcreatedb,rolreplication,rolbypassrls "
                "FROM pg_roles WHERE rolname='" + app_user + "'").stdout.strip()
            check(role_flags == b"f|f|f|f|f", "runtime-role-has-no-privileged-writer-flags")
            family_rows = docker("exec", name, "psql", "-X", "-q", "-A", "-t", "-U",
                "postgres", "-d", "totp_fixture", "-c",
                "SELECT DISTINCT family FROM totp_store_escrow ORDER BY family").stdout.strip()
            check(family_rows == b"TOTP", "sql-escrow-matches-one-family-fixture-allowlist")
            receipt["runtimeRole"] = {
                "superuser": False, "createRole": False, "createDatabase": False,
                "replication": False, "bypassRls": False, "deleteOrTruncate": False,
            }

            marker = work / "recovery.marker"
            lock = work / "recovery.lock"
            seal_key = base64.b64encode(secrets.token_bytes(32)).decode("ascii")
            next_seal_key = base64.b64encode(secrets.token_bytes(32)).decode("ascii")
            environment = dict(os.environ)
            environment.update(REVETSEC_TEST_DB_USER=app_user,
                               REVETSEC_TEST_DB_PASSWORD=app_password,
                               REVETSEC_TEST_DB_URL=f"jdbc:postgresql://127.0.0.1:{port}/totp_fixture",
                               REVETSEC_TEST_TOTP_MARKER=str(marker), REVETSEC_TEST_TOTP_LOCK=str(lock),
                               REVETSEC_TEST_TOTP_SEAL_KEY_BASE64=seal_key,
                               REVETSEC_TEST_TOTP_NEW_SEAL_KEY_BASE64=next_seal_key,
                               REVETSEC_TEST_TOTP_EPOCH=FIRST_EPOCH,
                               REVETSEC_TEST_TOTP_NOW=str(BASE_TIME),
                               REVETSEC_TEST_TOTP_AUTHORITY_NOW=str(BASE_TIME))
            environment.pop("JAVA_TOOL_OPTIONS", None)
            environment.pop("JDK_JAVA_OPTIONS", None)

            def command(class_name: str, *parameters: str) -> list[str]:
                return [str(args.java_home / "bin/java"), "-cp", classpath,
                        "example.pending." + class_name, *parameters]

            def configure_keys(process_env: dict[str, str], rotation: str,
                               key: str | None = None) -> None:
                if rotation not in ("old", "dual", "new"):
                    raise ValueError("Unknown fixture keyring")
                if rotation != "old":
                    process_env["REVETSEC_TEST_TOTP_ACTIVE_KEY_ID"] = "fixture-next"
                    process_env["REVETSEC_TEST_TOTP_SEAL_KEY_BASE64"] = next_seal_key
                    if rotation == "dual":
                        process_env["REVETSEC_TEST_TOTP_OLD_SEAL_KEY_BASE64"] = seal_key
                if key is not None:
                    process_env["REVETSEC_TEST_TOTP_SEAL_KEY_BASE64"] = key

            def probe(class_name: str, mode: str, *parameters: str,
                      now: int = BASE_TIME, key: str | None = None,
                      epoch: str = FIRST_EPOCH, rotation: str = "old",
                      timeout: int = 30, authority_now: int | None = None) -> str:
                process_env = dict(environment)
                process_env["REVETSEC_TEST_TOTP_NOW"] = str(now)
                process_env["REVETSEC_TEST_TOTP_AUTHORITY_NOW"] = str(now if authority_now is None else authority_now)
                process_env["REVETSEC_TEST_TOTP_EPOCH"] = epoch
                configure_keys(process_env, rotation, key)
                result = subprocess.run(command(class_name, mode, *parameters), capture_output=True,
                                        text=True, env=process_env, timeout=timeout)
                if result.returncode:
                    raise RuntimeError("totp-probe-failed-" + class_name + "-" + mode)
                return result.stdout.strip()

            def expect(class_name: str, mode: str, wanted: str, *parameters: str,
                       now: int = BASE_TIME, key: str | None = None,
                       epoch: str = FIRST_EPOCH, rotation: str = "old",
                       timeout: int = 30) -> None:
                actual = probe(class_name, mode, *parameters, now=now, key=key,
                               epoch=epoch, rotation=rotation, timeout=timeout)
                check(actual == wanted, class_name + "-" + mode + "-"
                      + wanted.split()[0].lower())

            def spawn(class_name: str, mode: str, *parameters: str,
                      now: int = BASE_TIME, epoch: str = FIRST_EPOCH,
                      rotation: str = "old") -> subprocess.Popen[bytes]:
                process_env = dict(environment)
                process_env["REVETSEC_TEST_TOTP_NOW"] = str(now)
                process_env["REVETSEC_TEST_TOTP_AUTHORITY_NOW"] = str(now)
                process_env["REVETSEC_TEST_TOTP_EPOCH"] = epoch
                configure_keys(process_env, rotation)
                child = subprocess.Popen(command(class_name, mode, *parameters),
                                         stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                         stderr=subprocess.PIPE, env=process_env, bufsize=0)
                children.append(child)
                return child

            store = "TotpStoreProbe"
            flow = "TotpFlowProbe"
            controller = "TotpRecoveryControllerProbe"
            application = "TotpApplicationSessionProbe"
            expect(store, "basic", "BASIC_OK")
            expect(store, "unknown", "UNKNOWN_REPORTED")
            expect(store, "unknown-check", "UNKNOWN_RETAINED")
            expect(store, "byte-cap", "BYTE_PROFILE_MISMATCH_CLOSED")
            temporal = probe("TotpTemporalStoreProbe", "all").splitlines()
            check(bool(temporal) and all(line.startswith("PASS ") for line in temporal),
                  "active-postgresql-temporal-source-receipt-checks")
            for line in temporal:
                check(True, line[5:])

            expect(store, "initialize-race", "RACE_INITIALIZED")
            race_children = [spawn(store, "race") for _ in range(2)]
            for child in race_children:
                check(read_line(child, 10) == "READY", "two-jvm-store-race-ready")
            for child in race_children:
                write_line(child, "go")
            race_results = sorted(finish(child, 15) for child in race_children)
            check(race_results == ["COMMITTED", "CONFLICT"], "two-jvm-store-one-commit")
            expect(store, "race-check", "RACE_RETAINED")

            expect(store, "load-initialize", "LOAD_INITIALIZED")
            workload_start = time.monotonic()
            workers = [spawn(store, "load", str(index), str(args.workload_operations))
                       for index in range(args.workload_workers)]
            latencies_ns: list[int] = []
            for child in workers:
                reported = finish(child, 120).split()
                check(len(reported) == args.workload_operations + 1
                      and reported[0] == "LOAD_NANOS", "workload-worker-complete")
                values = [int(value) for value in reported[1:]]
                check(all(value > 0 for value in values), "workload-positive-observations")
                latencies_ns.extend(values)
            elapsed = time.monotonic() - workload_start
            latencies_ns.sort()
            total = args.workload_workers * args.workload_operations
            count_rows = docker("exec", name, "psql", "-X", "-q", "-A", "-t", "-U",
                                "postgres", "-d", "totp_fixture", "-c",
                                "SELECT count(*) FROM totp_store_entry "
                                "WHERE namespace='fixture-totp-load'").stdout.strip()
            check(count_rows == str(total + 1).encode(), "workload-all-inserts-durable")

            def percentile_ms(percent: int) -> float:
                index = max(0, (len(latencies_ns) * percent + 99) // 100 - 1)
                return round(latencies_ns[index] / 1_000_000, 3)

            receipt["workload"] = {
                "workers": args.workload_workers,
                "operationsPerWorker": args.workload_operations,
                "completedOperations": total,
                "operation": "authoritative-read-plus-unique-account-insert",
                "p50Ms": percentile_ms(50), "p95Ms": percentile_ms(95),
                "p99Ms": percentile_ms(99),
                "wallSeconds": round(elapsed, 3),
                "throughputPerSecond": round(total / elapsed, 3),
            }

            holder = subprocess.Popen([
                "docker", "exec", name, "psql", "-X", "-q", "-v", "ON_ERROR_STOP=1",
                "-U", "postgres", "-d", "totp_fixture", "-c",
                "BEGIN; " + admission_lock_sql("fixture-totp-race")
                + "SELECT pg_advisory_xact_lock(89368819); SELECT pg_sleep(5); COMMIT;",
            ], stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=environment)
            children.append(holder)
            held = False
            for _ in range(40):
                query = docker("exec", name, "psql", "-X", "-q", "-A", "-t", "-U", "postgres",
                               "-d", "totp_fixture", "-c",
                               "SELECT pg_try_advisory_xact_lock(89368819)")
                if query.stdout.strip() == b"f":
                    held = True
                    break
                time.sleep(0.1)
            check(held, "physical-admission-lock-acquired-before-sentinel")
            expect(store, "deadline", "DEADLINE_CLOSED", timeout=10)
            if holder.wait(timeout=10):
                raise RuntimeError("physical-admission-lock-holder-failed")
            check(True, "bounded-fail-closed-under-physical-admission-lock")

            stale = spawn(store, "stale-writer")
            check(read_line(stale, 10) == "READY", "stale-store-writer-snapshot")
            expect(store, "fence", "EPOCH_FENCED")
            write_line(stale, "go")
            check(finish(stale, 15) == "STALE_WRITER_FENCED", "stale-store-writer-fenced")

            docker("stop", "--time", "3", name)
            expect(store, "outage", "OUTAGE_CLOSED", timeout=10)
            docker("start", name)
            ready()
            expect(store, "race-check", "RACE_RETAINED")
            check(True, "outage-and-durable-restart")

            expect(controller, "initial", "INITIALIZING")
            expect(flow, "initialize", "INITIALIZED")
            expect(controller, "open", "OPEN")
            prepared = probe(flow, "begin").split()
            check(len(prepared) == 3 and prepared[0] == "PREPARED", "public-enrollment-prepared")
            enrollment_id, manual_secret = prepared[1:]
            confirm_time = safe_step(manual_secret, BASE_TIME, 6)
            before_fast_worker = flow_storage_state()
            check(probe(flow, "confirm", enrollment_id, totp_code(manual_secret, confirm_time),
                        now=confirm_time + 86_400, authority_now=confirm_time) == "UNAVAILABLE",
                  "genuine-engine-fast-worker-health-refusal")
            check(flow_storage_state() == before_fast_worker,
                  "genuine-engine-fast-worker-does-not-poison-data-or-quota")
            confirmed = probe(flow, "confirm", enrollment_id,
                              totp_code(manual_secret, confirm_time), now=confirm_time).split()
            check(len(confirmed) == 8 and confirmed[0] == "CONFIRMED", "public-enrollment-confirmed")
            check(True, "genuine-engine-healthy-worker-recovers-after-skew-refusal")
            (factor_id, batch_id, recovery_zero, recovery_one, recovery_two,
             recovery_three, recovery_four) = confirmed[1:]
            expect(flow, "status", f"ACTIVE {factor_id} {batch_id} 10")
            before_status = flow_storage_state()
            check(probe(flow, "status", now=BASE_TIME + 86_400, authority_now=BASE_TIME)
                  == "UNAVAILABLE", "genuine-engine-status-fast-worker-health-refusal")
            check(flow_storage_state() == before_status, "genuine-engine-status-no-data-or-quota-write")

            binding = "fixture-session-login"
            seeded = probe(application, "seed", binding).split()
            check(len(seeded) == 3 and seeded[0] == "SEEDED",
                  "application-primary-pending-login-seeded")
            old_cookie, old_csrf = seeded[1:]
            expect(application, "session", "SESSION_ACTIVE PRIMARY", old_cookie)
            expect(application, "approve", "APPROVAL_REJECTED", old_cookie)
            expect(application, "pending", "PENDING", binding)
            session_time = safe_step(manual_secret, max(BASE_TIME + 30, confirm_time + 30))
            completed = probe(application, "complete-totp", binding,
                              totp_code(manual_secret, session_time), old_cookie, old_csrf,
                              now=session_time).split()
            check(len(completed) == 3 and completed[0] == "COMPLETED",
                  "application-confirmed-totp-session-completion")
            session_cookie, session_csrf = completed[1:]
            check(old_cookie != session_cookie and old_csrf != session_csrf,
                  "application-session-and-csrf-rotated")
            expect(application, "session", "SESSION_REJECTED", old_cookie, now=session_time)
            expect(application, "session", "SESSION_ACTIVE TOTP", session_cookie,
                   now=session_time)
            expect(application, "pending", "CONSUMED", binding, now=session_time)
            approved = probe(application, "approve", session_cookie, now=session_time).split()
            check(len(approved) == 2 and approved[0] == "APPROVED",
                  "application-synthetic-session-linked-approval-marker")
            approval_id = approved[1]
            expect(application, "approval", "APPROVAL_ACTIVE", approval_id,
                   now=session_time)

            restored_binding = "fixture-restored-pending"
            restored_seed = probe(application, "seed", restored_binding,
                                  now=session_time).split()
            check(len(restored_seed) == 3 and restored_seed[0] == "SEEDED",
                  "application-pending-login-before-backup")
            expect(application, "pending", "PENDING", restored_binding,
                   now=session_time)

            before_backup_rows = flow_rows()
            check(before_backup_rows.count(b"\n") >= 2, "pre-consumption-sealed-root-and-account")
            before_backup_application = application_row_counts()
            check(all(int(value) > 0 for value in before_backup_application.split(b"|")),
                  "pre-consumption-application-state-durable")
            backup = docker("exec", name, "pg_dump", "-Fc", "-U", "postgres", "-d", "totp_fixture",
                            timeout=60).stdout
            check(len(backup) > 1024, "pre-consumption-authentic-logical-backup")

            admission_time = safe_step(manual_secret, session_time + 30)
            admission_binding = "fixture-admission-bound-login"
            admission_seed = probe(application, "seed", admission_binding,
                                   now=admission_time).split()
            check(len(admission_seed) == 3 and admission_seed[0] == "SEEDED",
                  "application-bound-pending-login")
            admission_code = totp_code(manual_secret, admission_time)
            expect(application, "complete-totp", "ADMISSION_REJECTED",
                   "wrong-operation-binding", admission_code,
                   admission_seed[1], admission_seed[2], now=admission_time)
            expect(application, "complete-totp", "ADMISSION_REJECTED",
                   admission_binding, admission_code,
                   admission_seed[1] + "wrong", admission_seed[2], now=admission_time)
            expect(application, "complete-totp", "ADMISSION_REJECTED",
                   admission_binding, admission_code,
                   admission_seed[1], admission_seed[2] + "wrong", now=admission_time)
            expect(application, "pending", "PENDING", admission_binding,
                   now=admission_time)
            admitted_completion = probe(application, "complete-totp", admission_binding,
                                         admission_code, admission_seed[1], admission_seed[2],
                                         now=admission_time).split()
            check(len(admitted_completion) == 3 and admitted_completion[0] == "COMPLETED",
                  "bad-application-bindings-did-not-consume-valid-code")

            verify_time = safe_step(manual_secret, admission_time + 30)
            verification = totp_code(manual_secret, verify_time)
            rejected_binding = "fixture-invalid-code-login"
            invalid_seed = probe(application, "seed", rejected_binding,
                                 now=verify_time).split()
            check(len(invalid_seed) == 3 and invalid_seed[0] == "SEEDED",
                  "application-invalid-code-pending-login")
            expect(application, "complete-totp", "PROOF_REJECTED", rejected_binding,
                   "not-a-code", invalid_seed[1], invalid_seed[2], now=verify_time)
            expect(application, "pending", "PENDING", rejected_binding, now=verify_time)
            verify_racers = [spawn(flow, "race-verify", verification, now=verify_time) for _ in range(2)]
            for child in verify_racers:
                check(read_line(child, 10) == "READY", "two-jvm-public-verify-ready")
            for child in verify_racers:
                write_line(child, "go")
            check(sorted(finish(child, 20) for child in verify_racers) == ["REJECTED", "SUCCEEDED"],
                  "two-jvm-public-verify-one-proof")
            expect(flow, "verify", "REJECTED", verification, now=verify_time)

            recovery_time = verify_time + 330
            recovery_racers = [spawn(flow, "race-recovery", recovery_zero, now=recovery_time)
                               for _ in range(2)]
            for child in recovery_racers:
                check(read_line(child, 10) == "READY", "two-jvm-public-recovery-ready")
            for child in recovery_racers:
                write_line(child, "go")
            check(sorted(finish(child, 20) for child in recovery_racers) == ["REJECTED", "SUCCEEDED"],
                  "two-jvm-public-recovery-one-proof")
            expect(flow, "recovery", "REJECTED", recovery_zero, now=recovery_time)

            uncertain_time = safe_step(manual_secret, recovery_time + 360)
            uncertain_code = totp_code(manual_secret, uncertain_time)
            expect(flow, "unknown-verify", "INDETERMINATE", uncertain_code, now=uncertain_time)
            expect(flow, "verify", "REJECTED", uncertain_code, now=uncertain_time)
            check(True, "lost-ack-verify-consumed-without-proof")
            unknown_recovery_time = uncertain_time + 360
            expect(flow, "unknown-recovery", "INDETERMINATE", recovery_one,
                   now=unknown_recovery_time)
            expect(flow, "recovery", "REJECTED", recovery_one, now=unknown_recovery_time)
            expect(flow, "status", f"ACTIVE {factor_id} {batch_id} 8", now=unknown_recovery_time)
            check(True, "lost-ack-recovery-consumed-without-proof")
            expect(application, "approval", "APPROVAL_REJECTED", approval_id,
                   now=unknown_recovery_time)
            expect(application, "approval", "APPROVAL_UNAVAILABLE", approval_id,
                   now=session_time)
            check(True, "application-clock-rollback-cannot-revive-expired-approval")

            unknown_binding = "fixture-uncertain-session-login"
            unknown_time = safe_step(manual_secret, unknown_recovery_time + 30)
            unknown_seed = probe(application, "seed", unknown_binding, now=unknown_time).split()
            check(len(unknown_seed) == 3 and unknown_seed[0] == "SEEDED",
                  "application-uncertain-pending-login")
            expect(application, "complete-totp-unknown", "COMPLETION_UNKNOWN",
                   unknown_binding, totp_code(manual_secret, unknown_time),
                   unknown_seed[1], unknown_seed[2], now=unknown_time)
            expect(application, "pending", "CONSUMED", unknown_binding, now=unknown_time)
            expect(application, "session", "SESSION_REJECTED", unknown_seed[1],
                   now=unknown_time)
            check(True, "lost-ack-application-completion-withheld-cookie")

            pre_rotation_time = safe_step(manual_secret, unknown_time + 360)
            pre_rotation_code = totp_code(manual_secret, pre_rotation_time)
            expect(flow, "verify", "SUCCEEDED", pre_rotation_code, now=pre_rotation_time)

            expect(controller, "rotate", "KEYS_CHANGED")
            expect(flow, "status", "UNAVAILABLE", now=pre_rotation_time)
            expect(flow, "status", f"ACTIVE {factor_id} {batch_id} 8",
                   now=pre_rotation_time, rotation="dual")
            expect(flow, "unknown-reseal", "INDETERMINATE", "namespace",
                   now=pre_rotation_time, rotation="dual")
            expect(flow, "reseal", "ALREADY_CURRENT", "namespace",
                   now=pre_rotation_time, rotation="dual")
            expect(flow, "reseal", "RESEALED", "account",
                   now=pre_rotation_time, rotation="dual")
            expect(controller, "retire", "KEYS_CHANGED")
            expect(flow, "status", "UNAVAILABLE", now=pre_rotation_time,
                   rotation="dual")
            expect(flow, "status", f"ACTIVE {factor_id} {batch_id} 8",
                   now=pre_rotation_time, rotation="new")
            expect(application, "session", "SESSION_ACTIVE TOTP", session_cookie,
                   now=pre_rotation_time, rotation="new")
            check(probe(flow, "verify", pre_rotation_code, now=pre_rotation_time,
                        rotation="new") in ("REJECTED", "THROTTLED"),
                  "rotated-key-replay-withheld")
            check(probe(flow, "recovery", recovery_zero,
                        now=pre_rotation_time, rotation="new") in ("REJECTED", "THROTTLED"),
                  "rotated-key-spent-recovery-withheld")
            post_rotation_time = safe_step(manual_secret, pre_rotation_time + 360)
            expect(flow, "verify", "SUCCEEDED", totp_code(manual_secret, post_rotation_time),
                   now=post_rotation_time, rotation="new")
            expect(flow, "recovery", "SUCCEEDED", recovery_two,
                   now=post_rotation_time + 360, rotation="new")
            expect(flow, "recovery", "REJECTED", recovery_two,
                   now=post_rotation_time + 360, rotation="new")
            expect(flow, "status", f"ACTIVE {factor_id} {batch_id} 7",
                   now=post_rotation_time + 360, rotation="new")
            check(True, "drained-keyring-transition-reseal-and-retirement")

            app_race_time = post_rotation_time + 390
            app_race_binding = "fixture-recovery-session-race"
            app_race_seed = probe(application, "seed", app_race_binding,
                                  now=app_race_time, rotation="new").split()
            check(len(app_race_seed) == 3 and app_race_seed[0] == "SEEDED",
                  "application-recovery-race-pending-login")
            app_racers = [spawn(application, "complete-recovery-paused", app_race_binding,
                                recovery_code, app_race_seed[1], app_race_seed[2],
                                now=app_race_time, rotation="new")
                          for recovery_code in (recovery_three, recovery_four)]
            for child in app_racers:
                check(read_line(child, 15) == "PROOF_READY",
                      "two-jvm-application-recovery-proofs-ready")
            for child in app_racers:
                write_line(child, "go")
            app_race_results = [finish(child, 20).splitlines()[-1] for child in app_racers]
            winners = [result.split() for result in app_race_results
                       if result.startswith("RECOVERY_COMPLETED ")]
            check(len(winners) == 1 and len(winners[0]) == 3
                  and app_race_results.count("COMPLETION_REJECTED") == 1,
                  "two-jvm-application-one-recovery-session")
            recovery_cookie = winners[0][1]
            expect(application, "session", "SESSION_ACTIVE RECOVERY_CODE", recovery_cookie,
                   now=app_race_time, rotation="new")
            expect(application, "approve", "APPROVAL_REJECTED", recovery_cookie,
                   now=app_race_time, rotation="new")
            expect(application, "pending", "CONSUMED", app_race_binding,
                   now=app_race_time, rotation="new")
            expect(flow, "recovery", "REJECTED", recovery_three,
                   now=app_race_time, rotation="new")
            expect(flow, "recovery", "REJECTED", recovery_four,
                   now=app_race_time, rotation="new")
            expect(flow, "status", f"ACTIVE {factor_id} {batch_id} 5",
                   now=app_race_time, rotation="new")

            pause_time = safe_step(manual_secret, app_race_time + 30)
            pause_binding = "fixture-proof-before-admission-close"
            pause_seed = probe(application, "seed", pause_binding,
                               now=pause_time, rotation="new").split()
            check(len(pause_seed) == 3 and pause_seed[0] == "SEEDED",
                  "application-proof-pause-pending-login")
            paused = spawn(application, "complete-totp-paused", pause_binding,
                           totp_code(manual_secret, pause_time), pause_seed[1], pause_seed[2],
                           now=pause_time, rotation="new")
            check(read_line(paused, 15) == "PROOF_READY", "application-proof-before-drain")
            draining = spawn(controller, "retire", rotation="new")
            close_deadline = time.monotonic() + 10
            while time.monotonic() < close_deadline:
                if marker.is_file() and marker.read_text(encoding="ascii").splitlines()[1] == "CLOSED":
                    break
                time.sleep(0.05)
            else:
                raise RuntimeError("application-drain-marker-did-not-close")
            readable, _, _ = select.select([draining.stdout], [], [], 0.5)
            check(not readable, "application-permit-blocks-controller-drain")
            write_line(paused, "go")
            check(finish(paused, 15).splitlines()[-1] == "COMPLETION_UNAVAILABLE",
                  "closed-marker-withholds-post-proof-session")
            check(finish(draining, 15) == "KEYS_CHANGED",
                  "application-permit-drained-before-keyring-reopen")
            expect(application, "pending", "PENDING", pause_binding,
                   now=pause_time, rotation="new")

            tx_time = safe_step(manual_secret, pause_time + 30)
            tx_binding = "fixture-sql-transaction-before-admission-close"
            tx_seed = probe(application, "seed", tx_binding,
                            now=tx_time, rotation="new").split()
            check(len(tx_seed) == 3 and tx_seed[0] == "SEEDED",
                  "application-sql-drain-pending-login-seeded")
            in_transaction = spawn(application, "complete-totp-tx-paused", tx_binding,
                                   totp_code(manual_secret, tx_time), tx_seed[1], tx_seed[2],
                                   now=tx_time, rotation="new")
            check(read_line(in_transaction, 15) == "APP_TX_OPEN",
                  "application-sql-transaction-open-after-session-insert")
            row_lock = docker("exec", name, "psql", "-X", "-q", "-v", "ON_ERROR_STOP=1",
                              "-v", "VERBOSITY=verbose", "-U", "postgres", "-d", "totp_fixture",
                              "-c", "SELECT active_epoch FROM totp_store_namespace "
                              "WHERE namespace='fixture_totp_flow' FOR UPDATE NOWAIT",
                              required=False, timeout=5)
            check(row_lock.returncode != 0 and b"55P03" in row_lock.stderr,
                  "application-sql-transaction-holds-namespace-row-lock")
            draining_sql = spawn(controller, "retire", rotation="new")
            sql_close_deadline = time.monotonic() + 5
            while time.monotonic() < sql_close_deadline:
                if marker.is_file() and marker.read_text(encoding="ascii").splitlines()[1] == "CLOSED":
                    break
                time.sleep(0.05)
            else:
                raise RuntimeError("application-sql-drain-marker-did-not-close")
            readable, _, _ = select.select([draining_sql.stdout], [], [], 0.5)
            check(not readable, "application-sql-permit-blocks-controller-drain")
            write_line(in_transaction, "go")
            check(finish(in_transaction, 10) == "COMPLETION_UNAVAILABLE",
                  "closed-marker-withholds-inflight-sql-completion-cookie")
            check(finish(draining_sql, 10) == "KEYS_CHANGED",
                  "controller-drains-inflight-application-sql-transaction")
            expect(application, "pending", "CONSUMED", tx_binding,
                   now=tx_time, rotation="new")
            expect(application, "session", "SESSION_REJECTED", tx_seed[1],
                   now=tx_time, rotation="new")
            check(True, "inflight-sql-commit-reconciled-without-cookie-release")

            expiry_time = safe_step(manual_secret, tx_time + 30)
            expiry_binding = "fixture-expiring-pending-login"
            expiry_seed = probe(application, "seed", expiry_binding,
                                now=expiry_time, rotation="new").split()
            check(len(expiry_seed) == 3 and expiry_seed[0] == "SEEDED",
                  "application-expiring-pending-login-seeded")
            expiring = spawn(application, "complete-totp-paused", expiry_binding,
                             totp_code(manual_secret, expiry_time),
                             expiry_seed[1], expiry_seed[2],
                             now=expiry_time, rotation="new")
            check(read_line(expiring, 15) == "PROOF_READY",
                  "application-proof-before-pending-expiry")
            write_line(expiring, "go 300001")
            check(finish(expiring, 15).splitlines()[-1] == "COMPLETION_REJECTED",
                  "expired-pending-login-withholds-post-proof-session")
            expiry_after = expiry_time + 301
            expect(application, "pending", "PENDING_REJECTED", expiry_binding,
                   now=expiry_after, rotation="new")
            expect(application, "session", "SESSION_ACTIVE PRIMARY", expiry_seed[1],
                   now=expiry_after, rotation="new")
            post_expiry_time = expiry_after

            wrong_key = base64.b64encode(secrets.token_bytes(32)).decode("ascii")
            expect(flow, "status", "UNAVAILABLE", now=post_expiry_time,
                   key=wrong_key, rotation="new")
            check(True, "external-marker-rejects-wrong-key-material")

            docker("stop", "--time", "3", name)
            expect(flow, "status", "UNAVAILABLE", now=post_expiry_time,
                   rotation="new", timeout=10)
            docker("start", name)
            ready()
            expect(flow, "status", f"ACTIVE {factor_id} {batch_id} 5",
                   now=post_expiry_time, rotation="new")
            expect(flow, "remove", "REMOVED", factor_id,
                   now=post_expiry_time, rotation="new")
            expect(flow, "status", "INACTIVE", now=post_expiry_time, rotation="new")
            after_removal_rows = flow_rows()
            check(after_removal_rows != before_backup_rows,
                  "consumption-and-removal-changed-sealed-rows")
            check(after_removal_rows.count(b"\n") == before_backup_rows.count(b"\n"),
                  "removed-factor-retained-permanent-records")
            check(True, "public-flow-restart-and-permanent-removal-fence")

            stale_flow = spawn(flow, "stale-writer")
            check(read_line(stale_flow, 10) == "SNAPSHOT", "pre-restore-stale-writer-snapshot")
            admitted = spawn(flow, "hold-admission", now=post_expiry_time, rotation="new")
            check(read_line(admitted, 10) == "ADMITTED", "live-recovery-gate-permit-held")
            restore = spawn(controller, "restore", rotation="new")
            marker_closed = False
            marker_deadline = time.monotonic() + 10
            while time.monotonic() < marker_deadline:
                if marker.is_file():
                    lines = marker.read_text(encoding="ascii").splitlines()
                    if len(lines) > 1 and lines[1] == "CLOSED":
                        marker_closed = True
                        break
                time.sleep(0.05)
            check(marker_closed, "closed-marker-durable-before-drain")
            readable, _, _ = select.select([restore.stdout], [], [], 0.5)
            check(not readable, "restore-waits-for-live-permit")
            expect(flow, "status", "UNAVAILABLE", now=post_expiry_time,
                   rotation="new")
            expect(application, "session", "SESSION_UNAVAILABLE", session_cookie,
                   now=session_time, rotation="new")
            expect(application, "approval", "APPROVAL_UNAVAILABLE", approval_id,
                   now=session_time, rotation="new")
            expect(application, "pending", "PENDING_UNAVAILABLE", restored_binding,
                   now=session_time, rotation="new")
            write_line(admitted, "release")
            check(finish(admitted, 10) in ("RELEASED", "CLOSED"), "held-operation-drained")
            check(read_line(restore, 10) == "DRAINED", "closed-admission-drained-before-restore")

            docker("exec", "-i", name, "pg_restore", "--clean", "--if-exists", "-U", "postgres",
                   "-d", "totp_fixture", input_bytes=backup, timeout=60)
            check(flow_rows() == before_backup_rows, "authentic-restore-reanimated-exact-sealed-rows")
            check(application_row_counts() == before_backup_application,
                  "authentic-restore-reanimated-application-rows")
            grant_runtime_role()
            check(no_delete_or_truncate(), "restored-runtime-role-remains-delete-free")
            expect(flow, "status", "UNAVAILABLE", now=post_expiry_time,
                   rotation="new")
            expect(application, "session", "SESSION_UNAVAILABLE", session_cookie,
                   now=session_time, rotation="new")
            expect(application, "approval", "APPROVAL_UNAVAILABLE", approval_id,
                   now=session_time, rotation="new")
            expect(application, "pending", "PENDING_UNAVAILABLE", restored_binding,
                   now=session_time, rotation="new")
            expect(store, "provision-flow", "FLOW_EPOCH_PROVISIONED")
            expect(store, "flow-old-fenced", "RESTORED_EPOCH_FENCED")
            write_line(stale_flow, "go")
            check(finish(stale_flow, 15) == "FENCED", "pre-restore-stale-writer-fenced")
            write_line(restore, "fresh")
            check(read_line(restore, 10) == "FRESH_MARKED", "external-fresh-epoch-marked")
            write_line(restore, "release")
            check(finish(restore, 10) == "RELEASED", "restore-lease-released")

            expect(flow, "status", "UNAVAILABLE", epoch=FIRST_EPOCH,
                   now=post_expiry_time, rotation="new")
            expect(application, "session", "SESSION_UNAVAILABLE", session_cookie,
                   now=session_time, rotation="new")
            expect(flow, "initialize", "INITIALIZED", epoch=SECOND_EPOCH, rotation="new")
            expect(controller, "open-new", "OPEN_NEW", epoch=SECOND_EPOCH)
            expect(flow, "status", "ABSENT", epoch=SECOND_EPOCH,
                   now=post_expiry_time, rotation="new")
            expect(application, "session", "SESSION_REJECTED", session_cookie,
                   epoch=SECOND_EPOCH, now=session_time, rotation="new")
            expect(application, "approval", "APPROVAL_REJECTED", approval_id,
                   epoch=SECOND_EPOCH, now=session_time, rotation="new")
            expect(application, "pending", "PENDING_REJECTED", restored_binding,
                   epoch=SECOND_EPOCH, now=session_time, rotation="new")
            fresh_time = safe_step(manual_secret, post_expiry_time + 30)
            expect(flow, "verify", "REJECTED", totp_code(manual_secret, fresh_time),
                   epoch=SECOND_EPOCH, now=fresh_time, rotation="new")
            expect(flow, "recovery", "REJECTED", recovery_zero,
                   epoch=SECOND_EPOCH, now=fresh_time, rotation="new")
            expect(flow, "store-read", "FENCED", epoch=FIRST_EPOCH)
            check(True, "authentic-restore-fresh-empty-epoch-and-old-credential-fence")

            first_new_enrollment = probe(flow, "begin", epoch=SECOND_EPOCH,
                                         now=fresh_time + 30, rotation="new").split()
            check(len(first_new_enrollment) == 3 and first_new_enrollment[0] == "PREPARED",
                  "new-epoch-first-factor-prepared")
            first_new_time = safe_step(first_new_enrollment[2], fresh_time + 60)
            first_new_confirmed = probe(flow, "confirm", first_new_enrollment[1],
                                        totp_code(first_new_enrollment[2], first_new_time),
                                        epoch=SECOND_EPOCH, now=first_new_time,
                                        rotation="new").split()
            check(len(first_new_confirmed) == 8 and first_new_confirmed[0] == "CONFIRMED",
                  "new-epoch-first-factor-confirmed")
            old_factor_id = first_new_confirmed[1]
            factor_binding = "fixture-stale-factor-pending"
            old_factor_pending = probe(application, "seed", factor_binding,
                                       epoch=SECOND_EPOCH, now=first_new_time,
                                       rotation="new").split()
            check(len(old_factor_pending) == 3 and old_factor_pending[0] == "SEEDED",
                  "application-pending-pins-first-factor")
            expect(flow, "remove", "REMOVED", old_factor_id, epoch=SECOND_EPOCH,
                   now=first_new_time, rotation="new")
            second_new_enrollment = probe(flow, "begin", epoch=SECOND_EPOCH,
                                          now=first_new_time + 30, rotation="new").split()
            check(len(second_new_enrollment) == 3 and second_new_enrollment[0] == "PREPARED",
                  "new-epoch-replacement-factor-prepared")
            second_new_time = safe_step(second_new_enrollment[2], first_new_time + 60)
            second_new_confirmed = probe(flow, "confirm", second_new_enrollment[1],
                                         totp_code(second_new_enrollment[2], second_new_time),
                                         epoch=SECOND_EPOCH, now=second_new_time,
                                         rotation="new").split()
            check(len(second_new_confirmed) == 8 and second_new_confirmed[0] == "CONFIRMED"
                  and second_new_confirmed[1] != old_factor_id,
                  "new-epoch-replacement-factor-confirmed")
            factor_proof_time = safe_step(second_new_enrollment[2], second_new_time + 30)
            check(factor_proof_time < first_new_time + 300,
                  "replacement-proof-within-pending-lifetime")
            expect(application, "complete-totp", "COMPLETION_REJECTED", factor_binding,
                   totp_code(second_new_enrollment[2], factor_proof_time),
                   old_factor_pending[1], old_factor_pending[2], epoch=SECOND_EPOCH,
                   now=factor_proof_time, rotation="new")
            expect(application, "pending", "PENDING", factor_binding,
                   epoch=SECOND_EPOCH, now=factor_proof_time, rotation="new")
            expect(application, "session", "SESSION_ACTIVE PRIMARY", old_factor_pending[1],
                   epoch=SECOND_EPOCH, now=factor_proof_time, rotation="new")
            check(True, "replacement-factor-proof-cannot-complete-stale-pending-login")
            receipt["success"] = True
    except Exception as failure:
        receipt["failure"] = str(failure)[:4000]
    finally:
        for child in children:
            if child.poll() is None:
                child.terminate()
                try:
                    child.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    child.kill()
                    child.wait(timeout=5)
        if created_container:
            docker("rm", "-f", name, required=False)
            receipt["ownedContainerRemoved"] = docker("inspect", name, required=False).returncode != 0
        if created_volume:
            docker("volume", "rm", volume, required=False)
            receipt["ownedVolumeRemoved"] = docker("volume", "inspect", volume,
                                                    required=False).returncode != 0
        if receipt["sourceInputs"] != {str(path.relative_to(CORE)): digest(path) for path in INPUTS}:
            receipt["success"] = False
            receipt["failure"] = "source-changed-during-qualification"
        if args.output is not None:
            (args.output / "RESULT.json").write_text(
                json.dumps(receipt, indent=2, sort_keys=True) + "\n")
    print(json.dumps({"success": receipt["success"], "checks": len(checks),
                      "ownedContainerRemoved": receipt["ownedContainerRemoved"],
                      "ownedVolumeRemoved": receipt["ownedVolumeRemoved"]}))
    if not receipt["success"] or not receipt["ownedContainerRemoved"] or not receipt["ownedVolumeRemoved"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
