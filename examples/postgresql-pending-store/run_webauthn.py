#!/usr/bin/env python3
"""Qualify the application-owned WebAuthn SPI example against one disposable PostgreSQL primary."""
from __future__ import annotations

import argparse
import base64
import fcntl
import hashlib
import os
from pathlib import Path
import secrets
import select
import shutil
import socket
import subprocess
import tempfile
import time

from run import IMAGE, ROOT, check, docker

SOKLET_4_SHA256 = "f7f62f967045a8eb8f943a90d49d499b4c5b755d20ab901e12a34fe1d004319b"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("java-home", "core-jar", "pyranid-jar", "driver-jar", "jspecify-jar", "jsr305-jar"):
        parser.add_argument("--" + name, required=True, type=Path)
    parser.add_argument("--soklet-jar", type=Path,
                        help="pinned Soklet 4.0.0 JAR for the optional application lane")
    for name in ("browser-node", "browser-chrome", "browser-openssl"):
        parser.add_argument("--" + name, type=Path,
                            help="absolute tool path for the optional durable Chrome browser lane")
    args = parser.parse_args()
    browser_tools = (args.browser_node, args.browser_chrome, args.browser_openssl)
    browser_enabled = all(path is not None for path in browser_tools)
    if any(path is not None for path in browser_tools) and not browser_enabled:
        parser.error("The browser lane requires all three browser tool paths")
    if browser_enabled and (args.soklet_jar is None or any(
            not path.is_absolute() or not path.is_file() for path in browser_tools)):
        parser.error("The browser lane requires --soklet-jar and absolute existing tool paths")
    jars = [args.core_jar, args.pyranid_jar, args.driver_jar, args.jspecify_jar, args.jsr305_jar]
    if args.soklet_jar is not None:
        if not args.soklet_jar.is_file() or hashlib.sha256(args.soklet_jar.read_bytes()).hexdigest() \
                != SOKLET_4_SHA256:
            parser.error("--soklet-jar must be the pinned Soklet 4.0.0 artifact")
        jars.append(args.soklet_jar)
    if not all(path.is_file() for path in jars) or not (args.java_home / "bin/javac").is_file():
        parser.error("All input JARs and the Java home must exist")

    with tempfile.TemporaryDirectory(prefix="revetsec-webauthn-store-") as temp:
        work = Path(temp)
        classes = work / "classes"
        classes.mkdir()
        classpath = os.pathsep.join([str(classes), *(str(jar) for jar in jars)])
        sources = [
            ROOT / "src/main/java/example/pending/PostgresqlPyranidDataSource.java",
            ROOT / "src/main/java/example/pending/PostgresqlWebAuthnStore.java",
            ROOT / "src/test/java/example/pending/WebAuthnStoreProbe.java",
            ROOT / "src/test/java/example/pending/WebAuthnFixtureRecoveryGate.java",
            ROOT / "src/test/java/example/pending/WebAuthnFlowProbe.java",
        ]
        if args.soklet_jar is not None:
            app_root = ROOT.parent / "passkeys-soklet"
            sources.extend([
                app_root / "src/main/java/example/passkeys/PasskeyApp.java",
                app_root / "src/main/java/example/passkeys/PasskeySessions.java",
                ROOT / "src/test/java/example/pending/WebAuthnSokletAppProbe.java",
            ])
            if browser_enabled:
                sources.extend([
                    app_root / "src/main/java/example/passkeys/PasskeyPlayground.java",
                    ROOT / "src/test/java/example/pending/DurablePasskeyPlayground.java",
                ])
        compiled = subprocess.run([str(args.java_home / "bin/javac"), "--release", "17", "-proc:none",
                                   "-Xlint:all", "-Werror", "-cp", classpath, "-d", str(classes),
                                   *(str(source) for source in sources)], capture_output=True, text=True,
                                  timeout=60)
        if compiled.returncode:
            raise RuntimeError("Warning-fatal WebAuthn example compilation failed:\n" + compiled.stderr[-4000:])
        if args.soklet_jar is not None:
            shutil.copytree(ROOT.parent / "passkeys-soklet/src/main/resources", classes,
                            dirs_exist_ok=True)
        check(True, "warning-fatal-webauthn-compile")

        suffix = secrets.token_hex(5)
        name = "revetsec-wa-" + suffix
        volume = name + "-data"
        password = secrets.token_urlsafe(24)
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
            listener.bind(("127.0.0.1", 0))
            db_port = listener.getsockname()[1]
        env_file = work / "postgres.env"
        env_file.write_text("POSTGRES_PASSWORD=" + password + "\nPOSTGRES_DB=webauthn_fixture\n")
        env_file.chmod(0o600)
        created_volume = False
        created_container = False
        try:
            docker("volume", "create", "--label", "com.revetsec.owned-fixture=true", volume)
            created_volume = True
            docker("run", "-d", "--pull=never", "--name", name,
                   "--label", "com.revetsec.owned-fixture=true",
                   "-p", "127.0.0.1:" + str(db_port) + ":5432", "--env-file", str(env_file),
                   "--mount", "type=volume,source=" + volume + ",target=/var/lib/postgresql", IMAGE)
            created_container = True

            def ready() -> None:
                for _ in range(80):
                    result = subprocess.run(["docker", "exec", name, "pg_isready", "-h", "127.0.0.1",
                                             "-U", "postgres", "-d", "webauthn_fixture"],
                                            capture_output=True, timeout=10)
                    if result.returncode == 0:
                        return
                    time.sleep(0.25)
                raise RuntimeError("Owned WebAuthn PostgreSQL primary did not become ready")

            ready()
            docker("exec", "-i", name, "psql", "-X", "-q", "-v", "ON_ERROR_STOP=1",
                   "-U", "postgres", "-d", "webauthn_fixture",
                   input_text=(ROOT / "schema.sql").read_text() + "\nINSERT INTO webauthn_store_namespace(namespace) "
                   "VALUES ('fixture_wa_basic'),('fixture_wa_unknown'),('fixture_wa_race'),"
                   "('fixture_wa_flow'),('fixture_wa_app'),('fixture_wa_browser');\n")
            seal_key = base64.b64encode(secrets.token_bytes(32)).decode("ascii")
            sealer_digest = base64.urlsafe_b64encode(hashlib.sha256(
                base64.b64decode(seal_key)).digest()).decode("ascii").rstrip("=")
            epoch = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode("ascii").rstrip("=")
            marker_file = work / "webauthn-recovery.marker"
            lock_file = work / "webauthn-recovery.lock"
            lock_file.touch(mode=0o600)
            app_marker_file = work / "webauthn-app-recovery.marker"
            app_lock_file = work / "webauthn-app-recovery.lock"
            app_lock_file.touch(mode=0o600)
            app_epoch = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode("ascii").rstrip("=")
            browser_marker_file = work / "webauthn-browser-recovery.marker"
            browser_lock_file = work / "webauthn-browser-recovery.lock"
            browser_lock_file.touch(mode=0o600)
            browser_epoch = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode("ascii").rstrip("=")

            def write_marker(value: str, target: Path = marker_file) -> None:
                temporary = target.with_name(target.name + ".new")
                with temporary.open("w", encoding="ascii") as stream:
                    stream.write(value + "\n" + sealer_digest + "\n")
                    stream.flush()
                    os.fsync(stream.fileno())
                os.replace(temporary, target)

            write_marker(epoch)
            write_marker(app_epoch, app_marker_file)
            write_marker(browser_epoch, browser_marker_file)
            docker("exec", "-i", name, "psql", "-X", "-q", "-v", "ON_ERROR_STOP=1",
                   "-U", "postgres", "-d", "webauthn_fixture",
                   input_text="INSERT INTO webauthn_recovery_epoch(namespace,epoch,sealer_digest) "
                   "VALUES ('fixture_wa_flow','" + epoch + "','" + sealer_digest + "'),"
                   "('fixture_wa_app','" + app_epoch + "','" + sealer_digest + "'),"
                   "('fixture_wa_browser','" + browser_epoch + "','" + sealer_digest + "');\n")
            env = dict(os.environ, REVETSEC_TEST_DB_URL=("jdbc:postgresql://127.0.0.1:" + str(db_port)
                            + "/webauthn_fixture?sslmode=disable&gssEncMode=disable"),
                       REVETSEC_TEST_DB_USER="postgres", REVETSEC_TEST_DB_PASSWORD=password,
                       REVETSEC_TEST_WA_SEAL_KEY=seal_key,
                       REVETSEC_TEST_WA_MARKER_FILE=str(marker_file),
                       REVETSEC_TEST_WA_LOCK_FILE=str(lock_file))
            java_command = [str(args.java_home / "bin/java"), "-cp", classpath,
                            "example.pending.WebAuthnStoreProbe"]
            flow_command = [*java_command[:-1], "example.pending.WebAuthnFlowProbe"]
            app_command = [*java_command[:-1], "example.pending.WebAuthnSokletAppProbe"]
            app_env = dict(env, REVETSEC_TEST_WA_MARKER_FILE=str(app_marker_file),
                           REVETSEC_TEST_WA_LOCK_FILE=str(app_lock_file))

            def app(command: str, auth_key: str | None = None) -> str:
                selected_env = dict(app_env)
                if auth_key is not None:
                    selected_env["REVETSEC_TEST_WA_APP_AUTH_KEY"] = auth_key
                done = subprocess.run([*app_command, command], env=selected_env,
                                      capture_output=True, text=True, timeout=20)
                if done.returncode:
                    raise RuntimeError("WebAuthn Soklet application " + command
                                       + " failed: " + done.stderr[-2000:])
                return done.stdout.strip()

            def app_credential_form() -> str:
                return docker("exec", "-i", name, "psql", "-X", "-A", "-t",
                              "-v", "ON_ERROR_STOP=1", "-U", "postgres", "-d", "webauthn_fixture",
                              input_text="SELECT sealed_form FROM webauthn_store_entry "
                              "WHERE namespace='fixture_wa_app' AND kind='CREDENTIAL';\n")

            def probe(command: str, expected: str) -> None:
                done = subprocess.run([*java_command, command], env=env, capture_output=True,
                                      text=True, timeout=20)
                if done.returncode or done.stdout.strip() != expected:
                    raise RuntimeError("WebAuthn probe " + command + " failed: "
                                       + done.stdout[-1000:] + done.stderr[-2000:])
                check(True, command)

            def start(command: str) -> subprocess.Popen[str]:
                return subprocess.Popen([*java_command, command], env=env, stdin=subprocess.PIPE,
                                        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

            def flow(command: str, *arguments: str, auth_key: str | None = None,
                     seal_key_override: str | None = None) -> str:
                flow_env = dict(env)
                if auth_key is not None:
                    flow_env["REVETSEC_TEST_WA_AUTH_KEY"] = auth_key
                if seal_key_override is not None:
                    flow_env["REVETSEC_TEST_WA_SEAL_KEY"] = seal_key_override
                done = subprocess.run([*flow_command, command, *arguments], env=flow_env,
                                      capture_output=True, text=True, timeout=20)
                if done.returncode:
                    raise RuntimeError("WebAuthn RP flow " + command + " failed: " + done.stderr[-2000:])
                return done.stdout.strip()

            def begin(command: str) -> tuple[str, str]:
                parts = flow(command).split()
                if len(parts) != 3 or parts[0] != "BEGIN" or len(parts[1]) != 43 or len(parts[2]) != 43:
                    raise RuntimeError("WebAuthn RP did not prepare a bounded ceremony")
                check(True, command)
                return parts[1], parts[2]

            def first_line(process: subprocess.Popen[str], expected: str) -> None:
                assert process.stdout is not None
                if not select.select([process.stdout], [], [], 15)[0]:
                    raise RuntimeError("WebAuthn barrier did not become ready")
                if process.stdout.readline().strip() != expected:
                    raise RuntimeError("WebAuthn barrier failed before ready")

            probe("basic", "BASIC_OK")
            probe("unknown", "UNKNOWN_REPORTED")
            probe("reconcile", "RECONCILED")

            first = start("race")
            second = start("race")
            try:
                first_line(first, "READY")
                first_line(second, "READY")
                for process in (first, second):
                    assert process.stdin is not None
                    process.stdin.write("go\n")
                    process.stdin.flush()
                outcomes = []
                for process in (first, second):
                    stdout, stderr = process.communicate(timeout=20)
                    if process.returncode:
                        raise RuntimeError("WebAuthn race probe failed: " + stderr[-2000:])
                    outcomes.append(stdout.strip())
                check(sorted(outcomes) == ["COMMITTED", "CONFLICT"], "cross-jvm-single-winner")
            finally:
                for process in (first, second):
                    if process.poll() is None:
                        process.kill()
                        process.communicate()
            probe("race-check", "RACE_RECONCILED")

            app_auth_key = None
            if args.soklet_jar is not None:
                registered_app = app("register").split()
                if len(registered_app) != 2 or registered_app[0] != "APP_REGISTERED":
                    raise RuntimeError("Soklet application registration did not release one proof")
                app_auth_key = registered_app[1]
                check(True, "soklet-app-registration")
                docker("stop", name)
                check(app("closed") == "APP_RECOVERY_CLOSED",
                      "soklet-app-primary-outage-closes-protocol-routes")
                docker("start", name)
                ready()
                check(app("sign-in", auth_key=app_auth_key)
                      == "APP_SIGNED_IN_AND_REAUTHENTICATED",
                      "soklet-app-sign-in-and-step-up-after-primary-restart")
                live = subprocess.Popen([*app_command, "live-close"], env=app_env,
                                        stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                        stderr=subprocess.PIPE, text=True)
                try:
                    first_line(live, "APP_ADMITTED")
                    with app_lock_file.open("r+b") as operator_lock:
                        fcntl.lockf(operator_lock, fcntl.LOCK_EX)
                        write_marker(base64.urlsafe_b64encode(secrets.token_bytes(32))
                                     .decode("ascii").rstrip("="), app_marker_file)
                        fcntl.lockf(operator_lock, fcntl.LOCK_UN)
                    assert live.stdin is not None
                    live.stdin.write("go\n")
                    live.stdin.flush()
                    stdout, stderr = live.communicate(timeout=20)
                    if live.returncode or stdout.strip() != "APP_LIVE_CLOSED":
                        raise RuntimeError("Live Soklet marker closure failed: "
                                           + stdout[-1000:] + stderr[-2000:])
                    check(True, "soklet-live-session-closes-after-external-marker-change")
                finally:
                    if live.poll() is None:
                        live.kill()
                        live.communicate()
                    with app_lock_file.open("r+b") as operator_lock:
                        fcntl.lockf(operator_lock, fcntl.LOCK_EX)
                        write_marker(app_epoch, app_marker_file)
                        fcntl.lockf(operator_lock, fcntl.LOCK_UN)

            if browser_enabled:
                assert args.browser_node is not None and args.browser_chrome is not None
                assert args.browser_openssl is not None
                browser_root = ROOT.parent / "passkeys-soklet"
                browser_tls = work.resolve() / "browser-tls"
                prepared = subprocess.run(["python3", str(browser_root / "prepare_tls.py"),
                                           "--work", str(browser_tls), "--openssl",
                                           str(args.browser_openssl), "--rp-id", "passkeys.example.test"],
                                          capture_output=True, text=True, timeout=60)
                if prepared.returncode:
                    raise RuntimeError("Browser TLS preparation failed: " + prepared.stderr[-2000:])
                classpath_file = work / "browser-classpath"
                classpath_file.write_text(classpath + "\n", encoding="utf8")
                browser_env = dict(env,
                                   REVETSEC_TEST_WA_MARKER_FILE=str(browser_marker_file),
                                   REVETSEC_TEST_WA_LOCK_FILE=str(browser_lock_file),
                                   REVETSEC_TEST_WA_BROWSER_HANDLE=base64.urlsafe_b64encode(
                                       secrets.token_bytes(32)).decode("ascii").rstrip("="))
                browser = subprocess.run([str(args.browser_node),
                                          str(browser_root / "browser_check.mjs"),
                                          "--classpath-file", str(classpath_file),
                                          "--tls-dir", str(browser_tls),
                                          "--java", str(args.java_home / "bin/java"),
                                          "--chrome", str(args.browser_chrome),
                                          "--main-class", "example.pending.DurablePasskeyPlayground",
                                          "--restart-app", "--postgres-container", name], env=browser_env,
                                         capture_output=True, text=True, timeout=120)
                if browser.returncode or "and a primary outage." not in browser.stdout:
                    raise RuntimeError("Durable Chrome WebAuthn flow failed: "
                                       + browser.stdout[-1000:] + browser.stderr[-2500:])
                check(True, "chrome-durable-browser-outage-registration-sign-in-removal-restarts")

            registration_id, registration_challenge = begin("begin-register")
            registered = flow("complete-register", registration_id, registration_challenge).split()
            if len(registered) != 2 or registered[0] != "REGISTERED":
                raise RuntimeError("WebAuthn registration did not return a verified proof")
            auth_key = registered[1]
            check(flow("replay-register", registration_id, registration_challenge)
                  == "REGISTRATION_REJECTED", "registration-cross-jvm-single-use")
            check(flow("list-one") == "LISTED_1", "registered-credential-cross-jvm-list")

            sign_in_id, sign_in_challenge = begin("begin-auth")
            check(flow("complete-auth", sign_in_id, sign_in_challenge, "1", auth_key=auth_key)
                  == "SUCCEEDED_SIGN_IN", "cross-jvm-sign-in")
            check(flow("complete-auth", sign_in_id, sign_in_challenge, "1", auth_key=auth_key)
                  == "REJECTED", "authentication-cross-jvm-single-use")
            reauth_id, reauth_challenge = begin("begin-reauth")
            check(flow("complete-auth", reauth_id, reauth_challenge, "2", auth_key=auth_key)
                  == "SUCCEEDED_REAUTHENTICATION", "cross-jvm-account-pinned-reauthentication")

            race_id, race_challenge = begin("begin-auth")
            race_env = dict(env, REVETSEC_TEST_WA_AUTH_KEY=auth_key)
            race_command = [*flow_command, "race-auth", race_id, race_challenge, "3"]
            racers = [subprocess.Popen(race_command, env=race_env, stdin=subprocess.PIPE,
                                       stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                      for _ in range(2)]
            try:
                for racer in racers:
                    first_line(racer, "READY")
                for racer in racers:
                    assert racer.stdin is not None
                    racer.stdin.write("go\n")
                    racer.stdin.flush()
                outcomes = []
                for racer in racers:
                    stdout, stderr = racer.communicate(timeout=20)
                    if racer.returncode:
                        raise RuntimeError("WebAuthn completion race failed: " + stderr[-2000:])
                    outcomes.append(stdout.strip())
                check(outcomes.count("SUCCEEDED_SIGN_IN") == 1
                      and all(outcome in ("SUCCEEDED_SIGN_IN", "REJECTED", "UNAVAILABLE")
                              for outcome in outcomes),
                      "cross-jvm-authentication-one-proof")
            finally:
                for racer in racers:
                    if racer.poll() is None:
                        racer.kill()
                        racer.communicate()

            unknown_id, unknown_challenge = begin("begin-auth")
            check(flow("complete-auth-unknown", unknown_id, unknown_challenge, "4", auth_key=auth_key)
                  == "INDETERMINATE", "lost-commit-ack-withholds-authentication-proof")
            check(flow("complete-auth", unknown_id, unknown_challenge, "4", auth_key=auth_key)
                  == "REJECTED", "uncertain-authentication-reconciled-as-consumed")

            holder = start("hold-lock")
            try:
                first_line(holder, "LOCKED")
                started = time.monotonic()
                probe("short-budget", "LOCK_TIMEOUT")
                check(time.monotonic() - started < 3, "bounded-namespace-lock")
                assert holder.stdin is not None
                holder.stdin.write("release\n")
                holder.stdin.flush()
                stdout, stderr = holder.communicate(timeout=20)
                if holder.returncode:
                    raise RuntimeError("WebAuthn lock holder failed: " + stdout[-1000:] + stderr[-2000:])
            finally:
                if holder.poll() is None:
                    holder.kill()
                    holder.communicate()

            docker("stop", name)
            probe("outage", "OUTAGE_CLOSED")
            check(flow("outage") == "FLOW_OUTAGE_CLOSED", "rp-primary-outage-no-browser-options")
            docker("start", name)
            ready()
            probe("reconcile", "RECONCILED")
            probe("race-check", "RACE_RECONCILED")
            check(flow("list-one") == "LISTED_1", "credential-survives-primary-restart")
            restarted_id, restarted_challenge = begin("begin-auth")
            check(flow("complete-auth", restarted_id, restarted_challenge, "5", auth_key=auth_key)
                  == "SUCCEEDED_SIGN_IN", "sign-in-after-primary-restart")
            restoration_id, restoration_challenge = begin("begin-auth")
            before_state_hash = flow("raw-hash", restoration_id)
            if not before_state_hash.startswith("RAW_HASH ") or len(before_state_hash) != 52:
                raise RuntimeError("WebAuthn pre-restore state digest was unavailable")
            app_before_restore = app_credential_form() if args.soklet_jar is not None else None
            if app_before_restore is not None and not app_before_restore:
                raise RuntimeError("Soklet app credential row missing before restore")
            before_consumption = docker("exec", name, "pg_dump", "--clean", "--if-exists",
                                        "--no-owner", "--no-privileges", "-U", "postgres",
                                        "-d", "webauthn_fixture")
            check(flow("complete-auth", restoration_id, restoration_challenge, "6", auth_key=auth_key)
                  == "SUCCEEDED_SIGN_IN", "pre-restore-ceremony-consumed")
            check(flow("remove") == "REMOVED", "cross-jvm-credential-removal")
            check(flow("list-zero") == "LISTED_0", "removed-credential-absent-from-index")
            removed_id, removed_challenge = begin("begin-auth")
            check(flow("complete-auth", removed_id, removed_challenge, "7", auth_key=auth_key)
                  == "REJECTED", "removed-credential-cannot-sign-in")
            reuse_id, reuse_challenge = begin("begin-register")
            check(flow("replay-register", reuse_id, reuse_challenge) == "REGISTRATION_REJECTED",
                  "revoked-credential-id-cannot-be-reassigned")

            if args.soklet_jar is not None:
                assert app_auth_key is not None
                check(app("remove") == "APP_REMOVED", "soklet-app-cross-jvm-removal")
                check(app_credential_form() != app_before_restore,
                      "soklet-app-active-credential-replaced-by-tombstone")
                check(app("removed", auth_key=app_auth_key) == "APP_REMOVED_REJECTED",
                      "soklet-app-removed-credential-rejected")
                check(app("unknown-begin") == "APP_UNKNOWN_CLOSED_LOCAL_ADMISSION",
                      "soklet-app-unknown-write-closes-local-admission")
                with app_lock_file.open("r+b") as operator_lock:
                    fcntl.lockf(operator_lock, fcntl.LOCK_EX)
                    write_marker(base64.urlsafe_b64encode(secrets.token_bytes(32))
                                 .decode("ascii").rstrip("="), app_marker_file)
                    fcntl.lockf(operator_lock, fcntl.LOCK_UN)
                check(app("closed") == "APP_RECOVERY_CLOSED",
                      "soklet-app-external-marker-closes-new-process")

            alternate_seal_key = base64.b64encode(secrets.token_bytes(32)).decode("ascii")
            check(flow("outage", seal_key_override=alternate_seal_key) == "FLOW_OUTAGE_CLOSED",
                  "sealing-key-marker-mismatch-closes-admission")
            holder = subprocess.Popen([*flow_command, "hold-admission"], env=env,
                                      stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                      stderr=subprocess.PIPE, text=True)
            try:
                first_line(holder, "ADMITTED")
                with lock_file.open("r+b") as operator_lock:
                    try:
                        fcntl.lockf(operator_lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    except BlockingIOError:
                        check(True, "restore-waits-for-live-permit")
                    else:
                        fcntl.lockf(operator_lock, fcntl.LOCK_UN)
                        raise RuntimeError("Operator restore lock bypassed a live admission permit")
                assert holder.stdin is not None
                holder.stdin.write("release\n")
                holder.stdin.flush()
                stdout, stderr = holder.communicate(timeout=20)
                if holder.returncode:
                    raise RuntimeError("Recovery permit holder failed: " + stderr[-2000:])
            finally:
                if holder.poll() is None:
                    holder.kill()
                    holder.communicate()

            with lock_file.open("r+b") as operator_lock:
                fcntl.lockf(operator_lock, fcntl.LOCK_EX)
                check(flow("outage") == "FLOW_OUTAGE_CLOSED",
                      "operator-restore-lock-closes-new-admission")
                advanced_epoch = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode("ascii").rstrip("=")
                docker("exec", "-i", name, "psql", "-X", "-q", "-v", "ON_ERROR_STOP=1",
                       "-U", "postgres", "-d", "webauthn_fixture",
                       input_text="UPDATE webauthn_recovery_epoch SET epoch='" + advanced_epoch
                       + "' WHERE namespace='fixture_wa_flow';\n")
                write_marker(advanced_epoch)
                fcntl.lockf(operator_lock, fcntl.LOCK_UN)
            check(flow("list-zero") == "LISTED_0", "new-recovery-epoch-admits-current-state")

            with lock_file.open("r+b") as operator_lock:
                fcntl.lockf(operator_lock, fcntl.LOCK_EX)
                docker("exec", "-i", name, "psql", "-X", "-q", "-v", "ON_ERROR_STOP=1",
                       "-U", "postgres", "-d", "webauthn_fixture", input_text=before_consumption + "\n")
                fcntl.lockf(operator_lock, fcntl.LOCK_UN)
            restored_epoch = docker("exec", "-i", name, "psql", "-X", "-A", "-t",
                                    "-v", "ON_ERROR_STOP=1", "-U", "postgres", "-d", "webauthn_fixture",
                                    input_text="SELECT epoch FROM webauthn_recovery_epoch "
                                    "WHERE namespace='fixture_wa_flow';\n")
            check(restored_epoch == epoch, "logical-restore-reverted-store-marker")
            check(flow("raw-hash", restoration_id) == before_state_hash,
                  "logical-restore-reanimated-exact-ceremony-and-credential-state")
            check(flow("restored-closed", restoration_id, restoration_challenge,
                       auth_key=auth_key) == "RESTORED_CLOSED",
                  "restored-credential-and-ceremony-cannot-reopen-admission")
            if args.soklet_jar is not None:
                check(app_credential_form() == app_before_restore,
                      "logical-restore-reanimated-exact-soklet-app-credential")
                check(app("closed") == "APP_RECOVERY_CLOSED",
                      "restored-soklet-app-credential-cannot-reopen-admission")
            print("WebAuthn PostgreSQL store, RP and restore-barrier qualification: PASS", flush=True)
        finally:
            if created_container:
                subprocess.run(["docker", "rm", "-f", name], capture_output=True, timeout=30)
            if created_volume:
                subprocess.run(["docker", "volume", "rm", "-f", volume], capture_output=True, timeout=30)


if __name__ == "__main__":
    main()
