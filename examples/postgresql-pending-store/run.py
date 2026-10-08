#!/usr/bin/env python3
"""Run this application example against an owned, cached PostgreSQL container.

This is a local protocol check. It never archives callback state or database credentials.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import os
from pathlib import Path
import re
import secrets
import subprocess
import tempfile
import threading
import time
from urllib.parse import parse_qs

ROOT = Path(__file__).resolve().parent
IMAGE = "sha256:3a82e1f56c8f0f5616a11103ac3d47e632c3938698946a7ad26da0df1334744a"


def docker(*args: str, input_text: str | None = None) -> str:
    result = subprocess.run(["docker", *args], input=input_text, capture_output=True, text=True, timeout=60)
    if result.returncode:
        raise RuntimeError("Owned PostgreSQL operation failed: " + " ".join(args[:2]))
    return result.stdout.strip()


def check(condition: bool, label: str) -> None:
    if not condition:
        raise RuntimeError("Pending-store check failed: " + label)
    print(label + ": PASS", flush=True)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("java-home", "core-jar", "pyranid-jar", "driver-jar", "jspecify-jar", "jsr305-jar"):
        parser.add_argument("--" + name, required=True, type=Path)
    args = parser.parse_args()
    paths = [args.core_jar, args.pyranid_jar, args.driver_jar, args.jspecify_jar, args.jsr305_jar]
    if not all(path.is_file() for path in paths) or not (args.java_home / "bin/java").is_file():
        parser.error("All input JARs and the Java home must exist")
    check(docker("image", "inspect", "--format", "{{.Id}}", IMAGE) == IMAGE, "cached-image")

    with tempfile.TemporaryDirectory(prefix="revetsec-pending-") as work_name:
        work = Path(work_name)
        classes = work / "classes"
        classes.mkdir()
        classpath = os.pathsep.join(map(str, [classes, *paths]))
        sources = [ROOT / "src/main/java/example/pending/PostgresqlPendingAuthorizationStore.java",
                   ROOT / "src/test/java/example/pending/PendingStoreProbe.java"]
        compiled = subprocess.run([str(args.java_home / "bin/javac"), "--release", "17", "-Xlint:all",
                                   "-Werror", "-cp", os.pathsep.join(map(str, paths)), "-d", str(classes),
                                   *map(str, sources)], capture_output=True, text=True, timeout=60)
        if compiled.returncode:
            raise RuntimeError("Warning-fatal example compilation failed:\n" + compiled.stderr[-4000:])
        print("warning-fatal-compile: PASS", flush=True)

        suffix = secrets.token_hex(5)
        name = "revetsec-pending-" + suffix
        network = name + "-net"
        volume = name + "-data"
        password = secrets.token_urlsafe(24)
        env_file = work / "postgres.env"
        env_file.write_text("POSTGRES_PASSWORD=" + password + "\nPOSTGRES_DB=pending_fixture\n")
        env_file.chmod(0o600)
        created: list[tuple[str, str]] = []
        try:
            docker("network", "create", "--label", "com.revetsec.owned-fixture=true", network)
            created.append(("network", network))
            docker("volume", "create", "--label", "com.revetsec.owned-fixture=true", volume)
            created.append(("volume", volume))
            docker("run", "-d", "--pull=never", "--name", name, "--network", network,
                   "-p", "127.0.0.1::5432", "--env-file", str(env_file),
                   "--mount", "type=volume,source=" + volume + ",target=/var/lib/postgresql", IMAGE)
            created.append(("container", name))

            def ready() -> None:
                for _ in range(80):
                    result = subprocess.run(["docker", "exec", name, "pg_isready", "-h", "127.0.0.1",
                                             "-U", "postgres", "-d", "pending_fixture"], capture_output=True,
                                            timeout=10)
                    if result.returncode == 0:
                        return
                    time.sleep(0.25)
                raise RuntimeError("Owned PostgreSQL primary did not become ready")

            ready()
            schema = (ROOT / "schema.sql").read_text()
            docker("exec", "-i", name, "psql", "-X", "-q", "-v", "ON_ERROR_STOP=1", "-U", "postgres",
                   "-d", "pending_fixture", input_text=schema + "\nINSERT INTO pending_authorization_clock "
                   "(namespace,observed_seconds,observed_nanos) VALUES ('fixture',0,0),('fixture_clock',0,0);\n")

            def db_env() -> dict[str, str]:
                port = int(docker("port", name, "5432/tcp").rsplit(":", 1)[1])
                return dict(os.environ, REVETSEC_TEST_DB_URL=("jdbc:postgresql://127.0.0.1:" + str(port)
                                + "/pending_fixture?sslmode=disable&gssEncMode=disable"),
                            REVETSEC_TEST_DB_USER="postgres", REVETSEC_TEST_DB_PASSWORD=password)

            current_db_env = db_env()

            def run(*arguments: str) -> str:
                done = subprocess.run([str(args.java_home / "bin/java"), "-cp", classpath,
                                       "example.pending.PendingStoreProbe", *arguments], env=current_db_env,
                                      input="", capture_output=True, text=True, timeout=20)
                if done.returncode:
                    classes = re.findall(r"(?:[A-Za-z_$][\w$]*\.)*[A-Za-z_$][\w$]*(?:Exception|Error)", done.stderr)
                    raise RuntimeError("JVM probe failed in " + arguments[0]
                                       + ", exit=" + str(done.returncode) + ", types=" + ",".join(classes[:5]))
                return done.stdout.strip()

            for mode, expected in (("duplicate", "DUPLICATE_REJECTED"), ("expiry", "EXPIRED_ABSENT"),
                                   ("zero-budget", "ZERO_BUDGET_NO_MUTATION"),
                                   ("long-budget", "LONG_BUDGET_BOUNDED"),
                                   ("unknown-consume", "UNKNOWN_COMMIT_NO_RELEASE"),
                                   ("capacity", "CAPACITY_NO_EVICTION"), ("future-fence", "ROLLBACK_FENCED")):
                check(run(mode) == expected, mode)

            state = run("issue", "binding-main")
            check(run("callback", state, "other-binding") == "REJECTED:PENDING_AUTHORIZATION_NOT_FOUND",
                  "binding-isolation")
            check(run("callback", state, "binding-main") == "DENIED", "cross-jvm-completion")
            check(run("callback", state, "binding-main") == "REJECTED:PENDING_AUTHORIZATION_NOT_FOUND",
                  "replay-rejected")

            state = run("issue", "binding-race")
            contenders = [subprocess.Popen([str(args.java_home / "bin/java"), "-cp", classpath,
                            "example.pending.PendingStoreProbe", "callback-race", state, "binding-race"],
                            env=current_db_env, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, text=True) for _ in range(2)]
            try:
                check(all(proc.stdout is not None and proc.stdout.readline().strip() == "READY"
                          for proc in contenders), "race-ready")
                for proc in contenders:
                    assert proc.stdin is not None
                    proc.stdin.write("go\n")
                    proc.stdin.flush()
                outcomes = []
                for proc in contenders:
                    output, _ = proc.communicate(timeout=15)
                    check(proc.returncode == 0, "race-jvm")
                    outcomes.append(output.strip())
                check(sorted(outcomes) == ["DENIED", "REJECTED:PENDING_AUTHORIZATION_NOT_FOUND"],
                      "cross-jvm-single-winner")
            finally:
                for proc in contenders:
                    if proc.poll() is None:
                        proc.kill()
                        proc.wait(timeout=5)

            requests: list[bool] = []
            request_lock = threading.Lock()
            current_challenge = ""

            class TokenHandler(BaseHTTPRequestHandler):
                def log_message(self, format: str, *arguments: object) -> None:
                    pass

                def do_POST(self) -> None:
                    length = int(self.headers.get("Content-Length", "0"))
                    body = self.rfile.read(length) if 0 < length <= 4096 else b""
                    try:
                        form = parse_qs(body.decode("ascii"), strict_parsing=True)
                    except (UnicodeDecodeError, ValueError):
                        form = {}
                    valid = (self.path == "/token" and 0 < length <= 4096
                             and self.headers.get("Content-Type") == "application/x-www-form-urlencoded"
                             and self.headers.get("Accept") == "application/json"
                             and set(form) == {"grant_type", "code", "redirect_uri", "code_verifier", "client_id"}
                             and form.get("grant_type") == ["authorization_code"]
                             and form.get("code") == ["test-only-code"]
                             and form.get("redirect_uri") == ["https://consumer.example/callback"]
                             and form.get("client_id") == ["distributed-probe"]
                             and len(form.get("code_verifier", [])) == 1
                             and re.fullmatch(r"[A-Za-z0-9_-]{43}", form["code_verifier"][0]) is not None
                             and base64.urlsafe_b64encode(hashlib.sha256(form["code_verifier"][0].encode("ascii"))
                                                          .digest()).rstrip(b"=").decode("ascii") == current_challenge)
                    with request_lock:
                        requests.append(valid)
                    response = (b'{"access_token":"test-only-token","token_type":"Bearer","expires_in":60}'
                                if valid else b'{"error":"invalid_request"}')
                    self.send_response(200 if valid else 400)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Cache-Control", "no-store")
                    self.send_header("Pragma", "no-cache")
                    self.send_header("Content-Length", str(len(response)))
                    self.end_headers()
                    self.wfile.write(response)

            with ThreadingHTTPServer(("127.0.0.1", 0), TokenHandler) as token_server:
                token_thread = threading.Thread(target=token_server.serve_forever, daemon=True)
                token_thread.start()
                try:
                    issuer = "http://127.0.0.1:" + str(token_server.server_port)
                    check(run("issue-code-unknown", "binding-unknown-save", issuer)
                          == "UNCERTAIN_SAVE_NO_REDIRECT", "unknown-save-no-redirect")
                    check(requests == [], "unknown-save-no-token-request")
                    state, current_challenge = run("issue-code", "binding-code", issuer).split("\t", 1)
                    check(run("callback-code", state, "other-binding", issuer)
                          == "REJECTED:PENDING_AUTHORIZATION_NOT_FOUND", "code-binding-isolation")
                    check(requests == [], "wrong-binding-no-token-request")
                    check(run("callback-code", state, "binding-code", issuer) == "SUCCEEDED",
                          "cross-jvm-code-redemption")
                    check(requests == [True], "one-valid-token-request")
                    check(run("callback-code", state, "binding-code", issuer)
                          == "REJECTED:PENDING_AUTHORIZATION_NOT_FOUND", "code-replay-rejected")
                    check(requests == [True], "code-replay-no-token-request")

                    state, current_challenge = run("issue-code", "binding-unknown-consume", issuer).split("\t", 1)
                    check(run("callback-code-unknown", state, "binding-unknown-consume", issuer)
                          == "FAILED:PENDING_AUTHORIZATION_STORE_UNAVAILABLE", "unknown-consume-no-tokens")
                    check(requests == [True], "unknown-consume-no-token-request")
                    check(run("callback-code", state, "binding-unknown-consume", issuer)
                          == "REJECTED:PENDING_AUTHORIZATION_NOT_FOUND", "unknown-consume-replay-rejected")
                    check(requests == [True], "unknown-consume-replay-no-token-request")

                    state, current_challenge = run("issue-code", "binding-code-race", issuer).split("\t", 1)
                    contenders = [subprocess.Popen([str(args.java_home / "bin/java"), "-cp", classpath,
                                    "example.pending.PendingStoreProbe", "callback-code-race", state,
                                    "binding-code-race", issuer], env=current_db_env, stdin=subprocess.PIPE,
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True) for _ in range(2)]
                    try:
                        check(all(proc.stdout is not None and proc.stdout.readline().strip() == "READY"
                                  for proc in contenders), "code-race-ready")
                        for proc in contenders:
                            assert proc.stdin is not None
                            proc.stdin.write("go\n")
                            proc.stdin.flush()
                        outcomes = []
                        for proc in contenders:
                            output, _ = proc.communicate(timeout=15)
                            check(proc.returncode == 0, "code-race-jvm")
                            outcomes.append(output.strip())
                        check(sorted(outcomes) == ["REJECTED:PENDING_AUTHORIZATION_NOT_FOUND", "SUCCEEDED"],
                              "cross-jvm-code-single-winner")
                        check(requests == [True, True], "exactly-one-race-redemption")
                    finally:
                        for proc in contenders:
                            if proc.poll() is None:
                                proc.kill()
                                proc.wait(timeout=5)
                finally:
                    token_server.shutdown()
                    token_thread.join(timeout=5)

            state = run("issue", "binding-lock")
            holder = subprocess.Popen([str(args.java_home / "bin/java"), "-cp", classpath,
                        "example.pending.PendingStoreProbe", "hold"], env=current_db_env, stdin=subprocess.DEVNULL,
                        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            try:
                check(holder.stdout is not None and holder.stdout.readline().strip() == "READY", "lock-ready")
                check(run("callback-short", state, "binding-lock") == "FAILED:PENDING_AUTHORIZATION_STORE_UNAVAILABLE",
                      "blocked-consume-fails-closed")
                holder.communicate(timeout=5)
                check(holder.returncode == 0, "lock-release")
                check(run("callback", state, "binding-lock") == "DENIED", "timeout-left-record")
            finally:
                if holder.poll() is None:
                    holder.kill()
                    holder.wait(timeout=5)

            state = run("issue", "binding-restart")
            docker("stop", name)
            check(run("callback", state, "binding-restart") == "FAILED:PENDING_AUTHORIZATION_STORE_UNAVAILABLE",
                  "database-outage-fails-closed")
            docker("start", name)
            ready()
            current_db_env = db_env()
            check(run("callback", state, "binding-restart") == "DENIED", "restart-retains-pending")
        finally:
            if ("container", name) in created:
                subprocess.run(["docker", "rm", "-f", name], capture_output=True, timeout=60)
            if ("volume", volume) in created:
                subprocess.run(["docker", "volume", "rm", volume], capture_output=True, timeout=60)
            if ("network", network) in created:
                subprocess.run(["docker", "network", "rm", network], capture_output=True, timeout=60)
            env_file.unlink(missing_ok=True)
    print("pending-postgresql-example: PASS", flush=True)


if __name__ == "__main__":
    main()
