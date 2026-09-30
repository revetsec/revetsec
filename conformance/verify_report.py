#!/usr/bin/env python3
# Copyright 2026 Revetware LLC.
# Licensed under the Apache License, Version 2.0. See ../LICENSE.
"""Fail closed on missing modules, unrelated RP errors or undisposed suite findings."""
import json
import zipfile
from pathlib import Path

REJECTIONS = {
 "oidcc-client-test-invalid-iss": ("ISSUER_MISMATCH", "ISSUER_MISMATCH"),
 "oidcc-client-test-missing-sub": ("INVALID_SUBJECT", ""),
 "oidcc-client-test-invalid-aud": ("AUDIENCE_MISMATCH", "AUDIENCE_MISMATCH"),
 "oidcc-client-test-missing-iat": ("MISSING_CLAIM", "MISSING_CLAIM"),
 "oidcc-client-test-kid-absent-multiple-jwks": ("ID_TOKEN_SIGNATURE_INVALID", "AMBIGUOUS_KEY"),
 "oidcc-client-test-idtoken-sig-none": ("ALGORITHM_NOT_ALLOWED", "ALGORITHM_NOT_ALLOWED"),
 "oidcc-client-test-invalid-sig-rs256": ("ID_TOKEN_SIGNATURE_INVALID", "SIGNATURE_MISMATCH"),
 "oidcc-client-test-userinfo-invalid-sub": ("USERINFO_SUBJECT_MISMATCH", ""),
 "oidcc-client-test-nonce-invalid": ("NONCE_MISMATCH", ""),
 "oidcc-client-test-discovery-issuer-mismatch": ("OAUTH:ISSUER_MISMATCH", ""),
 "oidcc-client-test-refresh-token-invalid-issuer": ("ISSUER_MISMATCH", "ISSUER_MISMATCH"),
 "oidcc-client-test-refresh-token-invalid-sub": ("REFRESHED_ID_TOKEN_MISMATCH", ""),
}

def verify(output, manifest=None):
    output = Path(output)
    manifest = manifest or json.loads(Path(__file__).with_name("plans.json").read_text())
    server = json.loads((output / "server.json").read_text())
    if (server.get("tag"), server.get("revision")) != (manifest["release"], manifest["revision"]):
        raise ValueError("Unexpected suite revision")
    expected = {(plan, module) for plan, modules in manifest["plans"].items() for module in modules}
    rows = json.loads((output / "outcomes.json").read_text())
    seen = set()
    dispositions = []
    for row in rows:
        key = row["plan"], row["module"]
        if key in seen or key not in expected:
            raise ValueError("Duplicate or unexpected module")
        seen.add(key)
        name = row["module"]
        wanted = REJECTIONS.get(name, ("SUCCESS", ""))
        if (row.get("rp"), row.get("detail")) != wanted:
            raise ValueError("Unrelated RP outcome: " + name)
        result = "SKIPPED" if name == "oidcc-client-test-idtoken-sig-none" else "PASSED"
        if row.get("status") != "FINISHED" or row.get("result") != result or row.get("accepted") is not True:
            raise ValueError("Unexpected suite outcome: " + name)
        evidence = output / key[0] / key[1]
        final = json.loads((evidence / "final.json").read_text())
        outcome = json.loads((evidence / "outcome.json").read_text())
        if outcome != row or final.get("testId") != row["id"] or final.get("testName") != name or final.get("status") != "FINISHED" or final.get("result") != result:
            raise ValueError("Inconsistent module evidence")
        expected_variant = dict(client_auth_type="client_secret_basic", request_type="plain_http_request",
            response_type="code", client_registration="static_client",
            response_mode="form_post" if "formpost" in key[0] else "default")
        if final.get("variant") != expected_variant:
            raise ValueError("Module variant drift")
        logs = json.loads((evidence / "log.json").read_text())
        if not isinstance(logs, list) or not logs or any(entry.get("testId") != row["id"] for entry in logs):
            raise ValueError("Missing or mismatched raw logs")
        # No warning or review finding has been observed in the pinned four plans. New findings require review.
        if any(entry.get("result") in {"WARNING", "REVIEW", "FAILURE"} for entry in logs):
            raise ValueError("Undisposed raw-log finding: " + name)
        if result == "SKIPPED":
            if not any("not required to support unsigned" in str(entry.get("msg", "")) for entry in logs):
                raise ValueError("Missing unsigned-token skip evidence")
            dispositions.append({"plan": key[0], "module": name, "result": result,
                "disposition": "RP rejects unsigned ID tokens; this exact module permits rejection and times out as SKIPPED."})
    if seen != expected or len(rows) != 37:
        raise ValueError("Missing module outcomes")
    for plan, modules in manifest["plans"].items():
        created = json.loads((output / plan / "created.json").read_text())
        if created.get("name") != plan or [m["testModule"] for m in created["modules"]] != modules:
            raise ValueError("Plan module drift")
        if not zipfile.is_zipfile(output / plan / "suite-export.zip"):
            raise ValueError("Missing raw plan export")
    return dispositions

if __name__ == "__main__":
    import sys
    dispositions = verify(sys.argv[1])
    Path(sys.argv[1], "dispositions.json").write_text(json.dumps(dispositions, indent=2) + "\n")
    print("OIDF report verified: 37 modules, 3 documented unsigned-token skips")
