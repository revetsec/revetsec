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
 "oidcc-client-test-missing-aud": ("MISSING_CLAIM", "MISSING_CLAIM"),
 "oidcc-client-test-invalid-sig-es256": ("ID_TOKEN_SIGNATURE_INVALID", "SIGNATURE_MISMATCH"),
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

COMPREHENSIVE = "oidcc-client-test-plan"
PROFILE = json.loads(Path(__file__).with_name("comprehensive-profile.json").read_text())
EXCLUDED = {row["module"]: row for row in PROFILE["modules"] if row["selection"] == "PROFILE_EXCLUDED"}
ASSERTION_CONDITIONS = ("ExtractClientAssertion", "EnsureClientAssertionSignatureAlgorithmMatchesRegistered",
    "ValidateClientAssertionSignature", "EnsureClientAssertionTypeIsJwt", "ValidateClientAssertionClaims", "CheckForClientAssertionJtiReuse")
DISCOVERY_ONLY = {"oidcc-client-test-discovery-openid-config", "oidcc-client-test-discovery-jwks-uri-keys", "oidcc-client-test-discovery-issuer-mismatch"}

def check_private_key_logs(logs, registration, count):
    keys = registration.get("keys")
    if not isinstance(keys, list) or len(keys) != 1 or set(keys[0]) != {"kty", "kid", "use", "alg", "n", "e"} or keys[0]["kty"] != "RSA" or keys[0]["alg"] != "RS256" or keys[0]["use"] != "sig":
        raise ValueError("Invalid public-only assertion registration")
    registered = [entry for entry in logs if entry.get("src") == "OIDCCGetStaticClientConfigurationForRPTests" and entry.get("result") == "SUCCESS"]
    if len(registered) != 1 or registered[0].get("jwks") != registration:
        raise ValueError("Suite registration differs from original public key")
    for condition in ASSERTION_CONDITIONS:
        successes = [entry for entry in logs if entry.get("src") == condition and entry.get("result") == "SUCCESS"]
        if len(successes) != count:
            raise ValueError("Missing actual private-key oracle: " + condition)
    for entry in logs:
        if entry.get("src") == "ExtractClientAssertion" and entry.get("result") == "SUCCESS":
            assertion = entry.get("client_assertion", {})
            if assertion.get("header", {}).get("kid") != keys[0]["kid"] or assertion.get("header", {}).get("alg") != "RS256":
                raise ValueError("Assertion identifier/algorithm differs from registration")

def verify(output, manifest=None):
    output = Path(output)
    manifest = manifest or json.loads(Path(__file__).with_name("plans.json").read_text())
    server = json.loads((output / "server.json").read_text())
    if (server.get("tag"), server.get("revision")) != (manifest["release"], manifest["revision"]):
        raise ValueError("Unexpected suite revision")
    expected = {(plan, module) for plan, modules in manifest["plans"].items() for module in modules if plan != COMPREHENSIVE or module not in EXCLUDED}
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
        private_plan = key[0] == COMPREHENSIVE
        effective_auth = "private_key_jwt" if private_plan and name != "oidcc-client-test-client-secret-basic" else "client_secret_basic"
        if row.get("effectiveAuth") != effective_auth:
            raise ValueError("Effective authentication drift")
        expected_variant = dict(client_auth_type="private_key_jwt" if private_plan else "client_secret_basic", request_type="plain_http_request",
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
        if private_plan:
            registration = json.loads((output / COMPREHENSIVE / "public-registration.json").read_text())
            if name != "oidcc-client-test-client-secret-basic":
                count = 0 if name in DISCOVERY_ONLY else 2 if name == "oidcc-client-test-signing-key-rotation" else 1
                check_private_key_logs(logs, registration, count)
            elif not any(entry.get("src") == "ExtractClientCredentialsFromBasicAuthorizationHeader" and entry.get("result") == "SUCCESS" for entry in logs):
                raise ValueError("Missing mandatory Basic exception oracle")
            elif any(entry.get("src") in ASSERTION_CONDITIONS and entry.get("result") == "SUCCESS" for entry in logs):
                raise ValueError("Basic exception incorrectly counted as private-key authentication")
        if result == "SKIPPED":
            if not any("not required to support unsigned" in str(entry.get("msg", "")) for entry in logs):
                raise ValueError("Missing unsigned-token skip evidence")
            dispositions.append({"plan": key[0], "module": name, "result": result,
                "disposition": "RP rejects unsigned ID tokens; this exact module permits rejection and times out as SKIPPED."})
    if seen != expected or len(rows) != 60:
        raise ValueError("Missing module outcomes")
    for plan, modules in manifest["plans"].items():
        created = json.loads((output / plan / "created.json").read_text())
        if created.get("name") != plan or [m["testModule"] for m in created["modules"]] != modules:
            raise ValueError("Plan module drift")
        if not zipfile.is_zipfile(output / plan / "suite-export.zip"):
            raise ValueError("Missing raw plan export")
    profile_modules = [row["module"] for row in PROFILE["modules"] if row["selection"] != "VARIANT_EXCLUDED"]
    if manifest["plans"].get(COMPREHENSIVE) != profile_modules:
        raise ValueError("Comprehensive source selection drift")
    for name, row in EXCLUDED.items():
        if (output / COMPREHENSIVE / name).exists():
            raise ValueError("Excluded module unexpectedly executed")
        dispositions.append({"plan": COMPREHENSIVE, "module": name, "result": "NOT_RUN", "disposition": row["reason"],
            "sourceCommit": PROFILE["sourceCommit"], "sourceSha256": row["sourceSha256"]})
    return dispositions

if __name__ == "__main__":
    import sys
    dispositions = verify(sys.argv[1])
    Path(sys.argv[1], "dispositions.json").write_text(json.dumps(dispositions, indent=2) + "\n")
    print("OIDF report verified: 60 executed modules, 4 unsigned-token skips, 5 source-selected profile exclusions")
