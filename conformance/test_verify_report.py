#!/usr/bin/env python3
# Copyright 2026 Revetware LLC.
# Licensed under the Apache License, Version 2.0. See ../LICENSE.
import copy
import json
from pathlib import Path
import tempfile
import unittest
import zipfile
from verify_report import verify, REJECTIONS, COMPREHENSIVE, EXCLUDED, ASSERTION_CONDITIONS, DISCOVERY_ONLY

class ReportTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.manifest = json.loads(Path(__file__).with_name("plans.json").read_text())
        self.rows = []
        self.write("server.json", {"tag": self.manifest["release"], "revision": self.manifest["revision"]})
        for plan, modules in self.manifest["plans"].items():
            self.write(plan + "/created.json", {"name": plan, "modules": [{"testModule": name} for name in modules]})
            with zipfile.ZipFile(self.root / plan / "suite-export.zip", "w") as archive:
                archive.writestr("test-results.json", "{}")
            if plan == COMPREHENSIVE:
                self.write(plan + "/public-registration.json", {"keys": [dict(kty="RSA",kid="test-key",use="sig",alg="RS256",n="test-modulus",e="AQAB")]})
            for name in modules:
                if plan == COMPREHENSIVE and name in EXCLUDED: continue
                rp, detail = REJECTIONS.get(name, ("SUCCESS", ""))
                result = "SKIPPED" if name.endswith("idtoken-sig-none") else "PASSED"
                row = dict(plan=plan, module=name, id=str(len(self.rows)), status="FINISHED", result=result, rp=rp, detail=detail, accepted=True, effectiveAuth="private_key_jwt" if plan == COMPREHENSIVE and name != "oidcc-client-test-client-secret-basic" else "client_secret_basic")
                self.rows.append(row)
                path = plan + "/" + name + "/"
                self.write(path + "outcome.json", row)
                self.write(path + "final.json", dict(testId=row["id"], testName=name, status="FINISHED", result=result,
                    variant=dict(client_auth_type="private_key_jwt" if plan == COMPREHENSIVE else "client_secret_basic", request_type="plain_http_request", response_type="code",
                    client_registration="static_client", response_mode="form_post" if "formpost" in plan else "default")))
                message = "clients are not required to support unsigned id_tokens" if result == "SKIPPED" else "finished"
                logs = [{"testId": row["id"], "msg": message}]
                if plan == COMPREHENSIVE:
                    registration = json.loads((self.root / plan / "public-registration.json").read_text())
                    logs.append(dict(testId=row["id"],src="OIDCCGetStaticClientConfigurationForRPTests",result="SUCCESS",jwks=registration))
                    if name != "oidcc-client-test-client-secret-basic":
                        count = 0 if name in DISCOVERY_ONLY else 2 if name == "oidcc-client-test-signing-key-rotation" else 1
                        for _ in range(count):
                            for condition in ASSERTION_CONDITIONS:
                                entry = dict(testId=row["id"],src=condition,result="SUCCESS")
                                if condition == "ExtractClientAssertion": entry["client_assertion"] = dict(header=dict(kid="test-key",alg="RS256"))
                                logs.append(entry)
                    else: logs.append(dict(testId=row["id"],src="ExtractClientCredentialsFromBasicAuthorizationHeader",result="SUCCESS"))
                self.write(path + "log.json", logs)
        self.write("outcomes.json", self.rows)
    def write(self, path, value):
        target = self.root / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json.dumps(value))
    def check_reject(self):
        with self.assertRaises((ValueError, FileNotFoundError, json.JSONDecodeError)):
            verify(self.root)
    def test_accepts_all_executed_modules_with_exact_unsigned_skip_dispositions(self):
        self.assertEqual(9, len(verify(self.root)))
    def test_missing_or_duplicate_or_unexpected_module_fails(self):
        for change in (lambda rows: rows.pop(), lambda rows: rows.append(rows[0]), lambda rows: rows[0].update(module="unexpected")):
            with self.subTest(change=change):
                rows = copy.deepcopy(self.rows); change(rows); self.write("outcomes.json", rows); self.check_reject()
    def test_suite_terminal_and_result_fail_closed(self):
        for field, values in {"status": ["WAITING", "INTERRUPTED", "FAILED", "UNKNOWN"], "result": ["FAILED", "REVIEW", "WARNING", "SKIPPED", "UNKNOWN"]}.items():
            for value in values:
                with self.subTest(field=field, value=value):
                    rows = copy.deepcopy(self.rows); rows[0][field] = value; self.write("outcomes.json", rows); self.check_reject()
    def test_unrelated_negative_error_never_counts_as_rejection(self):
        rows = copy.deepcopy(self.rows); rows[1].update(rp="OAUTH:ENDPOINT_ERROR", detail=""); self.write("outcomes.json", rows); self.check_reject()
    def test_wrong_jose_reason_fails(self):
        rows = copy.deepcopy(self.rows)
        next(row for row in rows if row["module"].endswith("kid-absent-multiple-jwks"))["detail"] = "UNKNOWN_KEY"
        self.write("outcomes.json", rows); self.check_reject()
    def test_missing_skip_evidence_fails(self):
        row = next(row for row in self.rows if row["result"] == "SKIPPED")
        self.write(row["plan"] + "/" + row["module"] + "/log.json", [{"testId": row["id"], "msg": "skip"}]); self.check_reject()
    def test_warning_review_failure_logs_require_disposition(self):
        row = self.rows[0]
        for result in ["WARNING", "REVIEW", "FAILURE"]:
            with self.subTest(result=result):
                self.write(row["plan"] + "/" + row["module"] + "/log.json", [{"testId": row["id"], "result": result}]); self.check_reject()
    def test_empty_or_wrong_test_logs_fail(self):
        row = self.rows[0]
        for logs in [[], [{"testId": "other"}]]:
            self.write(row["plan"] + "/" + row["module"] + "/log.json", logs); self.check_reject()
    def test_module_final_and_outcome_must_agree(self):
        row = self.rows[0]
        for field in ["testId", "testName", "status", "result"]:
            final = dict(testId=row["id"], testName=row["module"], status="FINISHED", result="PASSED"); final[field] = "other"
            self.write(row["plan"] + "/" + row["module"] + "/final.json", final); self.check_reject()
    def test_wrong_response_mode_cannot_silently_replace_form_post(self):
        row = next(row for row in self.rows if "formpost" in row["plan"])
        path = row["plan"] + "/" + row["module"] + "/final.json"
        final = json.loads((self.root / path).read_text()); final["variant"]["response_mode"] = "default"
        self.write(path, final); self.check_reject()
    def test_missing_and_corrupt_exports_fail(self):
        export = self.root / self.rows[0]["plan"] / "suite-export.zip"
        export.unlink(); self.check_reject(); export.write_text("invalid"); self.check_reject()
    def test_plan_drift_fails(self):
        plan = self.rows[0]["plan"]; self.write(plan + "/created.json", {"name": plan, "modules": []}); self.check_reject()
    def test_wrong_release_or_revision_fails(self):
        for field in ["tag", "revision"]:
            server = dict(tag=self.manifest["release"], revision=self.manifest["revision"]); server[field] = "other"; self.write("server.json", server); self.check_reject()

    def private_path(self):
        row = next(row for row in self.rows if row["plan"] == COMPREHENSIVE and row["module"] == "oidcc-client-test")
        return row, row["plan"] + "/" + row["module"] + "/log.json"
    def test_every_private_key_oracle_condition_is_required(self):
        row, path = self.private_path(); original = json.loads((self.root / path).read_text())
        for condition in ASSERTION_CONDITIONS:
            with self.subTest(condition=condition):
                self.write(path, [entry for entry in original if entry.get("src") != condition]); self.check_reject()
    def test_registered_public_key_must_match_original_projection(self):
        row, path = self.private_path(); logs = json.loads((self.root / path).read_text())
        next(entry for entry in logs if entry.get("src") == "OIDCCGetStaticClientConfigurationForRPTests")["jwks"]["keys"][0]["n"] = "other-key"
        self.write(path, logs); self.check_reject()
    def test_registration_rejects_private_key_material(self):
        path = COMPREHENSIVE + "/public-registration.json"
        registration = json.loads((self.root / path).read_text()); registration["keys"][0]["d"] = "private"
        self.write(path, registration); self.check_reject()
    def test_assertion_key_id_and_algorithm_match_registration(self):
        row, path = self.private_path(); original = json.loads((self.root / path).read_text())
        for field in ["kid", "alg"]:
            logs = copy.deepcopy(original); next(entry for entry in logs if entry.get("src") == "ExtractClientAssertion")["client_assertion"]["header"][field] = "other"
            self.write(path, logs); self.check_reject()
    def test_private_authentication_cannot_fall_back_to_basic(self):
        row, path = self.private_path(); rows = copy.deepcopy(self.rows)
        next(entry for entry in rows if entry["id"] == row["id"])["effectiveAuth"] = "client_secret_basic"
        self.write("outcomes.json", rows); self.check_reject()
    def test_basic_exception_cannot_count_as_private_key_evidence(self):
        row = next(row for row in self.rows if row["plan"] == COMPREHENSIVE and row["module"] == "oidcc-client-test-client-secret-basic")
        path = row["plan"] + "/" + row["module"] + "/log.json"; logs = json.loads((self.root / path).read_text())
        logs.append(dict(testId=row["id"],src="ValidateClientAssertionSignature",result="SUCCESS")); self.write(path, logs); self.check_reject()
    def test_excluded_module_cannot_be_reported_as_executed(self):
        (self.root / COMPREHENSIVE / next(iter(EXCLUDED))).mkdir(); self.check_reject()
    def test_missing_comprehensive_module_in_created_plan_fails(self):
        path = COMPREHENSIVE + "/created.json"; created = json.loads((self.root / path).read_text()); created["modules"].pop()
        self.write(path, created); self.check_reject()

if __name__ == "__main__":
    unittest.main()
