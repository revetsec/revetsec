#!/usr/bin/env python3
# Copyright 2026 Revetware LLC.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Report nightly SCIM run evidence without a release-duration gate."""
import argparse
import datetime
import json
from pathlib import Path
import re

REQUIRED = {"user-create", "group-create-with-member", "membership-add", "membership-remove", "group-update",
            "user-update-deactivate", "unchanged-sync-no-write", "delete-and-empty-collection"}


def qualification(record, run):
    if not isinstance(record, dict):
        return False
    for field in ("applicationArtifactSha256", "pinsSha256", "toolingSha256"):
        if not isinstance(record.get(field), str) or re.fullmatch(r"[0-9a-f]{64}", record[field]) is None:
            return False
    return (record.get("formatVersion") == 1 and record.get("outcome") == "passed"
            and record.get("githubEvent") == "schedule"
            and str(record.get("githubRunId")) == str(run["id"])
            and str(record.get("githubRunAttempt")) == str(run.get("run_attempt", 1))
            and record.get("githubSha") == run["head_sha"]
            and record.get("testerOutcome") == "passed" and record.get("authentikOutcome") == "passed"
            and record.get("authentikCompatibilityMode") == "aws"
            and record.get("testerProfile") == "discovered-extension-schemas-field-excluded"
            and record.get("testerDefaultOutcome") == "failed-with-identified-fixture-defect"
            and set(record.get("requiredOutcomes", [])) == REQUIRED
            and set(record.get("tlsControls", [])) == {"scoped-ca-positive", "default-trust-negative", "foreign-hostname-negative"})


def evaluate(runs, evidence, now):
    scheduled = sorted((run for run in runs if run.get("event") == "schedule"), key=lambda row: row["created_at"])
    dispositions = []
    for run in scheduled:
        when = datetime.datetime.fromisoformat(run["created_at"].replace("Z", "+00:00"))
        record = evidence.get(str(run["id"]))
        reason = None
        if run.get("status") != "completed" or run.get("conclusion") != "success":
            reason = "scheduled run was not a completed success"
        elif record is None or not qualification(record, run):
            reason = "missing or incomplete required-outcome evidence"
        dispositions.append({"runId": run["id"], "scheduledAt": run["created_at"],
                             "outcome": "passed" if reason is None else "failed", "reason": reason,
                             "ageSeconds": max(0, int((now - when).total_seconds()))})
    return {"releaseDurationGate": False, "scheduledRunCount": len(dispositions),
            "outcome": dispositions[-1]["outcome"] if dispositions else "unavailable", "runs": dispositions}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runs-json", type=Path, required=True, help="GitHub REST workflow-runs response, including failed and skipped schedules")
    parser.add_argument("--evidence-directory", type=Path, required=True, help="One <run-id>/qualification.json from each matching GitHub artifact")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    history = json.loads(args.runs_json.read_text())
    runs = history["workflow_runs"] if isinstance(history, dict) else history
    evidence = {}
    for path in args.evidence_directory.glob("*/qualification.json"):
        evidence[path.parent.name] = json.loads(path.read_text())
    result = evaluate(runs, evidence, datetime.datetime.now(datetime.timezone.utc))
    args.output.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({key: result[key] for key in ("outcome", "scheduledRunCount", "releaseDurationGate")}))
    raise SystemExit(0 if result["outcome"] == "passed" else 1)


if __name__ == "__main__":
    main()
