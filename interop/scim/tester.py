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

"""Run the checksum-pinned independent tester against real HTTP routes."""
import argparse
import collections
import importlib.metadata
import json
import os
from pathlib import Path
import random
import re
import ssl


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-url", required=True)
    parser.add_argument("--ca-file", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--profile", choices=("default", "configured"), default="default")
    parser.add_argument("--diagnostic-request-directory", type=Path,
                        help="Optional private capture of up to three failing synthetic non-credential requests")
    arguments = parser.parse_args()
    if not arguments.base_url.startswith("https://"):
        parser.error("the qualification endpoint must use verified HTTPS")
    token = os.environ["SCIM_BEARER_TOKEN"]
    from httpx2 import Client
    from scim2_client.engines.httpx2 import SyncSCIMClient
    from scim2_tester import check_server

    if importlib.metadata.version("scim2-tester") != "0.5.2":
        raise RuntimeError("install the pinned requirements before qualification")
    random.seed(7644)
    context = ssl.create_default_context(cafile=str(arguments.ca_file))
    wire_errors = []
    diagnostic_kinds = set()
    if arguments.diagnostic_request_directory:
        arguments.diagnostic_request_directory.mkdir(mode=0o700, parents=True, exist_ok=False)

    def shape(value, name=""):
        if isinstance(value, dict):
            return {key: shape(child, key) for key, child in value.items()}
        if isinstance(value, list):
            return [shape(child, name) for child in value]
        if isinstance(value, str):
            if name in {"schemas", "op"} or name == "type" and value in {"User", "Group"}:
                return value
            if name == "path":
                return re.sub(r'"(?:\\.|[^"\\])*"', '"<synthetic-literal>"', value)
            if name == "$ref":
                return re.sub(r"/(Users|Groups)/[^/]+$", r"/\1/{synthetic-id}", value)
            if name == "value" and value.startswith(("u-", "g-")):
                return value[:2] + "{synthetic-id}"
            return "<synthetic-string>"
        return value

    def observe(response):
        if response.status_code == 400:
            request = response.request
            path = re.sub(r"/(Users|Groups)/[^/]+$", r"/\1/{synthetic-id}", request.url.path)
            try:
                body = json.loads(request.content) if request.content else None
            except ValueError:
                body = "<malformed-json>"
            wire_errors.append({"method": request.method, "path": path, "status": response.status_code,
                                "requestBodyShape": shape(body)})
            if arguments.diagnostic_request_directory and isinstance(body, dict):
                kind = "group-create" if request.method == "POST" and request.url.path.endswith("/Groups") else None
                operations = body.get("Operations", [])
                if request.method == "PATCH" and len(operations) == 1:
                    operation = operations[0]
                    if operation.get("path") == "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User":
                        kind = "enterprise-root-" + operation.get("op", "unknown")
                if kind in {"group-create", "enterprise-root-add", "enterprise-root-replace"} and kind not in diagnostic_kinds:
                    raw = request.content
                    if len(raw) <= 65536 and b'"password"' not in raw.lower():
                        (arguments.diagnostic_request_directory / (kind + ".json")).write_bytes(raw)
                        diagnostic_kinds.add(kind)

    with Client(base_url=arguments.base_url.rstrip("/"),
                headers={"Authorization": "Bearer " + token},
                verify=context, timeout=20, trust_env=False,
                event_hooks={"response": [observe]}) as transport:
        client = SyncSCIMClient(transport)
        if arguments.profile == "configured":
            from pydantic import Field, create_model
            from scim2_models import ScimProvider
            client.discover()
            catalog = []
            for model in client.provider.models:
                if str(model.__schema__) == "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User":
                    # Supported model registration retains the discovered schema facets.
                    # Only the inherited non-attribute serializer field is excluded;
                    # no emitted request is rewritten and all tester checks still run.
                    original = model.model_fields["schemas"]
                    model = create_model("QualifiedEnterpriseUser", __base__=model,
                                         schemas=(original.rebuild_annotation(), Field(default_factory=list, exclude=True)))
                catalog.append(model)
            client.provider = ScimProvider(catalog, client.provider.resource_types,
                                           client.provider.config, client.provider.policy)
        results = check_server(client, resource_types=["User", "Group"])
    # Tester debug bodies can contain provisioned values. Keep only assertion identities,
    # dispositions and tags in durable evidence; all test values are synthetic.
    rows = [{"status": result.status.name, "title": result.title,
             "resourceType": result.resource_type, "tags": sorted(result.tags),
             "reason": result.reason} for result in results]
    counts = dict(collections.Counter(row["status"] for row in rows))
    required = {"discovery", "crud:create", "crud:read", "crud:update", "crud:delete",
                "patch:add", "patch:remove", "patch:replace"}
    passed_tags = set()
    for row in rows:
        if row["status"] in {"SUCCESS", "COMPLIANT", "ACCEPTABLE"}:
            passed_tags.update(row["tags"])
    missing = sorted(required - passed_tags)
    failed = any(row["status"] in {"ERROR", "CRITICAL", "DEVIATION"} for row in rows) or bool(missing)
    report = {"tool": "scim2-tester", "version": "0.5.2", "evidenceKind": "live-independent-tester",
              "profile": arguments.profile,
              "counts": counts, "missingRequiredTags": missing,
              "outcome": "failed" if failed else "passed", "checks": rows}
    arguments.output.write_text(json.dumps(report, indent=2) + "\n")
    arguments.output.with_name(arguments.output.stem + "-wire-errors.json").write_text(json.dumps(wire_errors, indent=2) + "\n")
    print(json.dumps({key: report[key] for key in ("tool", "counts", "missingRequiredTags", "outcome")}))
    raise SystemExit(1 if failed else 0)


if __name__ == "__main__":
    main()
