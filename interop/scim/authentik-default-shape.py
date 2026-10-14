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

"""Reproduce the pinned default-mode defect without changing its serializer."""
import hashlib
import json
from pathlib import Path
from authentik import authentik_version
from authentik.providers.scim.clients.schema import PatchOp, PatchOperation, PatchRequest

request = PatchRequest(Operations=[PatchOperation(op=PatchOp.replace, path=None, value={
    "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
    "displayName": "Qualification Renamed", "externalId": "synthetic"})])
body = request.model_dump(mode="json", exclude_unset=True, exclude_none=True)
assert authentik_version() == "2026.8.3"
assert "schemas" not in body
print(json.dumps({
    "tool": "authentik", "version": authentik_version(), "compatibilityMode": "default",
    "outcome": "upstream-defect-reproduced", "topLevelKeys": sorted(body),
    "operationKeys": sorted(body["Operations"][0]),
    "valueKeys": sorted(body["Operations"][0]["value"]),
    "requiredPatchOpSchemasPresent": False,
    "productionGroupClientSha256": hashlib.sha256(Path("/authentik/providers/scim/clients/groups.py").read_bytes()).hexdigest()}))
