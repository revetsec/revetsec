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

"""Executed by the pinned authentik manage shell, using its production client."""
import json
import os
import time
from urllib.parse import urlsplit

from authentik import authentik_version
from authentik.core.models import Group, User
from authentik.providers.scim.clients.groups import SCIMGroupClient
from authentik.providers.scim.clients.users import SCIMUserClient
from authentik.providers.scim.models import SCIMCompatibilityMode, SCIMMapping, SCIMProvider

events = []
requests = []
assert authentik_version() == "2026.8.3"
provider = SCIMProvider.objects.create(
    name="revetsec qualification", url=os.environ["SCIM_BASE_URI"],
    token=os.environ["SCIM_BEARER_TOKEN"], verify_certificates=True,
    compatibility_mode=SCIMCompatibilityMode.AWS,
    discovery_enabled=False, service_provider_config_cache_timeout="minutes=0")
user_mapping = SCIMMapping.objects.create(
    name="qualification user", expression="return {'userName': request.user.username, 'displayName': request.user.name, 'active': request.user.is_active, 'emails': [{'value': request.user.email, 'type': 'work', 'primary': True}]}")
group_mapping = SCIMMapping.objects.create(
    name="qualification group", expression="return {'displayName': request.context['group'].name}")
provider.property_mappings.add(user_mapping)
provider.property_mappings_group.add(group_mapping)
first = User.objects.create(username="qualification-one", name="Qualification One",
                            email="one@example.test", is_active=True)
second = User.objects.create(username="qualification-two", name="Qualification Two",
                             email="two@example.test", is_active=True)
group = Group.objects.create(name="Qualification Group")
group.users.add(first)


def instrument(client):
    original = client._session.request

    def bounded(method, url, **keywords):
        keywords["timeout"] = (5, 20)
        response = original(method, url, **keywords)
        path = urlsplit(url).path
        pieces = path.split("/")
        if len(pieces) > 4 and pieces[3] in {"Users", "Groups"}:
            pieces[4] = "{synthetic-id}"
        requests.append({"method": method, "path": "/".join(pieces), "status": response.status_code})
        return response

    client._session.request = bounded
    return client


users = instrument(SCIMUserClient(provider))
groups = instrument(SCIMGroupClient(provider))
assert not users._config.is_fallback and not users._config.patch.supported
assert not groups._config.is_fallback and not groups._config.patch.supported
assert users._session.verify is True and groups._session.verify is True
assert provider.dry_run is False
assert provider.compatibility_mode == "aws"


def await_state(name, client, path, predicate):
    deadline = time.monotonic() + 20
    while True:
        state = client._request("GET", path)
        if predicate(state):
            events.append(name)
            return state
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise AssertionError("required outbound outcome missing: " + name)
        # Bounded observation of actual state, not an assumed propagation delay.
        time.sleep(min(0.1, remaining))


one, created = users.write(first)
assert one is not None and created
two, created = users.write(second)
assert two is not None and created
await_state("user-create", users, "/Users/" + one.scim_id,
            lambda value: value.get("userName") == first.username)
membership, created = groups.write(group)
assert membership is not None and created
path = "/Groups/" + membership.scim_id
await_state("group-create-with-member", groups, path,
            lambda value: [entry["value"] for entry in value.get("members", [])] == [one.scim_id])
group.users.add(second)
groups.write(group)
await_state("membership-add", groups, path,
            lambda value: {entry["value"] for entry in value.get("members", [])} == {one.scim_id, two.scim_id})
group.users.remove(first)
groups.write(group)
await_state("membership-remove", groups, path,
            lambda value: [entry["value"] for entry in value.get("members", [])] == [two.scim_id])
group.name = "Qualification Renamed"
group.save()
groups.write(group)
await_state("group-update", groups, path, lambda value: value.get("displayName") == group.name)
first.name = "Qualification Updated"
first.is_active = False
first.save()
users.write(first)
await_state("user-update-deactivate", users, "/Users/" + one.scim_id,
            lambda value: value.get("displayName") == first.name and value.get("active") is False)
before = len(requests)
users.write(first)
groups.write(group)
assert all(entry["method"] == "GET" for entry in requests[before:])
events.append("unchanged-sync-no-write")
groups.delete(membership.scim_id)
users.delete(one.scim_id)
users.delete(two.scim_id)
assert list(groups.paginate_resources("/Groups")) == []
assert list(users.paginate_resources("/Users")) == []
events.append("delete-and-empty-collection")
assert any(entry["method"] == "PUT" for entry in requests)
assert not any(entry["method"] == "PATCH" for entry in requests)
print("REVETSEC_SCIM_OUTBOUND=" + json.dumps({
    "tool": "authentik", "version": "2026.8.3", "evidenceKind": "live-production-outbound-client",
    "compatibilityMode": provider.compatibility_mode,
    "outcome": "passed", "requiredOutcomes": events, "requests": requests,
    "clientPatchEnabled": groups._config.patch.supported,
    "httpTimeoutSeconds": {"connect": 5, "response": 20}, "outcomeWaitDeadlineSeconds": 20,
    "certificateVerification": True, "dryRun": False}))
