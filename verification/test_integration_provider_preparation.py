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

"""Keep clean-runner provider preparation ahead of integration execution."""

import pathlib
import re
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]


class IntegrationProviderPreparationTests(unittest.TestCase):
    def test_ci_prepares_both_fixtures_before_integration(self):
        fixture = (ROOT / "src/test/java/com/revetsec/oauth/ResourceProviderFixturesIT.java").read_text()
        legacy = (ROOT / "src/test/java/com/revetsec/oauth/KeycloakOAuthIT.java").read_text()
        pin = re.search(r'KEYCLOAK_IMAGE\s*=\s*"([^"]+)"', fixture).group(1)
        legacy_pin = re.search(r'IMAGE\s*=\s*"([^"]+)"', legacy).group(1)
        self.assertEqual(pin, legacy_pin)
        self.assertRegex(pin, r'^quay\.io/keycloak/keycloak:[^@]+@sha256:[0-9a-f]{64}$')
        self.assertIn("withImagePullPolicy(image -> false)", fixture)
        workflow = (ROOT / ".github/workflows/ci.yml").read_text().split("\n  integration:", 1)[1]
        workflow = re.split(r'\n  [A-Za-z][^\n]*:', workflow, maxsplit=1)[0]
        pull = workflow.index("run: docker pull " + pin)
        build = workflow.index("run: docker build --pull=false -t revetsec-interop/node-oidc-provider:local")
        verify = workflow.index("run: mvn -B -ntp -Pintegration -Dmaven.javadoc.skip=true verify")
        self.assertLess(pull, verify)
        self.assertLess(build, verify)


if __name__ == "__main__":
    unittest.main()
