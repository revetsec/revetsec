#
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
#

"""Offline OASIS SAML 2.0 XSD checks for test-partner outbound observations."""

import hashlib
import pathlib

from lxml import etree


DIRECTORY = pathlib.Path(__file__).resolve().parents[1] / "schemas"
IMPORTS = {
    "http://www.w3.org/TR/2002/REC-xmldsig-core-20020212/xmldsig-core-schema.xsd":
        "xmldsig-core-schema.xsd",
    "http://www.w3.org/TR/2002/REC-xmlenc-core-20021210/xenc-schema.xsd":
        "xenc-schema.xsd",
    "http://www.w3.org/2001/xml.xsd": "xml.xsd",
    "saml-schema-assertion-2.0.xsd": "saml-schema-assertion-2.0.xsd",
}
FILES = frozenset({"saml-schema-protocol-2.0.xsd", "saml-schema-assertion-2.0.xsd",
                   "saml-schema-metadata-2.0.xsd", "xmldsig-core-schema.xsd",
                   "xenc-schema.xsd", "xml.xsd"})
SHA256 = {
    "saml-schema-protocol-2.0.xsd": "554250583cd5eacc6ce5f094f6ff50fc2547972c436dc96e2e7eb41abf2c817e",
    "saml-schema-assertion-2.0.xsd": "006eb7553843cb7baa9b08da2a9d444346c0e982fb9d9293babe08ede680924b",
    "saml-schema-metadata-2.0.xsd": "204bc7991055dbb889307abbd2ff58022753897dd7064a4d1ca13eb737d2617a",
    "xmldsig-core-schema.xsd": "35cf8197da812c85e40d57891b35c94187569ed474a2dac813ce5090dafcd35c",
    "xenc-schema.xsd": "5dd57f074870e1d91f7eb814aa92967cefcce9011a86adf5e12a769fcf2a237e",
    "xml.xsd": "61960fb3131e38022caad5360e2f33a3382578ab3c80cd58bd74320ede61b20c",
}


class OfflineResolver(etree.Resolver):
    def resolve(self, url, public_id, context):
        name = IMPORTS.get(url)
        if name is None:
            local = pathlib.Path(url)
            if local.is_absolute() and local.parent == DIRECTORY and local.name in FILES:
                name = local.name
        if name is None:
            raise OSError(f"unrecognized XSD import: {url}")
        return self.resolve_filename(str(DIRECTORY / name), context)


def load():
    """Compile the vendored schemas once; fail server startup on missing imports."""
    for name, expected in SHA256.items():
        if hashlib.sha256((DIRECTORY / name).read_bytes()).hexdigest() != expected:
            raise RuntimeError(f"vendored schema digest mismatch: {name}")
    parser = etree.XMLParser(resolve_entities=True, no_network=True, load_dtd=False,
                             huge_tree=False)
    parser.resolvers.add(OfflineResolver())
    result = {}
    for kind, filename in (("authn_request", "saml-schema-protocol-2.0.xsd"),
                           ("sp_metadata", "saml-schema-metadata-2.0.xsd")):
        result[kind] = etree.XMLSchema(etree.parse(str(DIRECTORY / filename), parser))
    return result


def validate(schemas, kind, root):
    """Return an exact schema verdict; do not let the schema parse fetch anything."""
    return schemas[kind].validate(root)
