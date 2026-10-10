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

"""Mint the fixed-key offline scripted-IdP corpus with a deliberate, explicit command.

Run inside the pinned container with /run/keys mounted read-only and /out writable.
The output XML is written exactly as returned by mint_response; no second serialization.
"""

import argparse
import hashlib
import itertools
import json
import pathlib

from scripted_idp import versions
from scripted_idp.mint import mint_response


CASES = (
    ("response-rsa256", "response", "rsa-sha256", "xmlsec", False, False),
    ("both-rsa384", "both", "rsa-sha384", "xmlsec", False, False),
    ("assertion-rsa512-encrypted", "assertion", "rsa-sha512", "xmlsec", True, False),
    ("assertion-ec256-encrypted-id", "assertion", "ecdsa-sha256", "xmlsec", False, True),
    ("assertion-ec384", "assertion", "ecdsa-sha384", "xmlsec", False, False),
    ("assertion-ec521", "assertion", "ecdsa-sha512", "xmlsec", False, False),
    ("assertion-signxml", "assertion", "rsa-sha256", "signxml", False, False),
    ("assertion-rsa-sha1", "assertion", "rsa-sha1", "xmlsec", False, False),
    ("unsigned", "none", "rsa-sha256", "xmlsec", False, False),
    ("unsigned-encrypted", "none", "rsa-sha256", "xmlsec", True, False),
)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", required=True, type=pathlib.Path)
    parser.add_argument("--keys", type=pathlib.Path, default=pathlib.Path("/run/keys"))
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)
    if not args.keys.is_dir():
        raise SystemExit("test key directory is missing")
    manifest = {"versions": versions.versions(), "cases": {}}
    for index, (name, placement, algorithm, engine, assertion, name_id) in enumerate(CASES, 1):
        spec = {
            "clock": {"now": "2026-09-01T00:00:00Z"},
            "sp": {"entity_id": "https://sp.test/Selftest", "acs_url": "https://sp.test/acs"},
            "subject": {"name_id": "minted-user"},
            "signing": {"placement": placement, "algorithm": algorithm, "engine": engine},
            "encryption": {"assertion": assertion, "name_id": name_id},
            "ids": {"response": f"_mint_response_{index}",
                    "assertion": f"_mint_assertion_{index}"},
        }
        result = mint_response(spec, args.keys)
        encoded = result["xml"].encode("utf-8")
        (args.out / f"{name}.xml").write_bytes(encoded)
        manifest["cases"][name] = {"spec": spec, "sha256": hashlib.sha256(encoded).hexdigest()}
    for index, (data, transport) in enumerate(itertools.product(
            ("aes128-gcm", "aes192-gcm", "aes256-gcm"),
            ("rsa-oaep-sha256-mgf1sha256", "rsa-oaep-mgf1p")), len(CASES) + 1):
        name = f"encrypted-{data}-{transport}"
        spec = {
            "clock": {"now": "2026-09-01T00:00:00Z"},
            "sp": {"entity_id": "https://sp.test/Selftest", "acs_url": "https://sp.test/acs"},
            "subject": {"name_id": "minted-user"},
            "signing": {"placement": "both", "algorithm": "rsa-sha256", "engine": "xmlsec"},
            "encryption": {"assertion": True, "data_algorithm": data,
                           "key_transport": transport},
            "ids": {"response": f"_mint_response_{index}",
                    "assertion": f"_mint_assertion_{index}"},
        }
        result = mint_response(spec, args.keys)
        encoded = result["xml"].encode("utf-8")
        (args.out / f"{name}.xml").write_bytes(encoded)
        manifest["cases"][name] = {"spec": spec, "sha256": hashlib.sha256(encoded).hexdigest()}
    for index, (data, placement) in enumerate((
            ("aes128-cbc", "response"), ("aes192-cbc", "response"),
            ("aes256-cbc", "response"), ("aes128-cbc", "assertion")), 17):
        name = f"encrypted-{data}-{placement}"
        spec = {
            "clock": {"now": "2026-09-01T00:00:00Z"},
            "sp": {"entity_id": "https://sp.test/Selftest", "acs_url": "https://sp.test/acs"},
            "subject": {"name_id": "minted-user"},
            "signing": {"placement": placement, "algorithm": "rsa-sha256"},
            "encryption": {"assertion": True, "data_algorithm": data,
                           "key_transport": "rsa-oaep-mgf1p"},
            "ids": {"response": f"_mint_response_{index}",
                    "assertion": f"_mint_assertion_{index}"},
        }
        result = mint_response(spec, args.keys)
        encoded = result["xml"].encode("utf-8")
        (args.out / f"{name}.xml").write_bytes(encoded)
        manifest["cases"][name] = {"spec": spec, "sha256": hashlib.sha256(encoded).hexdigest()}
    for index, (placement, algorithm, digest) in enumerate(itertools.product(
            ("response", "assertion", "both"),
            ("rsa-sha256", "rsa-sha384", "rsa-sha512", "ecdsa-sha256",
             "ecdsa-sha384", "ecdsa-sha512"),
            ("sha256", "sha384", "sha512")), 21):
        name = f"matrix-{placement}-{algorithm}-{digest}"
        spec = {
            "clock": {"now": "2026-09-01T00:00:00Z"},
            "sp": {"entity_id": "https://sp.test/Selftest", "acs_url": "https://sp.test/acs"},
            "subject": {"name_id": "minted-user"},
            "signing": {"placement": placement, "algorithm": algorithm,
                        "digest": digest, "engine": "xmlsec"},
            "ids": {"response": f"_mint_response_{index}",
                    "assertion": f"_mint_assertion_{index}"},
        }
        result = mint_response(spec, args.keys)
        encoded = result["xml"].encode("utf-8")
        (args.out / f"{name}.xml").write_bytes(encoded)
        manifest["cases"][name] = {"spec": spec, "sha256": hashlib.sha256(encoded).hexdigest()}
    name = "digest-rsa256-sha1"
    spec = {
        "clock": {"now": "2026-09-01T00:00:00Z"},
        "sp": {"entity_id": "https://sp.test/Selftest", "acs_url": "https://sp.test/acs"},
        "subject": {"name_id": "minted-user"},
        "signing": {"placement": "response", "algorithm": "rsa-sha256",
                    "digest": "sha1", "engine": "xmlsec"},
        "ids": {"response": "_mint_response_75", "assertion": "_mint_assertion_75"},
    }
    result = mint_response(spec, args.keys)
    encoded = result["xml"].encode("utf-8")
    (args.out / f"{name}.xml").write_bytes(encoded)
    manifest["cases"][name] = {"spec": spec, "sha256": hashlib.sha256(encoded).hexdigest()}
    for index, (data, transport, placement) in enumerate(itertools.product(
            ("aes128-gcm", "aes192-gcm", "aes256-gcm"),
            ("rsa-oaep-mgf1p-sha1", "rsa-oaep-mgf1p-sha256",
             "rsa-oaep-sha1-mgf1sha1", "rsa-oaep-sha256-mgf1sha1"),
            ("response", "assertion", "both")), 76):
        name = f"oaep-{data}-{transport}-{placement}"
        spec = {
            "clock": {"now": "2026-09-01T00:00:00Z"},
            "sp": {"entity_id": "https://sp.test/Selftest", "acs_url": "https://sp.test/acs"},
            "subject": {"name_id": "minted-user"},
            "signing": {"placement": placement, "algorithm": "rsa-sha256", "engine": "xmlsec"},
            "encryption": {"assertion": True, "data_algorithm": data,
                           "key_transport": transport},
            "ids": {"response": f"_mint_response_{index}",
                    "assertion": f"_mint_assertion_{index}"},
        }
        result = mint_response(spec, args.keys)
        encoded = result["xml"].encode("utf-8")
        (args.out / f"{name}.xml").write_bytes(encoded)
        manifest["cases"][name] = {"spec": spec, "sha256": hashlib.sha256(encoded).hexdigest()}
    for index, (name, encrypted_assertion, key_placement, extra) in enumerate((
            ("key-sibling-retrieval", True, "sibling-retrieval", 0),
            ("key-sibling-implicit", True, "sibling-implicit", 0),
            ("key-sibling-implicit-multi", True, "sibling-implicit", 1),
            ("encrypted-id-sibling-retrieval", False, "sibling-retrieval", 0),
            ("encrypted-id-sibling-implicit", False, "sibling-implicit", 0)), 112):
        spec = {
            "clock": {"now": "2026-09-01T00:00:00Z"},
            "sp": {"entity_id": "https://sp.test/Selftest", "acs_url": "https://sp.test/acs"},
            "subject": {"name_id": "minted-user"},
            "signing": {"placement": "both" if encrypted_assertion else "assertion",
                        "algorithm": "rsa-sha256", "engine": "xmlsec"},
            "encryption": {"assertion": encrypted_assertion,
                           "name_id": not encrypted_assertion,
                           "data_algorithm": "aes256-gcm",
                           "key_transport": "rsa-oaep-sha256-mgf1sha256",
                           "key_placement": key_placement,
                           "extra_encrypted_keys": extra},
            "ids": {"response": f"_mint_response_{index}",
                    "assertion": f"_mint_assertion_{index}"},
        }
        result = mint_response(spec, args.keys)
        encoded = result["xml"].encode("utf-8")
        (args.out / f"{name}.xml").write_bytes(encoded)
        manifest["cases"][name] = {"spec": spec, "sha256": hashlib.sha256(encoded).hexdigest()}
    for index, (name, transport, variant) in enumerate((
            ("negative-rsa-1_5", "rsa-1_5", "none"),
            ("negative-mgf-under-mgf1p", "rsa-oaep-mgf1p", "mgf-under-mgf1p"),
            ("negative-nonempty-oaep-params", "rsa-oaep-sha256-mgf1sha256", "nonempty-oaep-params"),
            ("negative-cipher-bit-flip", "rsa-oaep-sha256-mgf1sha256", "cipher-bit-flip")), 117):
        spec = {
            "clock": {"now": "2026-09-01T00:00:00Z"},
            "sp": {"entity_id": "https://sp.test/Selftest", "acs_url": "https://sp.test/acs"},
            "subject": {"name_id": "minted-user"},
            "signing": {"placement": "both", "algorithm": "rsa-sha256", "engine": "xmlsec"},
            "encryption": {"assertion": True, "data_algorithm": "aes256-gcm",
                           "key_transport": transport, "variant": variant},
            "ids": {"response": f"_mint_response_{index}",
                    "assertion": f"_mint_assertion_{index}"},
        }
        result = mint_response(spec, args.keys)
        encoded = result["xml"].encode("utf-8")
        (args.out / f"{name}.xml").write_bytes(encoded)
        manifest["cases"][name] = {"spec": spec, "sha256": hashlib.sha256(encoded).hexdigest()}
    (args.out / "capture.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")


if __name__ == "__main__":
    main()
