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

"""Library versions reported by /health and recorded by the selftest."""

import hashlib
import importlib.metadata
import pathlib
import platform
import re
import ssl

import lxml.etree
import xmlsec
from cryptography.hazmat.backends.openssl import backend as cryptography_backend

_APP_ROOT = pathlib.Path(__file__).resolve().parent

# The xmlsec wheel links OpenSSL statically and exports none of its symbols, so
# its version is read from the default provider's version string in the binary.
_PROVIDER_VERSION = re.compile(rb"OpenSSL Default Provider\x00+(\d+\.\d+\.\d+)\x00")


def _dotted(version):
    return ".".join(str(part) for part in version)


def _xmlsec_openssl_version():
    match = _PROVIDER_VERSION.search(pathlib.Path(xmlsec.__file__).read_bytes())
    return match.group(1).decode("ascii") if match else "unknown"


def _content_sha256():
    """SHA-256 over the app sources and the lock file (not the base image)."""
    digest = hashlib.sha256()
    files = sorted(_APP_ROOT.glob("*.py")) + [_APP_ROOT.parent / "requirements.txt"]
    for path in files:
        if path.is_file():
            digest.update(path.name.encode("utf-8") + b"\x00" + path.read_bytes() + b"\x00")
    return digest.hexdigest()


def libxml2_pairing():
    """Returns (lxml's libxml2, xmlsec's libxml2) as runtime and compiled version strings."""
    lxml_side = {"runtime": _dotted(lxml.etree.LIBXML_VERSION), "compiled": _dotted(lxml.etree.LIBXML_COMPILED_VERSION)}
    xmlsec_side = {"runtime": _dotted(xmlsec.get_libxml_version()), "compiled": _dotted(xmlsec.get_libxml_compiled_version())}
    return lxml_side, xmlsec_side


def check_libxml2_pairing():
    """Fails unless lxml and xmlsec carry the same libxml2, down to the patch level.

    python-xmlsec's own import-time check compares only major.minor.
    """
    lxml_side, xmlsec_side = libxml2_pairing()
    versions = set(lxml_side.values()) | set(xmlsec_side.values())
    if len(versions) != 1:
        raise RuntimeError(f"libxml2 mismatch: lxml {lxml_side}, xmlsec {xmlsec_side}")
    return versions.pop()


def versions():
    lxml_side, xmlsec_side = libxml2_pairing()
    try:
        alpine = pathlib.Path("/etc/alpine-release").read_text(encoding="ascii").strip()
    except OSError:
        alpine = None
    return {
        "python": platform.python_version(),
        "alpine": alpine,
        "machine": platform.machine(),
        "packages": {
            name: importlib.metadata.version(name)
            for name in ("xmlsec", "lxml", "signxml", "cryptography", "cffi", "pycparser", "certifi")
        },
        "libxml2": {"lxml": lxml_side, "xmlsec": xmlsec_side},
        "libxslt": {"lxml": _dotted(lxml.etree.LIBXSLT_VERSION)},
        "libxmlsec1": _dotted(xmlsec.get_libxmlsec_version()),
        "openssl": {
            "python-ssl": ssl.OPENSSL_VERSION,
            "cryptography": cryptography_backend.openssl_version_text(),
            "xmlsec": _xmlsec_openssl_version(),
        },
        "contentSha256": _content_sha256(),
    }
