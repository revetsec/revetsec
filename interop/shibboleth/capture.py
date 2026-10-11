#!/usr/bin/env python3
"""Capture GCM/CBC SAML responses from a pinned Shibboleth IdP 5.2.3 image.

Run from the repository root after compiling the current core classes. The output
contains only public test certificates, generated requests, pending handles,
metadata and IdP responses. The dummy password and browser cookies stay in a
temporary directory that is removed when this process exits.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
from html.parser import HTMLParser
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import time
from urllib.parse import parse_qs, urlencode, urljoin, urlparse
import xml.etree.ElementTree as ET
import zlib


ROOT = Path(__file__).resolve().parents[2]
IMAGE = "i2incommon/shib-idp:5.2.3_20260824_rocky10_multiarch"
DIGEST = "sha256:bb6bbf1cfe935d20cb2d312e121fc6540cd367d18eee40ea263592c873efc7e5"
IDP_HOST = "idp.example.org"
IDP_ENTITY = "https://idp.example.org/idp/shibboleth"
USER = "revetsec-capture"
PASSWORD = "revetsec-capture-pass"  # Public, disposable test credential only.


class FirstForm(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.action: str | None = None
        self.fields: dict[str, str] = {}
        self.in_form = False
        self.finished = False

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = dict(attrs)
        if tag == "form" and self.action is None and not self.finished:
            self.action = values.get("action")
            self.in_form = True
        elif tag == "input" and self.in_form and values.get("name"):
            self.fields[values["name"]] = values.get("value") or ""

    def handle_endtag(self, tag: str) -> None:
        if tag == "form" and self.in_form:
            self.in_form = False
            self.finished = True


def checked(*arguments: str) -> str:
    return subprocess.run(arguments, check=True, capture_output=True, text=True).stdout


def image_file(path: str) -> bytes:
    return subprocess.run(("docker", "run", "--rm", "--network", "none",
                           "--entrypoint", "/bin/cat", IMAGE, path),
                          check=True, capture_output=True).stdout


def verify_image() -> None:
    digests = json.loads(checked("docker", "image", "inspect", IMAGE,
                                 "--format", "{{json .RepoDigests}}"))
    if "i2incommon/shib-idp@" + DIGEST not in digests:
        raise RuntimeError("Shibboleth image manifest digest differs from the pinned capture")


def compile_generator(classes: Path) -> None:
    java_home = os.environ.get("JAVA_HOME")
    if not java_home:
        raise RuntimeError("JAVA_HOME must select JDK 17")
    jspecify = Path.home() / ".m2/repository/org/jspecify/jspecify/1.0.1/jspecify-1.0.1.jar"
    if not (ROOT / "target/classes").is_dir() or not jspecify.is_file():
        raise RuntimeError("Compile the current core with Maven before capturing")
    checked(str(Path(java_home) / "bin/javac"), "-cp",
            os.pathsep.join((str(ROOT / "target/classes"), str(jspecify))),
            "-d", str(classes), str(ROOT / "interop/shibboleth/CaptureAuthnRequest.java"))


def generate_request(classes: Path, directory: Path, idp_cert: Path) -> None:
    java_home = os.environ["JAVA_HOME"]
    checked(str(Path(java_home) / "bin/java"), "-cp",
            os.pathsep.join((str(ROOT / "target/classes"), str(classes))),
            "com.revetsec.saml.CaptureAuthnRequest", str(directory), str(idp_cert))


def config_files(directory: Path, mode: str, idp_cert: bytes) -> None:
    directory.mkdir()
    (directory / "idp-signing.crt").write_bytes(idp_cert)
    provider = image_file("/opt/shibboleth-idp/conf/metadata-providers.xml").decode()
    ending = provider.rfind("</MetadataProvider>")
    if ending < 0:
        raise RuntimeError("Shibboleth metadata configuration changed")
    provider = (provider[:ending] +
                '    <MetadataProvider id="RevetsecCapture" xsi:type="FilesystemMetadataProvider" '
                'metadataFile="%{idp.home}/metadata/revetsec-sp.xml"/>\n' + provider[ending:])
    (directory / "metadata-providers.xml").write_text(provider)

    password = image_file("/opt/shibboleth-idp/conf/authn/password-authn-config.xml").decode()
    old = '<ref bean="shibboleth.LDAPValidator" />'
    if password.count(old) != 1:
        raise RuntimeError("Shibboleth password flow changed")
    password = password.replace(old, '<bean parent="shibboleth.HTPasswdValidator" '
                                'p:resource="%{idp.home}/credentials/revetsec-capture.htpasswd" />')
    (directory / "password-authn-config.xml").write_text(password)
    digest = base64.b64encode(hashlib.sha1(PASSWORD.encode()).digest()).decode()
    (directory / "revetsec-capture.htpasswd").write_text(f"{USER}:{{SHA}}{digest}\n")

    if mode == "cbc":
        properties = image_file("/opt/shibboleth-idp/conf/idp.properties").decode()
        old = "idp.encryption.config=shibboleth.EncryptionConfiguration.GCM"
        if properties.count(old) != 1:
            raise RuntimeError("Shibboleth encryption configuration changed")
        (directory / "idp.properties").write_text(properties.replace(
            old, "idp.encryption.config=shibboleth.EncryptionConfiguration.CBC"))


def metadata_for_mode(directory: Path, mode: str) -> None:
    if mode == "cbc":
        generated = (directory / "sp-metadata.xml").read_text()
        adapted, count = re.subn(r'<md:EncryptionMethod Algorithm="[^"]+"/>', "", generated)
        if count != 4:
            raise RuntimeError("Generated SP encryption algorithm hints changed")
        (directory / "sp-metadata.xml").write_text(adapted)


def start_idp(directory: Path, mode: str) -> tuple[str, int]:
    name = f"revetsec-shib-{mode}-{os.getpid()}"
    command = ["docker", "run", "--rm", "-d", "--name", name,
               "-p", "127.0.0.1::443"]
    mounts = (
        ("metadata-providers.xml", "/opt/shibboleth-idp/conf/metadata-providers.xml"),
        ("password-authn-config.xml", "/opt/shibboleth-idp/conf/authn/password-authn-config.xml"),
        ("revetsec-capture.htpasswd", "/opt/shibboleth-idp/credentials/revetsec-capture.htpasswd"),
        ("sp-metadata.xml", "/opt/shibboleth-idp/metadata/revetsec-sp.xml"),
    )
    if mode == "cbc":
        mounts += (("idp.properties", "/opt/shibboleth-idp/conf/idp.properties"),)
    for source, target in mounts:
        command.extend(("-v", f"{directory / source}:{target}:ro"))
    checked(*command, IMAGE)
    try:
        published = checked("docker", "port", name, "443/tcp").strip()
        if not published.startswith("127.0.0.1:"):
            raise RuntimeError("Shibboleth port was not published on loopback")
        return name, int(published.rsplit(":", 1)[1])
    except Exception:
        subprocess.run(("docker", "stop", name), capture_output=True, text=True)
        raise


def request(url: str, port: int, cookies: Path, headers: Path,
            page: Path, fields: dict[str, str] | None = None) -> int:
    parsed = urlparse(url)
    if parsed.scheme != "https" or parsed.hostname != IDP_HOST or parsed.port not in (None, 443):
        raise RuntimeError("Shibboleth capture attempted a non-local IdP request")
    command = ["curl", "-ksS", "--noproxy", "*",
               "--connect-to", f"{IDP_HOST}:443:127.0.0.1:{port}",
               "--max-time", "20", "-D", str(headers), "-o", str(page),
               "-b", str(cookies), "-c", str(cookies), "-w", "%{http_code}"]
    if fields is not None:
        command.extend(("--data", urlencode(fields)))
    result = subprocess.run((*command, url), check=True, capture_output=True, text=True)
    return int(result.stdout)


def wait_for_idp(directory: Path, port: int) -> None:
    deadline = time.monotonic() + 120
    while time.monotonic() < deadline:
        try:
            status = request(IDP_ENTITY, port, directory / "health-cookies.txt",
                             directory / "health-headers.txt", directory / "health-body.xml")
            if status == 200:
                return
        except (subprocess.CalledProcessError, ValueError):
            pass
        time.sleep(1)
    raise RuntimeError("Shibboleth did not serve IdP metadata within 120 seconds")


def capture(directory: Path, mode: str, port: int) -> bytes:
    url = (directory / "redirect-url.txt").read_text()
    pending = (directory / "pending.txt").read_text().splitlines()
    if len(pending) != 4:
        raise RuntimeError("Revetsec pending state changed")
    cookies = directory / "browser-cookies.txt"
    fields: dict[str, str] | None = None
    for step in range(12):
        headers = directory / f"step-{step}-headers.txt"
        page = directory / f"step-{step}-body.html"
        status = request(url, port, cookies, headers, page, fields)
        if status == 302:
            location = next((line.split(":", 1)[1].strip() for line in headers.read_text().splitlines()
                             if line.lower().startswith("location:")), None)
            if location is None:
                raise RuntimeError(f"IdP redirect lacks Location at step {step}")
            url, fields = urljoin(url, location), None
            continue
        if status != 200:
            raise RuntimeError(f"IdP returned HTTP {status} at step {step}")
        form = FirstForm()
        form.feed(page.read_text(errors="replace"))
        if "SAMLResponse" in form.fields:
            if form.fields.get("RelayState") != pending[1]:
                raise RuntimeError("IdP returned a different RelayState")
            xml = base64.b64decode(form.fields["SAMLResponse"], validate=True)
            root = ET.fromstring(xml)
            ds = "{http://www.w3.org/2000/09/xmldsig#}"
            xenc = "{http://www.w3.org/2001/04/xmlenc#}"
            if (root.attrib.get("InResponseTo") != pending[0]
                    or root.findtext("{urn:oasis:names:tc:SAML:2.0:assertion}Issuer") != IDP_ENTITY
                    or len(root.findall(ds + "Signature")) != 1):
                raise RuntimeError("IdP response correlation, issuer or Response signature changed")
            expected = ("http://www.w3.org/2009/xmlenc11#aes128-gcm" if mode == "gcm"
                        else "http://www.w3.org/2001/04/xmlenc#aes128-cbc")
            methods = [element.attrib.get("Algorithm")
                       for element in root.findall(".//" + xenc + "EncryptionMethod")]
            if expected not in methods:
                raise RuntimeError(f"IdP {mode} response selected unexpected encryption: {methods}")
            return xml
        if form.action is None:
            raise RuntimeError(f"IdP page at step {step} has no form")
        if "j_username" in form.fields:
            form.fields.update(j_username=USER, j_password=PASSWORD, _eventId_proceed="Login")
        elif "shib_idp_ls_supported" in form.fields:
            form.fields["shib_idp_ls_supported"] = "false"
        else:
            raise RuntimeError(f"Unexpected IdP form at step {step}")
        url, fields = urljoin(url, form.action), form.fields
    raise RuntimeError("IdP flow exceeded 12 steps")


def save(output: Path, directory: Path, mode: str, response: bytes) -> None:
    url = (directory / "redirect-url.txt").read_text()
    encoded = parse_qs(urlparse(url).query)["SAMLRequest"][0]
    request_xml = zlib.decompress(base64.b64decode(encoded), wbits=-15)
    (output / f"{mode}-request.xml").write_bytes(request_xml)
    (output / f"{mode}-redirect-url.txt").write_text(url)
    (output / f"{mode}-response.xml").write_bytes(response)
    shutil.copyfile(directory / "pending.txt", output / f"{mode}-pending.txt")
    shutil.copyfile(directory / "sp-metadata.xml", output / f"{mode}-sp-metadata.xml")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True,
                        help="new empty directory for public capture artifacts")
    arguments = parser.parse_args()
    output = arguments.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    if any(output.iterdir()):
        raise RuntimeError("capture output directory must be empty")
    verify_image()
    temp_parent = Path("/private/tmp") if Path("/private/tmp").is_dir() else Path("/tmp")
    with tempfile.TemporaryDirectory(prefix="revetsec-shib-", dir=temp_parent) as name:
        temporary = Path(name)
        classes = temporary / "classes"
        classes.mkdir()
        compile_generator(classes)
        idp_cert = image_file("/opt/shibboleth-idp/credentials/idp-signing.crt")
        (output / "idp-signing.crt").write_bytes(idp_cert)
        for mode in ("gcm", "cbc"):
            directory = temporary / mode
            config_files(directory, mode, idp_cert)
            generate_request(classes, directory, directory / "idp-signing.crt")
            metadata_for_mode(directory, mode)
            container = None
            try:
                container, port = start_idp(directory, mode)
                wait_for_idp(directory, port)
                response = capture(directory, mode, port)
                save(output, directory, mode, response)
            except Exception as exception:
                if container is not None:
                    logs = subprocess.run(("docker", "logs", "--tail", "25", container),
                                          capture_output=True, text=True)
                    raise RuntimeError(f"{mode} capture failed; IdP tail:\n{logs.stdout[-4000:]}") from exception
                raise
            finally:
                if container is not None:
                    subprocess.run(("docker", "stop", container), capture_output=True, text=True)
            print(f"{mode}: captured {len(response)} bytes from {IMAGE}")
    manifest = {"image": IMAGE, "digest": DIGEST,
                "files": {path.name: hashlib.sha256(path.read_bytes()).hexdigest()
                          for path in sorted(output.iterdir()) if path.is_file()}}
    (output / "capture-manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")


if __name__ == "__main__":
    main()
