#!/usr/bin/env python3
"""Capture signed and assertion-only AES-CBC responses from SimpleSAMLphp 2.5.0.

Run from the repository root with JAVA_HOME set to JDK 17 after test-compile.
All HTTP traffic is mapped to a loopback-only Docker port. Disposable login
state and the test-only IdP private key stay in a removed temporary directory.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
from html.parser import HTMLParser
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import time
from urllib.parse import parse_qs, urlencode, urljoin, urlparse
import xml.etree.ElementTree as ET
import zlib


ROOT = Path(__file__).resolve().parents[2]
IMAGE = "cirrusid/simplesamlphp:v2.5.0"
DIGEST = "sha256:9ae050473c68ce13c5451839cb64257eaa17be3a4d2c9a3f87996bbe0cebb0aa"
HOST = "ssp.example.test"
IDP_ENTITY = "https://ssp.example.test/idp"
SSO = "https://ssp.example.test/simplesaml/module.php/saml/idp/singleSignOnService"
SP_ENTITY = "https://sp.test/SimpleCapture"
USER = "student"
PASSWORD = "studentpass"  # Public, disposable test credential only.
KEYS = ROOT / "src/test/resources/fixtures/keys"


class Forms(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.forms: list[dict[str, object]] = []
        self.current: dict[str, object] | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = dict(attrs)
        if tag == "form":
            self.current = {"action": values.get("action"), "fields": {}}
            self.forms.append(self.current)
        elif tag == "input" and self.current is not None and values.get("name"):
            fields = self.current["fields"]
            assert isinstance(fields, dict)
            fields[values["name"]] = values.get("value") or ""

    def handle_endtag(self, tag: str) -> None:
        if tag == "form":
            self.current = None


def checked(*args: str) -> str:
    return subprocess.run(args, check=True, capture_output=True, text=True).stdout


def verify_image() -> None:
    digests = json.loads(checked("docker", "image", "inspect", IMAGE,
                                 "--format", "{{json .RepoDigests}}"))
    if "cirrusid/simplesamlphp@" + DIGEST not in digests:
        raise RuntimeError("SimpleSAMLphp image manifest digest differs from the pinned capture")


def certificate_body(path: Path) -> str:
    lines = path.read_text().splitlines()
    if lines[0] != "-----BEGIN CERTIFICATE-----" or lines[-1] != "-----END CERTIFICATE-----":
        raise RuntimeError("test certificate PEM format changed")
    return "".join(lines[1:-1])


def write_configuration(directory: Path) -> None:
    certs = directory / "cert"
    certs.mkdir()
    for source, name in (("idp-signing-rsa-2048-key.pem", "server.pem"),
                         ("idp-signing-rsa-2048-cert.pem", "server.crt"),
                         ("sp-signing-rsa-2048-cert.pem", "sp-signing.crt"),
                         ("sp-encryption-rsa-2048-cert.pem", "sp-encryption.crt")):
        shutil.copyfile(KEYS / source, certs / name)
    (directory / "config-override.php").write_text(
        "<?php\n$config['production'] = false;\n"
        f"$config['baseurlpath'] = 'https://{HOST}/simplesaml/';\n"
        "$config['enable.saml20-idp'] = true;\n"
        "$config['module.enable']['exampleauth'] = true;\n")
    (directory / "authsources.php").write_text(
        "<?php\n$config = ['admin' => ['core:AdminPassword'], "
        "'example-userpass' => ['exampleauth:UserPass', "
        f"'users' => ['{USER}:{PASSWORD}' => ['uid' => ['{USER}']]]]];\n")
    (directory / "saml20-idp-hosted.php").write_text(
        f"<?php\n$metadata['{IDP_ENTITY}'] = ['host' => '__DEFAULT__', "
        "'privatekey' => 'server.pem', 'certificate' => 'server.crt', "
        "'auth' => 'example-userpass'];\n")
    signing = certificate_body(certs / "sp-signing.crt")
    encryption = certificate_body(certs / "sp-encryption.crt")
    (directory / "saml20-sp-remote.php").write_text(
        f"<?php\n$metadata['{SP_ENTITY}'] = ['entityid' => '{SP_ENTITY}', "
        "'AssertionConsumerService' => [['Binding' => "
        "'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST', "
        "'Location' => 'https://sp.example.test/acs', 'index' => 0, "
        "'isDefault' => true]], "
        "'NameIDFormat' => 'urn:oasis:names:tc:SAML:2.0:nameid-format:transient', "
        "'keys' => ["
        "['type' => 'X509Certificate', 'signing' => true, 'encryption' => false, "
        f"'X509Certificate' => '{signing}'], "
        "['type' => 'X509Certificate', 'signing' => false, 'encryption' => true, "
        f"'X509Certificate' => '{encryption}']], "
        "'saml20.sign.response' => true, 'saml20.sign.assertion' => false, "
        "'assertion.encryption' => true, 'validate.authnrequest' => true, "
        "'redirect.validate' => true];\n")


def signing_mode(directory: Path, response_signed: bool) -> None:
    path = directory / "saml20-sp-remote.php"
    text = path.read_text()
    signed = "'saml20.sign.response' => true, 'saml20.sign.assertion' => false"
    assertion = "'saml20.sign.response' => false, 'saml20.sign.assertion' => true"
    if text.count(signed if response_signed else assertion) == 1:
        return
    old, new = (assertion, signed) if response_signed else (signed, assertion)
    if text.count(old) != 1:
        raise RuntimeError("SimpleSAMLphp signing configuration changed")
    path.write_text(text.replace(old, new))


def start_idp(directory: Path) -> tuple[str, int]:
    name = f"revetsec-simplesaml-{os.getpid()}"
    command = ["docker", "run", "--rm", "-d", "--name", name,
               "-p", "127.0.0.1::443", "-e", "SSP_ENABLE_IDP=true",
               "-e", "SSP_SECRET_SALT=revetsec-test-salt",
               "-e", "SSP_ADMIN_PASSWORD=revetsec-test-admin"]
    mounts = (("cert", "/var/simplesamlphp/cert"),
              ("config-override.php", "/var/simplesamlphp/config/config-override.php"),
              ("authsources.php", "/var/simplesamlphp/config/authsources.php"),
              ("saml20-idp-hosted.php", "/var/simplesamlphp/metadata/saml20-idp-hosted.php"),
              ("saml20-sp-remote.php", "/var/simplesamlphp/metadata/saml20-sp-remote.php"))
    for source, target in mounts:
        command.extend(("--mount", f"type=bind,source={directory / source},target={target},readonly"))
    checked(*command, IMAGE)
    try:
        published = checked("docker", "port", name, "443/tcp").strip()
        if not published.startswith("127.0.0.1:"):
            raise RuntimeError("SimpleSAMLphp port was not published on loopback")
        return name, int(published.rsplit(":", 1)[1])
    except Exception:
        subprocess.run(("docker", "stop", name), capture_output=True, text=True)
        raise


def request(url: str, port: int, cookies: Path, headers: Path, page: Path,
            fields: dict[str, str] | None = None) -> int:
    parsed = urlparse(url)
    if parsed.scheme != "https" or parsed.hostname != HOST or parsed.port not in (None, 443):
        raise RuntimeError("SimpleSAMLphp capture attempted a non-local IdP request")
    command = ["curl", "-ksS", "--noproxy", "*", "--max-time", "20",
               "--connect-to", f"{HOST}:443:127.0.0.1:{port}",
               "-D", str(headers), "-o", str(page), "-b", str(cookies),
               "-c", str(cookies), "-w", "%{http_code}"]
    if fields is not None:
        command.extend(("--data", urlencode(fields)))
    return int(checked(*command, url))


def wait_for_idp(directory: Path, port: int) -> None:
    deadline = time.monotonic() + 90
    while time.monotonic() < deadline:
        try:
            status = request(f"https://{HOST}/simplesaml/saml2/idp/metadata.php", port,
                             directory / "health-cookies.txt", directory / "health-headers.txt",
                             directory / "health-metadata.xml")
            if status == 200 and IDP_ENTITY in (directory / "health-metadata.xml").read_text():
                return
        except (subprocess.CalledProcessError, ValueError):
            pass
        time.sleep(1)
    raise RuntimeError("SimpleSAMLphp did not serve IdP metadata within 90 seconds")


def compile_generator(classes: Path) -> None:
    java_home = os.environ.get("JAVA_HOME")
    if not java_home:
        raise RuntimeError("JAVA_HOME must select JDK 17")
    jspecify = Path.home() / ".m2/repository/org/jspecify/jspecify/1.0.1/jspecify-1.0.1.jar"
    if not (ROOT / "target/classes").is_dir() or not jspecify.is_file():
        raise RuntimeError("Compile current core classes with Maven before capturing")
    checked(str(Path(java_home) / "bin/javac"), "-cp",
            os.pathsep.join((str(ROOT / "target/classes"), str(jspecify))),
            "-d", str(classes), str(ROOT / "interop/shibboleth/CaptureAuthnRequest.java"))


def generate_request(classes: Path, directory: Path) -> None:
    java_home = os.environ["JAVA_HOME"]
    directory.mkdir()
    checked(str(Path(java_home) / "bin/java"), "-cp",
            os.pathsep.join((str(ROOT / "target/classes"), str(classes))),
            "com.revetsec.saml.CaptureAuthnRequest", str(directory),
            str(KEYS / "idp-signing-rsa-2048-cert.pem"), IDP_ENTITY, SSO,
            SP_ENTITY, "simplesaml-capture")


def capture(directory: Path, port: int, label: str, response_signed: bool) -> bytes:
    url = (directory / "redirect-url.txt").read_text()
    pending = (directory / "pending.txt").read_text().splitlines()
    if len(pending) != 4:
        raise RuntimeError("Revetsec pending state changed")
    cookies = directory / "browser-cookies.txt"
    fields: dict[str, str] | None = None
    for step in range(10):
        headers = directory / f"step-{step}-headers.txt"
        page = directory / f"step-{step}-body.html"
        status = request(url, port, cookies, headers, page, fields)
        if status in (302, 303):
            location = next((line.split(":", 1)[1].strip() for line in headers.read_text().splitlines()
                             if line.lower().startswith("location:")), None)
            if location is None:
                raise RuntimeError(f"IdP redirect lacks Location at step {step}")
            url, fields = urljoin(url, location), None
            continue
        if status != 200:
            raise RuntimeError(f"IdP returned HTTP {status} at step {step}")
        forms = Forms()
        forms.feed(page.read_text(errors="replace"))
        for form in forms.forms:
            values = form["fields"]
            assert isinstance(values, dict)
            if "SAMLResponse" not in values:
                continue
            if values.get("RelayState") != pending[1]:
                raise RuntimeError("IdP returned a different RelayState")
            xml = base64.b64decode(values["SAMLResponse"], validate=True)
            root = ET.fromstring(xml)
            saml = "{urn:oasis:names:tc:SAML:2.0:assertion}"
            ds = "{http://www.w3.org/2000/09/xmldsig#}"
            xenc = "{http://www.w3.org/2001/04/xmlenc#}"
            if (root.attrib.get("InResponseTo") != pending[0]
                    or root.findtext(saml + "Issuer") != IDP_ENTITY
                    or len(root.findall(ds + "Signature")) != int(response_signed)):
                raise RuntimeError("IdP Response binding, issuer or signature placement changed")
            methods = [element.attrib.get("Algorithm")
                       for element in root.findall(".//" + xenc + "EncryptionMethod")]
            if ("http://www.w3.org/2001/04/xmlenc#aes128-cbc" not in methods
                    or "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p" not in methods):
                raise RuntimeError(f"IdP {label} selected unexpected encryption: {methods}")
            return xml
        login = next((form for form in forms.forms
                      if "username" in form["fields"] and "password" in form["fields"]), None)
        if login is None or not isinstance(login["action"], str):
            raise RuntimeError(f"IdP page at step {step} has no test login form")
        fields = dict(login["fields"])
        fields.update(username=USER, password=PASSWORD)
        url = urljoin(url, login["action"])
    raise RuntimeError("IdP flow exceeded 10 steps")


def assert_signed_request_validation(directory: Path, port: int) -> None:
    url = (directory / "redirect-url.txt").read_text()
    relay = (directory / "pending.txt").read_text().splitlines()[1]
    bad = url.replace("RelayState=" + relay, "RelayState=X" + relay[1:], 1)
    if bad == url:
        raise RuntimeError("signed Redirect URL lacked the pending RelayState")
    status = request(bad, port, directory / "tampered-cookies.txt",
                     directory / "tampered-headers.txt", directory / "tampered-body.html")
    if status < 400 or "Invalid certificate signature" not in (
            directory / "tampered-body.html").read_text(errors="replace"):
        raise RuntimeError("SimpleSAMLphp did not reject the tampered signed Redirect query")


def save(output: Path, directory: Path, label: str, response: bytes) -> None:
    url = (directory / "redirect-url.txt").read_text()
    encoded = parse_qs(urlparse(url).query)["SAMLRequest"][0]
    request_xml = zlib.decompress(base64.b64decode(encoded), wbits=-15)
    (output / f"{label}-request.xml").write_bytes(request_xml)
    (output / f"{label}-response.xml").write_bytes(response)
    for name in ("pending.txt", "redirect-url.txt", "sp-metadata.xml"):
        shutil.copyfile(directory / name, output / f"{label}-{name}")


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
    parent = Path("/private/tmp") if Path("/private/tmp").is_dir() else Path("/tmp")
    with tempfile.TemporaryDirectory(prefix="revetsec-simplesaml-", dir=parent) as name:
        temporary = Path(name)
        write_configuration(temporary)
        classes = temporary / "classes"
        classes.mkdir()
        compile_generator(classes)
        container = None
        try:
            for label, signed in (("cbc-response-signed", True),
                                  ("cbc-assertion-signed", False)):
                signing_mode(temporary, signed)
                # SimpleSAMLphp caches remote SP metadata in the running IdP. Start a
                # fresh process for each signature placement so the second response
                # uses the configuration we just wrote.
                container, port = start_idp(temporary)
                wait_for_idp(temporary, port)
                directory = temporary / label
                generate_request(classes, directory)
                response = capture(directory, port, label, signed)
                if signed:
                    assert_signed_request_validation(directory, port)
                save(output, directory, label, response)
                print(f"{label}: captured {len(response)} bytes from {IMAGE}")
                subprocess.run(("docker", "stop", container), check=True,
                               capture_output=True, text=True)
                container = None
        except Exception as exception:
            if container is not None:
                logs = subprocess.run(("docker", "logs", "--tail", "25", container),
                                      capture_output=True, text=True)
                raise RuntimeError(f"SimpleSAMLphp capture failed; IdP tail:\n{logs.stdout[-4000:]}") \
                    from exception
            raise
        finally:
            if container is not None:
                subprocess.run(("docker", "stop", container), capture_output=True, text=True)
    manifest = {"image": IMAGE, "digest": DIGEST,
                "files": {path.name: hashlib.sha256(path.read_bytes()).hexdigest()
                          for path in sorted(output.iterdir()) if path.is_file()}}
    (output / "capture-manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")


if __name__ == "__main__":
    main()
