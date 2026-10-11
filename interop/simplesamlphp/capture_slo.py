#!/usr/bin/env python3
"""Capture and replay both SLO directions from the pinned SimpleSAMLphp image.

The browser, IdP and SP endpoints are test-only. Only the IdP runs on a
loopback Docker port; Revetsec handles the SP messages without contacting the
example SP hostname.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
from urllib.parse import quote, urljoin, urlparse

import capture as shared


SP_LOGOUT = "https://sp.example.test/slo"
IDP_LOGOUT = f"https://{shared.HOST}/simplesaml/module.php/saml/idp/singleLogout"
RETURN_TO = f"https://{shared.HOST}/simplesaml/"


def configure_logout(directory: Path) -> None:
    remote = directory / "saml20-sp-remote.php"
    source = remote.read_text()
    marker = "'saml20.sign.response' => true"
    if source.count(marker) != 1:
        raise RuntimeError("SimpleSAMLphp remote SP configuration changed")
    insert = ("'SingleLogoutService' => [['Binding' => "
              "'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect', "
              f"'Location' => '{SP_LOGOUT}']], "
              "'sign.logout' => true, 'redirect.sign' => true, "
              "'validate.logout' => true, ")
    remote.write_text(source.replace(marker, insert + marker))


def compile_verifier(classes: Path) -> None:
    java_home = Path(os.environ["JAVA_HOME"])
    jspecify = Path.home() / ".m2/repository/org/jspecify/jspecify/1.0.1/jspecify-1.0.1.jar"
    shared.checked(str(java_home / "bin/javac"), "-cp",
                   os.pathsep.join((str(shared.ROOT / "target/classes"), str(jspecify))),
                   "-d", str(classes),
                   str(shared.ROOT / "interop/simplesamlphp/CaptureLogoutRequest.java"),
                   str(shared.ROOT / "interop/simplesamlphp/CaptureSpInitiatedLogout.java"))


def follow_idp(directory: Path, port: int, cookies: Path, url: str,
               expected_external: str) -> str:
    for step in range(12):
        parsed = urlparse(url)
        if parsed.scheme != "https":
            raise RuntimeError("IdP returned a non-HTTPS redirect")
        if url == expected_external:
            return url
        if parsed.hostname == "sp.example.test":
            if url.split("?", 1)[0] != expected_external:
                raise RuntimeError("IdP redirected to an unexpected SP endpoint")
            return url
        if parsed.hostname != shared.HOST:
            raise RuntimeError("IdP redirected to an unexpected host")
        headers = directory / f"logout-{step}-headers.txt"
        page = directory / f"logout-{step}-body.html"
        status = shared.request(url, port, cookies, headers, page)
        if status not in (302, 303):
            raise RuntimeError(f"IdP logout returned HTTP {status}: "
                               + page.read_text(errors="replace")[:300])
        location = next((line.split(":", 1)[1].strip()
                         for line in headers.read_text().splitlines()
                         if line.lower().startswith("location:")), None)
        if location is None:
            raise RuntimeError("IdP logout redirect lacks Location")
        url = urljoin(url, location)
    raise RuntimeError("IdP logout exceeded twelve redirects")


def assert_tampered_reply_rejected(directory: Path, port: int, cookies: Path,
                                  reply: str) -> None:
    bad = reply.replace("RelayState=", "RelayState=X", 1)
    if bad == reply:
        raise RuntimeError("Revetsec LogoutResponse lacks signed RelayState")
    status = shared.request(bad, port, cookies, directory / "tampered-reply-headers.txt",
                            directory / "tampered-reply-body.html")
    body = (directory / "tampered-reply-body.html").read_text(errors="replace")
    if status < 400 or "Invalid certificate signature" not in body:
        raise RuntimeError("SimpleSAMLphp did not reject the tampered LogoutResponse signature")


def capture_sp_initiated(temporary: Path, output: Path, classes: Path,
                         port: int) -> None:
    login = temporary / "sp-initiated-login"
    shared.generate_request(classes, login)
    response = shared.capture(login, port, "sp-initiated-login", True)
    (login / "response.xml").write_bytes(response)
    state = temporary / "sp-initiated-state"
    state.mkdir()
    java_home = Path(os.environ["JAVA_HOME"])
    classpath = os.pathsep.join((str(shared.ROOT / "target/classes"), str(classes)))
    shared.checked(str(java_home / "bin/java"), "-cp", classpath,
                   "com.revetsec.saml.CaptureSpInitiatedLogout", "begin",
                   str(login), str(state))
    request_url = (state / "sp-initiated-request-url.txt").read_text().strip()
    if not request_url.startswith(IDP_LOGOUT + "?"):
        raise RuntimeError("Revetsec emitted an unexpected IdP logout URL")
    # A changed signed RelayState must fail at the real IdP before the valid request.
    bad = request_url.replace("RelayState=", "RelayState=X", 1)
    if bad == request_url:
        raise RuntimeError("Revetsec LogoutRequest lacks a signed RelayState")
    status = shared.request(bad, port, login / "browser-cookies.txt",
                            temporary / "sp-tampered-headers.txt",
                            temporary / "sp-tampered-body.html")
    body = (temporary / "sp-tampered-body.html").read_text(errors="replace")
    if status < 400 or "Invalid certificate signature" not in body:
        raise RuntimeError("SimpleSAMLphp did not reject the tampered SP LogoutRequest")
    reply = follow_idp(temporary, port, login / "browser-cookies.txt",
                       request_url, SP_LOGOUT)
    (state / "sp-initiated-response-url.txt").write_text(reply + "\n")
    shared.checked(str(java_home / "bin/java"), "-cp", classpath,
                   "com.revetsec.saml.CaptureSpInitiatedLogout", "complete",
                   str(state / "sp-initiated-response-url.txt"), str(state))
    for name in ("sp-initiated-request-url.txt", "sp-initiated-response-url.txt",
                 "sp-initiated-response.xml", "sp-initiated-session.txt"):
        shutil.copyfile(state / name, output / name)
    (output / "sp-initiated-login-response.xml").write_bytes(response)
    shutil.copyfile(login / "pending.txt", output / "sp-initiated-login-pending.txt")
    print(f"Revetsec signed LogoutRequest and {shared.IMAGE} signed LogoutResponse accepted")


def run(output: Path) -> None:
    output.mkdir(parents=True, exist_ok=True)
    if any(output.iterdir()):
        raise RuntimeError("capture output directory must be empty")
    shared.verify_image()
    parent = Path("/private/tmp") if Path("/private/tmp").is_dir() else Path("/tmp")
    with tempfile.TemporaryDirectory(prefix="revetsec-simplesaml-slo-", dir=parent) as name:
        temporary = Path(name)
        shared.write_configuration(temporary)
        configure_logout(temporary)
        classes = temporary / "classes"
        classes.mkdir()
        shared.compile_generator(classes)
        compile_verifier(classes)
        container = None
        try:
            container, port = shared.start_idp(temporary)
            shared.wait_for_idp(temporary, port)
            if IDP_LOGOUT not in (temporary / "health-metadata.xml").read_text():
                raise RuntimeError("IdP metadata did not advertise Redirect SLO")
            login = temporary / "login"
            shared.generate_request(classes, login)
            response = shared.capture(login, port, "slo-login", True)
            if not response:
                raise RuntimeError("IdP did not establish an SSO session")
            browser = login / "browser-cookies.txt"
            request_url = follow_idp(temporary, port, browser,
                                    IDP_LOGOUT + "?ReturnTo=" + quote(RETURN_TO, safe=""),
                                    SP_LOGOUT)
            (output / "logout-request-url.txt").write_text(request_url + "\n")
            java_home = Path(os.environ["JAVA_HOME"])
            shared.checked(str(java_home / "bin/java"), "-cp",
                           os.pathsep.join((str(shared.ROOT / "target/classes"), str(classes))),
                           "com.revetsec.saml.CaptureLogoutRequest", request_url, str(output))
            reply = (output / "logout-response-url.txt").read_text().strip()
            assert_tampered_reply_rejected(temporary, port, browser, reply)
            final = follow_idp(temporary, port, browser, reply, RETURN_TO)
            if final != RETURN_TO:
                raise RuntimeError("IdP did not finish the LogoutResponse exchange")
            (output / "logout-final-url.txt").write_text(final + "\n")
            (output / "login-response.xml").write_bytes(response)
            for name in ("pending.txt", "redirect-url.txt"):
                shutil.copyfile(login / name, output / f"login-{name}")
            print(f"SimpleSAMLphp signed LogoutRequest accepted; Revetsec reply accepted by {shared.IMAGE}")
            capture_sp_initiated(temporary, output, classes, port)
        except Exception as exception:
            if container is not None:
                logs = subprocess.run(("docker", "logs", "--tail", "25", container),
                                      capture_output=True, text=True)
                raise RuntimeError(f"SimpleSAMLphp SLO capture failed; IdP tail:\n{logs.stdout[-4000:]}") \
                    from exception
            raise
        finally:
            if container is not None:
                subprocess.run(("docker", "stop", container), capture_output=True, text=True)
    manifest = {"image": shared.IMAGE, "digest": shared.DIGEST,
                "files": {path.name: hashlib.sha256(path.read_bytes()).hexdigest()
                          for path in sorted(output.iterdir()) if path.is_file()}}
    (output / "capture-manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True,
                        help="new empty directory for public capture artifacts")
    run(parser.parse_args().output.resolve())
