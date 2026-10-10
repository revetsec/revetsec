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

"""Create a two-day private test CA, exact-DNS leaf and loopback Caddy configuration."""

import argparse
import ipaddress
import json
import os
from pathlib import Path
import re
import subprocess


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--work", type=Path, required=True, help="new private directory")
    parser.add_argument("--openssl", type=Path, required=True)
    parser.add_argument("--rp-id", required=True, help="lowercase DNS name controlled by the operator")
    parser.add_argument("--https-port", type=int, default=9443)
    parser.add_argument("--http-port", type=int, default=8093)
    args = parser.parse_args()
    work = args.work.resolve()
    source_root = Path(__file__).resolve().parents[2]
    if (not args.work.is_absolute() or work.exists()
            or work == source_root or source_root in work.parents
            or any(parent.is_symlink() for parent in args.work.parents)):
        parser.error("--work must be a new absolute private directory without symlink ancestors")
    if not args.openssl.is_absolute() or not args.openssl.is_file():
        parser.error("--openssl must be an absolute executable path")
    verify_help = subprocess.run([str(args.openssl), "verify", "-help"],
                                 capture_output=True, text=True, timeout=10)
    if "-verify_hostname" not in verify_help.stdout + verify_help.stderr:
        parser.error("--openssl must support verify -verify_hostname (for example OpenSSL 3)")
    labels = args.rp_id.split(".")
    if (len(labels) < 2 or any(not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
                               for label in labels) or len(args.rp_id) > 253):
        parser.error("--rp-id must be a canonical lowercase DNS name with at least two labels")
    try:
        ipaddress.ip_address(args.rp_id)
    except ValueError:
        pass
    else:
        parser.error("--rp-id must not be an IP address")
    if not 1 <= args.https_port <= 65535 or not 1 <= args.http_port <= 65535:
        parser.error("ports must be in 1..65535")

    os.umask(0o077)
    work.mkdir(mode=0o700, parents=True)

    def openssl(*command, expected=0):
        result = subprocess.run([str(args.openssl), *command], cwd=work,
                                capture_output=True, timeout=30)
        if result.returncode != expected:
            raise RuntimeError("Private TLS preparation failed")

    openssl("req", "-x509", "-newkey", "rsa:3072", "-nodes", "-sha256", "-days", "2",
            "-keyout", "ca.key", "-out", "ca.crt", "-subj", "/CN=Revetsec disposable passkey CA",
            "-addext", "basicConstraints=critical,CA:TRUE,pathlen:0",
            "-addext", "keyUsage=critical,keyCertSign,cRLSign")
    openssl("req", "-new", "-newkey", "rsa:3072", "-nodes", "-sha256",
            "-keyout", "leaf.key", "-out", "leaf.csr", "-subj", "/CN=" + args.rp_id)
    (work / "leaf.ext").write_text("basicConstraints=critical,CA:FALSE\n"
                                   "keyUsage=critical,digitalSignature,keyEncipherment\n"
                                   "extendedKeyUsage=serverAuth\n"
                                   "subjectAltName=DNS:" + args.rp_id + "\n")
    openssl("x509", "-req", "-in", "leaf.csr", "-CA", "ca.crt", "-CAkey", "ca.key",
            "-CAcreateserial", "-out", "leaf.crt", "-days", "2", "-sha256",
            "-extfile", "leaf.ext")
    openssl("verify", "-CAfile", "ca.crt", "-verify_hostname", args.rp_id, "leaf.crt")
    openssl("verify", "-CAfile", "ca.crt", "-verify_hostname", "foreign.invalid",
            "leaf.crt", expected=2)

    ambiguous = chr(96) + " || ".join("{http.request.header." + name + '}.contains(",")'
                                      for name in ("Origin", "Cookie", "Content-Type", "X-CSRF-Token",
                                                   "X-Ceremony-Id", "X-Credential-Id", "X-Demo-Access-Key")) + chr(96)
    caddyfile = ("{\n admin off\n auto_https off\n servers { protocols h1 h2 }\n}\n\n"
                 + "https://" + args.rp_id + ":" + str(args.https_port) + " {\n"
                 + " bind 127.0.0.1\n"
                 + " tls " + json.dumps(str(work / "leaf.crt")) + " "
                 + json.dumps(str(work / "leaf.key")) + "\n"
                 + " route {\n  @ambiguous expression " + ambiguous + "\n"
                 + '  respond @ambiguous "" 400\n'
                 + "  reverse_proxy 127.0.0.1:" + str(args.http_port) + "\n }\n}\n")
    (work / "Caddyfile").write_text(caddyfile)
    print("Private TLS files and Caddyfile ready for https://" + args.rp_id
          + ":" + str(args.https_port))
    print("No browser or system trust store was changed.")


if __name__ == "__main__":
    main()
