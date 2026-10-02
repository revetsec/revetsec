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

"""Run a checksum-checked packaged example from its private build result."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build", required=True, type=Path)
    parser.add_argument("--example", required=True, choices=["barebones-oidc", "playground"])
    parser.add_argument("--java-home", required=True, type=Path)
    parser.add_argument("--trust-store", type=Path)
    args = parser.parse_args()
    result = json.loads((args.build / "RESULT.json").read_text())
    example = result["examples"][args.example]
    for name, expected in example["artifacts"].items():
        if hashlib.sha256(Path(name).read_bytes()).hexdigest() != expected:
            raise RuntimeError("An example runtime artifact changed; rebuild before running")
    directory = Path(example["directory"])
    jars = sorted((directory / "target").glob("*.jar"))
    if len(jars) != 1 or len(example["runtimeDependencies"]) != 3:
        raise RuntimeError("Unexpected packaged example runtime")
    command = [str(args.java_home / "bin/java")]
    if args.trust_store:
        if not args.trust_store.is_absolute() or not args.trust_store.is_file():
            parser.error("The scoped trust store must be an existing absolute file")
        command += ["-Djavax.net.ssl.trustStore=" + str(args.trust_store),
                    "-Djavax.net.ssl.trustStoreType=PKCS12",
                    "-Djavax.net.ssl.trustStorePassword=changeit"]
    command += ["-cp", os.pathsep.join([str(jars[0]), *example["runtimeDependencies"]]),
                "example.playground.Playground" if args.example == "playground"
                else "com.revetsec.examples.barebones.BarebonesOidc"]
    try:
        raise SystemExit(subprocess.call(command, cwd=directory))
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
