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

"""Entry point: python -m scripted_idp {serve | selftest --out DIR}."""

import sys

USAGE = "usage: python -m scripted_idp {serve | selftest --out DIR}"


def main(argv):
    command = argv[0] if argv else "serve"
    if command == "serve":
        from .server import main as run
    elif command == "selftest":
        from .selftest import main as run
    else:
        print(USAGE, file=sys.stderr)
        return 2
    return run(argv[1:])


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
