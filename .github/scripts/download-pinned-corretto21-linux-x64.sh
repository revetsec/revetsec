#!/usr/bin/env bash
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

# Download the exact compiler used for the checksum-pinned Soklet 4.0.0 JAR.
# actions/setup-java's Corretto resolver accepts only major versions, so CI
# passes this verified archive to setup-java's jdkfile distribution instead.
# SHA-256: https://github.com/corretto/corretto-21/releases/tag/21.0.11.10.1
set -euo pipefail

archive=amazon-corretto-21.0.11.10.1-linux-x64.tar.gz
sha256=5b4dc8817df13f88f9bfc434e5d018adb535889ff2fe0ccf758bcebcc216f394
url=https://corretto.aws/downloads/resources/21.0.11.10.1/$archive

if [[ $# -ne 1 ]]; then
	printf 'Usage: %s <absolute-output-path/%s>\n' "$0" "$archive" >&2
	exit 64
fi
output_path=$1
[[ "$output_path" == /* && "${output_path##*/}" == "$archive" ]] \
	|| { printf 'The output must be an absolute path ending in %s.\n' "$archive" >&2; exit 64; }
[[ -d "${output_path%/*}" && ! -e "$output_path" && ! -L "$output_path" ]] \
	|| { printf 'The output must be a new file in an existing directory.\n' >&2; exit 1; }

trap 'rm -f -- "$output_path"' ERR
curl --proto '=https' --tlsv1.2 --fail --location --silent --show-error \
	--retry 3 "$url" --output "$output_path"
printf '%s  %s\n' "$sha256" "$output_path" | sha256sum --check --strict
trap - ERR
printf 'Verified %s (SHA-256 %s).\n' "$archive" "$sha256"
