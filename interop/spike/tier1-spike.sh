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

# Tier-1 container spike (milestone M0).
#
# For each Tier-1 partner it measures image pull time, start-to-ready time and
# teardown time, N runs each, runs a headless OIDC smoke check against every
# started OP, and writes the results to TIER1-RESULTS.md next to this script.
#
# Targets:
#   keycloak  Keycloak 26.7.x: start-dev, start-dev + realm import,
#             production-like `start` with TLS, and the same with realm import
#   oidf      OpenID Foundation conformance suite release-v5.3.1 (compose)
#   node      node-oidc-provider 9.12.x, built from ../node-oidc-provider
#
# Nothing is pushed anywhere. Every container, network and anonymous volume the
# script creates is removed on exit, including on failure or Ctrl-C. Images
# stay cached unless --remove-images is given.
#
# Portable to bash 3.2 (macOS) and GNU/Linux (GitHub ubuntu-24.04 runners).
# Needs docker (with compose and buildx), curl, perl, python3 and openssl.

set -euo pipefail
umask 077

usage() {
	cat >&2 <<'EOF'
Usage: tier1-spike.sh [options]

  --runs N          runs per measurement (default 3)
  --cold            remove each pinned image before every pull run, so pulls
                    download again; use only where removing them is acceptable
  --only LIST       comma-separated subset of: keycloak,oidf,node (default all)
  --remove-images   remove the pinned images and the built node image at exit
  --output FILE     results file (default: TIER1-RESULTS.md next to this script)
  -h, --help        this text

Environment:
  SPIKE_TLS_CERT, SPIKE_TLS_KEY, SPIKE_TLS_CA
                    PEM server certificate (SAN localhost), its key and the trust
                    anchor. When unset, the checked-in test CA is used
                    (src/test/resources/tls/server.pem, server-key.pem,
                    test-ca.pem); without it, a throwaway CA and leaf are
                    generated in a temp directory.
  KC_HTTP_PORT (28080), KC_HTTPS_PORT (28443), KC_MGMT_PORT (29000),
  NODE_PORT (23443)  host ports (bound to 127.0.0.1). The OIDF suite always
                    uses 8443 and 8444 (see oidf-compose.yml).
  SPIKE_READY_TIMEOUT  seconds to wait for readiness (default 300)
  SPIKE_JAVA, JAVA_HOME
                    a JDK 17+ to run KeycloakJdkLogin.java, the JDK-only headless
                    login check (skipped when no java is found)
EOF
	exit 64
}

fail() {
	printf 'tier1-spike: %s\n' "$*" >&2
	exit 1
}

log() {
	printf '[%s] %s\n' "$(date -u +%H:%M:%S)" "$*" >&2
}

script_dir=$(cd "$(dirname "$0")" && pwd -P)
interop_dir=$(cd "$script_dir/.." && pwd -P)
test_pki="$interop_dir/../src/test/resources/tls"

# ---------------------------------------------------------------------------
# Pins. Move them only in a deliberate change that re-runs this spike.
# ---------------------------------------------------------------------------

# Keycloak 26.7.4 (quay.io, 2026-09-16), multi-arch index digest.
KEYCLOAK_IMAGE="quay.io/keycloak/keycloak:26.7.4@sha256:82a77884f3af238beab1e7afd63b5f530e1b5c0590bd7aa60b40a40463e29b2c"
# The suite's images and mongo are pinned in the compose file.
OIDF_TAG="release-v5.3.1"
OIDF_COMPOSE="$script_dir/oidf-compose.yml"
# node-oidc-provider: base image pinned in the Dockerfile, packages in the lockfile.
NODE_DIR="$interop_dir/node-oidc-provider"
NODE_IMAGE_TAG="revetsec-interop/node-oidc-provider:tier1-spike"

REALM_FILE="$interop_dir/keycloak/revetsec-test-realm.json"
SMOKE="$script_dir/oidc_smoke.py"

# Test-only values, identical in the realm JSON, server.js and the smoke check.
TEST_CLIENT_ID="revetsec-test-client"
TEST_CLIENT_SECRET="test-only-client-secret-not-a-real-secret"
TEST_REDIRECT_URI="http://localhost:8080/callback"
TEST_USERNAME="test-user"
TEST_PASSWORD="test-only-password-not-a-secret"

KC_HTTP_PORT=${KC_HTTP_PORT:-28080}
KC_HTTPS_PORT=${KC_HTTPS_PORT:-28443}
KC_MGMT_PORT=${KC_MGMT_PORT:-29000}
NODE_PORT=${NODE_PORT:-23443}
OIDF_PORT=8443
OIDF_MTLS_PORT=8444
READY_TIMEOUT=${SPIKE_READY_TIMEOUT:-300}

runs=3
cold=0
only="keycloak,oidf,node"
remove_images=0
output="$script_dir/TIER1-RESULTS.md"
command_line="interop/spike/tier1-spike.sh${*:+ $*}"

while [[ $# -gt 0 ]]; do
	case "$1" in
		--runs) [[ $# -ge 2 ]] || usage; runs=$2; shift 2 ;;
		--cold) cold=1; shift ;;
		--only) [[ $# -ge 2 ]] || usage; only=$2; shift 2 ;;
		--remove-images) remove_images=1; shift ;;
		--output) [[ $# -ge 2 ]] || usage; output=$2; shift 2 ;;
		-h|--help) usage ;;
		*) usage ;;
	esac
done
[[ "$runs" =~ ^[1-9][0-9]*$ ]] || fail "--runs must be a positive integer."
case ",$only," in
	*,keycloak,*|*,oidf,*|*,node,*) ;;
	*) fail "--only must name keycloak, oidf and/or node." ;;
esac

wants() {
	case ",$only," in *",$1,"*) return 0 ;; *) return 1 ;; esac
}

# Optional: a JDK for KeycloakJdkLogin.java (SPIKE_JAVA, then JAVA_HOME, then PATH).
java=""
if [[ -n "${SPIKE_JAVA:-}" ]]; then
	java=$SPIKE_JAVA
elif [[ -n "${JAVA_HOME:-}" && -x "$JAVA_HOME/bin/java" ]]; then
	java="$JAVA_HOME/bin/java"
elif command -v java >/dev/null 2>&1; then
	java=$(command -v java)
fi

for command in docker curl perl python3 openssl; do
	command -v "$command" >/dev/null 2>&1 || fail "$command was not found on PATH."
done
docker info >/dev/null 2>&1 || fail "the Docker daemon is not reachable."
docker compose version >/dev/null 2>&1 || fail "docker compose is not available."
docker buildx version >/dev/null 2>&1 || fail "docker buildx is not available."
for required in "$OIDF_COMPOSE" "$NODE_DIR/Dockerfile" "$NODE_DIR/package-lock.json" "$REALM_FILE" "$SMOKE"; do
	[[ -f "$required" ]] || fail "missing $required"
done

session="$(date -u +%Y%m%dT%H%M%SZ)-$$"
label="com.revetsec.spike.session=$session"
oidf_project="revetsec-spike-oidf-$$"
work=$(mktemp -d "${TMPDIR:-/tmp}/revetsec-tier1.XXXXXX")
raw="$work/raw.tsv"
meta="$work/meta.tsv"
notes="$work/notes.txt"
failures="$work/failures.txt"
: >"$raw"
: >"$meta"
: >"$notes"
: >"$failures"

oidf() {
	docker compose -p "$oidf_project" -f "$OIDF_COMPOSE" "$@"
}

cleanup() {
	local status=$? ids
	set +e
	ids=$(docker ps -aq --filter "label=$label" 2>/dev/null)
	if [[ -n "$ids" ]]; then
		log "cleanup: removing leftover spike containers"
		# shellcheck disable=SC2086
		docker rm -f -v $ids >/dev/null 2>&1
	fi
	if [[ -n "$(oidf ps -aq 2>/dev/null)" ]]; then
		log "cleanup: removing the OIDF compose project"
		oidf down -v --remove-orphans >/dev/null 2>&1
	fi
	if [[ $remove_images -eq 1 ]]; then
		log "cleanup: removing pinned images"
		for ref in $(pinned_images); do
			remove_image "$ref"
		done
		docker rmi "$NODE_IMAGE_TAG" >/dev/null 2>&1
	fi
	rm -rf "$work"
	exit $status
}
trap cleanup EXIT
trap 'exit 130' INT TERM

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

now() {
	perl -MTime::HiRes=time -e 'printf "%.3f\n", time'
}

elapsed() {
	perl -e 'printf "%.2f\n", $ARGV[1] - $ARGV[0]' "$1" "$2"
}

# record TARGET STEP RUN VALUE NOTE
record() {
	printf '%s\t%s\t%s\t%s\t%s\n' "$1" "$2" "$3" "$4" "${5:-}" >>"$raw"
}

set_meta() {
	printf '%s\t%s\n' "$1" "$2" >>"$meta"
}

add_note() {
	printf '%s\n' "$*" >>"$notes"
}

# add_failure TITLE FILE: keeps the last lines of a log for the results file.
add_failure() {
	{
		printf '### %s\n\n```text\n' "$1"
		if [[ -n "${2:-}" && -f "$2" ]]; then
			tail -n 40 "$2" | cut -c1-240
		fi
		printf '```\n\n'
	} >>"$failures"
}

# port_free PORT: true when nothing listens on 127.0.0.1:PORT. SO_REUSEADDR
# keeps sockets in TIME_WAIT from a previous run from counting as "in use".
port_free() {
	python3 - "$1" <<'PY'
import socket, sys
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
try:
	s.bind(("127.0.0.1", int(sys.argv[1])))
except OSError:
	sys.exit(1)
finally:
	s.close()
PY
}

# repo@digest form of a name:tag@digest reference.
digest_ref() {
	local name=${1%@*} digest=${1#*@} base
	base=${name##*/}
	if [[ "$base" == *:* ]]; then
		name=${name%:*}
	fi
	printf '%s@%s\n' "$name" "$digest"
}

image_present() {
	docker image inspect "$(digest_ref "$1")" >/dev/null 2>&1
}

remove_image() {
	docker rmi "$(digest_ref "$1")" >/dev/null 2>&1 || true
}

node_base_image() {
	sed -n 's/^FROM[[:space:]]\{1,\}\([^[:space:]]\{1,\}\).*/\1/p' "$NODE_DIR/Dockerfile" | head -n 1
}

oidf_images() {
	oidf config --images
}

pinned_images() {
	printf '%s\n' "$KEYCLOAK_IMAGE"
	oidf_images
	node_base_image
}

host_arch() {
	docker version --format '{{.Server.Arch}}'
}

# Architecture of the local image, compared with the host to detect emulation.
image_arch() {
	docker image inspect --format '{{.Architecture}}' "$(digest_ref "$1")" 2>/dev/null || echo "?"
}

# image_sizes REF: prints "<on disk>\t<download>" for the host platform, from
# `docker image ls --tree` (containerd image store: unpacked size and
# compressed content size). Elsewhere it falls back to the inspect size and
# n/a for the download size.
image_sizes() {
	local ref=$1 sizes
	sizes=$(docker image ls --tree 2>/dev/null | python3 -c '
import re, sys
ref, arch = sys.argv[1], sys.argv[2]
lines = sys.stdin.read().splitlines()
for i, line in enumerate(lines):
	if line.split(" ")[0] == ref:
		for sub in lines[i + 1:]:
			if not re.match(r"^\W*[├└]", sub):
				break
			m = re.match(r"^\W*[├└]─\s+linux/" + re.escape(arch) + r"(/v\d)?\s+\S+\s+(\S+)\s+(\S+)", sub)
			if m:
				print(m.group(2) + "\t" + m.group(3))
				sys.exit(0)
sys.exit(1)
' "$ref" "$(host_arch)") && { printf '%s\n' "$sizes"; return; }
	sizes=$(docker image inspect --format '{{.Size}}' "$ref" 2>/dev/null) || { printf 'n/a\tn/a\n'; return; }
	perl -e 'printf "%.0fMB\tn/a\n", $ARGV[0] / 1000000' "$sizes"
}

# wait_ready URL EXPECT CONTAINER [curl args...]: polls every 0.1 s until URL
# answers 200 (and, if EXPECT is non-empty, the body contains it). Fails fast
# when CONTAINER (if non-empty) is no longer running.
wait_ready() {
	local url=$1 expect=$2 container=$3 deadline code polls=0
	shift 3
	deadline=$(( $(date +%s) + READY_TIMEOUT ))
	while :; do
		code=$(curl -s -o "$work/probe.out" -w '%{http_code}' --max-time 2 "$@" "$url" 2>/dev/null || true)
		if [[ "$code" == "200" ]]; then
			if [[ -z "$expect" ]] || grep -qF "$expect" "$work/probe.out"; then
				return 0
			fi
		fi
		polls=$((polls + 1))
		if [[ -n "$container" && $((polls % 20)) -eq 0 ]]; then
			[[ "$(docker inspect --format '{{.State.Running}}' "$container" 2>/dev/null)" == "true" ]] || return 1
		fi
		[[ $(date +%s) -lt $deadline ]] || return 1
		sleep 0.1
	done
}

# memory_of CONTAINER...: memory use per container, from one docker stats sample.
memory_of() {
	if [[ $# -eq 1 ]]; then
		docker stats --no-stream --format '{{.MemUsage}}' "$1" 2>/dev/null | sed 's| /.*||' || echo "n/a"
	else
		docker stats --no-stream --format '{{.Name}} {{.MemUsage}}' "$@" 2>/dev/null \
			| sed -e 's| /.*||' -e 's|^revetsec-spike-oidf-[0-9]*-\([a-z]*\)-[0-9]* |\1 |' \
			| sort | paste -sd ',' - | sed 's|,|, |g' || echo "n/a"
	fi
}

# teardown_container TARGET STEP RUN NAME: graceful stop (10 s grace) + rm -v.
teardown_container() {
	local target=$1 step=$2 run=$3 name=$4 t0 t1 exit_code note=""
	t0=$(now)
	docker stop -t 10 "$name" >/dev/null 2>&1 || true
	exit_code=$(docker inspect --format '{{.State.ExitCode}}' "$name" 2>/dev/null || echo "?")
	docker rm -v "$name" >/dev/null 2>&1 || true
	t1=$(now)
	[[ "$exit_code" == "137" ]] && note="SIGKILL after the 10 s grace period"
	record "$target" "$step" "$run" "$(elapsed "$t0" "$t1")" "$note"
}

# pull_group TARGET STEP REF...: pulls every REF in parallel, RUNS times.
pull_group() {
	local target=$1 step=$2 run ref i t0 t1 absent failed pulled existing verdict pids
	shift 2
	for ((run = 1; run <= runs; run++)); do
		if [[ $cold -eq 1 ]]; then
			for ref in "$@"; do
				remove_image "$ref"
			done
		fi
		absent=0
		for ref in "$@"; do
			image_present "$ref" || absent=$((absent + 1))
		done
		pids=""
		i=0
		t0=$(now)
		for ref in "$@"; do
			i=$((i + 1))
			docker pull "$ref" >"$work/pull-$i.log" 2>&1 &
			pids="$pids $!"
		done
		failed=0
		for pid in $pids; do
			wait "$pid" || failed=$((failed + 1))
		done
		t1=$(now)
		pulled=$(cat "$work"/pull-*.log | sed -n 's/^\([0-9a-f]\{12\}\): Pull complete.*/\1/p' | sort -u | wc -l | tr -d ' ')
		existing=$(cat "$work"/pull-*.log | sed -n 's/^\([0-9a-f]\{12\}\): Already exists.*/\1/p' | sort -u | wc -l | tr -d ' ')
		if [[ $failed -gt 0 ]]; then
			record "$target" "$step" "$run" "FAIL" "$failed pull(s) failed"
			i=0
			for ref in "$@"; do
				i=$((i + 1))
				add_failure "$target $step run $run: docker pull $ref" "$work/pull-$i.log"
			done
			rm -f "$work"/pull-*.log
			continue
		elif [[ $absent -eq 0 ]]; then
			verdict="warm: image already cached"
		elif [[ $pulled -eq 0 ]]; then
			verdict="not cold: layers already in the local content store"
		elif [[ $existing -gt 0 ]]; then
			verdict="cold: $pulled layers downloaded, $existing already local"
		else
			verdict="cold: $pulled layers downloaded"
		fi
		record "$target" "$step" "$run" "$(elapsed "$t0" "$t1")" "$verdict"
		rm -f "$work"/pull-*.log
	done
}

describe_images() {
	local target=$1 ref arch sizes
	shift
	for ref in "$@"; do
		arch=$(image_arch "$ref")
		sizes=$(image_sizes "$(digest_ref "$ref")")
		printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$target" "$ref" "$arch" "${sizes#*$'\t'}" "${sizes%%$'\t'*}" \
			"$( [[ "$arch" == "$(host_arch)" ]] && echo native || echo "EMULATED" )" >>"$work/images.tsv"
		[[ "$arch" == "$(host_arch)" ]] || add_note "$ref runs as $arch under emulation on this $(host_arch) host."
	done
}

# ---------------------------------------------------------------------------
# TLS material and staged files
# ---------------------------------------------------------------------------

stage="$work/stage"
mkdir -p "$stage/tls" "$stage/import"
if [[ -n "${SPIKE_TLS_CERT:-}" || -n "${SPIKE_TLS_KEY:-}" || -n "${SPIKE_TLS_CA:-}" ]]; then
	[[ -f "${SPIKE_TLS_CERT:-}" && -f "${SPIKE_TLS_KEY:-}" && -f "${SPIKE_TLS_CA:-}" ]] \
		|| fail "set all of SPIKE_TLS_CERT, SPIKE_TLS_KEY and SPIKE_TLS_CA to existing PEM files."
	cp "$SPIKE_TLS_CERT" "$stage/tls/cert.pem"
	cp "$SPIKE_TLS_KEY" "$stage/tls/key.pem"
	cp "$SPIKE_TLS_CA" "$work/ca.pem"
	tls_source="supplied through SPIKE_TLS_CERT/SPIKE_TLS_KEY/SPIKE_TLS_CA"
elif [[ -f "$test_pki/server.pem" && -f "$test_pki/server-key.pem" && -f "$test_pki/test-ca.pem" ]]; then
	# The checked-in test CA (src/test/resources/tls/README.md): public, test-only key material.
	cp "$test_pki/server.pem" "$stage/tls/cert.pem"
	cp "$test_pki/server-key.pem" "$stage/tls/key.pem"
	cp "$test_pki/test-ca.pem" "$work/ca.pem"
	tls_source="checked-in test CA: src/test/resources/tls/server.pem + server-key.pem, trust anchor test-ca.pem ($(openssl x509 -in "$test_pki/server.pem" -noout -fingerprint -sha256 | sed 's/.*=//' | tr -d ':' | cut -c1-16)… leaf SHA-256)"
else
	# A throwaway CA (P-256) and a localhost leaf, valid for one day.
	openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 1 \
		-subj "/CN=Revetsec Tier-1 spike throwaway CA" \
		-addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" \
		-keyout "$work/ca-key.pem" -out "$work/ca.pem" >/dev/null 2>&1 || fail "openssl could not create the CA."
	openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -subj "/CN=localhost" \
		-keyout "$stage/tls/key.pem" -out "$work/leaf.csr" >/dev/null 2>&1 || fail "openssl could not create the CSR."
	printf '%s\n' "basicConstraints=critical,CA:FALSE" "keyUsage=critical,digitalSignature" \
		"extendedKeyUsage=serverAuth" "subjectAltName=DNS:localhost,IP:127.0.0.1" >"$work/leaf.ext"
	openssl x509 -req -in "$work/leaf.csr" -CA "$work/ca.pem" -CAkey "$work/ca-key.pem" -CAcreateserial \
		-days 1 -sha256 -extfile "$work/leaf.ext" -out "$stage/tls/cert.pem" >/dev/null 2>&1 \
		|| fail "openssl could not sign the leaf."
	tls_source="throwaway P-256 CA + localhost leaf generated in a temp directory for this run (the checked-in test CA was not found)"
fi
cp "$REALM_FILE" "$stage/import/revetsec-test-realm.json"
# Containers run as non-root users (keycloak uid 1000, node uid 1000) and
# `docker cp` copies files as root with their modes, so make them readable.
chmod 755 "$stage" "$stage/tls" "$stage/import"
chmod 644 "$stage/tls/cert.pem" "$stage/tls/key.pem" "$stage/import/revetsec-test-realm.json"
ca="$work/ca.pem"

# ---------------------------------------------------------------------------
# Host information
# ---------------------------------------------------------------------------

collect_host_info() {
	local os cpu mem
	if [[ "$(uname -s)" == "Darwin" ]]; then
		os="$(sw_vers -productName) $(sw_vers -productVersion) ($(sw_vers -buildVersion)), $(uname -m)"
		cpu="$(sysctl -n machdep.cpu.brand_string), $(sysctl -n hw.ncpu) cores"
		mem=$(perl -e 'printf "%.0f GiB", $ARGV[0] / 1073741824' "$(sysctl -n hw.memsize)")
	else
		os="$(. /etc/os-release && echo "$PRETTY_NAME"), $(uname -m)"
		cpu="$(lscpu 2>/dev/null | sed -n 's/^Model name:[[:space:]]*//p' | head -n 1), $(nproc) CPUs"
		mem=$(perl -e 'printf "%.0f GiB", $ARGV[0] / 1073741824' "$(awk '/MemTotal/ {print $2 * 1024}' /proc/meminfo)")
	fi
	set_meta "Date (UTC)" "$(date -u '+%Y-%m-%d %H:%M')"
	set_meta "Host OS" "$os"
	set_meta "Host CPU" "$cpu"
	set_meta "Host memory" "$mem"
	set_meta "Docker" "client $(docker version --format '{{.Client.Version}}'), engine $(docker version --format '{{.Server.Version}}') ($(docker version --format '{{.Server.Os}}/{{.Server.Arch}}'))"
	set_meta "Docker platform" "$(docker version --format '{{.Server.Platform.Name}}' 2>/dev/null || echo n/a)"
	set_meta "Docker VM / daemon" "$(docker info --format '{{.OperatingSystem}}, kernel {{.KernelVersion}}, {{.NCPU}} CPUs'), $(perl -e 'printf "%.1f GiB", $ARGV[0] / 1073741824' "$(docker info --format '{{.MemTotal}}')") memory, storage $(docker info --format '{{.Driver}}')"
	set_meta "Image store" "$(docker info --format '{{range .DriverStatus}}{{index . 0}}={{index . 1}} {{end}}')"
	set_meta "Compose" "$(docker compose version --short)"
	set_meta "Buildx" "$(docker buildx version | awk '{print $2}')"
	set_meta "Other running containers" "$(docker ps -q | wc -l | tr -d ' ') (not ours; they share the VM's CPU and memory)"
	set_meta "curl" "$(curl --version | head -n 1 | awk '{print $1, $2}')"
	set_meta "python3" "$(python3 --version 2>&1 | awk '{print $2}')"
	set_meta "Java (KeycloakJdkLogin)" "$( [[ -n "$java" ]] && "$java" -version 2>&1 | head -n 1 || echo 'none found; JDK login check skipped')"
}

# ---------------------------------------------------------------------------
# Keycloak
# ---------------------------------------------------------------------------

keycloak_variant() {
	local variant=$1 run=$2 name t0 t1 t2 scheme ready_url realm_url curl_tls="" host_port container_port
	local -a command_args
	name="revetsec-spike-kc-$variant-$run-$$"
	case "$variant" in
		dev|dev-import)
			scheme=http
			host_port=$KC_HTTP_PORT
			container_port=8080
			command_args=(start-dev)
			;;
		tls|tls-import)
			scheme=https
			host_port=$KC_HTTPS_PORT
			container_port=8443
			command_args=(start --db=dev-file "--hostname=https://localhost:$KC_HTTPS_PORT" --http-enabled=false
				--https-certificate-file=/opt/keycloak/conf/tls/cert.pem
				--https-certificate-key-file=/opt/keycloak/conf/tls/key.pem)
			curl_tls="--cacert $ca"
			;;
	esac
	[[ "$variant" == *-import ]] && command_args=("${command_args[@]}" --import-realm)
	ready_url="$scheme://localhost:$KC_MGMT_PORT/health/ready"
	realm_url="$scheme://localhost:$host_port/realms/revetsec-test/.well-known/openid-configuration"

	docker create --name "$name" --label "$label" \
		-p "127.0.0.1:$host_port:$container_port" -p "127.0.0.1:$KC_MGMT_PORT:9000" \
		-e KC_HEALTH_ENABLED=true \
		"$KEYCLOAK_IMAGE" "${command_args[@]}" >/dev/null
	[[ "$scheme" == "https" ]] && docker cp "$stage/tls" "$name:/opt/keycloak/conf/tls" >/dev/null
	[[ "$variant" == *-import ]] && docker cp "$stage/import" "$name:/opt/keycloak/data/import" >/dev/null

	t0=$(now)
	docker start "$name" >/dev/null
	# shellcheck disable=SC2086
	if ! wait_ready "$ready_url" '"UP"' "$name" $curl_tls; then
		record keycloak "start kc-$variant" "$run" "FAIL" "not ready within ${READY_TIMEOUT}s"
		docker logs "$name" >"$work/kc.log" 2>&1 || true
		add_failure "keycloak kc-$variant run $run: not ready" "$work/kc.log"
		teardown_container keycloak "teardown kc-$variant" "$run" "$name"
		return
	fi
	t1=$(now)
	record keycloak "start kc-$variant" "$run" "$(elapsed "$t0" "$t1")" "$ready_url"

	if [[ "$variant" == *-import ]]; then
		# shellcheck disable=SC2086
		if wait_ready "$realm_url" '"issuer"' "$name" $curl_tls; then
			t2=$(now)
			record keycloak "realm visible kc-$variant" "$run" "$(elapsed "$t0" "$t2")" "imported realm's discovery document answers 200"
		else
			record keycloak "realm visible kc-$variant" "$run" "FAIL" "realm discovery never answered"
		fi
		local smoke_args=(--issuer "$scheme://localhost:$host_port/realms/revetsec-test"
			--client-id "$TEST_CLIENT_ID" --client-secret "$TEST_CLIENT_SECRET"
			--redirect-uri "$TEST_REDIRECT_URI" --username "$TEST_USERNAME" --password "$TEST_PASSWORD")
		[[ "$scheme" == "https" ]] && smoke_args=("${smoke_args[@]}" --cafile "$ca")
		if python3 "$SMOKE" "${smoke_args[@]}" >"$work/smoke.log" 2>&1; then
			record keycloak "smoke kc-$variant" "$run" "pass" "$(tail -n 1 "$work/smoke.log")"
		else
			record keycloak "smoke kc-$variant" "$run" "FAIL" "$(tail -n 1 "$work/smoke.log")"
			add_failure "keycloak kc-$variant run $run: smoke" "$work/smoke.log"
		fi
		# The recipe planned for the Java harness: java.net.http + CookieManager, no browser.
		if [[ -n "$java" ]]; then
			local jdk_args=("$scheme://localhost:$host_port/realms/revetsec-test" "$TEST_CLIENT_ID" "$TEST_CLIENT_SECRET"
				"$TEST_REDIRECT_URI" "$TEST_USERNAME" "$TEST_PASSWORD")
			[[ "$scheme" == "https" ]] && jdk_args=("${jdk_args[@]}" "$ca")
			if "$java" "$script_dir/KeycloakJdkLogin.java" "${jdk_args[@]}" >"$work/jdk.log" 2>&1; then
				if [[ "$scheme" == "https" ]]; then
					record keycloak "jdk login kc-$variant" "$run" "pass" "$(tail -n 1 "$work/jdk.log")"
				else
					record keycloak "jdk login kc-$variant" "$run" "pass (unexpected)" "$(tail -n 1 "$work/jdk.log")"
				fi
			elif [[ "$scheme" == "http" ]]; then
				record keycloak "jdk login kc-$variant" "$run" "fails (expected)" \
					"$(tail -n 1 "$work/jdk.log"); CookieManager withholds Keycloak's Secure cookies over plain HTTP (cookie_not_found)"
			else
				record keycloak "jdk login kc-$variant" "$run" "FAIL" "$(tail -n 1 "$work/jdk.log")"
				add_failure "keycloak kc-$variant run $run: JDK login" "$work/jdk.log"
			fi
		fi
	fi

	record keycloak "memory kc-$variant" "$run" "$(memory_of "$name")" "docker stats right after ready"
	docker logs "$name" >"$work/kc.log" 2>&1 || true
	record keycloak "log kc-$variant" "$run" \
		"$(sed -n 's/.*Quarkus augmentation completed in \([0-9]*\)ms.*/\1/p' "$work/kc.log" | head -n 1)" \
		"$(sed -n 's/.*started in \([0-9.]*s\)\..*/Keycloak reports started in \1/p' "$work/kc.log" | head -n 1)"
	if [[ "$variant" == *-import ]]; then
		# Import cost from Keycloak's own log timestamps: from "Importing from
		# directory" to "Import finished successfully".
		record keycloak "import kc-$variant" "$run" "$(perl -ne '
			if (/^(\d{4}-\d\d-\d\d) (\d\d):(\d\d):(\d\d),(\d{3}) .*(Importing from directory|Import finished successfully)/) {
				my $t = $2 * 3600 + $3 * 60 + $4 + $5 / 1000;
				if ($6 eq "Importing from directory") { $start = $t } elsif (defined $start) { printf "%.0f\n", ($t - $start) * 1000; exit }
			}' "$work/kc.log")" "ms from Importing from directory to Import finished successfully (Keycloak log)"
	fi
	teardown_container keycloak "teardown kc-$variant" "$run" "$name"
}

run_keycloak() {
	local variant run
	log "keycloak: pull x$runs"
	pull_group keycloak "pull" "$KEYCLOAK_IMAGE"
	image_present "$KEYCLOAK_IMAGE" || { add_note "Keycloak image missing after pulls; start runs skipped."; return; }
	describe_images keycloak "$KEYCLOAK_IMAGE"
	for variant in dev dev-import tls tls-import; do
		for ((run = 1; run <= runs; run++)); do
			log "keycloak: kc-$variant run $run/$runs"
			keycloak_variant "$variant" "$run"
		done
	done
}

# ---------------------------------------------------------------------------
# OpenID Foundation conformance suite
# ---------------------------------------------------------------------------

oidf_smoke() {
	local run=$1 base="https://localhost.emobix.co.uk:$OIDF_PORT" resolve plan_id test_json issuer variant
	resolve="localhost.emobix.co.uk:$OIDF_PORT:127.0.0.1"
	if ! curl -sk --max-time 10 --resolve "$resolve" "$base/api/plan/available" -o "$work/plans.json"; then
		record oidf "smoke" "$run" "FAIL" "could not list plans"
		return
	fi
	# The RP test plans Revetsec plans to run must exist in the pinned release.
	if ! python3 - "$work/plans.json" >"$work/smoke.log" 2>&1 <<'PY'
import json, sys
names = {p.get("planName") for p in json.load(open(sys.argv[1]))}
wanted = [
	"oidcc-client-basic-certification-test-plan",
	"oidcc-client-config-certification-test-plan",
	"oidcc-client-formpost-basic-certification-test-plan",
	"oidcc-client-refreshtoken-test-plan",
	"oidcc-client-test-plan",
	"fapi2-security-profile-final-client-test-plan",
]
missing = [w for w in wanted if w not in names]
if missing:
	sys.exit("missing plans: " + ", ".join(missing))
print(f"{len(names)} plans; all {len(wanted)} wanted RP test plans present")
PY
	then
		record oidf "smoke" "$run" "FAIL" "$(tail -n 1 "$work/smoke.log")"
		return
	fi
	# Create a Basic RP plan and start its happy-path module, with no login
	# (dev profile), then drive a code flow against the module's issuer.
	variant=$(python3 -c 'import json, urllib.parse; print(urllib.parse.quote(json.dumps({"client_registration": "static_client", "request_type": "plain_http_request"})))')
	plan_id=$(curl -sk --max-time 10 --resolve "$resolve" -X POST -H 'Content-Type: application/json' \
		"$base/api/plan?planName=oidcc-client-basic-certification-test-plan&variant=$variant" \
		-d "{\"alias\":\"revetsec-spike-$run\",\"description\":\"Revetsec Tier-1 spike (test only)\",\"client\":{\"client_id\":\"$TEST_CLIENT_ID\",\"client_secret\":\"$TEST_CLIENT_SECRET\",\"redirect_uri\":\"$TEST_REDIRECT_URI\"}}" \
		| python3 -c 'import json, sys; print(json.load(sys.stdin)["id"])' 2>/dev/null || true)
	if [[ -z "$plan_id" ]]; then
		record oidf "smoke" "$run" "FAIL" "POST /api/plan failed"
		return
	fi
	test_json=$(curl -sk --max-time 10 --resolve "$resolve" -X POST "$base/api/runner?test=oidcc-client-test&plan=$plan_id" || true)
	issuer=""
	if [[ -n "$test_json" ]]; then
		local test_id
		test_id=$(printf '%s' "$test_json" | python3 -c 'import json, sys; print(json.load(sys.stdin)["id"])' 2>/dev/null || true)
		local attempt status=""
		# The module accepts requests only once it reports WAITING.
		for attempt in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20; do
			status=$(curl -sk --max-time 10 --resolve "$resolve" "$base/api/info/$test_id" \
				| python3 -c 'import json, sys; print(json.load(sys.stdin).get("status", ""))' 2>/dev/null || true)
			[[ "$status" == "WAITING" ]] && break
			sleep 0.5
		done
		issuer=$(curl -sk --max-time 10 --resolve "$resolve" "$base/api/runner/$test_id" \
			| python3 -c 'import json, sys; print(json.load(sys.stdin)["exposed"]["issuer"])' 2>/dev/null || true)
		if [[ "$status" != "WAITING" ]]; then
			record oidf "smoke" "$run" "FAIL" "test module status ${status:-unknown}, never WAITING"
			return
		fi
	fi
	if [[ -z "$issuer" ]]; then
		record oidf "smoke" "$run" "FAIL" "test module did not expose an issuer"
		return
	fi
	# The suite's nginx serves its own certificate, hence --insecure. The
	# issuer hostname must resolve to 127.0.0.1 (public DNS does this).
	if python3 "$SMOKE" --insecure --issuer "$issuer" --client-id "$TEST_CLIENT_ID" \
		--client-secret "$TEST_CLIENT_SECRET" --redirect-uri "$TEST_REDIRECT_URI" >>"$work/smoke.log" 2>&1; then
		record oidf "smoke" "$run" "pass" "$(head -n 1 "$work/smoke.log"); oidcc-client-test: $(tail -n 1 "$work/smoke.log")"
	else
		record oidf "smoke" "$run" "FAIL" "$(tail -n 1 "$work/smoke.log")"
		add_failure "oidf run $run: smoke" "$work/smoke.log"
	fi
}

run_oidf() {
	local run t0 t1 t2 images killed ids sigterm_noted=0
	images=$(oidf_images)
	log "oidf: pull x$runs ($(printf '%s\n' "$images" | wc -l | tr -d ' ') images in parallel)"
	# shellcheck disable=SC2086
	pull_group oidf "pull (3 images, parallel)" $images
	for ref in $images; do
		image_present "$ref" || { add_note "OIDF image $ref missing after pulls; start runs skipped."; return; }
	done
	# shellcheck disable=SC2086
	describe_images oidf $images
	for ((run = 1; run <= runs; run++)); do
		log "oidf: run $run/$runs"
		t0=$(now)
		if ! oidf up -d --pull never >"$work/oidf-up.log" 2>&1; then
			record oidf "start" "$run" "FAIL" "docker compose up failed"
			add_failure "oidf run $run: compose up" "$work/oidf-up.log"
			oidf down -v >/dev/null 2>&1 || true
			continue
		fi
		if wait_ready "https://localhost.emobix.co.uk:$OIDF_PORT/api/server" "\"tag\":\"$OIDF_TAG\"" "" \
			-k --resolve "localhost.emobix.co.uk:$OIDF_PORT:127.0.0.1"; then
			t1=$(now)
			record oidf "start" "$run" "$(elapsed "$t0" "$t1")" "compose up -d until /api/server reports $OIDF_TAG"
			oidf_smoke "$run"
			ids=$(oidf ps -q)
			# shellcheck disable=SC2086
			record oidf "memory" "$run" "$(memory_of $ids)" "docker stats right after ready"
		else
			record oidf "start" "$run" "FAIL" "not ready within ${READY_TIMEOUT}s"
			oidf logs --no-color server >"$work/oidf.log" 2>&1 || true
			add_failure "oidf run $run: not ready" "$work/oidf.log"
		fi
		t0=$(now)
		oidf stop -t 10 >/dev/null 2>&1 || true
		t1=$(now)
		# shellcheck disable=SC2046
		killed=$(docker inspect --format '{{.Name}} {{.State.ExitCode}}' $(oidf ps -aq) 2>/dev/null \
			| awk '$2 == 137 {sub("^/", "", $1); print $1}' | paste -sd ',' - || true)
		oidf down -v >/dev/null 2>&1 || true
		t2=$(now)
		record oidf "teardown" "$run" "$(elapsed "$t0" "$t2")" "compose stop -t 10 + compose down -v"
		record oidf "teardown: compose stop -t 10" "$run" "$(elapsed "$t0" "$t1")" \
			"${killed:+SIGKILL after the 10 s grace period: $killed}"
		record oidf "teardown: compose down -v" "$run" "$(elapsed "$t1" "$t2")" "containers, network, anonymous volumes"
		if [[ "$killed" == *server* && $sigterm_noted -eq 0 ]]; then
			sigterm_noted=1
			add_note "The OIDF \`server\` container ignores SIGTERM: its image entrypoint is \`/bin/sh -c \"java …\"\`, and the shell (PID 1) does not forward the signal, so a graceful stop always waits out the grace period. The suite keeps no state worth saving between CI runs, so teardown there should be \`docker compose kill\` (or \`down -t 0\`) followed by \`down -v\`; the \`compose down -v\` row shows what remains."
		fi
	done
}

# ---------------------------------------------------------------------------
# node-oidc-provider
# ---------------------------------------------------------------------------

run_node() {
	local base run t0 t1 name sizes
	base=$(node_base_image)
	[[ "$base" == *@sha256:* ]] || fail "the node-oidc-provider Dockerfile base is not pinned by digest."
	log "node: base image pull x$runs"
	pull_group node "pull base image" "$base"
	image_present "$base" || { add_note "node base image missing after pulls; build skipped."; return; }
	describe_images node "$base"

	for ((run = 1; run <= runs; run++)); do
		log "node: build without cache, run $run/$runs"
		t0=$(now)
		if docker build --no-cache --progress=plain -t "$NODE_IMAGE_TAG" "$NODE_DIR" >"$work/build.log" 2>&1; then
			t1=$(now)
			record node "build --no-cache" "$run" "$(elapsed "$t0" "$t1")" "npm ci downloads the locked packages every time"
		else
			record node "build --no-cache" "$run" "FAIL" "docker build failed"
			add_failure "node build run $run" "$work/build.log"
		fi
	done
	for ((run = 1; run <= runs; run++)); do
		t0=$(now)
		if docker build --progress=plain -t "$NODE_IMAGE_TAG" "$NODE_DIR" >"$work/build.log" 2>&1; then
			t1=$(now)
			record node "build (cached)" "$run" "$(elapsed "$t0" "$t1")" "all layers from the build cache"
		else
			record node "build (cached)" "$run" "FAIL" "docker build failed"
		fi
	done
	docker image inspect "$NODE_IMAGE_TAG" >/dev/null 2>&1 || { add_note "node image did not build; start runs skipped."; return; }
	sizes=$(image_sizes "$NODE_IMAGE_TAG")
	printf '%s\t%s\t%s\t%s\t%s\t%s\n' node "$NODE_IMAGE_TAG (built locally)" \
		"$(docker image inspect --format '{{.Architecture}}' "$NODE_IMAGE_TAG")" "n/a (built)" \
		"${sizes%%$'\t'*}" native >>"$work/images.tsv"

	for ((run = 1; run <= runs; run++)); do
		log "node: run $run/$runs"
		name="revetsec-spike-node-$run-$$"
		docker create --name "$name" --label "$label" -p "127.0.0.1:$NODE_PORT:3000" \
			-e "ISSUER=https://localhost:$NODE_PORT" -e TLS_CERT_FILE=/tls/cert.pem -e TLS_KEY_FILE=/tls/key.pem \
			"$NODE_IMAGE_TAG" >/dev/null
		docker cp "$stage/tls" "$name:/tls" >/dev/null
		t0=$(now)
		docker start "$name" >/dev/null
		if wait_ready "https://localhost:$NODE_PORT/.well-known/openid-configuration" '"issuer"' "$name" --cacert "$ca"; then
			t1=$(now)
			record node "start (TLS)" "$run" "$(elapsed "$t0" "$t1")" "discovery document answers 200 over TLS"
			if python3 "$SMOKE" --cafile "$ca" --issuer "https://localhost:$NODE_PORT" --client-id "$TEST_CLIENT_ID" \
				--client-secret "$TEST_CLIENT_SECRET" --redirect-uri "$TEST_REDIRECT_URI" >"$work/smoke.log" 2>&1; then
				record node "smoke" "$run" "pass" "$(tail -n 1 "$work/smoke.log")"
			else
				record node "smoke" "$run" "FAIL" "$(tail -n 1 "$work/smoke.log")"
				docker logs "$name" >>"$work/smoke.log" 2>&1 || true
				add_failure "node run $run: smoke" "$work/smoke.log"
			fi
			record node "memory" "$run" "$(memory_of "$name")" "docker stats right after ready"
		else
			record node "start (TLS)" "$run" "FAIL" "not ready within ${READY_TIMEOUT}s"
			docker logs "$name" >"$work/node.log" 2>&1 || true
			add_failure "node run $run: not ready" "$work/node.log"
		fi
		teardown_container node "teardown" "$run" "$name"
	done
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

ports_needed=""
wants keycloak && ports_needed="$ports_needed $KC_HTTP_PORT $KC_HTTPS_PORT $KC_MGMT_PORT"
wants oidf && ports_needed="$ports_needed $OIDF_PORT $OIDF_MTLS_PORT"
wants node && ports_needed="$ports_needed $NODE_PORT"
for port in $ports_needed; do
	port_free "$port" || fail "host port 127.0.0.1:$port is in use; override it (see --help)."
done

: >"$work/images.tsv"
selected_images() {
	wants keycloak && printf '%s\n' "$KEYCLOAK_IMAGE"
	wants oidf && oidf_images
	wants node && node_base_image
	return 0
}
for ref in $(selected_images); do
	if image_present "$ref"; then
		add_note "Already cached when the script started: \`$ref\`$( [[ $cold -eq 1 ]] && echo ' (removed again before every pull run because of --cold)')."
	fi
done

collect_host_info
set_meta "TLS material" "$tls_source"
set_meta "Command" "$command_line"
set_meta "Runs per measurement" "$runs"
set_meta "Cold pulls requested (--cold)" "$( [[ $cold -eq 1 ]] && echo yes || echo no )"
set_meta "Load average at start" "$(uptime | sed 's/.*load averages*: //')"
set_meta "Script SHA-256" "$(python3 -c 'import hashlib, sys; print(hashlib.sha256(open(sys.argv[1], "rb").read()).hexdigest())' "$0")"

started=$(now)
wants keycloak && run_keycloak
wants oidf && run_oidf
wants node && run_node
set_meta "Total wall time" "$(elapsed "$started" "$(now)") s"
set_meta "Load average at end" "$(uptime | sed 's/.*load averages*: //')"

log "writing $output"
node_version=$(python3 -c 'import json, sys; print(json.load(open(sys.argv[1]))["dependencies"]["oidc-provider"])' \
	"$NODE_DIR/package.json")
github_hosted=no
if [[ "${GITHUB_ACTIONS:-}" == true && "${RUNNER_ENVIRONMENT:-}" == github-hosted ]]; then
	github_hosted=yes
fi
python3 - "$raw" "$meta" "$notes" "$failures" "$work/images.tsv" "$output" \
	"$KEYCLOAK_IMAGE" "$OIDF_TAG" "$node_version" "$github_hosted" <<'PY'
import statistics
import sys

raw_path, meta_path, notes_path, failures_path, images_path, output_path = sys.argv[1:7]
keycloak_image, oidf_tag, node_version, github_hosted = sys.argv[7:11]

def rows(path, width):
	out = []
	with open(path, encoding="utf-8") as handle:
		for line in handle:
			line = line.rstrip("\n")
			if line:
				parts = line.split("\t")
				out.append(parts + [""] * (width - len(parts)))
	return out

raw = rows(raw_path, 5)
meta = rows(meta_path, 2)
images = rows(images_path, 6)
notes = [line.rstrip("\n") for line in open(notes_path, encoding="utf-8") if line.strip()]
failures = open(failures_path, encoding="utf-8").read()
meta_map = {key: value for key, value in meta}

# Titles come from the pins this run used, so a re-run after moving a pin labels its rows correctly.
keycloak_name = keycloak_image.split("@")[0]
keycloak_version = keycloak_name.rsplit(":", 1)[1] if ":" in keycloak_name.rsplit("/", 1)[-1] else keycloak_image
TARGET_TITLES = {
	"keycloak": f"Keycloak {keycloak_version}",
	"oidf": f"OIDF conformance suite {oidf_tag}",
	"node": f"node-oidc-provider {node_version}",
}
host_os = meta_map.get("Host OS", "?")
docker_platform = meta_map.get("Docker platform", "?")
if docker_platform in ("", "?", "n/a"):
	docker_platform = "Docker"
on_github_runner = github_hosted == "yes"
other_containers = meta_map.get("Other running containers", "?").split(" ", 1)[0]

# Ordered (target, step) keys and per-run values.
series = {}
order = []
for target, step, run, value, note in raw:
	key = (target, step)
	if key not in series:
		series[key] = {}
		order.append(key)
	series[key][int(run)] = (value, note)

runs = max((run for values in series.values() for run in values), default=0)

def seconds(value):
	try:
		return float(value)
	except ValueError:
		return None

def fmt(value):
	number = seconds(value)
	return f"{number:.2f}" if number is not None else value

def summary(values):
	numbers = [seconds(v) for v, _ in values.values()]
	numbers = [n for n in numbers if n is not None]
	failed = sum(1 for v, _ in values.values() if v == "FAIL")
	if not numbers:
		return "", failed
	median = statistics.median(numbers)
	text = f"**{median:.2f}**"
	if len(numbers) > 1:
		text += f" ({min(numbers):.2f}–{max(numbers):.2f})"
	return text, failed

timed_prefixes = ("pull", "start", "realm visible", "teardown", "build")
lines = []
emit = lines.append

emit("# Tier-1 container spike results")
emit("")
emit(f"Generated by `interop/spike/tier1-spike.sh` on {meta_map.get('Date (UTC)', '?')} UTC. "
	"Every number below was measured by that script on the host described here; nothing is estimated. "
	"Re-running the script overwrites this file.")
emit("")
emit("The CI legs for these partners are to run on GitHub-hosted `ubuntu-24.04` and `ubuntu-24.04-arm` runners. "
	+ (f"This run is a GitHub-hosted runner leg, on **{host_os}** with {docker_platform}."
		if on_github_runner else
		f"This run is a local leg only, on **{host_os}** with {docker_platform}. "
		"The GitHub-runner legs will differ (see Caveats)."))
emit("")

emit("## Host")
emit("")
emit("| Item | Value |")
emit("|---|---|")
for key, value in meta:
	emit(f"| {key} | {value.replace('|', '/')} |")
emit("")

emit("## Images")
emit("")
emit("Pinned by multi-arch index digest. Download size is the compressed size of the host-platform manifest "
	"as recorded in the local content store; disk size is the unpacked size.")
emit("")
emit("| Target | Image | Arch | Download | On disk | Execution |")
emit("|---|---|---|---|---|---|")
for target, ref, arch, content, disk, execution in images:
	emit(f"| {target} | `{ref}` | {arch} | {content} | {disk} | {execution} |")
emit("")

emit("## Timings (seconds)")
emit("")
emit("Median of the successful runs in bold, then (min–max). Start-to-ready runs from `docker start` "
	"(container already created, files already copied in) or from `docker compose up -d` (OIDF) to the first "
	"HTTP 200 from the readiness endpoint, polled every 0.1 s. Teardown is a graceful `docker stop -t 10` "
	"plus `docker rm -v` (OIDF: `compose stop -t 10` plus `compose down -v`).")
emit("")
header = "| Target | Step | " + " | ".join(f"Run {i}" for i in range(1, runs + 1)) + " | Median (min–max) | Notes |"
emit(header)
emit("|" + "---|" * (runs + 4))
for key in order:
	target, step = key
	if not step.startswith(timed_prefixes):
		continue
	values = series[key]
	cells = [fmt(values[i][0]) if i in values else "" for i in range(1, runs + 1)]
	text, failed = summary(values)
	run_notes = []
	for i in range(1, runs + 1):
		if i in values and values[i][1] and values[i][1] not in run_notes:
			run_notes.append(values[i][1])
	if failed:
		run_notes.insert(0, f"{failed} run(s) FAILED")
	emit(f"| {TARGET_TITLES.get(target, target)} | {step} | " + " | ".join(cells)
		+ f" | {text} | {'; '.join(run_notes).replace('|', '/')} |")
emit("")

# Keycloak import cost.
def median_of(target, step):
	values = series.get((target, step), {})
	numbers = [seconds(v) for v, _ in values.values()]
	numbers = [n for n in numbers if n is not None]
	return statistics.median(numbers) if numbers else None

emit("### Derived")
emit("")
derived = []
for mode in ("dev", "tls"):
	base = median_of("keycloak", f"start kc-{mode}")
	imported = median_of("keycloak", f"realm visible kc-{mode}-import")
	from_log = median_of("keycloak", f"import kc-{mode}-import")
	if base is not None and imported is not None:
		text = (f"- Keycloak realm import at start ({mode}): median realm-visible time with `--import-realm` "
			f"minus median ready time without it = **{imported - base:+.2f} s** (run-to-run noise included)")
		if from_log is not None:
			text += f"; Keycloak's own log puts the import itself at a median **{from_log:.0f} ms**"
		derived.append(text + ".")
def megabytes(text):
	units = {"kB": 1e-3, "MB": 1.0, "GB": 1e3}
	for unit, factor in units.items():
		if text.endswith(unit):
			try:
				return float(text[: -len(unit)]) * factor
			except ValueError:
				return None
	return None

for key in order:
	target, step = key
	if not step.startswith("pull"):
		continue
	cold = [seconds(v) for v, note in series[key].values() if note.startswith("cold")]
	cold = [c for c in cold if c is not None]
	sizes = [megabytes(content) for t, _, _, content, _, _ in images if t == target and "(built locally)" not in _]
	if cold and sizes and all(size is not None for size in sizes):
		total = sum(sizes)
		median = statistics.median(cold)
		derived.append(f"- {TARGET_TITLES.get(target, target)} {step}: {total:.0f} MB compressed in a median "
			f"{median:.2f} s over {len(cold)} cold run(s) = **{total / median:.1f} MB/s** effective.")
if not derived:
	derived.append("- (no derived values: a required series failed or was not run)")
lines.extend(derived)
emit("")

emit("## Smoke checks, memory and logs")
emit("")
emit("Every started OP was exercised, untimed, after readiness: `oidc_smoke.py` runs discovery, an "
	"authorization-code flow with PKCE (auto-login for node-oidc-provider and the OIDF suite, the login form POST "
	"for Keycloak) and a code exchange, and checks the ID token's `iss`, `aud` and `nonce` (not its signature). "
	"For Keycloak, `KeycloakJdkLogin.java` repeats the login and code exchange with the JDK alone.")
emit("")
emit("| Target | Item | " + " | ".join(f"Run {i}" for i in range(1, runs + 1)) + " | Detail |")
emit("|" + "---|" * (runs + 3))
for key in order:
	target, step = key
	if step.startswith(timed_prefixes):
		continue
	values = series[key]
	cells = [values[i][0] if i in values else "" for i in range(1, runs + 1)]
	if step.startswith("log kc-"):
		cells = [f"{c} ms" if c else "" for c in cells]
		item = step.replace("log ", "Quarkus augmentation ")
	elif step.startswith("import kc-"):
		cells = [f"{c} ms" if c else "" for c in cells]
		item = step.replace("import ", "realm import (from log) ")
	else:
		item = step
	details = []
	for i in range(1, runs + 1):
		if i in values and values[i][1] and values[i][1] not in details:
			details.append(values[i][1])
	emit(f"| {TARGET_TITLES.get(target, target)} | {item} | " + " | ".join(c.replace('|', '/') for c in cells)
		+ f" | {'; '.join(details).replace('|', '/')} |")
emit("")

emit("## Caveats")
emit("")
static_caveats = [
	f"**One machine, one network.** These numbers come from a single host, {host_os}, running {docker_platform}"
	+ (f", with {other_containers} other containers sharing its Docker daemon (see Host)"
		if other_containers not in ("0", "?") else "")
	+ (". Another runner image, region or time of day will give different numbers."
		if on_github_runner else
		". GitHub `ubuntu-24.04` (x64) and `ubuntu-24.04-arm` runners have different CPUs, disks and network, "
		"so re-run the script there before using these numbers as CI time estimates."),
	"**Pull times measure this network.** Download sizes are the portable figure. With `--cold` the image is "
	"removed before every pull, but layers shared with other local images (\"already local\") and layers held "
	"by the BuildKit cache are not downloaded again; the per-run note says which. A GitHub-hosted runner starts "
	"with an empty cache, so every CI pull is cold.",
	"**Start-to-ready excludes `docker create`/`docker cp`** (tens of milliseconds each) for the single-container "
	"targets; the OIDF figure includes creating the network and all three containers. Polling every 0.1 s adds up "
	"to ~0.1 s.",
	"**Keycloak starts from the upstream image every time**, so each start includes the Quarkus build "
	"(\"augmentation\", reported above) for the options given. A derived image built with `kc.sh build` and "
	"started with `--optimized` would skip it; that is not measured here.",
	"**\"Production-like\" Keycloak is not production**: `start` with HTTPS only, the hostname set, health "
	"enabled and the default clustered cache, but the embedded `dev-file` database instead of PostgreSQL.",
	"**Keycloak's login cookies are `Secure` even over plain HTTP.** Browsers treat `http://localhost` as a "
	"secure context and send them; Python's `CookieJar` and `java.net.CookieManager` do not, which makes a "
	"headless login fail with `cookie_not_found`. The smoke check treats loopback as secure. The `jdk login` rows run "
	"`KeycloakJdkLogin.java` (`java.net.http` + `CookieManager`, the recipe planned for the Java harness); its "
	"plain-HTTP leg is expected to fail with `cookie_not_found`, so the Java harness must run Keycloak over TLS.",
	f"**TLS material**: {meta_map.get('TLS material', '?')}. Keycloak (production-like variants) and "
	"node-oidc-provider serve it, and every client verifies it against the trust anchor. "
	"The OIDF suite's nginx serves its own certificate for `localhost.emobix.co.uk`, so its smoke check skips "
	"TLS verification, and its issuer hostname relies on public DNS resolving `localhost.emobix.co.uk` to "
	"127.0.0.1 (an `/etc/hosts` entry is needed where DNS is unavailable). Its ports are fixed at 8443/8444 "
	"because the suite calls its own `BASE_URL`.",
	"**node-oidc-provider** uses the in-memory adapter and generates its signing keys and cookie keys at every "
	"start; tests must fetch the JWKS. Its `build --no-cache` time includes `npm ci` downloading the 40 locked "
	"packages from registry.npmjs.org.",
]
for caveat in static_caveats:
	emit(f"- {caveat}")
for note in notes:
	emit(f"- {note}")
emit("")

if failures.strip():
	emit("## Failures")
	emit("")
	emit(failures.rstrip())
	emit("")

emit("## Re-running")
emit("")
emit("```sh")
emit("interop/spike/tier1-spike.sh              # 3 runs, all targets, images kept")
emit("interop/spike/tier1-spike.sh --cold       # remove the pinned images before every pull")
emit("interop/spike/tier1-spike.sh --only oidf --runs 1")
emit("```")
emit("")
emit("The script removes every container, network and anonymous volume it creates, including on failure. "
	"It never pushes an image.")

with open(output_path, "w", encoding="utf-8") as handle:
	handle.write("\n".join(lines) + "\n")
PY

chmod 644 "$output"
log "done: $output"
