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

# RevetSec scripted IdP, a SAML test partner. Test tooling only: build it locally or in
# CI with load: true and push: false. Never push this image to a registry; that would be
# publication, and it would redistribute Alpine's GPL busybox and the xmlsec wheel's
# statically linked LGPL libiconv.
#
#   docker build -t revetsec-scripted-idp interop/scripted-idp
#   docker run --rm -v "$PWD/out:/out" revetsec-scripted-idp selftest --out /out
#   docker run --rm -p 8443:8443 -v <tls-dir>:/run/tls:ro \
#     -e SCRIPTED_IDP_TLS_CERT=/run/tls/server.crt -e SCRIPTED_IDP_TLS_KEY=/run/tls/server.key \
#     revetsec-scripted-idp serve

# python:3.13-alpine3.24 (Python 3.13.15, Alpine 3.24.2), multi-arch index digest resolved
# 2026-09-23 with `docker buildx imagetools inspect python:3.13-alpine3.24`.
FROM python:3.13-alpine3.24@sha256:79e7a9b9ff1cbceff819f856fb374477792a5967759d94df266de7b7b4120e6f

LABEL org.opencontainers.image.title="revetsec-scripted-idp" \
      org.opencontainers.image.description="RevetSec SAML test IdP (libxmlsec1 + signxml). Test tooling; never pushed." \
      org.opencontainers.image.licenses="Apache-2.0"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_ROOT_USER_ACTION=ignore

WORKDIR /app

# Wheels only, every file hash-checked, no resolver: an sdist can never silently change
# the libxmlsec1/libxml2/OpenSSL lineage bundled in the xmlsec wheel.
COPY requirements.txt ./
RUN pip install --require-hashes --only-binary=:all: --no-deps -r requirements.txt \
 && pip check

COPY scripted_idp ./scripted_idp
RUN python -m compileall -q scripted_idp

USER 65534:65534

# Build-time selftest: spike cases 1-6. A broken pin or pairing fails the image build.
RUN python -m scripted_idp selftest --out /tmp/selftest \
 && rm -rf /tmp/selftest

EXPOSE 8443
ENTRYPOINT ["python", "-m", "scripted_idp"]
CMD ["serve"]
