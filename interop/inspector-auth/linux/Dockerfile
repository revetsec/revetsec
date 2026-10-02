# Copyright 2026 Revetware LLC.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

FROM mcr.microsoft.com/playwright@sha256:eff16c30e6f3f4af0a03fa4b706120d5e9b0891c344a27d64559aff5900a4a27
COPY artifacts/nss-tools.deb /tmp/nss-tools.deb
RUN echo '02d5f5e9d7a40d79fd23448b3f4016b7c83113f2b0df9f55efa16a39be33ce97  /tmp/nss-tools.deb' | sha256sum -c - \
    && dpkg --install /tmp/nss-tools.deb \
    && rm -f /tmp/nss-tools.deb
COPY client/package.json client/package-lock.json /private/inspector-client/
RUN npm ci --prefix /private/inspector-client --ignore-scripts --no-audit --no-fund --registry https://registry.npmjs.org
USER pwuser
