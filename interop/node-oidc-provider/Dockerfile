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

# TEST-ONLY OpenID Provider image for Revetsec interop legs. Build it locally or
# in CI with --load; it is never pushed to a registry.
#
# Base: node 24.21.0 on Alpine 3.24, pinned by the multi-arch index digest
# (linux/amd64 and linux/arm64). Move the pin only in a deliberate PR.
FROM node:24.21.0-alpine3.24@sha256:ebfe2f90462722a7a4de65e91990e97fe0d401c70e0e762c5b53302f905ec1c1

ENV NODE_ENV=production \
	NPM_CONFIG_UPDATE_NOTIFIER=false \
	PORT=3000

WORKDIR /app

# Install exactly what package-lock.json pins (integrity-checked), without
# running any package lifecycle scripts.
COPY package.json package-lock.json ./
RUN npm ci --omit=dev --ignore-scripts --no-audit --no-fund \
	&& npm cache clean --force

COPY server.js ./

USER node
EXPOSE 3000
CMD ["node", "server.js"]
