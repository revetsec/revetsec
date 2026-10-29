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

# ClusterFuzzLite builder image for Revetsec's Jazzer targets (fuzz/).
#
# The build context is the repository root. ClusterFuzzLite clones the repository at the commit
# under test, runs `docker build -f .clusterfuzzlite/Dockerfile <clone>`, and then runs `compile`
# (which calls $SRC/build.sh) in this image. The repository must be copied to $SRC/<repo name>,
# which is $SRC/revetsec.
#
# JDK: the base image ships Temurin 17.0.16+8 as $JAVA_HOME (/usr/lib/jvm/java-17-openjdk-amd64),
# checked on 2026-10-28 for this digest and for gcr.io/oss-fuzz-base/clusterfuzzlite-run-fuzzers:v1
# (sha256:a0dd50326eb0dc912362a441304799d2fe3afff5442a718b9371715adef6d25d), the runner image.
# The ClusterFuzzLite docs still say "OpenJDK 15", which is stale. No extra JDK is installed here;
# build.sh fails if $JAVA_HOME is older than 17.
#
# JVM fuzzing in OSS-Fuzz and ClusterFuzzLite is x86_64 only, and this digest is a single-platform
# linux/amd64 image. On an arm64 machine, build and run it with --platform linux/amd64 (emulated);
# see fuzz/README.md.

# The v1 tag matches the ClusterFuzzLite v1 actions; on 2026-10-28 it and :latest resolved to this
# digest (image created 2026-10-12). The digest is what Docker uses; the tag is for readers and
# Dependabot. The workflows run the clusterfuzzlite-build-fuzzers and -run-fuzzers images as
# digest-pinned docker:// steps (.github/workflows/cflite_*.yml); move those digests with this one.
FROM gcr.io/oss-fuzz-base/base-builder-jvm:v1@sha256:bd13a763de1a0fb22099442094e7e0049657a8c47f01e9d7af8bb849e0ad4699

# Maven is not in the base image. Ubuntu 20.04's apt package is 3.6.3, older than the fuzz pom's
# enforcer floor (3.9.0), so install a pinned release from Maven Central and verify its SHA-512
# (the value published on Central next to the artifact).
SHELL ["/bin/bash", "-o", "pipefail", "-c"]
ARG MAVEN_VERSION=3.10.0
ARG MAVEN_SHA512=908b1501bfb420bf7c8affb855534a9c407fd6099367bfb9f2f2dcb8e9799102bffb84518cde74c679bd76870247c6528683abdd620581bffa90f95d92d175aa
RUN set -eux; \
	curl --fail --silent --show-error --location --proto '=https' --tlsv1.2 \
		--output /tmp/maven.tar.gz \
		"https://repo1.maven.org/maven2/org/apache/maven/apache-maven/${MAVEN_VERSION}/apache-maven-${MAVEN_VERSION}-bin.tar.gz"; \
	echo "${MAVEN_SHA512}  /tmp/maven.tar.gz" | sha512sum --check --strict -; \
	mkdir -p /opt/maven; \
	tar -xzf /tmp/maven.tar.gz --strip-components=1 --directory /opt/maven; \
	rm -f /tmp/maven.tar.gz; \
	/opt/maven/bin/mvn --version
ENV MVN=/opt/maven/bin/mvn

COPY . $SRC/revetsec
WORKDIR $SRC/revetsec
COPY .clusterfuzzlite/build.sh $SRC/
