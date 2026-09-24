#!/bin/bash -eu
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

# ClusterFuzzLite build script for RevetSec. The base image's `compile` command runs it inside the
# image built from .clusterfuzzlite/Dockerfile, with the repository at $SRC/revetsec. `compile`
# has already copied the base image's jazzer_driver, jazzer_agent_deploy.jar and jazzer_junit.jar
# into $OUT.
#
# Every Jazzer @FuzzTest method in fuzz/src/test/java/**/*FuzzTests.java becomes one libFuzzer
# target: an executable wrapper $OUT/<SimpleClassName>_<method> that runs the method through the
# base image's Jazzer driver (--target_class/--target_method), plus
# $OUT/<SimpleClassName>_<method>_seed_corpus.zip built from the checked-in seeds under
# fuzz/src/test/resources/<package>/<SimpleClassName>Inputs/<method>/.
#
# The same targets run locally, without Docker, as JUnit tests:
#   mvn -B -ntp -f fuzz/pom.xml verify                     (seed replay)
#   JAZZER_FUZZ=1 mvn -B -ntp -f fuzz/pom.xml test -Dtest=<Class>#<method>  (fuzzing)

readonly REPO_DIR="$SRC/revetsec"
readonly FUZZ_OUT="$OUT/revetsec-fuzz"
readonly DEPENDENCY_PLUGIN="org.apache.maven.plugins:maven-dependency-plugin:3.11.0"

fail() {
	echo "ERROR: $*" >&2
	exit 1
}

cd "$REPO_DIR"

# The base image's JDK is the one the runner uses too. RevetSec targets Java 17.
java_spec=$("$JAVA_HOME/bin/java" -XshowSettings:properties -version 2>&1 \
	| sed -n 's/^ *java\.specification\.version = //p')
[[ "$java_spec" =~ ^[0-9]+$ ]] || fail "could not read the Java version of $JAVA_HOME"
(( java_spec >= 17 )) || fail "RevetSec needs JDK 17 or newer; $JAVA_HOME is Java $java_spec"

for required in jazzer_driver jazzer_agent_deploy.jar jazzer_junit.jar; do
	[[ -f "$OUT/$required" ]] || fail "$OUT/$required is missing; is FUZZING_LANGUAGE=jvm set?"
done

# Fuzz target classes are the fuzz module's own *FuzzTests classes (the same set Surefire runs).
mapfile -t fuzz_classes < <(
	cd fuzz/src/test/java \
		&& find . -type f -name '*FuzzTests.java' \
		| sed -e 's|^\./||' -e 's|\.java$||' -e 's|/|.|g' \
		| LC_ALL=C sort
)
(( ${#fuzz_classes[@]} > 0 )) || fail "no *FuzzTests.java classes under fuzz/src/test/java"
class_list=$(IFS=,; echo "${fuzz_classes[*]}")

rm -rf "$FUZZ_OUT"
mkdir -p "$FUZZ_OUT/lib"

# Compile RevetSec's main sources and the fuzz module's test tree, then copy the test-scope jars
# the targets need at runtime (JUnit Platform, Jupiter and their dependencies). Jazzer's own jars
# are excluded: at runtime the base image's Jazzer agent and JUnit integration are used, and a
# second copy of Jazzer on the classpath would mix versions.
"$MVN" -B -ntp -f fuzz/pom.xml \
	test-compile \
	"$DEPENDENCY_PLUGIN:copy-dependencies" \
	-DincludeScope=test \
	-DexcludeGroupIds=com.code-intelligence \
	-DoutputDirectory="$FUZZ_OUT/lib"

cp -R fuzz/target/test-classes "$FUZZ_OUT/test-classes"
# Jazzer's JUnit runner adds <Class>Inputs/<method>/ from the classpath as extra input directories.
# ClusterFuzzLite supplies the same seeds through <target>_seed_corpus.zip, and its bad-build check
# requires a `-runs=4` start-up run to execute exactly four inputs, so the seed directories are
# removed from the runtime copy (they stay in fuzz/target for the Maven replay).
for fuzz_class in "${fuzz_classes[@]}"; do
	rm -rf "$FUZZ_OUT/test-classes/${fuzz_class//.//}Inputs"
done
if [[ -d fuzz/target/classes ]]; then
	cp -R fuzz/target/classes "$FUZZ_OUT/classes"
else
	mkdir -p "$FUZZ_OUT/classes"
fi

shopt -s nullglob
lib_jars=("$FUZZ_OUT"/lib/*.jar)
shopt -u nullglob
(( ${#lib_jars[@]} > 0 )) || fail "no runtime jars were copied to $FUZZ_OUT/lib"

build_cp="$FUZZ_OUT/classes:$FUZZ_OUT/test-classes"
# The literal $this_dir is expanded by the wrapper at run time (ClusterFuzzLite copies $OUT before
# running targets), so single quotes are intended here.
# shellcheck disable=SC2016
runtime_cp='$this_dir/revetsec-fuzz/classes:$this_dir/revetsec-fuzz/test-classes'
for jar in "${lib_jars[@]}"; do
	jar_name=$(basename "$jar")
	[[ "$jar_name" =~ ^[A-Za-z0-9._-]+$ ]] || fail "unexpected jar file name: $jar_name"
	build_cp="$build_cp:$jar"
	runtime_cp="$runtime_cp:\$this_dir/revetsec-fuzz/lib/$jar_name"
done
build_cp="$build_cp:$OUT/jazzer_junit.jar"
runtime_cp="$runtime_cp:\$this_dir/jazzer_junit.jar"

# Ask Jazzer itself which @FuzzTest methods those classes declare ("<class>::<method>" lines).
mapfile -t fuzz_tests < <(
	LD_LIBRARY_PATH="$JVM_LD_LIBRARY_PATH" "$OUT/jazzer_driver" \
		--agent_path="$OUT/jazzer_agent_deploy.jar" \
		--cp="$build_cp" \
		--list_fuzz_tests="$class_list" 2>/dev/null \
		| grep -F '::' \
		| LC_ALL=C sort -u
)
(( ${#fuzz_tests[@]} > 0 )) || fail "Jazzer listed no @FuzzTest methods in: $class_list"
for fuzz_test in "${fuzz_tests[@]}"; do
	# The names are pasted into the generated wrapper, so allow only plain identifiers.
	[[ "$fuzz_test" =~ ^[A-Za-z0-9_.]+::[A-Za-z0-9_]+$ ]] || fail "unsupported fuzz test name: $fuzz_test"
done

declare -A seen_targets=()
for fuzz_test in "${fuzz_tests[@]}"; do
	target_class=${fuzz_test%%::*}
	target_method=${fuzz_test##*::}
	simple_class=${target_class##*.}
	target_name="${simple_class}_${target_method}"

	# ClusterFuzzLite accepts only [A-Za-z0-9_-] in target names.
	[[ "$target_name" =~ ^[A-Za-z0-9_-]+$ ]] || fail "invalid fuzz target name: $target_name"
	[[ -z "${seen_targets[$target_name]:-}" ]] \
		|| fail "duplicate fuzz target name $target_name ($fuzz_test and ${seen_targets[$target_name]})"
	seen_targets[$target_name]="$fuzz_test"

	# The comment line below is how ClusterFuzzLite recognizes the script as a fuzz target.
	cat > "$OUT/$target_name" <<EOF
#!/bin/bash
# LLVMFuzzerTestOneInput for fuzzer detection.
# Generated by .clusterfuzzlite/build.sh: $fuzz_test
this_dir=\$(dirname "\$0")
classpath="$runtime_cp"
if [[ "\$*" =~ (^| )-runs=[0-9]+(\$| ) ]]; then
	mem_settings='-Xmx1900m:-Xss900k'
else
	mem_settings='-Xmx2048m:-Xss1024k'
fi
LD_LIBRARY_PATH="\${JVM_LD_LIBRARY_PATH:-$JVM_LD_LIBRARY_PATH}:\$this_dir" \\
"\$this_dir/jazzer_driver" --agent_path="\$this_dir/jazzer_agent_deploy.jar" \\
	--cp="\$classpath" \\
	--target_class=$target_class \\
	--target_method=$target_method \\
	'--instrumentation_includes=com.revetsec.**' \\
	--jvm_args="\$mem_settings" \\
	"\$@"
EOF
	chmod 0755 "$OUT/$target_name"

	seed_zip="$OUT/${target_name}_seed_corpus.zip"
	seed_dir="fuzz/src/test/resources/${target_class//.//}Inputs/$target_method"
	rm -f "$seed_zip"
	if [[ -d "$seed_dir" ]] && [[ -n "$(find "$seed_dir" -type f -print -quit)" ]]; then
		(cd "$seed_dir" && find . -type f | LC_ALL=C sort | zip -q -X -@ "$seed_zip")
	fi

	echo "Built fuzz target $target_name ($fuzz_test)"
done
