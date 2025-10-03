#!/bin/bash
# Copyright 2025 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
set -eo pipefail

SCRIPT_DIR=$(dirname $(realpath "$0"))
IMAGE_DB_DIR="$SCRIPT_DIR/../../image_db"
KXDB_TOOL_DIR="$SCRIPT_DIR/../../kxdb_tool"
LIBXDK_DIR="$SCRIPT_DIR/../../libxdk"
KXDB_FN="$SCRIPT_DIR/test.kxdb"

usage() {
    echo "Usage: $0 (kernelctf|ubuntu) <release-name> [--keep-image-db]";
    exit 1;
}

ARGS=()
while [[ $# -gt 0 ]]; do
  case $1 in
    --keep-image-db) KEEP_IMAGE_DB=1; shift;;
    --) # stop processing special arguments after "--"
        shift
        while [[ $# -gt 0 ]]; do ARGS+=("$1"); shift; done
        break
        ;;
    -*|--*) echo "Unknown option $1"; usage;;
    *) ARGS+=("$1"); shift;;
  esac
done
set -- "${ARGS[@]}"

DISTRO="$1"
RELEASE="$2"
RELEASE_DIR="$IMAGE_DB_DIR/releases/$DISTRO/$RELEASE"

if [[ ! "$DISTRO" =~ ^(kernelctf|ubuntu)$ || -z "$RELEASE" ]]; then usage; fi

if [ "$KEEP_IMAGE_DB" == "" ]; then
  # cleanup generated Image DB artifacts
  for FN in btf.json symbols.txt rop_actions.json stack_pivots.json structs.json vmlinux.thunk_replaced; do
    if [ -f "$RELEASE_DIR/$FN" ]; then
      rm "$RELEASE_DIR/$FN";
    fi
  done
fi

"$IMAGE_DB_DIR/download_release.sh" "$DISTRO" "$RELEASE" dbgsym,vmlinuz,process
"$IMAGE_DB_DIR/collect_runtime_data.sh"
"$KXDB_TOOL_DIR/kxdb_tool.py" --image-db-path "$IMAGE_DB_DIR" --release-filter "$DISTRO/$RELEASE" -o "$KXDB_FN"
cp "$KXDB_FN" "$LIBXDK_DIR/test/artifacts/kernelctf.kxdb"
cp "$KXDB_FN" "$LIBXDK_DIR/build/test/artifacts/kernelctf.kxdb"
cp "$KXDB_FN" "$LIBXDK_DIR/samples/pipe_buf_rop/target_db.kxdb"

cd "$LIBXDK_DIR"

printf "\n=======================\n"
printf "Running libxdk tests...\n"
printf "=======================\n\n"
./run_tests.sh "$DISTRO" "$RELEASE" 20 --tap --test-suites "^PivotStaticTests"

for ACTION in "test" "stability_test"; do
  printf "\n====================================\n"
  printf "Running pipe_buf_rop $ACTION...\n"
  printf "====================================\n\n"
  make -j`nproc` -C samples/pipe_buf_rop TARGET="$DISTRO $RELEASE" $ACTION
done
