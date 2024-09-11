#!/bin/bash
# Copyright 2024 Google LLC
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

set -e

SCRIPT_DIR=$(dirname $(realpath "$0"))
cd $SCRIPT_DIR

usage() {
    echo "Usage: $0 [(kernelctf|ubuntu) <release-name>]";
    exit 1;
}

DISTRO="$1"
RELEASE_NAME="$2"

# fallback to some default release in case we just want to
# test the module, but it does not really matter on which version
if [ -z "$DISTRO" ] && [ -z "$RELEASE_NAME"]; then
    DISTRO="kernelctf"
    RELEASE_NAME="lts-6.1.58"
fi

gcc -static -Werror -o ../rootfs/kpwn_test kpwn_test.c
../run.sh "$DISTRO" "$RELEASE_NAME" --custom-modules=kpwn -- /kpwn_test ${@:3}
