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

SCRIPT_DIR=$(dirname $(realpath "$0"))
RUNNER_DIR="$SCRIPT_DIR/../kernel-image-runner"

for RELEASE_DIR in releases/*/*; do
    RELEASE_DIR_PARTS=(${RELEASE_DIR//\// })
    DISTRO=${RELEASE_DIR_PARTS[1]}
    RELEASE_NAME=${RELEASE_DIR_PARTS[2]}
    for PROC_FN in version slabinfo; do
        OUT_FN="$RELEASE_DIR/$PROC_FN.txt"
        if [ -f "$OUT_FN" ]; then continue; fi

        echo "Getting $PROC_FN for $DISTRO $RELEASE_NAME..."
        $RUNNER_DIR/run.sh --only-command-output $DISTRO $RELEASE_NAME -- cat /proc/$PROC_FN > $OUT_FN
    done
done