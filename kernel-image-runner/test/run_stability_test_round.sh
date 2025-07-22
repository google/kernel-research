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

set -euo pipefail

STDOUT_DIR="stability_test_outputs"

SCRIPT_DIR=$(dirname $(realpath "$0"))
cd "$SCRIPT_DIR"

ROUND_ID="$1"
DISTRO="$2"
RELEASE="$3"
RUNNER_ARGS="${@:4}"

usage() {
    echo "Usage: $0 <round_id> <distro> <release> <runner_args>";
    exit 1;
}

if [ -z "$ROUND_ID" ]; then echo "ROUND_ID is missing"; usage; fi
if [ -z "$DISTRO" ]; then echo "DISTRO is missing"; usage; fi
if [ -z "$RELEASE" ]; then echo "DISTRO is missing"; usage; fi
if [ -z "$RUNNER_ARGS" ]; then echo "RUNNER_ARGS are missing"; usage; fi

OUTPUT_FN="$STDOUT_DIR/round_${ROUND_ID}_output.txt"
DMESG_FN="$STDOUT_DIR/round_${ROUND_ID}_dmesg.txt"

mkdir -p "$STDOUT_DIR" 2>/dev/null || true

if ! timeout --foreground -s SIGKILL 15s ../run.sh $DISTRO $RELEASE --only-command-output --no-rootfs-update --dmesg=$DMESG_FN $RUNNER_ARGS|sed s/\\r//g > "$OUTPUT_FN"; then
    echo "#$ROUND_ID: kernel-image-runner failed to run. Check the arguments: '$RUNNER_ARGS'"
    exit 2;
fi

OUTPUT=$(cat "$OUTPUT_FN")
DMESG=$(cat "$DMESG_FN")

set +eo pipefail
SUCCESS=$(echo "$OUTPUT"|grep 'secret_flag_deadbeef\|YOU.WON')
EXP_PANIC=$(echo "$DMESG"|grep -o '\(BUG:\|usercopy:\|RIP: 0\).*'|head -n 1)
EXP_EXITED=$(echo "$DMESG"|grep -o '\(Attempted to kill init\).*'|tail -n 1)
EXP_ERROR=$(echo "$OUTPUT"|grep -o '\(\[-\]\).*'|tail -n 1)
EXP_SEGFAULT=$(echo "$DMESG"|grep 'exp.*segfault at')
LAST_LINE=$(echo "$OUTPUT"|tail -n 1)

# echo needs to be one statement, otherwise the stdout is mixed with other rounds
if [ ! -z "$SUCCESS" ]; then echo "#$ROUND_ID: Success: $SUCCESS"; exit 0;
elif [ ! -z "$EXP_ERROR" ]; then echo "#$ROUND_ID: Exploit failed with: $EXP_ERROR"; exit 3;
elif [ ! -z "$EXP_EXITED" ]; then echo "#$ROUND_ID: Exploit exited with: $EXP_EXITED"; exit 4;
elif [ ! -z "$EXP_PANIC" ]; then echo "#$ROUND_ID: Kernel paniced with: $EXP_PANIC"; exit 5;
elif [ ! -z "$EXP_SEGFAULT" ]; then echo "#$ROUND_ID: Exploit segfaulted."; exit 6;
else echo "#$ROUND_ID: Unknown failure: $LAST_LINE"; exit 7; fi
