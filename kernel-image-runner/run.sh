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

usage() {
    echo "Usage: $0 (kernelctf|ubuntu) <release-name> [--custom-modules=helloworld,kpwn] [--only-command-output [--dmesg=<path>]] [--gdb] [--snapshot] [--nokaslr] -- [<commands-to-run-in-vm>]";
    exit 1;
}

DMESG="/dev/null"
ARGS=()
RUN_ARGS=""
while [[ $# -gt 0 ]]; do
  case $1 in
    --only-command-output) ONLY_COMMAND_OUTPUT=1; shift;;
    --dmesg=*) DMESG="${1#*=}"; shift;;
    --gdb|--snapshot|--nokaslr) RUN_ARGS+=" $1"; shift;;
    --dbgsym) DBGSYM=1; shift;;
    --custom-modules=*) CUSTOM_MODULES="${1#*=}"; shift;;
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
RELEASE_NAME="$2"
COMMAND_TO_RUN="${@:3}"

if [[ ! "$DISTRO" =~ ^(kernelctf|ubuntu)$ ]]; then usage; fi

RELEASE_DIR="$SCRIPT_DIR/../kernel-image-db/releases/$DISTRO/$RELEASE_NAME"
VMLINUZ="$RELEASE_DIR/vmlinuz"
MODULES_PATH="$RELEASE_DIR/linux-modules"

if [ -z "$RELEASE_NAME" ]; then
    $SCRIPT_DIR/../kernel-image-db/download_release.sh "$DISTRO" list
    exit 1
fi

if [ -z "$DBGSYM" ]; then
    $SCRIPT_DIR/../kernel-image-db/download_release.sh "$DISTRO" "$RELEASE_NAME" "vmlinuz,modules" 1>&2
else
    $SCRIPT_DIR/../kernel-image-db/download_release.sh "$DISTRO" "$RELEASE_NAME" "vmlinuz,modules,dbgsym" 1>&2
fi

RUN_ARGS="$VMLINUZ$RUN_ARGS"
if [ -d "$MODULES_PATH" ]; then RUN_ARGS+=" --modules-path=$MODULES_PATH"; fi

if [[ "$CUSTOM_MODULES" != "keep" && ( -z "$CUSTOM_MODULES_KEEP" || ! -f "$RELEASE_DIR/custom_modules.tar") ]]; then
    $SCRIPT_DIR/compile_custom_modules.sh "$DISTRO" "$RELEASE_NAME" "$CUSTOM_MODULES" 1>&2
fi

if [ ! -z "$CUSTOM_MODULES" ]; then RUN_ARGS+=" --custom-modules-tar=$RELEASE_DIR/custom_modules.tar"; fi

if [[ "$RUN_ARGS" == *"--gdb"* ]]; then
    if [ -z "$DBGSYM" ]; then
        printf "\nDebugging command:\n";
	printf "gdb -ex=\"target remote :1234\"\n";
    else
	printf "\nDebugging command:\n";
        printf "gdb -ex=\"target remote :1234\" $RELEASE_DIR/vmlinux\n";
    fi	
fi

# only-command-output handling + running the VM

if [ "$ONLY_COMMAND_OUTPUT" == "1" ]; then
    $SCRIPT_DIR/run_vmlinuz.sh $RUN_ARGS --stdout-file=$DMESG "/scripts/command-output.sh" -- "$COMMAND_TO_RUN"
else
    $SCRIPT_DIR/run_vmlinuz.sh $RUN_ARGS -- "$COMMAND_TO_RUN"
fi
