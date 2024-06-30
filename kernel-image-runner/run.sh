#!/bin/bash
set -e

usage() {
    echo "Usage: $0 (kernelctf|ubuntu) <release-name> [--only-script-output] [--gdb] <script-name> [<script-arguments>]";
    exit 1;
}

ARGS=()
while [[ $# -gt 0 ]]; do
  case $1 in
    --only-script-output) ONLY_SCRIPT_OUTPUT=1; shift;;
    --gdb) GDB="--gdb"; shift;;
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
SCRIPT_NAME="$3"
SCRIPT_ARGUMENTS="${@:4}"

if [ "$#" -ne 1 ] && [ "$#" -lt 3 ]; then usage; fi
if [[ ! "$DISTRO" =~ ^(kernelctf|ubuntu)$ ]]; then usage; fi

SCRIPT_DIR=$(dirname $(realpath "$0"))
RELEASE_DIR="$SCRIPT_DIR/../kernel-image-db/releases/$DISTRO/$RELEASE_NAME"
VMLINUZ="$RELEASE_DIR/vmlinuz"

if [ ! -z "$SCRIPT_NAME" ] && [ ! -f "rootfs/scripts/$SCRIPT_NAME.sh" ]; then echo "Script file '$SCRIPT_NAME.sh' is not found in the rootfs/scripts/ folder"; fi

if [ -z "$RELEASE_NAME" ]; then
    "$SCRIPT_DIR/../kernel-image-db/download_release.sh" "$DISTRO" list
    exit 1
fi

"$SCRIPT_DIR/../kernel-image-db/download_release.sh" "$DISTRO" "$RELEASE_NAME" "vmlinuz,modules"

if [ "$ONLY_SCRIPT_OUTPUT" == "1" ]; then
    ./run_vmlinuz.sh "$VMLINUZ" --only-print-output-file $GDB "/scripts/script-output.sh" "$SCRIPT_NAME" -- "$SCRIPT_ARGUMENTS"
else
    ./run_vmlinuz.sh "$VMLINUZ" $GDB "/scripts/$SCRIPT_NAME.sh" -- "$SCRIPT_ARGUMENTS"
fi
