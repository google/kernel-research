#!/bin/bash
set -e

SCRIPT_DIR=$(dirname $(realpath "$0"))
cd $SCRIPT_DIR

usage() {
    echo "Usage: $0 (kernelctf|ubuntu) <release-name> [--custom-modules=helloworld,kpwn] [--only-command-output] [--gdb] [--snapshot] -- [<commands-to-run-in-vm>]";
    exit 1;
}

ARGS=()
while [[ $# -gt 0 ]]; do
  case $1 in
    --only-command-output) ONLY_COMMAND_OUTPUT=1; shift;;
    --gdb) GDB=1; shift;;
    --snapshot) SNAPSHOT=1; shift;;
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
    ../kernel-image-db/download_release.sh "$DISTRO" list
    exit 1
fi

../kernel-image-db/download_release.sh "$DISTRO" "$RELEASE_NAME" "vmlinuz,modules"

ARGS="$VMLINUZ"
if [ "$GDB" == "1" ]; then ARGS+=" --gdb"; fi
if [ "$SNAPSHOT" == "1" ]; then ARGS+=" --snapshot"; fi
if [ -d "$MODULES_PATH" ]; then ARGS+=" --modules-path=$MODULES_PATH"; fi

if [ "$CUSTOM_MODULES" != "keep" ]; then
    ./compile_custom_modules.sh "$DISTRO" "$RELEASE_NAME" "$CUSTOM_MODULES"
fi

# only-command-output handling + running the VM

if [ "$ONLY_COMMAND_OUTPUT" == "1" ]; then
    ./run_vmlinuz.sh $ARGS --only-print-output-file "/scripts/command-output.sh" -- "$COMMAND_TO_RUN"
else
    ./run_vmlinuz.sh $ARGS -- "$COMMAND_TO_RUN"
fi
