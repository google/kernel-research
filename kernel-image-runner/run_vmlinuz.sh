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
    echo "Usage: $0 <vmlinuz-path> [--modules-path=<...>] [--custom-modules-tar=<...>] [--gdb] [--snapshot] [--no-rootfs-update] [--nokaslr] [--only-print-output-file] -- [<commands-to-run-in-vm>]";
    exit 1;
}

ARGS=()
while [[ $# -gt 0 ]]; do
  case $1 in
    --modules-path=*) MODULES_PATH="${1#*=}"; shift;;
    --custom-modules-tar=*) CUSTOM_MODULES_TAR="${1#*=}"; shift;;
    --only-print-output-file) ONLY_PRINT_OUTPUT_FILE=1; shift;;
    --no-rootfs-update) NO_ROOTFS_UPDATE=1; shift;;
    --snapshot) SNAPSHOT=1; shift;;
    --gdb) GDB=1; shift;;
    --nokaslr) NOKASLR=1; shift;;
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

VMLINUZ="$1"
COMMANDS_TO_RUN="${@:2}"

if [ -z "$VMLINUZ" ] ; then usage; fi

ROOTFS_DIR="$SCRIPT_DIR/rootfs"

echo_err() {
    echo "$@" 1>&2;
}

if [ "$NO_ROOTFS_UPDATE" == "" ]; then
    . $SCRIPT_DIR/update_rootfs_image.sh
fi

# ttyS0 (kernel messages) goes to stdout, ttyS1 (/output file) goes to ./output
SERIAL_PORTS="-serial mon:stdio -serial file:output"
if [ "$ONLY_PRINT_OUTPUT_FILE" == "1" ]; then
    # ttyS0 (kernel messages) goes to /dev/null, ttyS1 (/output file) goes to stdout
    SERIAL_PORTS="-serial null -serial mon:stdio"
fi

EXTRA_ARGS=""
EXTRA_CMDLINE=""
if [ "$GDB" == "1" ]; then EXTRA_ARGS+=" -s -S"; fi
if [ "$SNAPSHOT" == "1" ]; then EXTRA_ARGS+=" -snapshot"; fi
if [ "$NOKASLR" == "1" ]; then EXTRA_CMDLINE+=" nokaslr"; fi

ABC=({a..z})
IDE_IDX=0
if [ ! -z "$MODULES_PATH" ]; then
    if [[ "$MODULES_PATH" == */ ]]; then MODULES_PATH=${MODULES_PATH%/}; fi
    MODULES_IMG="$MODULES_PATH.img"
    check_archive_uptodate $MODULES_IMG $MODULES_PATH "virt-make-fs --type ext4 --size=+16M $MODULES_PATH $MODULES_IMG"
    EXTRA_ARGS+=" -drive file=$MODULES_IMG,if=ide,format=raw,snapshot=on"
    EXTRA_CMDLINE+=" MOUNT_MODULES=/dev/sd${ABC[IDE_IDX]}"
    IDE_IDX=$((IDE_IDX+1))
fi

if [ ! -z "$CUSTOM_MODULES_TAR" ]; then
    EXTRA_ARGS+=" -drive file=$CUSTOM_MODULES_TAR,if=ide,format=raw,snapshot=on"
    EXTRA_CMDLINE+=" MOUNT_CUSTOM_MODULES=/dev/sd${ABC[IDE_IDX]}"
    IDE_IDX=$((IDE_IDX+1))
fi

qemu-system-x86_64 -m 3.5G -nographic -nodefaults -no-reboot \
    -enable-kvm -cpu host -smp cores=2 \
    -kernel $VMLINUZ \
    -initrd $SCRIPT_DIR/initramfs.cpio \
    -nic user,model=virtio-net-pci \
    $SERIAL_PORTS $EXTRA_ARGS \
    -append "console=ttyS0 panic=-1 oops=panic loadpin.enable=0 loadpin.enforce=0$EXTRA_CMDLINE init=/init -- $COMMANDS_TO_RUN"

stty sane