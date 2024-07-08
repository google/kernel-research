#!/bin/bash
set -e

cd $(dirname $(realpath "$0"))

usage() {
    echo "Usage: $0 <vmlinuz-path> [--modules-path=<...>] [--gdb] [--snapshot] [--only-print-output-file] -- [<commands-to-run-in-vm>]";
    exit 1;
}

ARGS=()
while [[ $# -gt 0 ]]; do
  case $1 in
    --modules-path=*) MODULES_PATH="${1#*=}"; shift;;
    --only-print-output-file) ONLY_PRINT_OUTPUT_FILE=1; shift;;
    --snapshot) SNAPSHOT=1; shift;;
    --gdb) GDB=1; shift;;
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

ROOTFS_DIR="rootfs"

echo_err() {
    echo "$@" 1>&2;
}

. ./update_rootfs_image.sh

# ttyS0 (kernel messages) goes to stdout, ttyS1 (/output file) goes to ./output
SERIAL_PORTS="-serial mon:stdio -serial file:output"
if [ "$ONLY_PRINT_OUTPUT_FILE" == "1" ]; then
    # ttyS0 (kernel messages) goes to /dev/null, ttyS1 (/output file) goes to stdout
    SERIAL_PORTS="-serial null -serial mon:stdio"
fi

EXTRA_ARGS=""
if [ "$GDB" == "1" ]; then EXTRA_ARGS+=" -s -S"; fi
if [ "$SNAPSHOT" == "1" ]; then EXTRA_ARGS+=" -snapshot"; fi

if [ ! -z "$MODULES_PATH" ]; then
    if [[ "$MODULES_PATH" == */ ]]; then MODULES_PATH=${MODULES_PATH%/}; fi
    MODULES_IMG="$MODULES_PATH.img"
    check_archive_uptodate $MODULES_IMG $MODULES_PATH "virt-make-fs --type ext4 --size=+16M $MODULES_PATH $MODULES_IMG"
    EXTRA_ARGS+=" -drive file=$MODULES_IMG,if=ide,format=raw"
fi

qemu-system-x86_64 -m 3.5G -nographic -nodefaults \
    -enable-kvm -cpu host -smp cores=2 \
    -kernel $VMLINUZ \
    -initrd initramfs.cpio \
    -nic user,model=virtio-net-pci \
    -drive file=rootfs.img,if=virtio,format=raw,snapshot=on \
    -drive file=rootfs.tar,if=virtio,format=raw,readonly=on \
    $SERIAL_PORTS $EXTRA_ARGS \
    -append "console=ttyS0 root=/dev/vda1 rootfstype=ext4 rw nokaslr panic=-1 oops=panic loadpin.enable=0 loadpin.enforce=0 init=/init -- $COMMANDS_TO_RUN" \
    -nographic -no-reboot
