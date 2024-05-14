#!/bin/bash
set -e

usage() {
    echo "Usage: $0 <vmlinuz-path> [--only-print-output-file] <commands-to-run>";
    exit 1;
}

ARGS=()
while [[ $# -gt 0 ]]; do
  case $1 in
    --only-print-output-file) ONLY_PRINT_OUTPUT_FILE=1; shift;;
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

if [ "$#" -lt 2 ] ; then usage; fi

ROOTFS_DIR="rootfs"
ROOTFS_IMG="rootfs.img"
ROOTFS_TAR="rootfs.tar"
INITRAMFS="initramfs.cpio"

echo_err() {
    echo "$@" 1>&2;
}

download_busybox_if_missing() {
    if [ ! -f $ROOTFS_DIR/busybox ]; then
        echo_err "busybox was not found in the rootfs folder, downloading it..."
        curl -f https://busybox.net/downloads/binaries/1.35.0-x86_64-linux-musl/busybox -o $ROOTFS_DIR/busybox
        chmod u+x $ROOTFS_DIR/busybox
    fi
}

regenerate_rootfs_img() {
    if ! command -v guestfish > /dev/null; then
        echo_err "guestfish binary is missing (try apt intall libguestfs-tools), downloading pre-generated binary"
        # was uploaded via: gsutil cp -Z -a public-read rootfs.img gs://kernelctf-build/files/rootfs_image_runner_v4.img
        curl -f https://storage.googleapis.com/kernelctf-build/files/rootfs_image_runner_v4.img -o $ROOTFS_IMG
    else
        download_busybox_if_missing
        cat ./guestfish_script | guestfish -N $ROOTFS_IMG=fs:ext4:8M
    fi
}

regenerate_rootfs_tar() {
    tar --directory=$ROOTFS_DIR --exclude='./busybox' --exclude='./init' -cf $ROOTFS_TAR .
}

regenerate_initramfs() {
    download_busybox_if_missing
    pushd $ROOTFS_DIR
    find . ! -name 'guestfish*' -print0 | cpio --null -ov --format=newc > ../$INITRAMFS
    popd
}

check_archive_uptodate() {
    ARCHIVE_FILE=$1
    SRC_FILES=$2
    REGEN_SCRIPT=$3
    EXTRA_NOTE=$4

    if [[ ! -z "$EXTRA_NOTE" ]]; then EXTRA_NOTE=" ($EXTRA_NOTE)"; fi

    src_last_mod() {
        LAST_MOD=0
        for FILE in ${SRC_FILES}; do
            if [ -f $FILE ]; then
                FILE_MOD=$(date -r $FILE +%s)
            elif [ -d $FILE ]; then
                FILE_MOD=$(find $FILE -type f -printf "%T@ %p\n" | sort -n | cut -d'.' -f -1 | tail -n 1)
            fi
            if [[ "$FILE_MOD" > "$LAST_MOD" ]]; then
                LAST_MOD="$FILE_MOD";
            fi
        done
        echo $LAST_MOD
    }

    if [ ! -f $ARCHIVE_FILE ]; then
        echo_err "Regenerating $ARCHIVE_FILE$EXTRA_NOTE as it is missing..."
    elif [[ "$(src_last_mod)" > "$(date -r $ARCHIVE_FILE +%s)" ]]; then
        echo_err "Regenerating $ARCHIVE_FILE$EXTRA_NOTE as files ($SRC_FILES) changed..."
    else
        return 0;
    fi

    $REGEN_SCRIPT
    touch -m -t $(date --date=@$(src_last_mod) +%Y%m%d%H%M.%S) $ARCHIVE_FILE
}

check_archive_uptodate $ROOTFS_IMG "guestfish_script rootfs/init rootfs/busybox" regenerate_rootfs_img "with guestfish"
check_archive_uptodate $ROOTFS_TAR rootfs regenerate_rootfs_tar
check_archive_uptodate $INITRAMFS rootfs regenerate_initramfs

# ttyS0 (kernel messages) goes to stdout, ttyS1 (/output file) goes to ./output
SERIAL_PORTS="-serial mon:stdio -serial file:output"
if [ "$ONLY_PRINT_OUTPUT_FILE" == "1" ]; then
    # ttyS0 (kernel messages) goes to /dev/null, ttyS1 (/output file) goes to stdout
    SERIAL_PORTS="-serial null -serial mon:stdio"
fi

qemu-system-x86_64 -m 3.5G -nographic -nodefaults \
    -enable-kvm -cpu host -smp cores=2 \
    -kernel $VMLINUZ \
    -initrd $INITRAMFS \
    -nic user,model=virtio-net-pci \
    -drive file=$ROOTFS_IMG,if=virtio,format=raw,snapshot=on \
    -drive file=$ROOTFS_TAR,if=virtio,format=raw,readonly=on \
    $SERIAL_PORTS \
    -append "console=ttyS0 root=/dev/vda1 rootfstype=ext4 rw init=/init panic=-1 custom.stuff=x -- $COMMANDS_TO_RUN" \
    -nographic -no-reboot
