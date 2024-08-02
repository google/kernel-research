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
        chmod a+rx $ROOTFS_DIR/busybox
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
    tar --directory=$ROOTFS_DIR --exclude='./busybox' --exclude='./init' --owner=root --group=root -cf $ROOTFS_TAR . > /dev/null
}

regenerate_initramfs() {
    download_busybox_if_missing
    pushd $ROOTFS_DIR > /dev/null
    find . ! -name 'guestfish*' -print0 | cpio --owner 0:0 --null -ov --format=newc > ../$INITRAMFS 2>/dev/null
    popd > /dev/null
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
#check_archive_uptodate $ROOTFS_TAR rootfs regenerate_rootfs_tar
#check_archive_uptodate $INITRAMFS rootfs regenerate_initramfs
regenerate_rootfs_tar
regenerate_initramfs
