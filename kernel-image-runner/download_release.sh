#!/bin/bash
set -e

usage() {
    echo "Usage: $0 (kernelctf|ubuntu) <release-name>";
    exit 1;
}

list_ubuntu_releases() {
    echo -n "Supported Ubuntu releases: "
    curl -s http://archive.ubuntu.com/ubuntu/pool/main/l/linux-signed/ | sed -n 's/.*linux-image-[0-9][^>]*-generic_\([^>]*\)_amd64.deb.*/\1/p' | sort | sed -z '$ s/\n$//' | sed -z 's/\n/, /g'
    echo
}

DISTRO="$1"
RELEASE_NAME="$2"

if [[ ! "$DISTRO" =~ ^(kernelctf|ubuntu)$ ]]; then usage; fi

SCRIPT_DIR=$(dirname $(realpath "$0"))
RELEASE_DIR="$SCRIPT_DIR/releases/$DISTRO/$RELEASE_NAME"
VMLINUZ="$RELEASE_DIR/vmlinuz"

if [ -f "$VMLINUZ" ]; then exit 0; fi

mkdir -p $RELEASE_DIR

printf "Downloading release...\n\n"

case $DISTRO in
  kernelctf)
    if ! curl -f https://storage.googleapis.com/kernelctf-build/releases/$RELEASE_NAME/bzImage -o $VMLINUZ; then
        printf "\nkernelCTF release '$RELEASE_NAME' was not found\n\n";
        echo -n "Valid release names: "
        curl -s https://raw.githubusercontent.com/google/security-research/master/kernelctf/server/releases.yaml | \
            grep -Eoh "^[^: ]*" | sort | sed -z '$ s/\n$//' | sed -z 's/\n/, /g'
        echo
        exit 1
    fi
    ;;
  ubuntu)
    if ! [[ "$RELEASE_NAME" =~ ^(.*?)[.](.*)$ ]]; then
        echo "Invalid release name."
        list_ubuntu_releases
        exit 1
    fi
    RELEASE_SHORT=${BASH_REMATCH[1]}

    DEB_FN="$RELEASE_DIR/linux-image.deb"

    if [ ! -f "$DEB_FN" ]; then
        if ! curl -f http://archive.ubuntu.com/ubuntu/pool/main/l/linux-signed/linux-image-$RELEASE_SHORT-generic_${RELEASE_NAME}_amd64.deb -o "$DEB_FN"; then
            printf "\nUbuntu release '$RELEASE_NAME' was not found\n\n";
            list_ubuntu_releases
            exit 1
        fi
    fi

    mkdir -p "$RELEASE_DIR/linux-image"
    ar -x "$DEB_FN" --output "$RELEASE_DIR/linux-image"

    TAR_FN="data.tar.xz"
    TAR_EXTRA_ARG=""
    if [ -f "$RELEASE_DIR/linux-image/data.tar.zst" ]; then
        TAR_FN="data.tar.zst"
        TAR_EXTRA_ARG="--use-compress-program=unzstd";
    fi

    tar -C "$RELEASE_DIR/linux-image" $TAR_EXTRA_ARG -xvf "$RELEASE_DIR/linux-image/$TAR_FN"
    mv "$RELEASE_DIR/linux-image/boot/vmlinuz-$RELEASE_SHORT-generic" "$VMLINUZ"
    rm -rf "$RELEASE_DIR/linux-image"
    ;;
  *)
    usage ;;
esac

if [ ! -f "$VMLINUZ" ]; then echo "Could not download / extract the vmlinuz file..."; exit 2; fi

echo "Release is available at $VMLINUZ"