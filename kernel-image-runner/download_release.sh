#!/bin/bash
set -e

usage() {
    echo "Usage: $0 (kernelctf|ubuntu) <release-name> (vmlinux|headers|modules)";
    exit 1;
}

ARGS=()
while [[ $# -gt 0 ]]; do
  case $1 in
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

list_ubuntu_releases() {
    echo "Supported Ubuntu releases: "
    curl -s http://archive.ubuntu.com/ubuntu/pool/main/l/linux-signed/ | sed -n 's/.*linux-image-[0-9][^>]*-generic_\([^>]*\)_amd64.deb.*/\1/p' | sort -V | sed -z '$ s/\n$//'
    echo
}

DISTRO="$1"
RELEASE_NAME="$2"
DOWNLOAD_TYPE="$3"

if [[ -z $"DOWNLOAD_TYPE" ]]; then DOWNLOAD_TYPE="vmlinuz"; fi

if [[ ! "$DISTRO" =~ ^(kernelctf|ubuntu)$ ]]; then usage; fi

SCRIPT_DIR=$(dirname $(realpath "$0"))
RELEASE_DIR="$SCRIPT_DIR/releases/$DISTRO/$RELEASE_NAME"
VMLINUZ="$RELEASE_DIR/vmlinuz"

if [ -f "$VMLINUZ" ] && [[ "$DOWNLOAD_TYPE" -eq "vmlinuz" ]]; then exit 0; fi

mkdir -p $RELEASE_DIR

printf "Downloading release...\n\n"

case $DISTRO in
  kernelctf)
    if ! curl -f https://storage.googleapis.com/kernelctf-build/releases/$RELEASE_NAME/bzImage -o $VMLINUZ; then
        printf "\nkernelCTF release '$RELEASE_NAME' was not found\n\n";
        echo -n "Valid release names: "
        curl -s https://raw.githubusercontent.com/google/security-research/master/kernelctf/server/releases.yaml | \
            grep -Eoh "^[^: ]*" | sort -V | sed -z '$ s/\n$//' | sed -z 's/\n/, /g'
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

    if [[ "$DOWNLOAD_TYPE" =~ "vmlinuz" ]]; then
        DEB_FN="$RELEASE_DIR/linux-image.deb"
        if [ ! -f "$DEB_FN" ]; then
            if ! curl -f http://archive.ubuntu.com/ubuntu/pool/main/l/linux-signed/linux-image-$RELEASE_SHORT-generic_${RELEASE_NAME}_amd64.deb -o "$DEB_FN"; then
                printf "\nUbuntu release '$RELEASE_NAME' was not found\n\n";
                list_ubuntu_releases
                exit 1
            fi
        fi

        dpkg-deb -x "$RELEASE_DIR/linux-image.deb" "$RELEASE_DIR/linux-image"
        mv "$RELEASE_DIR/linux-image/boot/vmlinuz-$RELEASE_SHORT-generic" "$VMLINUZ"
        rm -rf "$RELEASE_DIR/linux-image"
    fi

    if [[ "$DOWNLOAD_TYPE" =~ "headers" ]]; then
        if [ ! -f "$RELEASE_DIR/linux-headers.deb" ]; then
            echo "Downloading headers..."
            if ! curl -f https://mirrors.edge.kernel.org/ubuntu/pool/main/l/linux/linux-headers-${RELEASE_SHORT}_${RELEASE_NAME}_all.deb -o "$RELEASE_DIR/linux-headers.deb"; then
                printf "\nUbuntu headers for release '$RELEASE_NAME' were not found\n\n";
                exit 1
            fi
        fi

        if [ ! -f "$RELEASE_DIR/linux-headers-generic.deb" ]; then
            echo "Downloading generic headers..."
            if ! curl -f https://mirrors.edge.kernel.org/ubuntu/pool/main/l/linux/linux-headers-${RELEASE_SHORT}-generic_${RELEASE_NAME}_amd64.deb -o "$RELEASE_DIR/linux-headers-generic.deb"; then
                printf "\nUbuntu generic headers for release '$RELEASE_NAME' were not found\n\n";
                exit 1
            fi
        fi

        echo "Extracting headers..."
        dpkg-deb -x "$RELEASE_DIR/linux-headers.deb" "$RELEASE_DIR/linux-headers"

        echo "Extracting generic headers..."
        dpkg-deb -x "$RELEASE_DIR/linux-headers-generic.deb" "$RELEASE_DIR/linux-headers"
    fi

    if [[ "$DOWNLOAD_TYPE" =~ "modules" ]]; then
        if [ ! -f "$RELEASE_DIR/linux-modules.deb" ]; then
            echo "Downloading modules..."
            if ! curl -f https://mirrors.edge.kernel.org/ubuntu/pool/main/l/linux/linux-modules-${RELEASE_SHORT}-generic_${RELEASE_NAME}_amd64.deb -o "$RELEASE_DIR/linux-modules.deb"; then
                printf "\nUbuntu modules for release '$RELEASE_NAME' were not found\n\n";
                exit 1
            fi
        fi

        echo "Extracting modules..."
        dpkg-deb -x "$RELEASE_DIR/linux-modules.deb" "$RELEASE_DIR/linux-modules"
    fi
    ;;
  *)
    usage ;;
esac

if [[ "$DOWNLOAD_TYPE" ~= "vmlinuz" ]]; then
    if [ ! -f "$VMLINUZ" ]; then echo "Could not download / extract the vmlinuz file..."; exit 2; fi
    echo "Release is available at $VMLINUZ"
fi