#!/bin/bash
set -e

SCRIPT_DIR=$(dirname $(realpath "$0"))
cd $SCRIPT_DIR

usage() {
    echo "Usage: $0 [(kernelctf|ubuntu) <release-name>]";
    exit 1;
}

DISTRO="$1"
RELEASE_NAME="$2"

# fallback to some default release in case we just want to
# test the module, but it does not really matter on which version
if [ -z "$DISTRO" ] && [ -z "$RELEASE_NAME"]; then
    DISTRO="ubuntu"
    RELEASE_NAME="5.4.0-26.30"
fi

gcc -static -o ../rootfs/kpwn_test kpwn_test.c
../run.sh "$DISTRO" "$RELEASE_NAME" --custom-modules=kpwn -- /kpwn_test
