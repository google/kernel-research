#!/bin/bash
set -e

if [[ -z "$KERNELXDK_INSTALL_PREFIX" ]]; then
    export KERNELXDK_INSTALL_PREFIX="$PWD"
    export KERNELXDK_LIB_DIR="$PWD/build"
fi

for SAMPLE_DIR in samples/*; do
    if [[ ! -d "$SAMPLE_DIR" ]]; then continue; fi

    if [ "$PREREQ" != "" ]; then
        echo "Installing prerequisites for sample: $SAMPLE_DIR"
        if make -C $SAMPLE_DIR -n prerequisites; then make -C $SAMPLE_DIR prerequisites; fi
    else
        echo "Building sample: $SAMPLE_DIR"
        make -j`nproc` -C $SAMPLE_DIR build
    fi
done
