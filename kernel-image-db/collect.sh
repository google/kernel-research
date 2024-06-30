#!/bin/bash
set -e

process_distro() {
    DISTRO_NAME="$1"
    DISTRO_ID="${DISTRO_NAME,,}"

    yq -r ".$DISTRO_ID|keys[]" releases.yaml | while read -r RELEASE; do
        echo "====================================================="
        echo "Processing $DISTRO_NAME release: $RELEASE"
        echo "====================================================="
        ./download_release.sh $DISTRO_ID $RELEASE
    done
}

process_distro kernelCTF
process_distro Ubuntu
