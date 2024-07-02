#!/bin/bash
SCRIPT_DIR=$(dirname $(realpath "$0"))
RUNNER_DIR="$SCRIPT_DIR/../kernel-image-runner"

for RELEASE_DIR in releases/*/*; do
    RELEASE_DIR_PARTS=(${RELEASE_DIR//\// })
    DISTRO=${RELEASE_DIR_PARTS[1]}
    RELEASE_NAME=${RELEASE_DIR_PARTS[2]}
    for SCRIPT in version slabinfo; do
        OUT_FN="$RELEASE_DIR/$SCRIPT.txt"
        if [ -f "$OUT_FN" ]; then continue; fi

        echo "Getting $SCRIPT for $DISTRO $RELEASE_NAME..."
        $RUNNER_DIR/run.sh --only-script-output $DISTRO $RELEASE_NAME $SCRIPT > $OUT_FN
    done
done