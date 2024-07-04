#!/bin/bash
SCRIPT_DIR=$(dirname $(realpath "$0"))
RUNNER_DIR="$SCRIPT_DIR/../kernel-image-runner"

for RELEASE_DIR in releases/*/*; do
    RELEASE_DIR_PARTS=(${RELEASE_DIR//\// })
    DISTRO=${RELEASE_DIR_PARTS[1]}
    RELEASE_NAME=${RELEASE_DIR_PARTS[2]}
    for PROC_FN in version slabinfo; do
        OUT_FN="$RELEASE_DIR/$PROC_FN.txt"
        if [ -f "$OUT_FN" ]; then continue; fi

        echo "Getting $PROC_FN for $DISTRO $RELEASE_NAME..."
        $RUNNER_DIR/run.sh --only-command-output $DISTRO $RELEASE_NAME -- cat /proc/$PROC_FN > $OUT_FN
    done
done