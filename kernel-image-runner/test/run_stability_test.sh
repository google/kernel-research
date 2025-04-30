#!/bin/bash
set -e

SCRIPT_DIR=$(dirname $(realpath "$0"))
RUNNER_DIR="$SCRIPT_DIR/.."
LOG_DIR="$SCRIPT_DIR/stability_test_outputs"

cd "$SCRIPT_DIR"

DISTRO="${1:-ubuntu}"
RELEASE="${2:-4.15.0-20.21}"
# echo "${@:3}"
RELEASE_DIR="$SCRIPT_DIR/../../kernel-image-db/releases/$DISTRO/$RELEASE"

echo "Updating rootfs..."
(cd $RUNNER_DIR; ./update_rootfs_image.sh)

if [[ ( ! -v CUSTOM_MODULES_KEEP || ! -f "$RELEASE_DIR/custom_modules.tar") ]]; then
    echo "Compiling kpwn module..."
    (cd $RUNNER_DIR; ./compile_custom_modules.sh "$DISTRO" "$RELEASE" kpwn) || (echo "failed: $?..." && exit 1)
fi

mkdir -p $LOG_DIR || true
rm $LOG_DIR/round_* 2>/dev/null || true

echo "Running tests..."
ROUNDS=20
RESULT=$(parallel -j$(nproc) -i ./run_stability_test_round.sh {} "$DISTRO" "$RELEASE" --custom-modules=keep ${@:3} -- $(seq 1 $ROUNDS) | sort -V || true)
stty sane 2>/dev/null || true

echo "Results:"
echo "$RESULT"
echo
SUCCESS=$(echo "$RESULT"|grep Success|wc -l)
FIRST_PANIC_FN_ID=$(echo "$RESULT"|grep panic|head -n 1|grep -o '[0-9]\+'|head -n 1 || true)
PERCENT=$(( (SUCCESS * 100) / ROUNDS))

echo "Summary: $SUCCESS success runs out of $ROUNDS => $PERCENT%"
if [ ! -z "$FIRST_PANIC_FN_ID" ]; then
    FN="$LOG_DIR/round_${FIRST_PANIC_FN_ID}"
    cp "${FN}_dmesg.txt" "$LOG_DIR/panic_sample.txt"
    echo "First panic:"
    cat "${FN}_dmesg.txt"|grep -m1 -A14 "\] BUG: "
    echo "See ${FN}_{dmesg,output} for more info"
fi
stty sane 2>/dev/null || true

exit $(( $PERCENT < 100 ))
