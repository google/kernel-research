#!/bin/bash
set -e

SCRIPT_DIR=$(dirname $(realpath "$0"))

DISTRO="${1:-kernelctf}"
RELEASE_NAME="${2:-lts-6.1.81}"
TIMES="${3:-1}"
TEST_RUNNER_ARGS="${@:4}"

RELEASE_DIR="$SCRIPT_DIR/../kernel-image-db/releases/$DISTRO/$RELEASE_NAME"

make bin/test
cp bin/test ../kernel-image-runner/rootfs/test_runner

mkdir -p ../kernel-image-runner/rootfs/test/
cp -r test/artifacts ../kernel-image-runner/rootfs/test/

echo "Updating rootfs..."
(cd  ../kernel-image-runner; ./update_rootfs_image.sh)

$SCRIPT_DIR/../kernel-image-db/download_release.sh "$DISTRO" "$RELEASE_NAME" "vmlinuz"

if [[ "$CUSTOM_MODULES" != "keep" && ( -z "$CUSTOM_MODULES_KEEP" || ! -f "$RELEASE_DIR/custom_modules.tar") ]]; then
    echo "Building kpwn kernel module..."
    $SCRIPT_DIR/../kernel-image-db/download_release.sh "$DISTRO" "$RELEASE_NAME" "modules"
    $SCRIPT_DIR/../kernel-image-runner/compile_custom_modules.sh "$DISTRO" "$RELEASE_NAME" kpwn
fi

mkdir -p test_results
rm test_results/round_* test_results/dmesg_* 2>/dev/null || true

echo "Running tests..."
for i in $(seq 1 $TIMES); do
    $SCRIPT_DIR/../kernel-image-runner/run.sh "$DISTRO" "$RELEASE_NAME" --custom-modules=keep --only-command-output --no-rootfs-update --dmesg=test_results/dmesg_$i.txt -- /test_runner --target-db test/artifacts/kernelctf.kpwn $TEST_RUNNER_ARGS > test_results/round_$i.txt &
done

wait

printf "\nTAP results:\n"
cat test_results/round_1.txt

FAIL=0
printf "\nSummary:\n"
if [[ "$TIMES" == "1" ]]; then
    test/check_test_run.py 1
else
    for i in $(seq 1 $TIMES); do
        echo -n "Round #$i: "
        test/check_test_run.py $i && echo "ok" || FAIL=1
    done
fi

exit $FAIL