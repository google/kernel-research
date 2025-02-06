set -ex

DISTRO="${1:-kernelctf}"
RELEASE_NAME="${2:-lts-6.1.81}"
TEST_RUNNER_ARGS="${@:3}"

make test
cp bin/test ../kernel-image-runner/rootfs/test_runner

mkdir -p ../kernel-image-runner/rootfs/test/
cp -r test/artifacts ../kernel-image-runner/rootfs/test/

../kernel-image-runner/run.sh "$DISTRO" "$RELEASE_NAME" --custom-modules=kpwn --only-command-output --dmesg=dmesg.txt -- /test_runner --tap --target-db test/artifacts/kernelctf.kpwn $TEST_RUNNER_ARGS | tee tap_results.txt
test/check_test_run.py
