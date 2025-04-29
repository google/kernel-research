set -e

DISTRO="${1:-kernelctf}"
RELEASE_NAME="${2:-lts-6.1.81}"
TIMES="${3:-1}"
TEST_RUNNER_ARGS="${@:4}"

make bin/test
cp bin/test ../kernel-image-runner/rootfs/test_runner

mkdir -p ../kernel-image-runner/rootfs/test/
cp -r test/artifacts ../kernel-image-runner/rootfs/test/

../kernel-image-runner/compile_custom_modules.sh "$DISTRO" "$RELEASE_NAME" kpwn

mkdir -p test_results
rm test_results/round_* test_results/dmesg_* 2>/dev/null || true

for i in $(seq 1 $TIMES); do
    ../kernel-image-runner/run.sh "$DISTRO" "$RELEASE_NAME" --custom-modules=keep --only-command-output --dmesg=test_results/dmesg_$i.txt -- /test_runner --target-db test/artifacts/kernelctf.kpwn $TEST_RUNNER_ARGS > test_results/round_$i.txt &
done

wait

printf "\nTAP results:\n"
cat test_results/round_1.txt

printf "\nSummary:\n"
if [[ "$TIMES" == "1" ]]; then
    test/check_test_run.py test_results/round_1.txt
else
    for i in $(seq 1 $TIMES); do
        echo -n "Round #$i: "
        test/check_test_run.py test_results/round_$i.txt && echo "ok" || cat test_results/round_$i.txt
    done
fi