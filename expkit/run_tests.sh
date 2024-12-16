set -ex
make test
cp bin/test ../../tools/kernel-image-runner/rootfs/test_runner
mkdir -p ../../tools/kernel-image-runner/rootfs/test/
cp -r test/artifacts ../../tools/kernel-image-runner/rootfs/test/
../../tools/kernel-image-runner/run.sh kernelctf lts-6.1.81 --custom-modules=kpwn --only-command-output --dmesg=dmesg.txt -- /test_runner --tap --target-db test/artifacts/target_db_lts-6.1.81.kpwn
test/check_test_run.py