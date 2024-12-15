set -ex
make test
cp bin/test ../../tools/kernel-image-runner/rootfs/test_runner
mkdir -p ../../tools/kernel-image-runner/rootfs/test/
cp -r test/artifacts ../../tools/kernel-image-runner/rootfs/test/
../../tools/kernel-image-runner/run.sh kernelctf lts-6.1.31 --custom-modules=kpwn --only-command-output -- /test_runner --tap
