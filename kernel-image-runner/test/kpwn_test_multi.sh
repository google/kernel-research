set -e

SCRIPT_DIR=$(dirname $(realpath "$0"))
cd $SCRIPT_DIR

gcc -static -Werror -o ../rootfs/kpwn_test kpwn_test.c
cd ..
./update_rootfs_image.sh
./multi_runner.py /kpwn_test --pipebuf-test
