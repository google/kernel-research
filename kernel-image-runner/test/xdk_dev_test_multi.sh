#!/bin/bash
set -e

SCRIPT_DIR=$(dirname $(realpath "$0"))
cd $SCRIPT_DIR

gcc -static -Werror -o ../rootfs/xdk_dev_test xdk_dev_test.c
cd ..
./update_rootfs_image.sh
./multi_runner.py /xdk_dev_test --pipebuf-test
