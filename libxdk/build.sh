#!/bin/bash
set -e

mkdir -p build 2>/dev/null
cd build
cmake ..
cd ..
cmake --build build --target kernelXDKTests
