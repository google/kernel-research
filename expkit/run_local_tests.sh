#!/bin/bash
set -e

./build.sh
build/test/kernelXDKTests --test-suites StaticTests --tests ^TODO
