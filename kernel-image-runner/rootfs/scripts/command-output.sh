#!/bin/sh
dmesg -n 1 # suppress kernel messages
echo "=== COMMAND-BEGIN: $@ ==="
eval $@ > /output
echo "=== COMMAND-END ==="
