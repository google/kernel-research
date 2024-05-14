#!/bin/sh
dmesg -n 1 # suppress kernel messages
echo "=== SCRIPT-BEGIN: $1 ==="
/scripts/$1.sh > /output
echo "=== SCRIPT-END ==="
