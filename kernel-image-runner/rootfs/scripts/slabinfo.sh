#!/bin/sh
mkdir /proc
mount proc /proc -t proc
cat /proc/slabinfo
