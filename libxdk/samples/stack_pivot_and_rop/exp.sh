#!/bin/sh
echo "CTF{secret_flag_deadbeef}" > /flag
chmod 0000 /flag
if [ -e /dev/xdk ]; then
    chmod o+rw /dev/xdk
fi
chmod o+rx /exp
echo "Running id and then the exploit: /exp $@"
ARG="id; /exp $@"
su user -c /bin/sh -c "$ARG"
