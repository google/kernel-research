#!/bin/sh
echo "CTF{secret_flag_deadbeef}" > /flag
chmod 0000 /flag
if [ -e /dev/kpwn ]; then
    chmod o+rw /dev/kpwn
fi
chmod o+rx /exp
echo "Running id and then the exploit: /exp $@"
ARG="id; /exp $@"
su user -c /bin/sh -c "$ARG"
