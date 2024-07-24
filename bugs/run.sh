#!/bin/bash
set -e
set -v

if [[  ! -e "$1"  ]]; then
    echo "File $1 does not exist"
    exit 1
fi

docker run --name debug_libssh2 --rm -p 12345:22 debug_libssh2 /usr/sbin/sshd -D -ddd -e -p 22 &
sleep 2
echo "running"
LD_LIBRARY_PATH=$PWD/../submodules/libssh2/build/src ./"$1"
docker stop debug_libssh2
sleep 1
