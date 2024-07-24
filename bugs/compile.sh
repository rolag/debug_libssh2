#!/bin/bash
set -e
set -v

pwd=$PWD
mkdir -p ../submodules/libssh2/build/
cd ../submodules/libssh2/build/
cmake ../ -DBUILD_SHARED_LIBS=ON -DENABLE_ZLIB_COMPRESSION=ON -DCRYPTO_BACKEND=OpenSSL
cmake --build . --config Release
cd "$pwd"

for f in *.c; do
    gcc -I ../submodules/libssh2/include/ -I ../submodules/libssh2/src/ -I /usr/include/openssl/ -L../submodules/libssh2/build/src/ -o "$(basename --suffix=.c "$f")" "$f" -l ssl -l crypto -l ssh2 -g
done
