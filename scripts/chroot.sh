#!/bin/bash

if [ $# -ne 1 ]; then
    echo "Usage: ./chroot.sh <install_dir>"
    exit 1
fi

set -e

cd $1
mkdir bin

# Install dependencies
cp -v /bin/bash ./bin

list="$(ldd /bin/bash | egrep -o '/lib.*\.[0-9]')"
for i in $list; do cp -v --parents "$i" .; done

list="$(ldd ./server | egrep -o '/lib.*\.[0-9]')"
for i in $list; do cp -v --parents "$i" .; done

# Start server with <install_dir> as root
sudo chroot . ./server www.server.com