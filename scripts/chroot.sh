#!/bin/bash

if [ $# -ne 1 ]; then
    echo "Usage: ./chroot.sh <install_dir>"
    exit 1
fi

set -e

INSTALL_DEST=$1

cd $INSTALL_DEST
mkdir -p bin

# Install dependencies
cp /bin/bash ./bin
cp /bin/openssl ./bin

list="$(ldd /bin/bash | egrep -o '/lib.*\.[0-9]')"
for i in $list; do cp --parents "$i" .; done

list="$(ldd /bin/openssl | egrep -o '/lib.*\.[0-9]')"
for i in $list; do cp --parents "$i" .; done

list="$(ldd ./server | egrep -o '/lib.*\.[0-9]')"
for i in $list; do cp --parents "$i" .; done

cd ..
sudo chown root:root $INSTALL_DEST
sudo chown --recursive root:root $INSTALL_DEST/*
sudo chmod --recursive o-r $INSTALL_DEST/*
sudo chmod --recursive o-w $INSTALL_DEST/*
sudo chmod --recursive o-x $INSTALL_DEST/*

echo -e "Starting server..."
echo -e "\n"

cd $INSTALL_DEST
# Start server with <install_dir> as root
sudo chroot . ./server www.server.com