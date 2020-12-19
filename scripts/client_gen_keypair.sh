#!/bin/bash

if [ $# -ne 2 ]; then
    echo "Usage: ./client_gen_keypair <dest>"
    exit 1
fi

# Only create private key if it does not exist
FILE=$1
if test -f "$FILE"; then
    echo "$FILE exists."
else
    # Create a private key
	openssl genrsa -aes256 \
        -out $1 2048
fi

chmod 400 $1