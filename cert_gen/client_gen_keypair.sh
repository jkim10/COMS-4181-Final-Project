#!/bin/bash

if [ $# -ne 3 ]; then
    echo "Usage: ./client_gen_keypair <unique_identifier> <dest> <pass_out>"
    exit 1
fi

# Generate config file
./generate_config client_config.cnf intermediate $1 usr
mv client_config.cnf ./intermediate

# Only create private key if it does not exist
FILE=$2
if test -f "$FILE"; then
    echo "$FILE exists."
else
    # Create a private key
	openssl genrsa -aes256 \
        -out $2 \
        -passout pass:$3 2048
fi

chmod 400 $2