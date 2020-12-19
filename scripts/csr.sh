#!/bin/bash

### Params: <path_to_private_key> <csr_dest> <common_name>

if [ $# -ne 3 ]; then
    echo "Usage: ./csr.sh <path_to_private_key> <csr_dest> <common_name>"
    exit 1
fi

# Generate config file
./generate_config.sh csr_config.cnf ./certificates $3 encrypt

# Create CSR from client's private key
openssl req -config csr_config.cnf \
        -key $1 \
        -new -sha256 -out $2

exit 0