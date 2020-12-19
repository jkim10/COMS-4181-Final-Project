#!/bin/bash

if [ $# != 2 ]; then
    echo "Usage: ./getcert-server.sh <path_to_csr> <dest>"
    exit 1
fi

cd certs

# Check if a certificate already exists at <dest>
# If so, delete it
if test -f "$2"; then
	rm -f $2
fi

# Use intermediate CA to sign CSR
openssl ca -config client_config.cnf \
        -extensions usr_cert -days 375 -notext -md sha256 \
        -in $1 -out $2 \
        -cert ../intermediate/certs/intermediate.cert.pem \
        -passin pass:pass
chmod 444 $2

# Verify certificate
openssl verify -CAfile ../intermediate/certs/ca-chain.cert.pem \
        $2