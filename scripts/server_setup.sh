#!/bin/bash

if [ $# != 2 ]; then
    echo "Usage: ./server_setup <pass_in> <pass_out>"
    exit 1
fi

# We will say FQDN is www.server.com
url=www.server.com

mkdir certs
cd certs

# Generate config file
.././generate_config server_config.cnf ../intermediate $url server
# Also generate a config file for client certificates
.././generate_config client_config.cnf ../intermediate tmp usr

# Create a key
openssl genrsa -aes256 \
        -out $url.key.pem \
        -passout pass:$1 2048
chmod 400 $url.key.pem

echo "created key"

# Create a certificate
# 1. Certificate-Signing Request (CSR)
openssl req -config server_config.cnf \
        -key $url.key.pem \
        -new -sha256 -out $url.csr.pem \
        -passin pass:$1 -passout pass:$2

echo "created csr"

# 2. Use intermediate CA to sign CSR
openssl ca -config server_config.cnf \
        -extensions server_cert -days 375 -notext -md sha256 \
        -in $url.csr.pem \
        -out $url.cert.pem \
        -cert ../intermediate/certs/intermediate.cert.pem -passin pass:$2
chmod 444 $url.cert.pem

# Verify certificate
openssl verify -CAfile ../intermediate/certs/ca-chain.cert.pem \
        $url.cert.pem