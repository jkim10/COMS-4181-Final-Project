#!/bin/bash

if [ $# != 1 ]; then
    echo "Usage: ./root_intermediate <password>"
    exit 1
fi

# Make directory
mkdir root_ca

# Generate configfile
./generate_config.sh root_config.cnf . Root root
mv root_config.cnf root_ca

# Create directory structure
cd root_ca
mkdir certs crl newcerts private
chmod 700 private
touch index.txt
echo 1000 > serial

# Create root key
openssl genrsa -aes256 -out private/ca.key.pem \
        -passout pass:$1 \
        4096
chmod 400 private/ca.key.pem

# Create root certificate
openssl req -config root_config.cnf \
        -key private/ca.key.pem \
        -new -x509 -days 7300 -sha256 -extensions v3_ca \
        -out certs/ca.cert.pem \
        -passout pass:$1 -passin pass:$1

chmod 444 certs/ca.cert.pem

# Verify root certificate
openssl x509 -noout -text -in certs/ca.cert.pem

# Now make the intermediate certificate
mkdir intermediate

# Directory structure
cd ./intermediate
mkdir certs crl csr newcerts private public
chmod 700 private
touch index.txt
echo 1000 > serial

# Generate configfile
../../generate_config.sh inter_config.cnf . Intermediate intermediate

# Create intermediate key
cd ..
openssl genrsa -aes256 \
        -out intermediate/private/intermediate.key.pem \
        -passout pass:$1 4096
chmod 400 intermediate/private/intermediate.key.pem

# Create intermediate certificate
openssl req -config intermediate/inter_config.cnf -new -sha256 \
        -key intermediate/private/intermediate.key.pem \
        -out intermediate/csr/intermediate.csr.pem \
        -passin pass:$1 -passout pass:$1

openssl ca -config root_config.cnf -extensions v3_intermediate_ca \
        -days 3650 -notext -md sha256 \
        -in intermediate/csr/intermediate.csr.pem \
        -out intermediate/certs/intermediate.cert.pem \
        -passin pass:$1 
chmod 444 intermediate/certs/intermediate.cert.pem

# Verify intermediate certificate
openssl x509 -noout -text \
        -in intermediate/certs/intermediate.cert.pem \
        -passin pass:$1
openssl verify -CAfile certs/ca.cert.pem \
        intermediate/certs/intermediate.cert.pem \

# Create certificate chain file
cat intermediate/certs/intermediate.cert.pem \
        certs/ca.cert.pem > intermediate/certs/ca-chain.cert.pem
chmod 444 intermediate/certs/ca-chain.cert.pem

mv intermediate ..