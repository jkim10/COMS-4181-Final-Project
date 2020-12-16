#!/bin/bash

## Root CA ##

echo generating root CA
# create structure
mkdir $HOME/ca
cd $HOME/ca
mkdir certs newcerts private
chmod 700 private
touch index.txt
echo 1000 > serial

# copy the configuration file
cp $HOME/Assignment2/opensslrootca.cnf ./openssl.cnf

# create private key
openssl genrsa -aes256 -out private/ca.key.pem 4096
chmod 400 private/ca.key.pem

# create certificate
openssl req -config openssl.cnf \
	-key private/ca.key.pem \
	-new -x509 -days 7300 -sha256 -extensions v3_ca \
	-out certs/ca.cert.pem \
	-subj "/C=US/ST=New York/O=COMS4181/OU=COMS4181 Certificate Authority/CN=COMS4181 Root Certificate Authority"
chmod 444 certs/ca.cert.pem

# verify certificate
openssl x509 -noout -text -in certs/ca.cert.pem

## Intermediate CA ##

echo generating intermediate CA
# create structure
mkdir $HOME/ca/intermediate
cd $HOME/ca/intermediate
mkdir certs csr newcerts private
chmod 700 private
touch index.txt
echo 1000 > serial

# copy the configuration file
cp $HOME/Assignment2/opensslinterca.cnf ./openssl.cnf

# create private key
cd $HOME/ca
openssl genrsa -aes256 -out intermediate/private/intermediate.key.pem 4096
chmod 400 intermediate/private/intermediate.key.pem

# create certificate
openssl req -config intermediate/openssl.cnf -new -sha256 \
	-key intermediate/private/intermediate.key.pem \
	-out intermediate/csr/intermediate.csr.pem \
	-subj "/C=US/ST=New York/O=COMS4181/OU=COMS4181 Certificate Authority/CN=COMS4181 Intermediate Certificate Authority"
openssl ca -config openssl.cnf -extensions v3_intermediate_ca \
	-days 3650 -notext -md sha256 \
	-in intermediate/csr/intermediate.csr.pem \
	-out intermediate/certs/intermediate.cert.pem
chmod 444 intermediate/certs/intermediate.cert.pem

# verify certificate
openssl x509 -noout -text -in intermediate/certs/intermediate.cert.pem
openssl verify -CAfile certs/ca.cert.pem intermediate/certs/intermediate.cert.pem

# create certificate chain
cat intermediate/certs/intermediate.cert.pem \
	certs/ca.cert.pem > intermediate/certs/ca-chain.cert.pem
chmod 444 intermediate/certs/ca-chain.cert.pem