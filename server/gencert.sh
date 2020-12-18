#!/bin/bash

## Server Certificate ##

echo generating server certificate
# create private key
cd $HOME/ca
openssl genrsa -out intermediate/private/www.mysite.com.key.pem 2048
chmod 400 intermediate/private/www.mysite.com.key.pem

# create certificate
openssl req -config intermediate/openssl.cnf \
	-key intermediate/private/www.mysite.com.key.pem \
	-new -sha256 -out intermediate/csr/www.mysite.com.csr.pem \
	-subj "/C=US/ST=New York/O=COMS4181/OU=COMS4181 Services/CN=www.mysite.com"
openssl ca -config intermediate/openssl.cnf \
	-extensions server_cert -days 375 -notext -md sha256 \
	-in intermediate/csr/www.mysite.com.csr.pem \
	-out intermediate/certs/www.mysite.com.cert.pem
chmod 444 intermediate/certs/www.mysite.com.cert.pem

# verify certificate
openssl x509 -noout -text -in intermediate/certs/www.mysite.com.cert.pem
openssl verify -CAfile intermediate/certs/ca-chain.cert.pem intermediate/certs/www.mysite.com.cert.pem

## Client Certificate ##

echo generating client certificate
# create private key
cd $HOME/ca
openssl genrsa -out intermediate/private/myclient.key.pem 2048
chmod 400 intermediate/private/myclient.key.pem

# create certificate
openssl req -config intermediate/openssl.cnf \
	-key intermediate/private/myclient.key.pem \
	-new -sha256 -out intermediate/csr/myclient.csr.pem \
	-subj "/C=US/ST=New York/O=COMS4181/OU=COMS4181 Services/CN=myclient"
openssl ca -config intermediate/openssl.cnf \
	-extensions usr_cert -days 375 -notext -md sha256 \
	-in intermediate/csr/myclient.csr.pem \
	-out intermediate/certs/myclient.cert.pem
chmod 444 intermediate/certs/myclient.cert.pem

# verify certificate
openssl x509 -noout -text -in intermediate/certs/myclient.cert.pem
openssl verify -CAfile intermediate/certs/ca-chain.cert.pem intermediate/certs/myclient.cert.pem

## Encryption Certificate ##

echo generating encryption certificate
# create private key
cd $HOME/ca
openssl genrsa -out intermediate/private/encrypt.key.pem 2048
chmod 400 intermediate/private/encrypt.key.pem

# create certificate
openssl req -config intermediate/openssl.cnf \
	-key intermediate/private/encrypt.key.pem \
	-new -sha256 -out intermediate/csr/encrypt.csr.pem \
	-subj "/C=US/ST=New York/O=COMS4181/OU=COMS4181 Services/CN=myencrypt"
openssl ca -config intermediate/openssl.cnf \
	-extensions server_cert -days 375 -notext -md sha256 \
	-in intermediate/csr/encrypt.csr.pem \
	-out intermediate/certs/encrypt.cert.pem
chmod 444 intermediate/certs/encrypt.cert.pem

# verify certificate
openssl x509 -noout -text -in intermediate/certs/encrypt.cert.pem
openssl verify -CAfile intermediate/certs/ca-chain.cert.pem intermediate/certs/encrypt.cert.pem

## Signing Certificate ##

echo generating signing certificate
# create private key
cd $HOME/ca
openssl genrsa -out intermediate/private/sign.key.pem 2048
chmod 400 intermediate/private/sign.key.pem

# create certificate
openssl req -config intermediate/openssl.cnf \
	-key intermediate/private/sign.key.pem \
	-new -sha256 -out intermediate/csr/sign.csr.pem \
	-subj "/C=US/ST=New York/O=COMS4181/OU=COMS4181 Services/CN=mysign"
openssl ca -config intermediate/openssl.cnf \
	-extensions server_cert -days 375 -notext -md sha256 \
	-in intermediate/csr/sign.csr.pem \
	-out intermediate/certs/sign.cert.pem
chmod 444 intermediate/certs/sign.cert.pem

# verify certificate
openssl x509 -noout -text -in intermediate/certs/sign.cert.pem
openssl verify -CAfile intermediate/certs/ca-chain.cert.pem intermediate/certs/sign.cert.pem