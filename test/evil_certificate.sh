### The certificate generated here can be used to test sendmsg/recvmsg
# Put password into file
rm pass
touch pass
echo "pass" > pass
# Generate another CA to sign evil bad certificates
cd ../scripts
./root_intermediate.sh ../../test/pass ../../test/pass
cd ../test
# Generate a CSR
../scripts/csr.sh addleness.key.pem certificates/csr/addleness-evil.csr.pem addleness
# Sign it
cd ../scripts
openssl ca -config ../scripts/certs/client_config.cnf \
    -extensions usr_cert -days 375 -notext -md sha256 -batch \
    -in ../test/certificates/csr/addleness-evil.csr.pem -passin pass:pass \
    -out ../test/certificates/addleness-evil.cert.pem

cd ../test
rm -rf root_ca