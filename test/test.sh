mkdir certificates
mkdir certificates/csr

set -e

../scripts/client_gen_key.sh addleness.key.pem
../scripts/client_gen_key.sh polypose.key.pem

### Success
res=$(./getcert_success)
res=$(./changepw_success)

### Failure
# These test both getcert and changepw
res=$(./bad_password)
res=$(./bad_username)
res=$(./input_too_long)
res=$(./invalid_private_key)

# sendmsg/rcvmsg
res=$(./nonexistent_cert)
res=$(./invalid_recips)

# Generate a certificate using another CA
./evil_certificate.sh
res=$(./other_ca)

set +e

echo -e "\n"
echo -e "Test finished successfully!"
echo -e "\n"