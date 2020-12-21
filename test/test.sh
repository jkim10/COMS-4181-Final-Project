mkdir certificates
mkdir certificates/csr

set -e

../scripts/client_gen_keypair.sh addleness.key.pem

res=$(./getcert_success)
res=$(./changepw_success)

# These test both getcert and changepw
res=$(./bad_password)
res=$(./bad_username)
res=$(./input_too_long)
res=$(./invalid_private_key)

# sendmsg/rcvmsg
#res=$(./nonexistent_cert)
res=$(./invalid_recips)

set +e

echo -e "\n"
echo -e "Test finished successfully!"
echo -e "\n"