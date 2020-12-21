mkdir certificates
mkdir certificates/csr

set -e

../scripts/client_gen_keypair.sh addleness.key.pem

res=$(./getcert_success)
res=$(./changepw_success)

res=$(./bad_password)

set +e