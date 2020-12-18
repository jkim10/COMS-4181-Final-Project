### Params: <path_to_private_key> <csr_dest>

if [ $# -ne 3 ]; then
    echo "Usage: ./getcert-client.sh <path_to_private_key> <csr_dest> <common_name>"
    exit 1
fi

# Generate config file
./generate_config csr_config.cnf ../client/certificates $3 usr

# Create CSR from client's private key
openssl req -config csr_config.cnf \
        -key $1 \
        -new -sha256 -out ../client/$2

echo ../client/$2


exit 0