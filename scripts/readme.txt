Create 3 files, owned by root: root_password, intermediate_password, server_password. Then:
    sudo ./root_intermediate.sh root_password intermediate_password
    sudo ./server_setup.sh intermediate_password server_password


./root_intermediate.sh <path_to_pass_in> <path_to_pass_out>
    This will create 2 directories: root_ca and intermediate. Intermediate contains
    the intermediate CA as well as client certificates, private and public keys

./server_setup.sh <path_to_pass_in> <path_to_pass_out>

./cert_from_csr.sh <path_to_csr> <dest>

./client_gen_keypair.sh <unique_identifier> <dest>
    Call this once for each user to create a private key. <dest> should be
    the full name of the destination for the file. You will be prompted for a password; this
    password will again be prompted for when you use getcert or changepw

./getcert-client.sh <path_to_private_key> <csr_dest> <common_name>
    This is called by getcert.c, which sets <common_name> as username.
