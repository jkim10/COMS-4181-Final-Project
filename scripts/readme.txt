./root_intermediate <password>
    This will create 2 directories: root_ca and intermediate. Intermediate contains
    the intermediate CA as well as client certificates, private and public keys

./server_setup <passin> <passout>

./cert_from_csr.sh <path_to_csr> <dest>

./client_gen_keypair <unique_identifier> <dest> <pass_out>
    Call this once for each user to create a private key. <dest> should be
    the full name of the destination for the file.

./getcert-client.sh <path_to_private_key> <csr_dest> <common_name>
    This is called by getcert.c, which sets <common_name> as username.
