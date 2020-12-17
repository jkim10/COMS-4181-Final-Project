- ./root_intermediate <password>
    This will create 2 directories: root_ca and intermediate. Intermediate contains
    the intermediate CA as well as client certificates, private and public keys
- ./server_certificate <hostname> <pass_in> <pass_out>
- ./client_certificate <user> <pass_in> <pass_out>
    - <user> should be the username of the calling user, as
      the generated public/private key will be chowned to them
    - If a certificate already exists for <user>, creation will fail
    - <user>'s public key can be found in intermediate/public/<user>.pub, private
      key is at intermediate/private/<user>.key.pem