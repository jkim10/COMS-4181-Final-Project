Compile server by make (clang++ is needed). (install libssl-dev if no openssl/bio.h)
make clean to restore



NEW README FOR SENDMSG/RECVMSG
- Running 'make' will create a tree called mailbox and add a cert to addleness (we need to remove once we get certs working)
- To test sendmsg run sendmsg from client_copy with a valid username
- TODO: Sendmsg needs a cert to send to server other than the default one
