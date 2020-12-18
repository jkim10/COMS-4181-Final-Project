1. Put "Assignment2" folder into $HOME/

2. Run genca and gencert to generate CAs and certs. The passwords to generate private keys need to be entered manually. 

3. Compile server.cpp by make (g++ is needed). (install libssl-dev if no openssl/bio.h)

4. Call ./server and ./client

CAs and certs generated will be under $HOME/ca/

5. make clean to restore



NEW README FOR SENDMSG/RECVMSG
- Running 'make' will create a tree called mailbox and add a cert to addleness (we need to remove once we get certs working)
- To test sendmsg run sendmsg from client_copy with a valid username
- TODO: Sendmsg needs a cert to send to server other than the default one