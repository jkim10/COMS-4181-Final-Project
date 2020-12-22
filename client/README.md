# Instructions on how to sendmsg and recvmsg

## Prequisites
- Need a client certificate (you can generate one using the test script for addleness or do below)

  1. /scripts/client_gen_key.sh $FILEDIR
  2. ./getcert
  
## Instructions to Send Message 
1. Write a message to a file (example file is in file message)
2. run ./sendmsg <path/to/client_cert> <path/to/private_key> <recipients> < message_file

## Instructions to Receive Message
1. run ./recv <path/to/cert> <path/to/private_key>
