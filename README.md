# COMS-4181-Final-Project - Team Gamma

## Members
Zach Chen zc2399
Justin Kim jyk2149
Sarah Seidman ss5311
Jiayang Zhou jz3121

## Instructions
1. Run `./install.sh $DEST` to install the server in (assumed to be previously non-existent) directory `$DEST`

2. Type `make` in client directory to compile client programs. To generate private keys for testing, use `scripts/client_gen_key.sh $DEST`.

3. Run `./server www.server.com` in `$DEST`. You will be prompted for a password; it is located in `$DEST/pwds/server_pass`.

3. Run ./test.sh in test folder for `getcert` and `changepw` tests. Tests of `sendmsg` and `recvmsg` need to be done manually.