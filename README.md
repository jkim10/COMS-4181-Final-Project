# COMS-4181-Final-Project - Team Gamma

## Members
Zach Chen zc2399

Justin Kim jyk2149

Sarah Seidman ss5311

Jiayang Zhou jz3121

## Instructions
1. Run `./install.sh $INSTALL_DEST` to install and start the server in (assumed to be previously non-existent) directory `$INSTALL_DEST`. You will be prompted for a password; it is located in `$INSTALL_DEST/pwds/server_pass`.

2. Type `make` in client directory to compile client programs. To generate private keys for testing, use `scripts/client_gen_key.sh $FILE_DEST`.

3. Run ./test.sh in test directory for `getcert` and `changepw` tests. Tests of `sendmsg` and `recvmsg` need to be done manually.

See design documents for more detailed information.