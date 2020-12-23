#!/bin/bash

if [ $# -ne 1 ]; then
    echo "Usage: ./install.sh <install_dir>"
    exit 1
fi

set -e

function get_rand() {
	cat /dev/urandom | base64 | head -c 32
}

INSTALL_DEST=$(readlink -m $1)
rm -rf $1
mkdir -p $1

PWDS_DIR=$(readlink -m $INSTALL_DEST/pwds)
mkdir -p $PWDS_DIR
for p in rca_pass ica_pass server_pass; do
	p=$PWDS_DIR/$p
	get_rand > $p
	printf "$p: "
	cat $p
	echo
	chmod 400 $p
	#sudo chown root:root $p
done
chmod 500 $PWDS_DIR
#sudo chown root:root $PWDS_DIR

TMP_DIR=$(readlink -m $INSTALL_DEST/tmp)
mkdir -p $TMP_DIR

cd scripts
./root_intermediate.sh $PWDS_DIR/rca_pass $PWDS_DIR/ica_pass
sudo cp root_ca/certs/ca.cert.pem ../client
./server_setup.sh $PWDS_DIR/server_pass $PWDS_DIR/ica_pass
cp -r intermediate $INSTALL_DEST/intermediate
sudo cp intermediate/certs/intermediate.cert.pem ../client
mkdir -p $INSTALL_DEST/serv_conf
cp certs/*.cert.pem $INSTALL_DEST/serv_conf/
cp certs/*.key.pem $INSTALL_DEST/serv_conf/
cp certs/client_config.cnf $INSTALL_DEST/serv_conf/
cp create-tree.sh $INSTALL_DEST/
cp users.init.txt $INSTALL_DEST/serv_conf/users.txt
cd ..

cd server
make
cp server $INSTALL_DEST
sudo cp ../scripts/root_ca/certs/ca.cert.pem $INSTALL_DEST
cd ..


pushd $INSTALL_DEST
./create-tree.sh
rm create-tree.sh
popd

set +e

echo -e "\n"
echo -e "Installation finished successfully!"
echo -e "\n"

scripts/chroot.sh $INSTALL_DEST