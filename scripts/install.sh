#!/bin/bash

if [ $# -ne 1 ]; then
    echo "Usage: ./install.sh <install_dir>"
    exit 1
fi

set -e

function get_rand() {
	cat /dev/urandom | base64 | head -c 32
}

for p in rca_pass ica_pass server_pass; do
	echo get_rand > $p
	printf "$p: "
	cat $p
	chmod 400 $p
	sudo chown root:root $p
done

rm -rf $1
mkdir -p $1

cd scripts
./root_intermediate.sh rca_pass ica_pass
./server_setup.sh ica_pass server_pass
mkdir -p $1/serv_conf
cp certs/*.cert.pem $1/serv_conf/
cp certs/*.key.pem $1/serv_conf/
cp client_config.cnf $1/serv_conf/
cp create-tree.sh $1/
cp users.init.txt $1/serv_conf/users.txt
cd ..

cd server
make
cp server $1
cd ..

pushd $1
./create-tree.sh
rm create-tree.sh
popd

set +e

echo -e "\n"
echo -e "Installation finished successfully!"
echo -e "\n"
