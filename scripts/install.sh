#!/bin/bash

if [ $# -ne 4 ]; then
    echo "Usage: ./install.sh <install_dir>"
    exit 1
fi

rm -rf $1
mkdir -p $1

cd scripts
./root_intermediate.sh
./server_setup.sh
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

echo -e "\n"
echo -e "Installation finished successfully!"
echo -e "\n"