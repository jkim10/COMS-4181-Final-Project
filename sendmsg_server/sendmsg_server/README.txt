0. Add valid users as in HW3/4

1. make TREE=[TREE NAME]

The duckduckgo.pem will be copied to the tree (act as the client cert received) and to users/addleness/certs (act as the cert for encryption)

2. Go into the tree and call ./bin/sendmsg_server

The client cert will be put into tmp to assess validness. The encryption cert will be extract to the current place. 

3. make clean TREE=[TREE NAME] to restore