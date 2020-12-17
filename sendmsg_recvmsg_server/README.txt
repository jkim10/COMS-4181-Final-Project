0. Add valid users as in HW3/4

1. make TREE=[TREE NAME]

The duckduckgo.pem will be copied to the tree (act as the client cert received) and to users/addleness/certs (act as the cert for encryption)

2. Go into the tree and call ./bin/sendmsg

The client cert will be put into tmp to assess validness. The cert for encryption will be extracted to the current place. The message will be uploaded to users/[recipient]/messages/

3. Call ./bin/recvmsg

Only user addleness will have some message after 2. The message will be extracted to the current place.

4. make clean TREE=[TREE NAME] to restore