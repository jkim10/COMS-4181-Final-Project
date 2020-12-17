all: sendmsg recvmsg
	./create-tree $(TREE)
	mv sendmsg $(TREE)/bin
	mv recvmsg $(TREE)/bin
	cp duckduckgo.pem $(TREE)/client.cert.pem
	cp duckduckgo.pem $(TREE)/users/addleness/certs/encrypt.cert.pem
	cp message $(TREE)/message
	cp recipients $(TREE)/recipients
sendmsg: sendmsg.cpp utils.cpp utils.h
	g++ sendmsg.cpp utils.cpp -o sendmsg -lssl -lcrypto
recvmsg: recvmsg.cpp utils.cpp utils.h
	g++ recvmsg.cpp utils.cpp -o recvmsg -lssl -lcrypto

.PHONY: clean
clean:
	rm -rf $(TREE)