all: sendmsg
sendmsg: sendmsg.cpp utils.cpp utils.h
	g++ sendmsg.cpp utils.cpp -o sendmsg -lssl -lcrypto
	./create-tree $(TREE)
	mv sendmsg $(TREE)/bin
	cp duckduckgo.pem $(TREE)/client.cert.pem
	cp duckduckgo.pem $(TREE)/users/addleness/certs/encrypt.cert.pem
	cp message $(TREE)/message

.PHONY: clean
clean:
	rm -rf $(TREE)