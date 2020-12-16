all: main
main: main.cpp utils.cpp utils.h
	g++ main.cpp utils.cpp -o sendmsg_server -lssl -lcrypto
	./create-tree $(TREE)
	mv sendmsg_server $(TREE)/bin
	cp duckduckgo.pem $(TREE)/client.cert.pem
	cp duckduckgo.pem $(TREE)/users/addleness/certs/encrypt.cert.pem

.PHONY: clean
clean:
	rm -rf $(TREE)