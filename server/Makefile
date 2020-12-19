CC=clang++
CXX=clang++
CXXFLAGS=-std=c++14 -O3 -Wall
LDFLAGS=
LDLIBS=-lssl -lcrypto

OS=$(shell uname -s)
ifeq ($(OS),Linux)
	LDLIBS+= -lcrypt
endif
ifeq ($(OS),Darwin)
	CXXFLAGS+=-I/usr/local/opt/openssl@1.1/include/
	LDFLAGS+=-L/usr/local/opt/openssl@1.1/lib/
endif

.PHONY: all clean clean_all clean_certs test mem_check

all: server server-certificate.pem users.txt
	./create-tree
	# This is only for testing please remove once we have certs in mailbox working
	cp encrypt.cert.pem ./mailbox/users/addleness/certs/encrypt.cert.pem
	cp intermediate.cert.pem ./mailbox/tmp
	
server: utils.o utils_server.o

utils.o: utils.cpp
 
utils_server.o: utils_server.cpp

regex_test: 

server-certificate.pem: server-public-key.pem
	openssl req -new -x509 -sha256 -key server-private-key.pem -subj "/CN=duckduckgo.com" -out server-certificate.pem

server-public-key.pem: server-private-key.pem
	openssl ec -in server-private-key.pem -pubout -out server-public-key.pem

server-private-key.pem:
	openssl ecparam -genkey -name prime256v1 -noout -out server-private-key.pem

users.txt: 
	cp users.init.txt users.txt

clean:
	rm -f server *.o regex_test users.txt
	rm -rf mailbox

clean_all: clean clean_certs

clean_certs: 
	rm -f server-*.pem

test: server
	printf "addleness\nCardin_pwns\nnew_pass\ncertificate" | curl -v --cacert server-certificate.pem --resolve duckduckgo.com:8080:127.0.0.1 --data-binary @- https://duckduckgo.com:8080/changepw && printf "\n\n"
	printf "addleness\nnew_pass\nCardin_pwns\ncertificate" | curl -v --cacert server-certificate.pem --resolve duckduckgo.com:8080:127.0.0.1 --data-binary @- https://duckduckgo.com:8080/changepw && printf "\n\n"
	printf "addleness\nCardin_pwns\ncertificate" | curl -v --cacert server-certificate.pem --resolve duckduckgo.com:8080:127.0.0.1 --data-binary @- https://duckduckgo.com:8080/getcert && printf "\n\n"
	printf "wusername\nCardin_pwns\ncertificate" | curl -v --cacert server-certificate.pem --resolve duckduckgo.com:8080:127.0.0.1 --data-binary @- https://duckduckgo.com:8080/getcert && printf "\n\n"
	printf "addleness\nW_password\ncertificate" | curl -v --cacert server-certificate.pem --resolve duckduckgo.com:8080:127.0.0.1 --data-binary @- https://duckduckgo.com:8080/getcert && printf "\n\n"
	printf "username\npassword\ncertificate" | curl -v --cacert server-certificate.pem --resolve duckduckgo.com:8080:127.0.0.1 --data-binary @- https://duckduckgo.com:8080/ && printf "\n\n"
	printf "rand_str" | nc localhost 8080 && printf "\n\n"

mem_check: CXXFLAGS+= -g
mem_check: clean all server
	valgrind --leak-check=full --show-leak-kinds=all --track-origins=yes ./server
