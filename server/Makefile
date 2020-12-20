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

.PHONY: all clean test mem_check

all: server
	
server: utils.o utils_server.o

utils.o: utils.cpp
 
utils_server.o: utils_server.cpp

hpw_file: 
	mkdir -p serv_conf
	cp ../scripts/users.init.txt serv_conf/users.txt

mailbox:
	../scripts/create-tree.sh
	# This is only for testing please remove once we have certs in mailbox working
	cp encrypt.cert.pem ./mailbox/users/addleness/certs/encrypt.cert.pem
    cp intermediate.cert.pem ./mailbox/tmp

clean:
	rm -f server *.o users.txt
	rm -rf mailbox

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
	valgrind --leak-check=full --show-leak-kinds=all --track-origins=yes --track-fds=yes ./server
