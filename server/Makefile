CC=clang
CPP=clang++
CXXFLAGS=-std=c++14 -Wall -I/usr/local/opt/openssl@1.1/include/
LDFLAGS=-L/usr/local/opt/openssl@1.1/lib/
LDLIBS=-lssl -lcrypto

.PHONY: all clean clean_all clean_certs test mem_check

all: server server-certificate.pem
	
server: 

regex_test: 

server-certificate.pem: server-public-key.pem
	openssl req -new -x509 -sha256 -key server-private-key.pem -subj "/CN=duckduckgo.com" -out server-certificate.pem

server-public-key.pem: server-private-key.pem
	openssl ec -in server-private-key.pem -pubout -out server-public-key.pem

server-private-key.pem:
	openssl ecparam -genkey -name prime256v1 -noout -out server-private-key.pem

clean:
	rm -f server regex_test

clean_all: clean clean_certs

clean_certs: 
	rm -f server-*.pem

test: server
	printf "username\npassword\ncertificate" | curl -v --cacert server-certificate.pem --resolve duckduckgo.com:8080:127.0.0.1 --data-binary @- https://duckduckgo.com:8080/getcert && printf "\n\n"
	printf "username\npassword\nnew_pass" | curl -v --cacert server-certificate.pem --resolve duckduckgo.com:8080:127.0.0.1 --data-binary @- https://duckduckgo.com:8080/changepw && printf "\n\n"
	printf "username\npassword\ncertificate" | curl -v --cacert server-certificate.pem --resolve duckduckgo.com:8080:127.0.0.1 --data-binary @- https://duckduckgo.com:8080/ && printf "\n\n"
	printf "" | nc localhost 8080 && printf "\n\n"

mem_check: CXXFLAGS+= -g
mem_check: clean all server
	valgrind --leak-check=full --show-leak-kinds=all --track-origins=yes --verbose ./server