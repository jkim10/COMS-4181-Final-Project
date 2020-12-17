CC=clang
CPP=clang++
CXXFLAGS=-std=c++14 -I/usr/local/opt/openssl@1.1/include/
LDFLAGS=-L/usr/local/opt/openssl@1.1/lib/
LDLIBS=-lssl -lcrypto

.PHONY: all clean test

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
	rm -f server regex_test server-*.pem

test:
	printf "username\npassword\ncertificate" | curl -v --cacert server-certificate.pem --resolve duckduckgo.com:8080:127.0.0.1 --data-binary @- https://duckduckgo.com:8080/getcert