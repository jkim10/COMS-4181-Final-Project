CC = gcc
CFLAGS = -g -Wall -lssl -lcrypto "-I/usr/local/opt/openssl@1.1/include"
LDFLAGS="-L/usr/local/opt/openssl@1.1/lib"

getcert:

.PHONY: clean
clean:
	rm -f *.o getcert

.PHONY: all
all: clean getcert