CC = gcc
CFLAGS = -g -Wall "-I/usr/local/opt/openssl@1.1/include"
LDFLAGS="-L/usr/local/opt/openssl@1.1/lib"
LDLIBS= -lssl -lcrypto 
make: getcert changepw

getcert: getcert.o client_utils.o

changepw: changepw.o client_utils.o

getcert.o: getcert.c client_utils.h

changepw.o: getcert.c client_utils.h

client_utils.o: client_utils.c client_utils.h

.PHONY: clean
clean:
	rm -f *.o getcert changepw

.PHONY: all
all: clean getcert changepw