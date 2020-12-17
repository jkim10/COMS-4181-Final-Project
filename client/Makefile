CC = gcc
CFLAGS = -g -Wall -lssl -lcrypto "-I/usr/local/opt/openssl@1.1/include"
LDFLAGS="-L/usr/local/opt/openssl@1.1/lib"

make: getcert changepw

getcert: getcert.o client_utils.o
	$(CC) $(CFLAGS) $(LDFLAGS) getcert.o client_utils.o -o getcert

changepw: changepw.o client_utils.o
	$(CC) $(CFLAGS) $(LDFLAGS) changepw.o client_utils.o -o changepw

getcert.o: getcert.c client_utils.h

changepw.o: getcert.c client_utils.h

client_utils.o: client_utils.c client_utils.h

.PHONY: clean
clean:
	rm -f *.o getcert

.PHONY: all
all: clean getcert changepw