CC = gcc
CFLAGS = -g -Wall 
LDFLAGS= -lssl -lcrypto

c_all: getcert recvmsg sendmsg

getcert: getcert.o client_utils.o
	$(CC) $(CFLAGS) getcert.o client_utils.o -o getcert  $(LDFLAGS)

getcert.o: getcert.c client_utils.h

client_utils.o: client_utils.c client_utils.h

recvmsg: recvmsg.o client_utils.o
	$(CC) $(CFLAGS) recvmsg.o client_utils.o -o recvmsg  $(LDFLAGS)

recvmsg.o: recvmsg.c client_utils.h

sendmsg: sendmsg.o client_utils.o
	g++ $(CFLAGS) sendmsg.o client_utils.o -o sendmsg  $(LDFLAGS)

sendmsg.o: sendmsg.cpp client_utils.h

.PHONY: clean
clean:
	rm -f *.o getcert recvmsg sendmsg 

.PHONY: all
all: clean getcert