CC = gcc
CFLAGS = -g -Wall 
LDLIBS= -lssl -lcrypto

c_all: getcert changepw recvmsg sendmsg

getcert: getcert.o client_utils.o
	
changepw: changepw.o client_utils.o

getcert.o: getcert.c client_utils.h

changepw.o: changepw.c client_utils.h

client_utils.o: client_utils.c client_utils.h

recvmsg: recvmsg.o client_utils.o utils.o
	g++ $(CFLAGS) recvmsg.o client_utils.o utils.o -o recvmsg  $(LDLIBS)

recvmsg.o: recvmsg.cpp client_utils.h

sendmsg: sendmsg.o client_utils.o utils.o
	g++ $(CFLAGS) sendmsg.o client_utils.o utils.o -o sendmsg  $(LDLIBS)

utils.o: utils.cpp utils.h

sendmsg.o: sendmsg.cpp client_utils.h

.PHONY: clean
clean:
	rm -f *.o getcert recvmsg sendmsg changepw

.PHONY: all
all: clean getcert