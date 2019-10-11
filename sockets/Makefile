###################################################
#
# Makefile
# Simple TCP/IP communication using sockets
#
# Vangelis Koukis <vkoukis@cslab.ece.ntua.gr>
#
###################################################

CC = gcc

CFLAGS = -Wall
CFLAGS += -g
# CFLAGS += -O2 -fomit-frame-pointer -finline-functions

LIBS =

BINS = socket-server-z3 socket-client-z3 socket-server-z1 socket-client-z1

all: $(BINS)

socket-server-z3: socket-server-z3.c socket-common.h
	$(CC) $(CFLAGS) -o $@ $< $(LIBS)

socket-client-z3: socket-client-z3.c socket-common.h
	$(CC) $(CFLAGS) -o $@ $< $(LIBS)

socket-server-z1: socket-server-z1.c socket-common.h
	$(CC) $(CFLAGS) -o $@ $< $(LIBS)

socket-client-z1: socket-client-z1.c socket-common.h
	$(CC) $(CFLAGS) -o $@ $< $(LIBS)

clean:
	rm -f *.o *~ $(BINS)
