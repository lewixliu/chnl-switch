CC = gcc

obj = sniffer.o cb_handlers.o usr_iface.o counter.o
LIB_PATH = /usr/lib/
INC_PATH = /usr/include/
CFLAGS = -Wall -g -pedantic
LDFLAGS = -lnl

all: sniff

sniff : $(obj) 
	$(CC) -o sniff -L$(LIB_PATH) -I$(INC_PATH) $(LDFLAGS) $(obj)

sniffer.o: sniffer.c
	$(CC) $(CFLAGS) -c sniffer.c

cb_handlers.o: cb_handlers.c
	$(CC) $(CFLAGS) -c cb_handlers.c

usr_iface.o: usr_iface.c
	$(CC) $(CFLAGS) -c usr_iface.c

counter.o: counter.c
	$(CC) $(CFLAGS) -c counter.c

clean :
	rm sniff $(obj)
