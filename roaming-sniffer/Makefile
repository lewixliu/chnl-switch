CC = gcc

obj = unpack.o ieee802_11.o sniffer.o
CFLAGS = -Wall -g -pedantic
LDFLAGS= -lpcap

all: sniff

sniff : $(obj)
	$(CC) -o sniff $(LDFLAGS) $(obj)

sniffer.o: sniffer.c
	$(CC) $(CFLAGS) -c sniffer.c

ieee802_11.o: ieee802_11.c
	$(CC) $(CFLAGS) -c ieee802_11.c

unpack.o: unpack.c
	$(CC) $(CFLAGS) -c unpack.c

clean:
	rm sniff $(obj)
