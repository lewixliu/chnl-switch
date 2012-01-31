CC = gcc

obj = unpack.o ieee802_11.o sniffer.o
CFLAGS = -Wall -g -pedantic
LDFLAGS= -lpcap -lm

all: hop-sniffer

hop-sniffer: $(obj)
	$(CC) -o hop-sniffer $(obj) $(LDFLAGS)

sniffer.o: sniffer.c
	$(CC) $(CFLAGS) -c sniffer.c

ieee802_11.o: ieee802_11.c
	$(CC) $(CFLAGS) -c ieee802_11.c

unpack.o: unpack.c
	$(CC) $(CFLAGS) -c unpack.c

clean:
	rm hop-sniffer $(obj)
