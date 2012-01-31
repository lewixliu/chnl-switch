CC = gcc

obj = winject.o
LIB_PATH = /usr/lib/
INC_PATH = /usr/include/
CFLAGS = -Wall -g -pedantic
LDFLAGS = -lnl

all: winject

winject: $(obj) 
	$(CC) -o winject -L$(LIB_PATH) -I$(INC_PATH) $(LDFLAGS) $(obj)

winject.o: winject.c
	$(CC) $(CFLAGS) -c winject.c

clean :
	rm winject $(obj)
