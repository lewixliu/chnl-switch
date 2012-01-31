CC = gcc

obj = winject.o cb_handlers.o
LIB_PATH = /usr/lib/
INC_PATH = /usr/include/
CFLAGS = -Wall -g -pedantic
LDFLAGS = -lnl

all: winject

winject: $(obj) 
	$(CC) -o winject -L$(LIB_PATH) -I$(INC_PATH) $(LDFLAGS) $(obj)

winject.o: winject.c
	$(CC) $(CFLAGS) -c winject.c

cb_handlers.o: cb_handlers.c
	$(CC) $(CFLAGS) -c cb_handlers.c

clean :
	rm winject $(obj)
