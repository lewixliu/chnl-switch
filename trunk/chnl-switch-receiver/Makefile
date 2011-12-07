CC = gcc

src = scan.c
obj = scan.o
LIB_PATH = /usr/lib/
INC_PATH = /usr/include/
CFLAGS = -Wall -g
LDFLAGS = -lnl

scan : $(obj) 
	$(CC) -o scan -L$(LIB_PATH) -I$(INC_PATH) $(LDFLAGS) $(obj)

.c.o:
	$(CC) $(CFLAGS) -c $*.c

clean :
	rm scan $(obj)
