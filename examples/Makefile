CFLAGS=-g -I../include
LDFLAGS=../out/libmstream.a -lpthread -lm

all: single multi

single: single.c
	$(CC) $(CFLAGS) single.c -o single $(LDFLAGS)

multi: multi.c
	$(CC) $(CFLAGS) multi.c -o multi $(LDFLAGS)

clean:
	rm -f single multi
