CFLAGS=-O3 -I../include
LDFLAGS=../out/libmstream.a -lpthread -lm

all: simple

simple: simple.c
	$(CC) $(CFLAGS) simple.c -o simple $(LDFLAGS)

clean:
	rm -f simple
