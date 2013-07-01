CFLAGS=-g -fPIC -Isrc -Iinclude

OBJECTS = \
  out/daemon.o \
  out/stream.o \
  out/congestion.o \
  out/heap.o \
  out/common.o

all: libmstream

out/%.o: src/%.c
	@mkdir -p `dirname out/$*.o`
	$(CC) $(CFLAGS) -c src/$*.c -o out/$*.o

libmstream: $(OBJECTS)
	$(CC) -shared -Wl,-soname,libmstream.so.1 -o out/libmstream.so.1.0.1 $(OBJECTS)
	ar rcs out/libmstream.a $(OBJECTS)

clean:
	rm -rf out
