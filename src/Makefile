SOURCES := $(shell find . -name '*.c')
OBJECTS := $(SOURCES:.cpp=.o)

CFLAGS = -Wall -O0 -fPIC -D_GNU_SOURCE -I../lib -g
LDLIBS = -ldl -lads
LDFLAGS = -shared -L../lib
all: socket.so

socket.so: $(OBJECTS)
	@install -d bin -m 755
	$(CC) $(OBJECTS) -o ../bin/$@ $(LDLIBS) $(LDFLAGS) $(CFLAGS)

%.o: %.cpp
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

clean:
	rm -f ../bin/socket.so

distclean: clean
	rm -f configure
	rm -f config.h
	rm -f config.log
	rm -rf autom4te.cache
	rm -f config.status

.PHONY: clean distclean
