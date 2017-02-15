SOURCES := $(shell find . -name '*.c')
OBJECTS := $(SOURCES:.cpp=.o)

# External libraries, lib and include files
LIBS := ../lib/libads

CFLAGS = -Wall -O0 -fPIC -D_GNU_SOURCE 
CFLAGS += $(foreach includedir,$(LIBS),-I$(includedir)/include)

LDLIBS = -ldl -lads
LDFLAGS = -shared $(foreach libdir,$(LIBS),-L$(libdir)/lib)

all: socket.so

socket.so: $(OBJECTS)
	autoconf
	./configure
	make -C ../lib/libads
	$(CC) $(OBJECTS) -o ../lib/$@ $(LDLIBS) $(LDFLAGS) $(CFLAGS)

%.o: %.cpp
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f ../lib/socket.so

distclean: clean
	rm -f configure
	rm -f config.h
	rm -f config.log
	rm -rf autom4te.cache
	rm -f config.status

.PHONY: clean distclean
