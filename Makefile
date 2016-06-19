SOURCES := $(shell find . -name '*.c')
OBJECTS := $(SOURCES:.cpp=.o)

CFLAGS = -Wall -O0 -fPIC -D_GNU_SOURCE
LDLIBS = -ldl
LDFLAGS = -shared
all: socket.so

socket.so: $(OBJECTS)
	$(CC) $(OBJECTS) -o $@ $(LDLIBS) $(LDFLAGS) $(CFLAGS)

%.o: %.cpp
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

clean:
	rm -f socket.so

.PHONY: clean
