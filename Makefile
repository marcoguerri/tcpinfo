SOURCES := $(shell find ./src -name '*.c')
OBJECTS := $(SOURCES:.cpp=.o)

CFLAGS = -Wall -O0 -fPIC -D_GNU_SOURCE -Ilib
LDLIBS = -ldl -L../libads/bin -lads -Wl,-rpath ../libads/bin
LDFLAGS = -shared -Llib
all: socket.so

socket.so: $(OBJECTS)
	@install -d bin -m 755
	$(CC) $(OBJECTS) -o ./bin/$@ $(LDLIBS) $(LDFLAGS) $(CFLAGS)

%.o: %.cpp
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

clean:
	rm -f ./bin/socket.so

.PHONY: clean
