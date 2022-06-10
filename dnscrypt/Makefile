CFLAGS=-Wall -O2 -std=c99 -D_GNU_SOURCE -I/opt/libsodium/include
LDFLAGS=-s
LDLIBS=-lsqlite3 -L/opt/libsodium/lib -lsodium
BINS=mini_dnscrypt

.PHONY: all clean

all: $(BINS)

mini_dnscrypt: mini_dnscrypt.c config.h

clean:
	rm -f $(BINS)

