CFLAGS=-Wall -Os -std=c99 -D_BSD_SOURCE
LDFLAGS=-s
LDLIBS=-lsqlite3 -ltls
BINS=dnstls_proxy

.PHONY: all clean

all: $(BINS)

clean:
	rm -f $(BINS)

