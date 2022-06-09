CFLAGS=-Wall -O2 -std=c99 -D_BSD_SOURCE
LDFLAGS=-s
LDLIBS=-lsqlite3 -ltls
BINS=dnstls_proxy

.PHONY: all clean

all: $(BINS)

dnstls_proxy: dnstls_proxy.c config.h

clean:
	rm -f $(BINS)

