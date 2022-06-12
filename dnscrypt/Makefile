CFLAGS=-Wall -O2 -std=c99 -D_GNU_SOURCE -I/opt/libsodium/include -pthread
LDFLAGS=-s
LDLIBS=-lsqlite3 -L/opt/libsodium/lib -lsodium
BINS=mini_dnscrypt sdns_decode

.PHONY: all clean

all: sdns_decode mini_dnscrypt mini_dnscrypt_mt

mini_dnscrypt: mini_dnscrypt.c config.h

public-resolvers.md:
	curl -o public-resolvers.md https://raw.githubusercontent.com/DNSCrypt/dnscrypt-resolvers/master/v2/public-resolvers.md

public-resolvers.h: sdns_decode public-resolvers.md
	./sdns_decode < public-resolvers.md > public-resolvers.h

clean:
	rm -f $(BINS)

.PHONY: clean public-resolvers.md

