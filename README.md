# dnstls_proxy, mini_dnscrypt
Simple stub resolvers for DoTLS/DoHTTPS/DNSCrypt upstream servers

## Features

- Supports DNS-over-TLS, DNS-over-HTTPS and DNSCrypt v2 (UDP and TCP transports, XChacha20-Poly1305 crypto)
- Persistent disk cache (SQLite)
- Small memory footprint
- No runtime configuration (suckless-style)

## Limitations

- Cache never expires (by design; you can however use a simple SQLite query to clean up stale cache entries when you want to, and insert fake cache entries to run a filtering server or to add a private zone)
- Only queries with one question are correctly handled
- Queries and answers must fit in one datagram
- Queries are processed sequentially
- DoH is HTTP/1.1-only

## Dependencies

- SQLite <https://www.sqlite.org>
- For DoTLS/DoHTTPS : LibTLS <https://www.libressl.org> or libreTLS for OpenSSL <https://git.causal.agency/libretls/>
- For DNSCrypt : libsodium <https://www.libsodium.org>
- POSIX C library with chroot()

## Installation for DoTLS/DoHTTPS

- Edit doth/config.h file
- Create the daemon chroot directory and cache database, for instance, as root:
``` 
umask 077
mkdir /var/dnstls_proxy
chown nobody:nobody /var/dnstls_proxy
cp /etc/ssl/cert.pem /var/dnstls_proxy/
cat schema.txt | sqlite3 /var/dnstls_proxy/cache
chown nobody:nobody /var/dnstls_proxy/*
```
- Compile with make -C doth
- Run with doth/dnstls_proxy
- Set 127.0.0.1 as nameserver
- To clean the cache, run for instance
```
echo 'delete from doh_cache where timestamp<unixepoch()-3600;' | sqlite3 /var/dnstls_proxy/cache
```
to clean the cache entries created more than 1 hour ago.

## Installation for DNSCrypt

- Generate the list of public resolvers with make -C dnscrypt public-resolvers.h
- Edit dnscrypt/config.h file
- Create the daemon chroot directory and cache databases as for DoTLS/DoHTTPS
- Compile with make -C dnscrypt
- Run with dnscrypt/mini_dnscrypt
- Set 127.0.0.1 as nameserver
- To clean the cache, run the same command as for DoTLS/DoHTTPS.

## References

- RFC1035: Domain names - implementation and specification <https://datatracker.ietf.org/doc/html/rfc1035> 
- RFC7858: Specification for DNS over Transport Layer Security (TLS)  <https://datatracker.ietf.org/doc/html/rfc7858>
- RFC8484: DNS queries over HTTPS (DoH) <https://datatracker.ietf.org/doc/html/rfc8484>
- DNSCrypt protocol specification <https://dnscrypt.info/protocol/>
- DoT/DoH/DNSCrypt public server list <https://dnscrypt.info/public-servers>
- DNS stamp calculator <https://dnscrypt.info/stamps>



