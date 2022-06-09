# dnstls_proxy
Simple stub resolver for DoTLS/DoHTTPS upstream servers

## Features

- Supports DNS-over-TLS and DNS-over-HTTPS
- Persistent disk cache (SQLite)
- Small memory footprint
- No runtime configuration (suckless-style)

## Limitations

- Cache never expires (by design; you can however use a simple SQLite query to clean up stale cache entries when you want to)
- Only queries with one question are correctly handled
- Queries and answers must fit in one datagram
- Queries are processed sequentially
- DoH is HTTP/1.1-only

## Dependencies

- SQLite <https://www.sqlite.org>
- LibTLS <https://www.libressl.org> or libreTLS for OpenSSL <https://git.causal.agency/libretls/>
- POSIX C library with chroot()

## Installation

- Edit config.h file
- Create the daemon chroot directory, for instance, as root:
``` 
mkdir /var/dnstls_proxy
chown nobody:nobody /var/dnstls_proxy
chmod 0700 /var/dnstls_proxy
cp /etc/ssl/cert.pem /var/dnstls_proxy/
cat schema.txt | sqlite3 /var/dnstls_proxy/cache
chown nobody:nobody /var/dnstls_proxy/*
chmod 0600 /var/dnstls_proxy/*   
```
- Compile with make
- Run with ./dnstls_proxy
- Set 127.0.0.1 as your nameserver
- To clean the cache, run for instance
```
echo 'delete from doh_cache where timestamp<unixepoch()-3600;' | sqlite3 /var/dnstls_proxy/cache
```
to clean the cache entries created more than 1 hour ago.

## References

- RFC1035: Domain names - implementation and specification <https://datatracker.ietf.org/doc/html/rfc1035> 
- RFC7858: Specification for DNS over Transport Layer Security (TLS)  <https://datatracker.ietf.org/doc/html/rfc7858>
- RFC8484: DNS queries over HTTPS (DoH) <https://datatracker.ietf.org/doc/html/rfc8484>


