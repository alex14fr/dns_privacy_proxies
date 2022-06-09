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
echo 'CREATE TABLE doh_cache(question BLOB, answer BLOB, timestamp INTEGER, hit_count integer);CREATE INDEX i1 on doh_cache (question);CREATE INDEX i2 on doh_cache (timestamp);|sqlite3 /var/dnstls_proxy/cache
chown nobody:nobody /var/dnstls_proxy/*
chmod 0600 /var/dnstls_proxy/*   
```
- Compile with make
- Run with ./dnstls_proxy



