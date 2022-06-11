// Configuration file for mini_dnscrypt
// Edit as you need and recompile with make.
//



// Listen adress : INADDR_LOOPBACK, INADDR_ANY, inet_addr("192.168.1.1") 
#define LISTEN_ADDR INADDR_LOOPBACK

// Listening UDP port, usually 53
#define LOCAL_PORT 53

// unprivilegied UIDs to run under after bind()
#define DROP_UID 65534
#define DROP_GID 65534

// Root directory for the daemon, must be writable by DROP_UID:DROP_GID
#define CHROOTPATH "/var/dnstls_proxy"

// Path (relative to CHROOTPATH) containing the cache SQLite database
// See schema.txt for DB schema.
#define CACHEDB "/cache"

// Keep the hit count on each cache entry, leave undef to save a write to the DB at each request
//#define CACHEDB_KEEP_HIT_COUNT

// Upstream configuration; available presets in public-resolvers.h, or see below to set your custom parameters.
// See <https://github.com/DNSCrypt/dnscrypt-resolvers/blob/master/v2/public-resolvers.md> for a list of sdns:// adresses
// Run `make public-resolvers.h' to get an up-to-date list.
#define UPSTREAM_P315    // Set UPSTREAM_Px (choose x in public-resolvers.h)
#include "public-resolvers.h"

// Prefer UDP transport if your firewall allows it, unset if it fails.
#define UPSTREAM_UDP

// Timeout in seconds for upstream answer
#define TIMEOUT_SECS 2

// Debug options
// #define DUMP_RTRIP     // show hexdump of the packets sent and received to/from upstream
// #define DUMP_KEYS		  // show server and client keys and crypto details (nonces, paddings)
// #define DUMP_CLEAR	  // show clear queries and answers
// #define DUMP_CACHE	  // dump cache hits and misses
// #define DUMP_LOCAL	  // dump downstream packets 
//
//
//

