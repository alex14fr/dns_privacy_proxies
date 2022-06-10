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

// Upstream configuration; available presets, or see below to set your custom parameters.
// See <https://github.com/DNSCrypt/dnscrypt-resolvers/blob/master/v2/public-resolvers.md> for a list of sdns:// adresses
// and <https://dnscrypt.info/stamps/> to convert the sdns:// stamp into suitable parameters.
#define UPSTREAM_SCALEWAY_PAR

#ifdef UPSTREAM_ACSACSAR_AMS   // hosted in Amsterdam, run by acsacsar
#define UPSTREAM_HOST "51.158.166.97"			// host IP as a string
#define UPSTREAM_PORT 443
#define UPSTREAM_SRVNAME "\1" "2\xd" "dnscrypt-cert\xc" "acsacsar-ams\x3" "com\0"  	// provider name in DNS format
#define UPSTREAM_PUBKEY "0327f3cf927e995f46fb2381e07c1c764ef25f5d8442ce48bdaee4577a06b651"	// long-term server pubkey (leave empty for no verification)
#define UPSTREAM_UDP
#endif

#ifdef UPSTREAM_SCALEWAY_PAR  // hosted in Paris, run by Frank Denis, hosted by scaleway
#define UPSTREAM_HOST "212.47.228.136"
#define UPSTREAM_PORT 443
#define UPSTREAM_SRVNAME "\1" "2\xd" "dnscrypt-cert\x2" "fr\x8" "dnscrypt\x3" "org\0"
#define UPSTREAM_PUBKEY "e801b84ea606bfb0bac0ce43445bb15eba64b02fa3c4aa31ae10636a0790324d"
#define UPSTREAM_UDP
#endif

#define TIMEOUT_SECS 2   // timeout in seconds for upstream answer

// Debug options
// #define DUMP_RTRIP     // show hexdump of the packets sent and received to/from upstream
// #define DUMP_KEYS		  // show server and client keys and crypto details (nonces, paddings)
// #define DUMP_CLEAR	  // show clear queries and answers
// #define DUMP_CACHE	  // dump cache hits and misses
// #define DUMP_LOCAL	  // dump downstream packets 
//
