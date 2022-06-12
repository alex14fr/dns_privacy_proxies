// Configuration file for dnstls_proxy
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

// Path of the CA certificate database; usually a copy of /etc/ssl/cert.pem
#define CADB "/cert.pem"

// Upstream configuration; available presets, or see below to set your custom parameters.
//    GOOG_DOT    8.8.8.8 (Google), DNS over TLS
//    GOOG_DOH    8.8.8.8 (Google), DNS over HTTPS
//    CFLR_DOT    1.1.1.1 (Cloudflare), DNS over TLS
//    CFLR_DOH    1.1.1.1 (Cloudflare), DNS over HTTPS
// Preferer DNS over TLS if your network configuration allow TCP connections to port 853.
#define QUAD9_DOT

// Use session resumption to decrease connection latency, force TLSv1.2.
#define SESSION_RESUME

// Customized upstream:
//#define IS_DOH   								// for DNS over HTTPS, leave undefined for DNS over TLS
//#define UPSTREAM_HOST "54.39.15.77:853"			// host IP:port as a string
//#define UPSTREAM_SRVNAME "dns.anondns.org"  	// server subject name for certificate validation
//#define DOH_PATH "/dns-query"				// path to use for DNS over HTTPS (leave undefined for DNS over TLS)



