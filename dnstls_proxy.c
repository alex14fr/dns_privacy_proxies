#include <sys/socket.h>
#include <netinet/in.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <tls.h>
#include <sqlite3.h>

#define tlserr(s) { printf(s ": %s\n", (tls_error(ctx)?:" no error")); }
#define tlsfatal(s) { printf(s ": %s\n", (tls_error(ctx)?:"no error")); exit(1); }
#define dieunless(x,s) if(!x) { puts("!" s); exit(1); }

#define LISTEN_ADDR INADDR_LOOPBACK
#define LOCAL_PORT 53
#define DROP_UID 65534
#define DROP_GID 65534

// CREATE TABLE doh_cache(question BLOB, answer BLOB, timestamp INTEGER, hit_count integer);
// CREATE INDEX i1 on doh_cache (question);
// CREATE INDEX i2 on doh_cache (timestamp);
#define CHROOTPATH "/var/dnstls_proxy"
#define CACHEDB "/cache"
#define CADB "/cert.pem"

#define GOOG_DOT

#ifdef GOOG_DOH
#define IS_DOH
#define UPSTREAM_HOST "8.8.8.8:443"
#define UPSTREAM_SRVNAME "dns.google"
#define DOH_PATH "/dns-query"
#endif

#ifdef GOOG_DOT
#define IS_DOT
#define UPSTREAM_HOST "8.8.8.8:853"
#define UPSTREAM_SRVNAME "dns.google"
#endif

#ifdef CFLR_DOH
#define IS_DOH
#define UPSTREAM_HOST "1.1.1.1:443"
#define UPSTREAM_SRVNAME "cloudflare-dns.com"
#define DOH_PATH "/dns-query"
#endif

#ifdef CFLR_DOT
#define IS_DOT
#define UPSTREAM_HOST "1.1.1.1:853"
#define UPSTREAM_SRVNAME "cloudflare-dns.com"
#endif




char *dbErr=0;
sqlite3 *db;
sqlite3_stmt *insertStmt;
sqlite3_stmt *queryStmt;
sqlite3_stmt *incHitStmt;

void hexdump(char *s, int len) {
	for(int i=0;i<len;i++) {
		if(i>0 && (i%16==0)) printf("\n");
		printf("%02hhx ",s[i]);
	}
	puts("");
}

void tlsconnect(struct tls *ctx) {
	puts("Connecting to " UPSTREAM_HOST);
	if(tls_connect_servername(ctx, UPSTREAM_HOST, NULL, UPSTREAM_SRVNAME)) { tlserr("tls_connect"); }
}

void cache_init(void) {
	if(sqlite3_open(CACHEDB, &db)) {
		printf("error opening database %s : %s\n",CACHEDB,sqlite3_errmsg(db));
	}
#define stmt1 "INSERT INTO doh_cache (question,answer,timestamp,hit_count) VALUES (?,?,datetime(),1)"
#define stmt2 "SELECT question,answer,hit_count FROM doh_cache WHERE question=?"
#define stmt3 "UPDATE doh_cache SET hit_count=? where question=?"

	if(sqlite3_prepare_v2(db,stmt1,strlen(stmt1),&insertStmt,NULL)) {
		printf("error preparing stmt : %s\n",sqlite3_errmsg(db));
	}
	if(sqlite3_prepare_v2(db,stmt2,strlen(stmt2),&queryStmt,NULL)) {
		printf("error preparing stmt : %s\n",sqlite3_errmsg(db));
	}
	if(sqlite3_prepare_v2(db,stmt3,strlen(stmt3),&incHitStmt,NULL)) {
		printf("error preparing stmt : %s\n",sqlite3_errmsg(db));
	}
}

void cache_search(char *inpacket, int psize, char *answer, int *answersz) {
	*answersz=0;
	if(sqlite3_bind_blob(queryStmt,1,inpacket+12,psize-12,SQLITE_TRANSIENT)) { printf("error binding param : %s\n",sqlite3_errmsg(db)); } 
	int rc;
	rc=sqlite3_step(queryStmt);
	if(rc==SQLITE_DONE) { printf("cache: miss\n"); sqlite3_reset(queryStmt); return; }
	else if(rc==SQLITE_ROW) {
		printf("cache: hit\n");
		*answersz=sqlite3_column_bytes(queryStmt, 1);
		memcpy(answer,sqlite3_column_blob(queryStmt, 1),*answersz);
		answer[0]=inpacket[0];
		answer[1]=inpacket[1];
		int hitCnt=sqlite3_column_int(queryStmt, 2)+1;
		if(sqlite3_bind_int(incHitStmt, 1, hitCnt)) { printf("cache_search : error binding param 1 : %s\n",sqlite3_errmsg(db)); }
		if(sqlite3_bind_blob(incHitStmt, 2, inpacket+12, psize-12, SQLITE_TRANSIENT)) { printf("cache_search : error binding param 2 : %s\n",sqlite3_errmsg(db)); }
		rc=sqlite3_step(incHitStmt);
		if(rc!=SQLITE_DONE) { printf("cache_search : error during sqlite3_step (rc=%d) : %s\n", rc, sqlite3_errmsg(db)); }
		sqlite3_reset(incHitStmt);
	} else {
		printf("error during sqlite3_step : %s\n", sqlite3_errmsg(db));
	}
	sqlite3_reset(queryStmt);
}

void cache_save(char *inpacket, int psize, char *answer, int answersz) {
	if(sqlite3_bind_blob(insertStmt,1,inpacket+12,psize-12,SQLITE_TRANSIENT)) { printf("cache_save : error binding param 1 : %s\n",sqlite3_errmsg(db)); } 
	if(sqlite3_bind_blob(insertStmt,2,answer,answersz,SQLITE_TRANSIENT)) { printf("cache_save : error binding param 2 : %s\n",sqlite3_errmsg(db)); } 
	int rc=sqlite3_step(insertStmt);
	if(rc!=SQLITE_DONE) { printf("cache_save : error during sqlite3_step (rc=%d): %s\n", rc, sqlite3_errmsg(db)); }
	sqlite3_reset(insertStmt);
}

int tlswrite(struct tls *ctx, char *s, int slen) {
	if(tls_write(ctx,s,slen)<0) { 
		tlsconnect(ctx); 
		if(tls_handshake(ctx)<0) { printf("error during TLS handshake"); return(1); }
		printf("cert hash: %s\ncert subj: %s\ncert issuer: %s\n", tls_peer_cert_hash(ctx), tls_peer_cert_subject(ctx), tls_peer_cert_issuer(ctx));
		if(tls_write(ctx,s,slen)<0) { tlserr("tls_write"); return(1); } 
	}
	return(0);
}

#ifdef IS_DOH 
int upstream_query(struct tls *ctx, char *inpacket, int psize, char *answer, unsigned int *answersz) {
	int i, j;
	*answersz=snprintf(answer,1024,"POST " DOH_PATH " HTTP/1.1\r\nhost:" UPSTREAM_SRVNAME "\r\ncontent-type:application/dns-message\r\naccept:*/*\r\ncontent-length:%d\r\n\r\n",(int)psize);
	memcpy(answer+*answersz, inpacket, psize);
	*answersz+=psize;
	if(tlswrite(ctx, answer, *answersz)==1) return(1);
	*answersz=tls_read(ctx,answer,1024);
	if(*answersz<0) { printf("tls_read()=%d\n",*answersz); tlserr("tls_read"); return(1); }
	printf("> "); for(int i=0;i<12;i++) printf("%c", answer[i]); puts("");
	if(strstr(answer,"HTTP/1.1 200")!=answer) { printf("bad http response status "); return(1); }
	for(i=0;i<*answersz-4 && (answer[i]!='\r' || answer[i+1]!='\n' || answer[i+2]!='\r' || answer[i+3]!='\n');i++);
	if(i==*answersz-4) { puts("error parsing http response"); return(1); }
	i+=4;
	printf("DNS response message found at %d\n",i);
	hexdump(answer+i,*answersz-i); 
	for(j=0;j<*answersz-i;j++) answer[j]=answer[i+j];
	*answersz-=i;
	return(0);
}
#else /* IS_DOT */
int upstream_query(struct tls *ctx, char *inpacket, int psize, char *answer, unsigned int *answersz) {
	char x[2];
	x[0]=(psize>>8)%256;
	x[1]=psize%256;
	if(tlswrite(ctx, x, 2)==1) return(1);
	if(tlswrite(ctx, inpacket, psize)==1) return(1);
	*answersz=tls_read(ctx,answer,1024);
	if(*answersz<0) { printf("tls_read()=%d\n",*answersz); tlserr("tls_read"); return(1); }
	for(int j=0;j<*answersz-2;j++) answer[j]=answer[j+2];
	*answersz-=2;
	printf("> "); hexdump(answer,*answersz);
	return(0);
}
#endif

int main(int argc, char **argv) {
	struct sockaddr_in addr, cl_addr;
	char inpacket[512];
	struct tls_config *config;
	struct tls *ctx;
	ssize_t psize;
	char answer[1024];
	unsigned int answersz;
	socklen_t claddrsz=sizeof(struct sockaddr_in);
	int s=socket(AF_INET,SOCK_DGRAM,0);
	char cacheAnsw[512];
	int cacheAnswSz;
	addr.sin_family=AF_INET;
	addr.sin_addr.s_addr=htonl(LISTEN_ADDR);
	addr.sin_port=htons(53);
	if(bind(s,(struct sockaddr *)&addr,sizeof(struct sockaddr_in))<0) { perror("bind"); exit(1); }
	chroot(CHROOTPATH);
	setuid(DROP_UID);
	setgid(DROP_GID);
	config=tls_config_new();
	tls_config_set_ca_file(config,CADB); 
	ctx=tls_client();
	dieunless(ctx,"tls_client()");
	if(tls_configure(ctx, config)) { tlsfatal("tls_configure"); }
	cache_init();
	while((psize=recvfrom(s,inpacket,512,0,(struct sockaddr *)&cl_addr,&claddrsz))>0) {
		puts("> "); hexdump(inpacket,psize); 
		cache_search(inpacket,psize,cacheAnsw,&cacheAnswSz);
		if(cacheAnswSz>0) {
			printf("in main:\n"); hexdump(cacheAnsw,cacheAnswSz);
			sendto(s,cacheAnsw,cacheAnswSz,0,(struct sockaddr*)&cl_addr,claddrsz);
		} else {
			if(upstream_query(ctx, inpacket, psize, answer, &answersz)==1) {
				printf("upstream_query()==1\n");
				continue;
			}
			cache_save(inpacket,psize,answer,answersz);
			sendto(s,answer,answersz,0,(struct sockaddr*)&cl_addr,claddrsz);
		}
	}
}
