/* dnstls_proxy - Simple stub resolver for DoTLS/DoHTTPS upstream servers.
 * *
 * * BSD 2-Clause License
 * *
 * * Copyright (c) 2022, Alexandre Janon <alex14fr@gmail.com>
 * * All rights reserved.
 * *
 * * Redistribution and use in source and binary forms, with or without
 * * modification, are permitted provided that the following conditions are met:
 * *
 * * 1. Redistributions of source code must retain the above copyright notice, this
 * * list of conditions and the following disclaimer.
 * *
 * * 2. Redistributions in binary form must reproduce the above copyright notice,
 * * this list of conditions and the following disclaimer in the documentation
 * * and/or other materials provided with the distribution.
 * *
 * * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
 * * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 * *
 * */

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

#include "config.h"


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

#ifdef QUAD9_DOT
#define IS_DOT
#define UPSTREAM_HOST "9.9.9.9:853"
#define UPSTREAM_SRVNAME "dns.quad9.net"
#endif

#ifdef QUAD9_DOH
#define IS_DOH
#define UPSTREAM_HOST "9.9.9.9:443"
#define UPSTREAM_SRVNAME "dns.quad9.net"
#endif


int sessionFd;
static struct tls_config *config;
static struct tls *ctx;
static sqlite3 *db;
static sqlite3_stmt *insertStmt;
static sqlite3_stmt *queryStmt;
#ifdef CACHEDB_KEEP_HIT_COUNT
static sqlite3_stmt *incHitStmt;
#endif

static void hexdump_pr(char *s, int len) {
	for(int i=0;i<16-len;i++) printf("   ");
	printf("   | ");
	for(int i=0;i<len;i++)
		if(s[i]>32 && s[i]<127)
			printf("%c",s[i]);
		else
			printf(".");
	printf("\n");
}

static void hexdump(char *s, int len) {
	for(int i=0;i<len;i++) {
		if(i>0 && (i%16==0)) {
			hexdump_pr(s+i-16,16);
		}
		printf("%02hhx ",s[i]);
	}
	hexdump_pr(s+len-(len%16 == 0 ? 16 : len%16),(len%16 == 0 ? 16 : len%16));
}

static void tlsconnect(void) {
	if(ctx) {
		tls_close(ctx);
		tls_free(ctx);
	}
	ctx=tls_client();
	dieunless(ctx,"tls_client()");
	if(tls_configure(ctx, config)) { tlsfatal("tls_configure"); }
	puts("Connecting to " UPSTREAM_HOST);
	if(tls_connect_servername(ctx, UPSTREAM_HOST, NULL, UPSTREAM_SRVNAME)) { tlserr("tls_connect"); }
	tls_handshake(ctx);
	printf("TLS ver : %s\ncipher : %s\ncert hash: %s\ncert subj: %s\ncert issuer: %s\n", tls_conn_version(ctx), tls_conn_cipher(ctx), tls_peer_cert_hash(ctx), tls_peer_cert_subject(ctx), tls_peer_cert_issuer(ctx));
	if(tls_conn_session_resumed(ctx)==1) { printf("TLS session resumed\n"); }
}

static void cache_init(void) {
	if(sqlite3_open(CACHEDB, &db)) {
		printf("error opening database %s : %s\n",CACHEDB,sqlite3_errmsg(db));
	}
#define stmt1 "INSERT INTO doh_cache (question,answer,timestamp) VALUES (?,?,unixepoch())"
#define stmt2 "SELECT answer FROM doh_cache WHERE question=?"
	if(sqlite3_prepare_v2(db,stmt1,strlen(stmt1),&insertStmt,NULL)) {
		printf("error preparing stmt : %s\n",sqlite3_errmsg(db));
	}
	if(sqlite3_prepare_v2(db,stmt2,strlen(stmt2),&queryStmt,NULL)) {
		printf("error preparing stmt : %s\n",sqlite3_errmsg(db));
	}
#ifdef CACHEDB_KEEP_HIT_COUNT
#undef stmt1
#define stmt1 "INSERT INTO doh_cache (question,answer,timestamp,hit_count) VALUES (?,?,unixepoch(),1)"
#define stmt3 "UPDATE doh_cache SET hit_count=hit_count+1 where question=?"
	if(sqlite3_prepare_v2(db,stmt3,strlen(stmt3),&incHitStmt,NULL)) {
		printf("error preparing stmt : %s\n",sqlite3_errmsg(db));
	}
#endif
}

static void cache_search(char *inpacket, int psize, char *answer, int *answersz) {
	*answersz=0;
	if(sqlite3_bind_blob(queryStmt,1,inpacket+12,psize-12,SQLITE_TRANSIENT)) { printf("error binding param : %s\n",sqlite3_errmsg(db)); } 
	int rc;
	rc=sqlite3_step(queryStmt);
	if(rc==SQLITE_DONE) { printf("cache: miss\n"); sqlite3_reset(queryStmt); return; }
	else if(rc==SQLITE_ROW) {
		printf("cache: hit\n");
		*answersz=sqlite3_column_bytes(queryStmt, 0);
		memcpy(answer,sqlite3_column_blob(queryStmt, 0),*answersz);
		answer[0]=inpacket[0];
		answer[1]=inpacket[1];
#ifdef CACHEDB_KEEP_HIT_COUNT
		if(sqlite3_bind_blob(incHitStmt, 1, inpacket+12, psize-12, SQLITE_TRANSIENT)) { printf("cache_search : error binding param : %s\n",sqlite3_errmsg(db)); }
		rc=sqlite3_step(incHitStmt);
		if(rc!=SQLITE_DONE) { printf("cache_search : error during sqlite3_step (rc=%d) : %s\n", rc, sqlite3_errmsg(db)); }
		sqlite3_reset(incHitStmt);
#endif
	} else {
		printf("error during sqlite3_step : %s\n", sqlite3_errmsg(db));
	}
	sqlite3_reset(queryStmt);
}

static void cache_save(char *inpacket, int psize, char *answer, int answersz) {
	if(answersz<=0) { printf("cache_save : won't save null answer\n"); return; }
	if(sqlite3_bind_blob(insertStmt,1,inpacket+12,psize-12,SQLITE_TRANSIENT)) { printf("cache_save : error binding param 1 : %s\n",sqlite3_errmsg(db)); } 
	if(sqlite3_bind_blob(insertStmt,2,answer,answersz,SQLITE_TRANSIENT)) { printf("cache_save : error binding param 2 : %s\n",sqlite3_errmsg(db)); } 
	int rc=sqlite3_step(insertStmt);
	if(rc!=SQLITE_DONE) { printf("cache_save : error during sqlite3_step (rc=%d): %s\n", rc, sqlite3_errmsg(db)); }
	sqlite3_reset(insertStmt);
}

static int tlswrite(char *s, int slen) {
	if(!ctx) tlsconnect();
	b: int rc=tls_write(ctx,s,slen);
	if(rc==TLS_WANT_POLLIN || rc==TLS_WANT_POLLOUT) goto b;
	if(rc==-1) { 
		printf("tlswrite():reconnect\n");
		tlsconnect(); 
		goto b;
	}
	return(0);
}

#ifdef IS_DOH 
#define PKT_OFF 0
static int upstream_query(char *inpacket, int psize, char *answer, unsigned int *answersz) {
	int i, j;
	*answersz=snprintf(answer,1024,"POST " DOH_PATH " HTTP/1.1\r\nhost:" UPSTREAM_SRVNAME "\r\ncontent-type:application/dns-message\r\naccept:*/*\r\ncontent-length:%d\r\n\r\n",(int)psize);
	memcpy(answer+*answersz, inpacket, psize);
	*answersz+=psize;
	b: if(tlswrite(answer, *answersz)==1) return(1);
	c: *answersz=tls_read(ctx,answer,1024);
	if(*answersz==TLS_WANT_POLLIN || *answersz==TLS_WANT_POLLOUT) goto c;
	if(*answersz<=0) { printf("tls_read()=%d\n",*answersz); tlserr("tls_read"); tlsconnect(); goto b; }
	printf("> (*answersz=%d) ",*answersz); for(int i=0;i<12;i++) printf("%c", answer[i]); puts("");
	if(strstr(answer,"HTTP/1.1 200")!=answer) { printf("bad http response status "); return(1); }
	for(i=0;i<*answersz-4 && (answer[i]!='\r' || answer[i+1]!='\n' || answer[i+2]!='\r' || answer[i+3]!='\n');i++);
	if(i==*answersz-4) { puts("error parsing http response : "); hexdump(answer,*answersz); return(1); }
	i+=4;
	printf("DNS response message found at %d :\n",i);
	hexdump(answer+i,*answersz-i); 
	for(j=0;j<*answersz-i;j++) answer[j]=answer[i+j];
	*answersz-=i;
	return(0);
}
#else /* IS_DOT */
#define PKT_OFF 2
static int upstream_query(char *inpacket, int psize, char *answer, unsigned int *answersz) {
	inpacket[0]=(psize>>8)%256;
	inpacket[1]=psize%256;
	b: if(tlswrite(inpacket, psize+2)==1) return(1);
	c: *answersz=tls_read(ctx,answer,1024);
	if(*answersz==TLS_WANT_POLLIN || *answersz==TLS_WANT_POLLOUT) goto c;
	if(*answersz<=0) { printf("tls_read()=%d\n",*answersz); tlserr("tls_read"); tlsconnect(); goto b; }
	printf("DNS response (*answersz=%d):\n",*answersz); hexdump(answer,2); hexdump(answer+2,*answersz-2);
	return(0);
}
#endif

int main(int argc, char **argv) {
	struct sockaddr_in addr, cl_addr;
	char inpacket[512];
	ssize_t psize;
	char answer[1024];
	unsigned int answersz;
	socklen_t claddrsz=sizeof(struct sockaddr_in);
	int s=socket(AF_INET,SOCK_DGRAM,0);
	char cacheAnsw[512];
	int cacheAnswSz;
	addr.sin_family=AF_INET;
	addr.sin_addr.s_addr=htonl(LISTEN_ADDR);
	addr.sin_port=htons(LOCAL_PORT);
	if(bind(s,(struct sockaddr *)&addr,sizeof(struct sockaddr_in))<0) { perror("bind"); exit(1); }
	if(chroot(CHROOTPATH)<0) { perror("chroot"); exit(1); }
	chdir("/");
	if(setgid(DROP_GID)<0) { perror("setgid"); exit(1); }
	if(setuid(DROP_UID)<0) { perror("setuid"); exit(1); }
	config=tls_config_new();
	tls_config_set_ca_file(config,CADB); 
#ifdef SESSION_RESUME
	sessionFd=open("tls_session",O_CREAT|O_RDWR,0600);
	tls_config_set_session_fd(config,sessionFd);
	tls_config_set_protocols(config,TLS_PROTOCOL_TLSv1_2);
#endif
	cache_init();
	while((psize=recvfrom(s,inpacket+PKT_OFF,512-PKT_OFF,0,(struct sockaddr *)&cl_addr,&claddrsz))>0) {
		puts("Got request :"); hexdump(inpacket+PKT_OFF,psize-PKT_OFF); 
		cache_search(inpacket+PKT_OFF,psize-PKT_OFF,cacheAnsw,&cacheAnswSz);
		if(cacheAnswSz>0) {
			puts("Response :"); hexdump(cacheAnsw,cacheAnswSz);
			sendto(s,cacheAnsw,cacheAnswSz,0,(struct sockaddr*)&cl_addr,claddrsz);
		} else {
			if(upstream_query(inpacket, psize, answer, &answersz)==1) {
				printf("upstream_query()==1\n");
				continue;
			}
			cache_save(inpacket+PKT_OFF,psize-PKT_OFF,answer+PKT_OFF,answersz-PKT_OFF);
			sendto(s,answer+PKT_OFF,answersz-PKT_OFF,0,(struct sockaddr*)&cl_addr,claddrsz);
		}
	}
}
