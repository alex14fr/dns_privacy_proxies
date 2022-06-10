/* mini_dnscrypt - Simple client resolver for DNSCrypt upstream servers.
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
#include <arpa/inet.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <setjmp.h>
#include <signal.h>
#include <sqlite3.h>
#include <sodium.h>

#include "config.h"

static sigjmp_buf env;

static sqlite3 *db;
static sqlite3_stmt *insertStmt;
static sqlite3_stmt *queryStmt;
#ifdef CACHEDB_KEEP_HIT_COUNT
static sqlite3_stmt *incHitStmt;
#endif

static void timeout(int s) {
	printf("Timeout\n");
	siglongjmp(env, 1);
}

static void hexdump_pr(unsigned char *s, int len) {
	for(int i=0;i<16-len;i++) printf("   ");
	printf("   | ");
	for(int i=0;i<len;i++)
		if(s[i]>32 && s[i]<127)
			printf("%c",s[i]);
		else
			printf(".");
	printf("\n");
}

static void hexdump(unsigned char *s, int len) {
	for(int i=0;i<len;i++) {
		if(i>0 && (i%16==0)) {
			hexdump_pr(s+i-16,16);
		}
		printf("%02hhx ",s[i]);
	}
	hexdump_pr(s+len-(len%16 == 0 ? 16 : len%16),(len%16 == 0 ? 16 : len%16));
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

static void cache_search(unsigned char *inpacket, int psize, unsigned char *answer, int *answersz) {
	*answersz=0;
	if(sqlite3_bind_blob(queryStmt,1,inpacket+12,psize-12,SQLITE_TRANSIENT)) { printf("error binding param : %s\n",sqlite3_errmsg(db)); } 
	int rc;
	rc=sqlite3_step(queryStmt);
	if(rc==SQLITE_DONE) { 
#ifdef DUMP_CACHE
		printf("cache: miss\n"); 
#endif
		sqlite3_reset(queryStmt); 
		return; 
	}
	else if(rc==SQLITE_ROW) {
#ifdef DUMP_CACHE
		printf("cache: hit\n");
#endif
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

static void cache_save(unsigned char *inpacket, int psize, unsigned char *answer, int answersz) {
	if(answersz<=0) { printf("cache_save : won't save null answer\n"); return; }
	if(sqlite3_bind_blob(insertStmt,1,inpacket+12,psize-12,SQLITE_TRANSIENT)) { printf("cache_save : error binding param 1 : %s\n",sqlite3_errmsg(db)); } 
	if(sqlite3_bind_blob(insertStmt,2,answer,answersz,SQLITE_TRANSIENT)) { printf("cache_save : error binding param 2 : %s\n",sqlite3_errmsg(db)); } 
	int rc=sqlite3_step(insertStmt);
	if(rc!=SQLITE_DONE) { printf("cache_save : error during sqlite3_step (rc=%d): %s\n", rc, sqlite3_errmsg(db)); }
	sqlite3_reset(insertStmt);
}

#ifdef UPSTREAM_UDP
#define PKT_OFF 0

static int upstreamsock;
static struct sockaddr_in upstreamaddr;
static int sinfo_ts;
static unsigned char sinfoBuf[512];
static unsigned char *sinfo;
static unsigned char *sinfo_clientMagic;
static unsigned char *sinfo_resolverPk;
static uint32_t sinfo_tsend;
static int sinfo_len;
static unsigned char clientPk[32], clientSk[32];
static unsigned char sharedK[32];


static int rtrip_upstream(unsigned char *in, int insize, unsigned char *out, int *outsize) {
	int rc;
	if(!upstreamsock)
		upstreamsock=socket(AF_INET,SOCK_DGRAM,0);
	if(!upstreamaddr.sin_addr.s_addr) {
		upstreamaddr.sin_family=AF_INET;
		upstreamaddr.sin_addr.s_addr=inet_addr(UPSTREAM_HOST);
		upstreamaddr.sin_port=htons(UPSTREAM_PORT);
	}
#ifdef DUMP_RTRIP
	printf("Sending :\n"); hexdump(in, insize);
#endif
	if((rc=sendto(upstreamsock, in, insize, 0, (struct sockaddr*)&upstreamaddr, sizeof(struct sockaddr_in)))<0) {
		perror("sendto");
		return(rc);
	}
	socklen_t claddrsz=sizeof(struct sockaddr_in);
	alarm(TIMEOUT_SECS);
	signal(SIGALRM,timeout);
	if(sigsetjmp(env, 1)==0) {
		*outsize=recvfrom(upstreamsock, out, 512, 0, (struct sockaddr*)&upstreamaddr, &claddrsz);
		alarm(0);
		if(*outsize<0) { perror("recvfrom"); return(*outsize); }
#ifdef DUMP_RTRIP
		printf("Received :\n"); hexdump(out, *outsize);
#endif
		return(0);
	} else {
		alarm(0);
		return(1);
	}
}

static int get_sinfo(void) {
	unsigned char qry[512];
	bzero(qry,512);
	qry[0]='\x55'; qry[1]='\xaa';
	qry[2]=qry[5]='\x01'; 
	memcpy(qry+12, UPSTREAM_SRVNAME, strlen(UPSTREAM_SRVNAME));
	qry[12+strlen(UPSTREAM_SRVNAME)+2]='\x10';
	qry[12+strlen(UPSTREAM_SRVNAME)+4]='\x01';
	sinfo_len=0;
	rtrip_upstream(qry, 12+strlen(UPSTREAM_SRVNAME)+5, sinfoBuf, &sinfo_len);
	if(sinfo_len==0) {
		printf("Error reading server info from upstream\n");
		return(1);
	}
	sinfo=memmem(sinfoBuf,sinfo_len,"DNSC",4);
	if(sinfo==NULL) {
		printf("cert-magic not found");
		return(2);
	}
	sinfo_resolverPk=sinfo+72;
	sinfo_clientMagic=sinfo+104;

	if(sinfo[4]==0 && sinfo[5]==2) {
		printf("Crypto suite : Ed25519-X25519-XChacha20-Poly1305\n"); 
	} else {
		printf("Unsupported crypto suite %d\n", (sinfo[4]<<8)+sinfo[5]);
		return(2);
	}
//	printf("Protocol-minor-version : \n"); hexdump(sinfo+6,2);
	uint32_t serial=sinfo[115]+(sinfo[114]<<8)+(sinfo[113]<<16)+(sinfo[112]<<24);
	printf("Serial : %d\n", serial); //hexdump(sinfo+112,4);
	time_t tsstart=sinfo[119]+(sinfo[118]<<8)+(sinfo[117]<<16)+(sinfo[116]<<24);
	printf("TS-start : %s", asctime(gmtime(&tsstart))); //hexdump(sinfo+116,4);
	time_t tsend=sinfo[123]+(sinfo[122]<<8)+(sinfo[121]<<16)+(sinfo[120]<<24);
	printf("TS-end : %s", asctime(gmtime(&tsend))); //hexdump(sinfo+120,4);
	sinfo_tsend=(uint32_t)tsend;
	time_t now=time(NULL);
	if(now<tsstart || now>tsend) {
		printf("Warning : certificate not yet valid or expired\n");
	}

#ifdef DUMP_KEYS
	printf("Client magic : \n"); hexdump(sinfo_clientMagic,8);
	printf("Resolver PK : \n"); hexdump(sinfo_resolverPk,32);
#endif
	unsigned char *signature=sinfo+8;
	unsigned char *tosign=sinfo+72;
	int tosignlen=52;
	
	unsigned char longtermPk[32];
	size_t binlen;
	sodium_hex2bin(longtermPk, 32, UPSTREAM_PUBKEY, strlen(UPSTREAM_PUBKEY), NULL, &binlen, NULL);
	int rc;
	if(binlen>0) {
		rc=crypto_sign_ed25519_verify_detached(signature, tosign, tosignlen, longtermPk);
		if(rc!=0) {
			printf("Upstream certificate verification failed\n");
			printf("Provided public key : \n"); hexdump(longtermPk,32);
			return(2);
		} else {
			printf("Upstream certificate matches provided longterm public key\n");
		}
	} else {
		printf("No longterm public key provided, skipping certificate validation\n");
	}

	crypto_box_curve25519xchacha20poly1305_keypair(clientPk, clientSk);
#ifdef DUMP_KEYS
	printf("Client PK : \n"); hexdump(clientPk,32);
	printf("Client SK : \n"); hexdump(clientSk,32);
#endif
	rc=crypto_box_curve25519xchacha20poly1305_beforenm(sharedK, sinfo_resolverPk, clientSk);
	if(rc!=0) {
		printf("Error during shared key derivation\n");
		return(2);
	}
#ifdef DUMP_KEYS
	printf("Shared key : \n"); hexdump(sharedK,32);
#endif

	sinfo_ts=now;

	return(0);
}


static int upstream_query(unsigned char *inpacket, int psize, unsigned char *answer, unsigned int *answersz) {
	unsigned char nonce[24];
	bzero(nonce,24);
	randombytes_buf(nonce,12); 
#ifdef DUMP_KEYS
	printf("nonce:\n"); hexdump(nonce,24);
#endif

	if(sinfo_ts<time(NULL)-3600 || sinfo_tsend<time(NULL)) {
		get_sinfo();
	}

	inpacket[psize++]=0x80;	
	int psize2=psize;
	if(psize2<256) psize2=256;
	else psize2=psize2+64-(psize2%64);
	if(psize2>512) { printf("error: padded query too large"); return(1); }
	bzero(inpacket+psize,psize2-psize);
#ifdef DUMP_KEYS
	printf("padded query: \n"); hexdump(inpacket, psize2);
#endif

	unsigned char outpacket[1024];
	memcpy(outpacket, sinfo_clientMagic, 8);
	memcpy(outpacket+8, clientPk, 32);
	memcpy(outpacket+40, nonce, 12);
	int rc=crypto_box_curve25519xchacha20poly1305_easy_afternm(outpacket+52, inpacket, psize2, nonce, sharedK);
	//int rc=crypto_box_curve25519xchacha20poly1305_easy(outpacket+52, inpacket, psize2, nonce, sinfo_resolverPk, clientSk);
	if(rc!=0) { 
		printf("error during encryption\n");
		return(1);
	}
	unsigned char answerCr[1024];
	int answerCrSz;

	rtrip_upstream(outpacket, 52+16+psize2, answerCr, &answerCrSz);

	if(memcmp(answerCr,"\x72\x36\x66\x6e\x76\x57\x6a\x38",8)!=0) {
		printf("bad resolver-magic\n");
		return(1);
	}

	if(memcmp(answerCr+8,nonce,12)) {
		printf("bad client-nonce\n");
		return(1);
	}

	rc=crypto_box_curve25519xchacha20poly1305_open_easy(answer, answerCr+32, answerCrSz-32, answerCr+8, sinfo_resolverPk, clientSk);
	if(rc!=0) {
		printf("error during decryption\n");
		return(1);
	}
#ifdef DUMP_KEYS
	printf("decrypted, padded packet: \n"); hexdump(answer, answerCrSz-48);
#endif
	*answersz=answerCrSz-48;
	for(;*answersz>1 && answer[*answersz-1]=='\x00';(*answersz)--);
	(*answersz)--;
#if (defined(DUMP_CLEAR) || defined(DUMP_LOCAL))
	printf("decrypted packet length after unpadding = %d\n", *answersz);
	hexdump(answer, *answersz);
#endif
	return(0);
}
#else /* UPSTREAM_TCP */
#define PKT_OFF 2
static int upstream_query(char *inpacket, int psize, char *answer, unsigned int *answersz) {
}
#endif

int main(int argc, char **argv) {
	if(sodium_init()==1) {
		printf("sodium_init() failed\n");
		exit(1);
	}

	struct sockaddr_in addr, cl_addr;
	unsigned char inpacket[512];
	ssize_t psize;
	unsigned char answer[1024];
	unsigned int answersz;
	socklen_t claddrsz=sizeof(struct sockaddr_in);
	int s=socket(AF_INET,SOCK_DGRAM,0);
	unsigned char cacheAnsw[512];
	int cacheAnswSz;
	addr.sin_family=AF_INET;
	addr.sin_addr.s_addr=htonl(LISTEN_ADDR);
	addr.sin_port=htons(LOCAL_PORT);
	if(bind(s,(struct sockaddr *)&addr,sizeof(struct sockaddr_in))<0) { perror("bind"); exit(1); }
	chroot(CHROOTPATH);
	chdir("/");
	setuid(DROP_UID);
	setgid(DROP_GID);
	printf("Fetching initial upstream certificate from %s://%s:%d... \n", (PKT_OFF==0 ? "udp" : "tcp"), UPSTREAM_HOST, UPSTREAM_PORT);
	int retry_in=5;
	a: 
	retry_in+=retry_in/4;
	int rc=get_sinfo();
	if(rc==1) {
		printf("Error fetching initial upstream certificate, retrying in %d secs...\n", retry_in);
		sleep(retry_in);
		goto a;
	} else if(rc==2) {
		printf("Fatal error during initial upstream certificate fetch. \n");
		exit(1);
	}
	cache_init();
	printf("Listening for requests on udp://%s:%d...\n", inet_ntoa(addr.sin_addr), LOCAL_PORT);
	while((psize=recvfrom(s,inpacket+PKT_OFF,512-PKT_OFF,0,(struct sockaddr *)&cl_addr,&claddrsz))>0) {
#ifdef DUMP_LOCAL
		puts("Got request :"); hexdump(inpacket+PKT_OFF,psize-PKT_OFF); 
#endif
		cache_search(inpacket+PKT_OFF,psize-PKT_OFF,cacheAnsw,&cacheAnswSz);
		if(cacheAnswSz>0) {
#ifdef DUMP_LOCAL
			puts("Response :"); hexdump(cacheAnsw,cacheAnswSz);
#endif
			sendto(s,cacheAnsw,cacheAnswSz,0,(struct sockaddr*)&cl_addr,claddrsz);
		} else {
			if(upstream_query(inpacket, psize, answer, &answersz)==1) {
				printf("upstream_query failed\n");
				continue;
			}
			cache_save(inpacket+PKT_OFF,psize-PKT_OFF,answer+PKT_OFF,answersz-PKT_OFF);
			sendto(s,answer+PKT_OFF,answersz-PKT_OFF,0,(struct sockaddr*)&cl_addr,claddrsz);
		}
	}
}
