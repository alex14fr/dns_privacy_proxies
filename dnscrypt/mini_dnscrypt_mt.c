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
#include <pthread.h>
#include <signal.h>
#include <sodium.h>
#include "config.h"
#ifndef UPSTREAM_UDP
#include <netinet/tcp.h>
#endif
#ifdef CACHE
#include <sqlite3.h>
#endif


#ifdef CACHE
static sqlite3 *db;
static sqlite3_stmt *insertStmt;
static sqlite3_stmt *queryStmt;
#ifdef CACHEDB_KEEP_HIT_COUNT
static sqlite3_stmt *incHitStmt;
#endif
#endif

struct timeoutarg {
	pthread_t tid;
	int upstreamsock;
};

static void* timeout(void *arg) {
//	pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, NULL);
	sleep(TIMEOUT_SECS);
	printf("Timeout\n");
	close(((struct timeoutarg*)arg)->upstreamsock);
	pthread_cancel(((struct timeoutarg*)arg)->tid);
	return(NULL);
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

static char db_schema[]="CREATE TABLE doh_cache(question BLOB PRIMARY KEY, answer BLOB, timestamp INTEGER, hit_count INTEGER) WITHOUT ROWID;CREATE INDEX i1 on doh_cache(question);";

#ifdef CACHE
static void cache_init(void) {
	if(sqlite3_open(CACHEDB, &db)) {
		printf("error opening database %s : %s\n",CACHEDB,sqlite3_errmsg(db));
	}
	if(strcmp(CACHEDB,"")==0) {
		if(sqlite3_exec(db, db_schema, NULL, NULL, NULL)) {
			printf("error creating tables in in-memory cache\n");
		}
	}
#ifdef SQLITE_ASYNC_AND_JOURNAL_OFF
	if(sqlite3_exec(db,"PRAGMA synchronous=0; PRAGMA journal_mode=off",NULL,NULL,NULL)) {
		printf("error in PRAGMA : %s\n", sqlite3_errmsg(db));
	}
#endif
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
	sqlite3_mutex_enter(sqlite3_db_mutex(db));
	if(sqlite3_bind_blob(queryStmt,1,inpacket+12,psize-12,SQLITE_STATIC)) { printf("error binding param : %s\n",sqlite3_errmsg(db)); } 
	int rc;
	rc=sqlite3_step(queryStmt);
	if(rc==SQLITE_DONE) { 
#ifdef DUMP_CACHE
		printf("cache: miss\n"); 
#endif
		sqlite3_reset(queryStmt); 
		sqlite3_clear_bindings(queryStmt);
		sqlite3_mutex_leave(sqlite3_db_mutex(db));
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
		if(sqlite3_bind_blob(incHitStmt, 1, inpacket+12, psize-12, SQLITE_STATIC)) { printf("cache_search : error binding param : %s\n",sqlite3_errmsg(db)); }
		rc=sqlite3_step(incHitStmt);
		if(rc!=SQLITE_DONE) { printf("cache_search : error during sqlite3_step (rc=%d) : %s\n", rc, sqlite3_errmsg(db)); }
		sqlite3_reset(incHitStmt);
		sqlite3_clear_bindings(incHitStmt);
#endif
	} else {
		printf("error during sqlite3_step : %s\n", sqlite3_errmsg(db));
	}
	sqlite3_reset(queryStmt);
	sqlite3_clear_bindings(queryStmt);
	sqlite3_mutex_leave(sqlite3_db_mutex(db));
}

static void cache_save(unsigned char *inpacket, int psize, unsigned char *answer, int answersz) {
	if(answersz<=0) { printf("cache_save : won't save null answer\n"); return; }
	sqlite3_mutex_enter(sqlite3_db_mutex(db));
	if(sqlite3_bind_blob(insertStmt,1,inpacket+12,psize-12,SQLITE_STATIC)) { printf("cache_save : error binding param 1 : %s\n",sqlite3_errmsg(db)); } 
	if(sqlite3_bind_blob(insertStmt,2,answer,answersz,SQLITE_STATIC)) { printf("cache_save : error binding param 2 : %s\n",sqlite3_errmsg(db)); } 
	int rc=sqlite3_step(insertStmt);
	if(rc!=SQLITE_DONE) { printf("cache_save : error during sqlite3_step (rc=%d): %s\n", rc, sqlite3_errmsg(db)); }
	sqlite3_reset(insertStmt);
	sqlite3_clear_bindings(insertStmt);
#ifdef SQLITE_RELEASE_MEM
	sqlite3_db_release_memory(db);
#endif
	sqlite3_mutex_leave(sqlite3_db_mutex(db));
}

#endif /* CACHE */


#define PKT_OFF 0

#ifdef UPSTREAM_UDP
#define PROTO "udp"
#define UP_PKT_OFF 0
#else
#define PROTO "tcp"
#define UP_PKT_OFF 2
#endif

#define MIN(a,b) ((a)<(b)?(a):(b))
#define MAX(a,b) ((a)>(b)?(a):(b))

static struct sockaddr_in upstreamaddr;
static socklen_t claddrsz=sizeof(struct sockaddr_in);
static uint32_t sinfo_tsend;
static pthread_mutex_t sinfo_mutex=PTHREAD_MUTEX_INITIALIZER;
static unsigned char sinfo_clientMagic[8];
static unsigned char sharedK[32];
static unsigned char clientPk[32];

static int rtrip_upstream(unsigned char *in, int insize, unsigned char *out, int *outsize, int length_be) {
	int rc;
	int upstreamsock;
#ifdef UPSTREAM_UDP
	upstreamsock=socket(AF_INET,SOCK_DGRAM,0);
#else
	upstreamsock=socket(AF_INET,SOCK_STREAM,0);
	int one[1]={1};
	setsockopt(upstreamsock, IPPROTO_TCP, TCP_NODELAY, (void*)one, sizeof(int)); 
	if(!length_be) {
		in[1]=insize>>8;
		in[0]=insize%256;
	} else {
		in[1]=insize%256;
		in[0]=insize>>8;
	}
	insize+=2;
#endif
#ifdef DUMP_RTRIP
	printf("Sending :\n"); hexdump(in, insize);
#endif
	//pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, NULL);
	pthread_t timer_thr;
	struct timeoutarg arg;
	arg.tid=pthread_self();
	arg.upstreamsock=upstreamsock;
	pthread_create(&timer_thr,NULL,timeout,(void*)&arg);
	pthread_detach(timer_thr);
	if((rc=connect(upstreamsock, (struct sockaddr*)&upstreamaddr, sizeof(struct sockaddr_in)))<0) {
		perror("connect");
		pthread_cancel(timer_thr);
		close(upstreamsock);
		return(-rc);
	}
	if((rc=write(upstreamsock, in, insize))<0) {
		perror("write");
		pthread_cancel(timer_thr);
		close(upstreamsock);
		return(-rc);
	}
#ifdef UPSTREAM_UDP
	*outsize=read(upstreamsock, out, 512);
#else
	unsigned char length[2]; ssize_t lengthInt;
	*outsize=read(upstreamsock, length, 2);
	if(*outsize>0) {
		lengthInt=(length[0]<<8)+length[1];
		*outsize=read(upstreamsock, out, lengthInt);
	}
#endif
	pthread_cancel(timer_thr);
	close(upstreamsock);
	if(*outsize<0) { 
		perror("read"); 
		return(- *outsize); 
	}
#ifdef DUMP_RTRIP
	printf("Received :\n"); hexdump(out, *outsize);
#endif
	return(0);
}

static int get_sinfo(void) {
	unsigned char sinfoBuf[512];
	unsigned char *sinfo;
	unsigned char *sinfo_clientMagic_;
	unsigned char *sinfo_resolverPk;
	int sinfo_len;
	unsigned char clientPk_[32], clientSk[32];
	unsigned char sharedK_[32];
	int rc;
	unsigned char qry[512];
	bzero(qry,512);
	unsigned char* qryptr=qry+UP_PKT_OFF;
	randombytes_buf(qryptr,2);
	qryptr[2]=qryptr[5]='\x01'; 
	memcpy(qryptr+12, UPSTREAM_SRVNAME, strlen(UPSTREAM_SRVNAME));
	qryptr[12+strlen(UPSTREAM_SRVNAME)+2]='\x10';
	qryptr[12+strlen(UPSTREAM_SRVNAME)+4]='\x01';
	sinfo_len=0;
	rc=rtrip_upstream(qry, 12+strlen(UPSTREAM_SRVNAME)+5, sinfoBuf, &sinfo_len, 1);
	if(rc!=0 || sinfo_len==0 || sinfo_len==UP_PKT_OFF) {
		printf("Error reading server info from upstream\n");
		return(1);
	}
	sinfo=memmem(sinfoBuf,sinfo_len,"DNSC",4);
	if(sinfo==NULL) {
		printf("cert-magic not found");
		return(2);
	}
	if(memmem(sinfo+4,sinfo_len-(sinfo-sinfoBuf)-4,"DNSC",4)!=NULL) {
		printf("Warning: FIXME : multiple certificates found, using the first presented\n");
	}
	sinfo_resolverPk=sinfo+72;
	sinfo_clientMagic_=sinfo+104;

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
	printf("Client magic : \n"); hexdump(sinfo_clientMagic_,8);
	printf("Resolver PK : \n"); hexdump(sinfo_resolverPk,32);
#endif
	unsigned char *signature=sinfo+8;
	unsigned char *tosign=sinfo+72;
	int tosignlen=52;
	
	unsigned char longtermPk[32];
	size_t binlen;
	sodium_hex2bin(longtermPk, 32, UPSTREAM_PUBKEY, strlen(UPSTREAM_PUBKEY), NULL, &binlen, NULL);
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

	crypto_box_curve25519xchacha20poly1305_keypair(clientPk_, clientSk);
#ifdef DUMP_KEYS
	printf("Client PK : \n"); hexdump(clientPk_,32);
	printf("Client SK : \n"); hexdump(clientSk,32);
#endif
	rc=crypto_box_curve25519xchacha20poly1305_beforenm(sharedK_, sinfo_resolverPk, clientSk);
	if(rc!=0) {
		printf("Error during shared key derivation\n");
		return(2);
	}
#ifdef DUMP_KEYS
	printf("Shared key : \n"); hexdump(sharedK_,32);
#endif

	pthread_mutex_lock(&sinfo_mutex);
	memcpy(sinfo_clientMagic,sinfo_clientMagic_,8);
	memcpy(sharedK,sharedK_,32);
	memcpy(clientPk,clientPk_,32);
	pthread_mutex_unlock(&sinfo_mutex);

	return(0);
}

void *update_sinfo_thr(void*) {
	while(1) {
		printf("Fetching upstream certificate from %s://%s:%d... \n", PROTO, UPSTREAM_HOST, UPSTREAM_PORT);
		int retry_in=5;
		a:
		int rc=get_sinfo();
		if(rc==1) {
			printf("Error fetching upstream certificate, retrying in %d secs...\n", retry_in);
			retry_in+=retry_in/2;
			goto a;
		} else if(rc==2) {
			printf("Fatal error during upstream certificate fetch. \n");
			exit(1);
		}
		int time_to_expire=MAX(30, (time_t)(sinfo_tsend)-time(NULL));
		int time_to_sleep=MIN(3600, time_to_expire);
		printf("Will refetch upstream certificate in %d secs.\n", time_to_sleep);
		sleep(time_to_sleep);
	}
	return(NULL);
}

static int upstream_query(unsigned char *inpacket, int psize, unsigned char *answer, int *answersz, unsigned char *mySharedK, unsigned char *myClientPk, unsigned char *myClientMagic) {
	unsigned char nonce[24];
	bzero(nonce,24);
	randombytes_buf(nonce,12); 
#ifdef DUMP_KEYS
	printf("nonce:\n"); hexdump(nonce,24);
#endif
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
	unsigned char *outpacketptr=outpacket+UP_PKT_OFF;
	memcpy(outpacketptr, myClientMagic, 8);
	memcpy(outpacketptr+8, myClientPk, 32);
	memcpy(outpacketptr+40, nonce, 12);
	int rc=crypto_box_curve25519xchacha20poly1305_easy_afternm(outpacketptr+52, inpacket, psize2, nonce, mySharedK);
	if(rc!=0) { 
		printf("error during encryption\n");
		return(1);
	}
	unsigned char answerCr[1024];
	int answerCrSz;
	if(rtrip_upstream(outpacket, 52+16+psize2, answerCr, &answerCrSz, 1)!=0) {
		printf("error when communicating to upstream\n");
		return(1);
	}
	if(memcmp(answerCr,"\x72\x36\x66\x6e\x76\x57\x6a\x38",8)!=0) {
		printf("bad resolver-magic\n");
		return(1);
	}

	if(memcmp(answerCr+8,nonce,12)) {
		printf("bad client-nonce\n");
		return(1);
	}

	//rc=crypto_box_curve25519xchacha20poly1305_open_easy(answer, answerCr+32, answerCrSz-32, answerCr+8, sinfo_resolverPk, clientSk);
	rc=crypto_box_curve25519xchacha20poly1305_open_easy_afternm(answer, answerCr+32, answerCrSz-32, answerCr+8, mySharedK);
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

struct handlequeryarg {
	unsigned char sharedK[32];
	unsigned char clientPk[32];
	unsigned char clientMagic[8];
	unsigned char inpacket[512];
	ssize_t psize;
	struct sockaddr_in cl_addr;
	int s;
};

void handle_query_cleanup(void *arg) {
	free(arg);
}

void *handle_query(void *arg) {
	struct handlequeryarg argg=*((struct handlequeryarg*)arg);
	unsigned char answer[512];
	int answersz;
	pthread_cleanup_push(handle_query_cleanup, arg);
#ifdef DUMP_LOCAL
	puts("Got request :"); hexdump(argg.inpacket+PKT_OFF,argg.psize-PKT_OFF); 
#endif
#ifdef CACHE
	cache_search(argg.inpacket+PKT_OFF,argg.psize-PKT_OFF,answer,&answersz);
#endif
	if(answersz==0) {
		if(upstream_query(argg.inpacket, argg.psize, answer, &answersz,argg.sharedK,argg.clientPk,argg.clientMagic)==1) {
			printf("upstream_query failed\n");
		} else {
			sendto(argg.s, answer, answersz, 0, (struct sockaddr*)(&(argg.cl_addr)), claddrsz);
#ifdef CACHE
			cache_save(argg.inpacket+PKT_OFF, argg.psize-PKT_OFF, answer+PKT_OFF, answersz-PKT_OFF);
#endif
		}
	} else {
		sendto(argg.s, answer, answersz, 0, (struct sockaddr*)(&(argg.cl_addr)), claddrsz);
	}
	pthread_cleanup_pop(1);
	return(NULL);
}

int main(int argc, char **argv) {
	if(sodium_init()==1) {
		printf("sodium_init() failed\n");
		exit(1);
	}

	struct handlequeryarg* arg_thr;
	int s=socket(AF_INET,SOCK_DGRAM,0);
	struct sockaddr_in addr;
	addr.sin_family=AF_INET;
	addr.sin_addr.s_addr=htonl(LISTEN_ADDR);
	addr.sin_port=htons(LOCAL_PORT);
	if(bind(s,(struct sockaddr *)&addr,sizeof(struct sockaddr_in))<0) { perror("bind"); exit(1); }
	chroot(CHROOTPATH);
	chdir("/");
	setuid(DROP_UID);
	setgid(DROP_GID);
	upstreamaddr.sin_family=AF_INET;
	upstreamaddr.sin_addr.s_addr=inet_addr(UPSTREAM_HOST);
	upstreamaddr.sin_port=htons(UPSTREAM_PORT);
	pthread_t update_thr;
	pthread_create(&update_thr,NULL,update_sinfo_thr,NULL);
	pthread_detach(update_thr);
#ifdef CACHE
	cache_init();
#endif
	printf("Listening for requests on udp://%s:%d...\n", inet_ntoa(addr.sin_addr), LOCAL_PORT);
	char inpacket[512];
	struct sockaddr_in cl_addr;
	ssize_t psize;
	while(1) {
		psize=recvfrom(s,inpacket+PKT_OFF,512-PKT_OFF,0,(struct sockaddr*)&cl_addr,&claddrsz);
		if(psize<0) { perror("recvfrom"); exit(1); }
		arg_thr=malloc(sizeof(struct handlequeryarg));
		arg_thr->s=s;
		memcpy(arg_thr->inpacket,inpacket,512);
		arg_thr->psize=psize;
		memcpy(&arg_thr->cl_addr,&cl_addr,sizeof(struct sockaddr_in));
		pthread_mutex_lock(&sinfo_mutex);
		memcpy(arg_thr->sharedK, sharedK, 32);
		memcpy(arg_thr->clientPk, clientPk, 32);
		memcpy(arg_thr->clientMagic, sinfo_clientMagic, 8);
		pthread_mutex_unlock(&sinfo_mutex);
		pthread_t thr;
		pthread_create(&thr, NULL, handle_query, arg_thr);
		pthread_detach(thr);
		//pthread_join(thr, NULL);
	}
}
