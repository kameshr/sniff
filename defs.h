/**
 * $$File$$ defs.h 	$$Date$$ December 02, 2004
 * This file contains the declarations of key variables and
 * clean up code common to all the processes
 **/
#ifndef __DEFS__
#define __DEFS__
#include "headers.h"
#include "semaphore.h"
// #define SHMSZ 65536
#define SHMSZ 1048576 // 1 MB of shared memory
#define NUM_MACHINES 100
#define WEB_REFRESH 5

/* IDs of the shared memory and semaphores used by the tool */
pcap_t* descr;
struct pcap_stat ps;
int shmid, semid, numPacket;
int sumid, pidid;
key_t key, sumkey;
char *shm, *reader, *writer;
char *smwrite, *smread;
struct basket *basket_pool;
int SUMSIZE;
int row, col;
FILE *web;

/* Clean up all the semaphores, shared memory and files */
void cleanUp() {
#ifdef FILE_OUTPUT
	fclose(fp);
#endif
	if( delSem(semid) == -1 )
		fprintf(stderr, "[ERROR] Semaphore could not be closed successfully.\n");
	if( shmctl(shmid, IPC_RMID, NULL) == -1 )
		fprintf(stderr, "[ERROR] Shared memory could not be closed successfully.\n");
	if( shmctl(sumid, IPC_RMID, NULL) == -1 )
		fprintf(stderr, "[ERROR] Shared memory for summary could not be closed successfully.\n");
//	fprintf(stdout, "\n\n[INFO] Shutting down all the engines...\n");
//	fprintf(stdout, "Thank you for using Sniff\n");
	exit(0);
}

/* Die! */
void suicide() {
	endwin();
	exit(0);
}
#endif
