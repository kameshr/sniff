/**
 * $$File$$	semaphore.h
 * $$Date$$	November 24, 2004
 *
 * This file provides functions to perform common semaphore functions
 **/
#ifndef __SEMAPHORE__
#define __SEMAPHORE__

#include <sys/sem.h>
#include "headers.h"

#if defined(__GNU_LIBRARY__) && !defined(_SEM_SEMUN_UNDEFINED)
/* union semun is defined by including <sys/sem.h> */
#else
/* according to X/OPEN we have to define it ourselves */
union semun {
	int val;                  /* value for SETVAL */
	struct semid_ds *buf;     /* buffer for IPC_STAT, IPC_SET */
	unsigned short *array;    /* array for GETALL, SETALL */
	/* Linux specific part: */
	struct seminfo *__buf;    /* buffer for IPC_INFO */
};
#endif

/* Initialize a new semaphore */
int initSem() {
	return semget(IPC_PRIVATE, 1, SHM_R|SHM_W);
}

/* Return the value of the semaphore */
int getSem(int semid) {
	int value = semctl(semid, 0, GETVAL);
	return value;
}

/* Set the value of the semaphore */
void setSem(int semid, int val) {
	struct sembuf sb;
	sb.sem_num = 0;
	sb.sem_op = val;
	sb.sem_flg = IPC_NOWAIT;
	semop(semid, &sb, 1);
}

/* Close the semaphore */
int delSem(int semid) {
	return semctl(semid, 0, IPC_RMID);
}
#endif
