/**
 * $$File$$ headers.h 	$$Date$$ December 09, 2004
 * All the header files that need to be routinely included for compilation
 **/
#ifndef __HEADERS__
#define __HEADERS__

#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/types.h>
#include <unistd.h>  
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <limits.h>
#include <sys/shm.h>
#include <sys/ipc.h>
#include <signal.h>
#include <ncurses.h>
#include "basket.h"

#define FILE_OUTPUT 1

/* Extracting lower 16 bits from unaligned numbers */
typedef struct {
	u_int16_t	val;
} __attribute__((packed)) unaligned_u_int16_t;

#define EXTRACT_16BITS(p) ((u_int16_t)ntohs(((const unaligned_u_int16_t *)(p))->val))

/* Nature of logs - file / console */
#ifdef FILE_OUTPUT
FILE *fp;
#define OUT fp
#else
#define OUT stdout
#endif

#endif
