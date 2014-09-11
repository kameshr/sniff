/**
 * $$File$$ packet_dump.h 	$$Date$$ December 02, 2004
 * This file contains the code run by the parent process that dumps the
 * packets onto the memory
 **/
#ifndef __PACKET_DUMP__
#define __PACKET_DUMP__
#include "headers.h"
#include "defs.h"

/* Overflow while writing - loop to the beginning */
void reinit_memory_writer() {
	/* Set the writer to the begining of the memory */
//	fprintf(stdout, "[WARNING] Rolling back on writer's memory.\n");
	writer = shm;
}

/* Quickly dumping all the packets onto the shared memory buffer */
void packet_handler(u_char *args,const struct pcap_pkthdr* pkthdr,const u_char* packet)
{
	int length, i;

	/* Write the header first */
	struct pcap_pkthdr* head = (struct pcap_pkthdr*) writer;
	*head = *pkthdr;
	length = pkthdr->len;

	writer += sizeof(struct pcap_pkthdr);

	/* Buffer overflow */
	if( writer - shm >= SHMSZ ) {
//		fprintf(stderr,"Writer = %X, shm = %X, diff = %d\n", writer, shm, (writer - shm));
		reinit_memory_writer();
		return;
	}

	for(i=0; i < length; i++) {
		*writer = *packet;
		writer++;
		packet++;
		
		/* Buffer overflow */
		if( writer - shm >= SHMSZ ) {
			reinit_memory_writer();
			return;
		}
	}

	/* Update semaphore with one more packet being added */
	setSem(semid, 1);
}
#endif
