/**
 * $$File$$ packet_analyse.h 	$$Date$$ December 02, 2004
 * This file contains the code run by the (child) process that analyses the packets
 * dumped onto the shared memory
 **/
#ifndef __PACKET_ANALYSE__
#define __PACKET_ANALYSE__
#include "headers.h"
#include "defs.h"

/* Overflow while reading - go to the beginning as it is a circular buffer */
void reinit_memory_reader() {
	/* Set the reader to the begining */
//	fprintf(stdout, "[WARNING] Rolling back on reader's memory.\n");
	reader = shm;
}

/**
 * Slowly analyze dumped packets
 * The process always loops through the following block of code
 **/
void analyze_dump() {
	struct pcap_pkthdr* header;
	int length, i;

	/* Summary information */
	struct timeval *first, *last;
	int *pknum;

	char *summary = smwrite;

	first = (struct timeval*)summary;
	last = (struct timeval*)(summary + sizeof(struct timeval));
	pknum = (int*)(summary + 2*sizeof(struct timeval));

	header = (struct pcap_pkthdr*) reader;

	*first = header->ts;
	*pknum = 0;
	
	/* Always keep analyzing */
	for(i = 0; i < numPacket; i++) {
		/* Wait till something is dumped */
		while( getSem(semid) <= 0 )
			sleep(0.01);

		/* Check for incompletely written header --- memory overflow */
		if( ( (reader +  sizeof(struct pcap_pkthdr)) - shm ) >= SHMSZ ) {
			reinit_memory_reader();
			continue;
		}
		
		/* Remove the header */
		header = (struct pcap_pkthdr*) reader;
		length = header->len;

		/* Summary updation */
		(*pknum)++;
		*last = header->ts;

		fprintf(OUT, "Packet No: %d     ", *(pknum));

		/* Get to the actual packet */
		reader += sizeof(struct pcap_pkthdr);

		/* Check if the packet overflows the alloted memory */
		if( (reader + length) - shm >= SHMSZ ) {
			reinit_memory_reader();
			continue;
		}

		/* Call functions to analyze the packet */
		handle_ethernet(NULL, header, reader);

		fprintf(OUT, "\n");
		reader += length;
		/* One more packet read, decrement semaphore */
		setSem(semid, -1);
	}
	exit(0);
}
#endif
