/**
 * $$File$$	ethernet.h 	$$Date$$ December 09, 2004
 * This file contains functions and data structures the handle the
 * machine layer analysis of the packets
 **/
#ifndef __ETHERNET__
#define __ETHERNET__
#include <netinet/if_ether.h> 
#include <net/ethernet.h>
#include <netinet/ether.h> 
#include "headers.h"
#include "defs.h"

/* tcpdump header (ether.h) defines ETHER_HDRLEN) */
#ifndef ETHER_HDRLEN 
#define ETHER_HDRLEN 14
#endif

#define PRINT_ETHERNET 1

/*
#ifdef FILE_OUTPUT
extern FILE *fp;
#endif*/

/**
 * The struct ether_header as defined in the file net/ethernet.h
struct ether_header
{
  u_int8_t  ether_dhost[ETH_ALEN];	// destination eth addr
  u_int8_t  ether_shost[ETH_ALEN];	// source ether addr
  u_int16_t ether_type;		        // packet type ID field
} __attribute__ ((__packed__));
*/


/* handle ethernet packets, much of this code borrowed from
 * print-ether.c from tcpdump source
 */
int handle_ethernet
(u_char *args,const struct pcap_pkthdr* pkthdr,const u_char*
 packet)
{
	u_int caplen = pkthdr->caplen;
	u_int length = pkthdr->len;
	struct ether_header *eptr;  /* net/ethernet.h */
	u_short ether_type;

	if (caplen < ETHER_HDRLEN)
	{
		fprintf(stderr,"Packet length less than ethernet header length\n");
		return -1;
	}

	/* lets start with the ether header... */
	eptr = (struct ether_header *) packet;
	ether_type = ntohs(eptr->ether_type);

#ifdef ONLINE
	/* Cache the machine whose packet is being analysed */
	selectmach(basket_pool, eptr->ether_shost);
#endif
	
	/* Lets print SOURCE DEST TYPE LENGTH */
	fprintf(OUT, "Time Stamp: %d\n", (pkthdr->ts).tv_sec);
	fprintf(OUT,"ETH: ");
	fprintf(OUT,"From: %s | "
			,ether_ntoa((struct ether_addr*)eptr->ether_shost));
	fprintf(OUT,"To: %s | "
			,ether_ntoa((struct ether_addr*)eptr->ether_dhost));
	switch(ether_type) {
		case ETHERTYPE_IP:
			fprintf(OUT, "Type: (IP)\n");
			break;
		case ETHERTYPE_REVARP:
			fprintf(OUT, "Type: (RARP)\n");
#ifdef ONLINE
			update(RARP_FLAG);
#endif
			break;
		case ETHERTYPE_ARP:
			fprintf(OUT, "Type: (ARP)\n");
#ifdef ONLINE
			update(ARP_FLAG);
#endif
			break;
		default:
			fprintf(OUT, "Type: (?)\n");
#ifdef ONLINE
			update(ALIEN_FLAG);
#endif
			break;
	}

	/* check to see if we have an ip packet */
	if (ether_type == ETHERTYPE_IP)
	{
		handle_IP(args, pkthdr, packet);
	}
	return 0;
}
#endif
