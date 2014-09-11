/**
 * $$File$$ udp.h 	$$Date$$ December 09, 2004
 * This file provides functions that analyse the UDP (transport layer) packets.
 * The port numbers, seq numbers, etc. are extracted from the TCP header.
 **/
#ifndef __UDP__
#define __UDP__

#include "headers.h"
#include "defs.h"

#define PRINT_UDP 1

/*
 * UDP header
 */
struct my_udp {
	u_int16_t	uh_sport;		/* source port */
	u_int16_t	uh_dport;		/* destination port */
	u_int16_t	uh_ulen;		/* udp length */
	u_int16_t	uh_sum;			/* udp checksum */
};

int handle_UDP(u_char *args,const struct pcap_pkthdr* pkthdr,const u_char* packet)
{
	const struct my_udp* udp;
	u_int length = pkthdr->len;

	/* Jump off ethernet and IP headers */
	udp = (struct my_udp*)(packet + sizeof(struct ether_header) + sizeof(struct my_ip));
	length -= sizeof(struct ether_header); 
	length -= sizeof(struct my_ip); 

	/* check to see we have a packet of valid length */
	if (length < sizeof(struct my_udp))
	{
		fprintf(stderr, "truncated udp %d",length);
		return 0;
	}

#ifdef ONLINE
	update(UDP_FLAG);
#endif
	/* Print SOURCE-PORT DEST-PORT */
#ifdef PRINT_UDP
	fprintf(OUT, "UDP: Source Port: %d |Dest Port: %d \n", EXTRACT_16BITS(&udp->uh_sport), EXTRACT_16BITS(&udp->uh_dport));
#endif

	return 0;
}
#endif
