/**
 * $$File$$ icmp.h 	$$Date$$ December 09, 2004
 * Code that analyses ICMP (semi-transport layer) packets
 * The current code just codes, further analysis may be included here
 **/
#ifndef __ICMP__
#define __ICMP__
#include "headers.h"

#define PRINT_ICMP 1

int handle_ICMP(u_char *args,const struct pcap_pkthdr* pkthdr,const u_char* packet)
{
#ifdef ONLINE
	update(ICMP_FLAG);
#endif
#ifdef PRINT_ICMP
	fprintf(OUT, "ICMP packet\n");
#endif
	return 0;
}
#endif
