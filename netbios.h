/**
 * $$File$$ netbios.h 	$$Date$$ December 09, 2004
 * This file analyses netbios (application layer) packets.
 * As of now, just logs. Further analysis code may be added here.
 **/
#ifndef __NETBIOS__
#define __NETBIOS__

#include "headers.h"

int handle_netbios(u_char *args,const struct pcap_pkthdr* pkthdr,const u_char* packet)
{
	fprintf(OUT, "MS File Share Packet\n");
	return 0;
}
#endif
