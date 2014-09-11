/**
 * $$File$$ telnet.h 	$$Date$$ December 09, 2004
 * As of now, it just counts the TELNET packets. Further analysis
 * code may be added here.
 **/
#ifndef __TELNET__
#define __TELNET__

#include "headers.h"

int handle_telnet(u_char *args,const struct pcap_pkthdr* pkthdr,const u_char* packet)
{
	fprintf(OUT, "TELNET Packet\n");
	return 0;
}
#endif
