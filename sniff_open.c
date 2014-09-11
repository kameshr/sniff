/**
 * File: sniff_open.c
 * Date: November 23, 2004    
 * Last Modified: November 23, 2004
 * Description: 
 * This file analyzes, offline, the packets stored in a file.
 * Usage: ./sniff_open <dumpfile name> <options>
 **/

#ifndef __SNIFFOPEN__
#define __SNIFFOPEN__
#include "headers.h"
#include "ethernet.h"
#include "ip.h"
#include "icmp.h"
#include "tcp.h"
#include "udp.h"
#include "defs.h"
#include "parse.h"

/* looking at ethernet headers */
void packet_handler(u_char *args,const struct pcap_pkthdr* pkthdr,const u_char* packet)
{
	handle_ethernet(args,pkthdr,packet);
	fprintf(OUT, "\n");
}

int main(int argc,char **argv)
{ 
	char *dev; 
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* descr;
	struct bpf_program fcp;      /* hold compiled program     */
	bpf_u_int32 maskp;          /* subnet mask               */
	bpf_u_int32 netp;           /* ip                        */
	u_char* args = NULL;
	char options[250];

	/* Options must be passed in as a string because I am lazy */
	if(argc < 2){ 
		fprintf(stdout,"Usage: %s <dumpfile name> <config file>\n",argv[0]);
		return 0;
	}

	fprintf(stdout, "***************** Sniff Dump Opener ver1.0 ****************\n");

#ifdef FILE_OUTPUT
	if( (fp = fopen("log.txt", "w")) == NULL ) {
		fprintf(stderr, "Error opening log file.\n");
		exit(-1);
	}
#endif

	/* Open a device to listen to */
	dev = pcap_lookupdev(errbuf);
	if(dev == NULL)
	{ fprintf(stderr, "%s\n",errbuf); exit(1); }

	/* Ask pcap for the network address and mask of the device */
	pcap_lookupnet(dev,&netp,&maskp,errbuf);

	/* Open device for reading. NOTE: defaulting to
	 * promiscuous mode*/
	descr = pcap_open_offline(argv[1],errbuf);
	if(descr == NULL)
	{ printf("pcap_open_offline(): %s\n",errbuf); exit(1); }


	if(argc > 2)
	{
		parse_file(argv[2], options);
		/* Lets try and compile the program.. non-optimized */
		if(pcap_compile(descr,&fcp,options,0,netp) == -1)
		{ fprintf(stderr,"Error calling pcap_compile\n"); exit(1); }

		/* set the compiled program as the filter */
		if(pcap_setfilter(descr,&fcp) == -1)
		{ fprintf(stderr,"Error setting filter\n"); exit(1); }
	}

	fprintf(stdout, "[INFO] Started packet dump analysis engine.\n", getpid());
    /* The loop that sniffs required number of packets */ 
	pcap_loop(descr,atoi(argv[1]),packet_handler,args);

	fprintf(stdout, "[INFO] Offline analysis of packets complete.\n");

	return 0;
}
#endif
