#ifndef __SNIFFDUMP__
#define __SNIFFDUMP__

/**
 * $$File$$	sniff_dump.c
 * $$Date$$	November 22, 2004
 * Usage: ./sniff_dump <number of packets> <dumpfile name>
 * This program dumps the specified number of packets with the headers
 * onto the dumpfile specified. Use a RAMdisk file for good performance
 */
#include "headers.h"

int main(int argc,char **argv)
{ 
	char *dev; 
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* descr;
	struct bpf_program fp;      /* hold compiled program     */
	bpf_u_int32 maskp;          /* subnet mask               */
	bpf_u_int32 netp;           /* ip                        */
	u_char* args = NULL;
	pcap_dumper_t* dump;

	/* Options must be passed in as a string because I am lazy */
	if(argc < 2){ 
		fprintf(stdout,"Usage: %s <numpackets> <dumpfile name>\n",argv[0]);
		return 0;
	}
	fprintf(stdout, "***************** Sniff Dump ver2.1 ****************\n");

	/* Open a device to listen to */
	dev = pcap_lookupdev(errbuf);
	if(dev == NULL)
	{ printf("%s\n",errbuf); exit(1); }

	/* Ask pcap for the network address and mask of the device */
	pcap_lookupnet(dev,&netp,&maskp,errbuf);

	/* Open device for reading. NOTE: defaulting to
	 * promiscuous mode*/
	descr = pcap_open_live(dev,BUFSIZ,1,-1,errbuf);
	if(descr == NULL)
	{ printf("pcap_open_live(): %s\n",errbuf); exit(1); }


	dump = pcap_dump_open( descr, argv[2] );
	fprintf(stdout, "[INFO] Started packet dump engine.\n", getpid());
    /* The loop that sniffs required number of packets */ 
	pcap_loop(descr,atoi(argv[1]),pcap_dump,(u_char*)dump);

	pcap_dump_close(dump);

	fprintf(stdout, "[INFO] Completed dumping all the packets.\n");

	return 0;
}
#endif
