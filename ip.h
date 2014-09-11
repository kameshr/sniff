/**
 * $$File$$ ip.h 	$$Date$$ December 09, 2004
 * This file analyses the IP (network layer) packets and extracts
 * IP addresses (source & destination), length, version, and other information
 * available in the IP header.
 **/
#ifndef __IP__
#define __IP__

#include "headers.h"
#include "defs.h"
#include <netinet/ip.h> 

#ifndef IPPROTO_IP
#define IPPROTO_IP 0
#define	IPPROTO_ICMP	1		/* control message protocol */
#define	IPPROTO_TCP		6		/* tcp */
#define	IPPROTO_UDP		17		/* user datagram protocol */
#endif

#define PRINT_IP 1

/*
 * Structure of an internet header, naked of options.
 * Borrowed from tcpdump source
 */
struct my_ip {
	u_int8_t	ip_vhl;		/* header length, version */
#define IP_V(ip)	(((ip)->ip_vhl & 0xf0) >> 4)
#define IP_HL(ip)	((ip)->ip_vhl & 0x0f)
	u_int8_t	ip_tos;		/* type of service */
	u_int16_t	ip_len;		/* total length */
	u_int16_t	ip_id;		/* identification */
	u_int16_t	ip_off;		/* fragment offset field */
#define	IP_DF 0x4000			/* dont fragment flag */
#define	IP_MF 0x2000			/* more fragments flag */
#define	IP_OFFMASK 0x1fff		/* mask for fragmenting bits */
	u_int8_t	ip_ttl;		/* time to live */
	u_int8_t	ip_p;		/* protocol */
	u_int16_t	ip_sum;		/* checksum */
	struct	in_addr ip_src,ip_dst;	/* source and dest address */
};

/*
 * Extract information from the IP header
 */
int handle_IP(u_char *args,const struct pcap_pkthdr* pkthdr,const u_char* packet)
{
	const struct my_ip* ip;
	u_int length = pkthdr->len;
	u_int hlen,off,version;
	int i;
	u_char* result;

	int len;

	/* jump pass the ethernet header */
	ip = (struct my_ip*)(packet + sizeof(struct ether_header));
	length -= sizeof(struct ether_header); 

	/* check to see we have a packet of valid length */
	if (length < sizeof(struct my_ip))
	{
		printf("truncated ip %d",length);
		return 0;
	}

	len     = ntohs(ip->ip_len);
	hlen    = IP_HL(ip); /* header length */
	version = IP_V(ip);/* ip version */

	/* check version */
	if(version != 4)
	{
		fprintf(stderr,"Unknown version %d\n",version);
		return 0;
	}

	/* check header length */
	if(hlen < 5 )
	{
		fprintf(stderr,"bad-hlen %d \n",hlen);
	}

	/* see if we have as much packet as we should */
	if(length < len)
		printf("\ntruncated IP - %d bytes missing\n",len - length);

	/* Check to see if we have the first fragment */
	off = ntohs(ip->ip_off);
#ifdef ONLINE
	ip_update(ip->ip_src);
#endif
	if((off & 0x1fff) == 0 )/* aka no 1's in first 13 bits */
	{/* print SOURCE DESTINATION hlen version len offset */
#ifdef PRINT_IP
		fprintf(OUT,"IP: ");
		fprintf(OUT,"From: %s | ",
				inet_ntoa(ip->ip_src));
		fprintf(OUT,"To: %s |Header Len: %d |Version: %d |Length: %d |Offset: %d\n",
				inet_ntoa(ip->ip_dst),
				hlen,version,len,off);
#endif
	}

	switch(ip->ip_p) {
		case IPPROTO_TCP:
			/* Handle TCP packets */
			handle_TCP(args, pkthdr, packet);
			break;
			
		case IPPROTO_UDP:
			/* Handle UDP packets */
			handle_UDP(args, pkthdr, packet);
			break;

		case IPPROTO_ICMP:
			/* Handle ICMP (Ping!) packets */
			handle_ICMP(args, pkthdr, packet);
			break;
	}

	return 0;
}

#endif
