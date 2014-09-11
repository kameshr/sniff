/**
 * $$File$$ tcp.h 	$$Date$$ December 09, 2004
 * This file provides functions that analyse the TCP (transport layer) packets.
 * The port numbers, seq numbers, etc. are extracted from the TCP header.
 **/
#ifndef __TCP__
#define __TCP__

#include "headers.h"
#include "defs.h"
#include "telnet.h"
#include "netbios.h"

#define PRINT_TCP 1

#define TELNET_PORT	23
#define BGP_PORT	179
#define NETBIOS_SSN_PORT 139
#define PPTP_PORT	1723
#define NFS_PORT	2049
#define MSDP_PORT	639
#define LDP_PORT    646

/**
 * Structure of a TCP header
 **/
typedef	u_int32_t	tcp_seq;
struct my_tcp {
	u_int16_t	th_sport;		/* source port */
	u_int16_t	th_dport;		/* destination port */
	tcp_seq		th_seq;			/* sequence number */
	tcp_seq		th_ack;			/* acknowledgement number */
	u_int8_t	th_offx2;		/* data offset, rsvd */
#define TH_OFF(th)	(((th)->th_offx2 & 0xf0) >> 4)
	u_int8_t	th_flags;
#define	TH_FIN	0x01
#define	TH_SYN	0x02
#define	TH_RST	0x04
#define	TH_PUSH	0x08
#define	TH_ACK	0x10
#define	TH_URG	0x20
#define TH_ECNECHO	0x40	/* ECN Echo */
#define TH_CWR		0x80	/* ECN Cwnd Reduced */
	u_int16_t	th_win;			/* window */
	u_int16_t	th_sum;			/* checksum */
	u_int16_t	th_urp;			/* urgent pointer */
};

/*
 * extract information from the TCP header
 */
int handle_TCP(u_char *args,const struct pcap_pkthdr* pkthdr,const u_char* packet)
{
	const struct my_tcp* tcp;
	u_int length = pkthdr->len;
	int s_port, d_port;

	/* Jump off ethernet and IP headers */
	tcp = (struct my_tcp*)(packet + sizeof(struct ether_header) + sizeof(struct my_ip));
	length -= sizeof(struct ether_header); 
	length -= sizeof(struct my_ip); 

	/* check to see we have a packet of valid length */
	if (length < sizeof(struct my_tcp))
	{
		fprintf(stderr, "truncated tcp %d",length);
		return 0;
	}

	s_port = EXTRACT_16BITS(&tcp->th_sport);
	d_port = EXTRACT_16BITS(&tcp->th_dport);

#ifdef ONLINE
	update(TCP_FLAG);
#endif
	/* Print SOURCE-PORT DEST-PORT SEQ-NO */
#ifdef PRINT_TCP
	fprintf(OUT, "TCP: Source Port: %d |Dest Port: %d |Seq No: %u\n", s_port, d_port, tcp->th_seq);
#endif

	if( s_port == TELNET_PORT || d_port == TELNET_PORT )
		handle_telnet(args, pkthdr, packet);
	else if( s_port == NETBIOS_SSN_PORT || d_port == NETBIOS_SSN_PORT )
		handle_netbios(args, pkthdr, packet);
	
	return 0;
}

#endif
