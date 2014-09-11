/**
 * $$File$$	basket.h 	$Date$	December 10, 2004
 * The online summary needs machinewise consolidation of the information gathered
 * from the analysis of the packets. Each of the machines is represented by a "basket"
 * and the counters in the basket are incremented to keep track of the machines profile.
 * New baskets are created online, when new machines send packets into the network.
 * This file creates and maintains a linked list of such baskets.
 * Baskets are identified by machine addresses.
 **/
#ifndef __BASKET__
#define __BASKET__
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h> 
#include <net/ethernet.h>
#include <netinet/ether.h> 
#include "itoa.h"
#include "defs.h"

#define NUM_PARAM 8 // Number of parameters in each of the baskets

// The list of parameters
#define PKCOUNT_FLAG 0
#define ARP_FLAG 1
#define IP_FLAG 2
#define TCP_FLAG 3
#define UDP_FLAG 4
#define RARP_FLAG 5
#define ALIEN_FLAG 6
#define ICMP_FLAG 7

#define LIST_LEN 15 // Length of the list displayed at the interface

/* A cache that points to the current basket whose machine's packet is being analysed */
u_int8_t CURRENT_MACHINE[ETH_ALEN];
struct basket* current_basket;
struct basket* list[LIST_LEN];

int protocnt[NUM_PARAM];
char publish;

/* The basket required for each of the machines in the network */
struct basket {
	char valid; // Valid bit --- 0 -> ready to use; 1 -> used; -1 -> sentinel
	u_int8_t eth_addr[ETH_ALEN]; // machine address
	struct in_addr ip_addr; // IP address
	int params[NUM_PARAM]; // Parameters include total number of packets and protocolwise distribution
};

/* Copy machine adrress */
void addrcpy(u_int8_t* dst, u_int8_t* src) {
	int i;
	for(i=0; i<ETH_ALEN; i++)
		dst[i] = src[i];
}

/* Compare machine addresses */
int addrcmp(u_int8_t* addr1, u_int8_t* addr2) {
	int i;
	for(i=0; i<ETH_ALEN; i++) {
		if(addr1[i] != addr2[i])
			return 0;
	}
	return 1;
}

/* Creates a list of machine baskets for summary information */
struct basket* create_list(char *mempool, int size) {
	int numbaskets, i;
	struct basket *first, *last, *iter;
	struct basket buf1, buf2;
	char *end;
	
	numbaskets = size/sizeof(struct basket);

	/* Check for enough memory in the pool */
	if( numbaskets < 2 ) {
		fprintf(stderr, "[ERROR] Memory not sufficient for basket list.\n");
		return NULL;
	}

	/* No machine selected yet */
	current_basket = NULL;

	first = (struct basket*)mempool;
	iter = first;
	/* First basket ready to be used */
	buf1.valid = 0;
	inet_aton("0.0.0.0", &(buf1.ip_addr));
	for(i=0; i<NUM_PARAM;i++)
		buf1.params[i] = 0;
	*first = buf1;

	end = mempool + (numbaskets-1)*sizeof(struct basket);
	last = (struct basket*)end;
	buf2.valid = -1;
	*last = buf2;

	for(i=0; i<LIST_LEN; i++)
		list[i] = NULL;

	for(i=0; i<NUM_PARAM; i++)
		protocnt[i] = 0;

	/* Initialize all baskets in the list */
	for(i=0; i < numbaskets - 2; i++) {
		iter++;
		*iter = buf1;
	}

	return first;
}

/* Select and cache the machine whose packets ae being analysed */
int selectmach(struct basket* pool, u_int8_t* mach) {
	struct basket add;
	addrcpy(CURRENT_MACHINE, mach);
	// Till end of the list
	while( pool->valid != -1 ) {
		
		// If the machine is being selected for the first time
		if(pool->valid == 0) {
			addrcpy(pool->eth_addr, mach);
			/* Its a used basket now! */
			pool->valid = 1;

			current_basket = pool;
			current_basket->params[PKCOUNT_FLAG]++; // Increment number of packets
			return 1;
		}
		// Old machine
		else if( addrcmp(pool->eth_addr, mach) == 1 ) {
			current_basket = pool;
			current_basket->params[PKCOUNT_FLAG]++; // Increment number of packets
			return 0;
		}

		pool++;
	}
	
	// List overflow -- Sorry!
	current_basket = NULL;
	return -1;
}

/* IP address check and updation */
int ip_update(struct in_addr ipadd) {
	if(current_basket == NULL)
		return -1;
	current_basket->ip_addr = ipadd;
	current_basket->params[IP_FLAG]++;
	return 0;
}

/* Other protocol updates */
void update(int flag) {
	if(current_basket == NULL )
		return;
	current_basket->params[flag]++;
}

/* Machines that spew maximum number of packets for the online display */
void list_maximum(struct basket *pool) {
	int i,j;
	struct basket *temp, *buf;

	for(i=0; i<LIST_LEN; i++)
		list[i] = NULL;

	for(i=0; i < NUM_PARAM; i++)
		protocnt[i] = 0;

	/* Go through all the machines once */
	while( pool->valid == 1 ) {

		/*Get protocolwise statistics */
		protocnt[PKCOUNT_FLAG] += pool->params[PKCOUNT_FLAG];
		protocnt[ARP_FLAG] += pool->params[ARP_FLAG];
		protocnt[RARP_FLAG] += pool->params[RARP_FLAG];
		protocnt[IP_FLAG] += pool->params[IP_FLAG];
		protocnt[ICMP_FLAG] += pool->params[ICMP_FLAG];
		protocnt[TCP_FLAG] += pool->params[TCP_FLAG];
		protocnt[UDP_FLAG] += pool->params[UDP_FLAG];
		protocnt[ALIEN_FLAG] += pool->params[ALIEN_FLAG];
		/* Check if the machine needs to be inserted in the toppers list */
		for(i=0; i < LIST_LEN; i++) {
			/* Oh theres an empty slot - so fill it with this machine */
			if(list[i] == NULL) {
				list[i] = pool;
				break;
			}
			/* This guy has a higher rank - so move on */
			else if( list[i]->params[PKCOUNT_FLAG] >= pool->params[PKCOUNT_FLAG])
				continue;
			/* Ah! a lower rank guy - insert! */
			else {
				temp = list[i];
				list[i] = pool; // Insert at the right position

				/* People below get one rank lower */
				for(j=i+1; j < LIST_LEN; j++) {
					if(list[j] == NULL) {
						list[j] = temp;
						break;
					}
					else {
						buf = list[j];
						list[j] = temp;
						temp = buf;
					}
				}
				break; // Machine dealt with - goto the next machine
			}
		}
		pool++; // Next machine
	}
}

/* Print the lists summary on the console display */
int print_summary(struct basket *pool, int offset) {
	int i;
	char *zero = "0.0.0.0";
	char *str = "(Unknown)";
	char *stars = "***";
	char tmpbuf[10];

	list_maximum(pool);

	mvprintw(offset, 0, "Machinewise analysis of the packets:");
	offset++;
	attron(A_BOLD|COLOR_PAIR(1));
	mvprintw(offset, 0, "Machine Address");
	mvprintw(offset, 18, "IP Address");
	mvprintw(offset, 34, "Total");
	mvprintw(offset, 41, "ARP");
	mvprintw(offset, 48, "RARP");
	mvprintw(offset, 53, "IP ");
	mvprintw(offset, 59, "ICMP");
	mvprintw(offset, 65, "TCP");
	mvprintw(offset, 71, "UDP");
	mvprintw(offset, 77, "(?)");
	attroff(A_BOLD|COLOR_PAIR(1)); 
	offset++;

	for(i=0; i<LIST_LEN; i++) {
		if(list[i] == NULL)
			break;
		mvprintw( offset, 0, "                                                                                ");
		mvprintw( offset, 0, "%s", ether_ntoa((struct ether_addr*)list[i]->eth_addr));
		mvprintw( offset, 18, "                   ");
		mvprintw( offset, 18, "%s", (strcmp(inet_ntoa(list[i]->ip_addr), zero) == 0)?str:inet_ntoa(list[i]->ip_addr));
		mvprintw( offset, 34, "%s", (list[i]->params[PKCOUNT_FLAG]<=999999)?itoa(list[i]->params[PKCOUNT_FLAG], tmpbuf):stars);
		mvprintw( offset, 41, "%s", (list[i]->params[ARP_FLAG]<=999999)?itoa(list[i]->params[ARP_FLAG], tmpbuf):stars);
		mvprintw( offset, 48, "%s", (list[i]->params[RARP_FLAG]<=9999)?itoa(list[i]->params[RARP_FLAG], tmpbuf):stars);
		mvprintw( offset, 53, "%s", (list[i]->params[IP_FLAG]<=99999)?itoa(list[i]->params[IP_FLAG], tmpbuf):stars);
		mvprintw( offset, 59, "%s", (list[i]->params[ICMP_FLAG]<=99999)?itoa(list[i]->params[ICMP_FLAG], tmpbuf):stars);
		mvprintw( offset, 65, "%s", (list[i]->params[TCP_FLAG]<=99999)?itoa(list[i]->params[TCP_FLAG], tmpbuf):stars);
		mvprintw( offset, 71, "%s", (list[i]->params[UDP_FLAG]<=99999)?itoa(list[i]->params[UDP_FLAG], tmpbuf):stars);
		mvprintw( offset, 77, "%s", (list[i]->params[ALIEN_FLAG]<=999)?itoa(list[i]->params[ALIEN_FLAG], tmpbuf):stars);
		if(publish == WEB_REFRESH)
			fprintf(web, "%s %s %d %d %d %d %d %d %d %d\n", ether_ntoa((struct ether_addr*)list[i]->eth_addr), (strcmp(inet_ntoa(list[i]->ip_addr), zero) == 0)?str:inet_ntoa(list[i]->ip_addr), list[i]->params[PKCOUNT_FLAG], list[i]->params[ARP_FLAG], list[i]->params[RARP_FLAG], list[i]->params[IP_FLAG], list[i]->params[ICMP_FLAG], list[i]->params[TCP_FLAG], list[i]->params[UDP_FLAG], list[i]->params[ALIEN_FLAG]);
		refresh();
		offset++;
	}

	if(publish == WEB_REFRESH)
		fprintf(web, "\n");

	mvprintw(offset, 0, "                                                                                ");

	mvprintw(offset+1, 0, "Protocolwise analysis of the packets:                                           ");
	offset+=2;
	attron(A_BOLD|COLOR_PAIR(1));
	mvprintw(offset, 0, "Total       ");
	mvprintw(offset, 16, "ARP       ");
	mvprintw(offset, 32, "RARP       ");
	mvprintw(offset, 48, "IP       ");
	mvprintw(offset+1, 0, "ICMP       ");
	mvprintw(offset+1, 16, "TCP       ");
	mvprintw(offset+1, 32, "UDP       ");
	mvprintw(offset+1, 48, "OTHR       ");
	attroff(A_BOLD|COLOR_PAIR(1));
	mvprintw(offset,6 , "%d", protocnt[PKCOUNT_FLAG]);
	mvprintw(offset, 22, "%d", protocnt[ARP_FLAG]);
	mvprintw(offset, 38, "%d", protocnt[RARP_FLAG]);
	mvprintw(offset, 54, "%d", protocnt[IP_FLAG]);
	mvprintw(offset+1, 6, "%d", protocnt[ICMP_FLAG]);
	mvprintw(offset+1, 22, "%d", protocnt[TCP_FLAG]);
	mvprintw(offset+1, 38, "%d", protocnt[UDP_FLAG]);
	mvprintw(offset+1, 54, "%d", protocnt[ALIEN_FLAG]);
	if(publish == WEB_REFRESH)
		fprintf(web, "%d %d %d %d %d %d %d %d\n", protocnt[PKCOUNT_FLAG], protocnt[ARP_FLAG], protocnt[RARP_FLAG], protocnt[IP_FLAG], protocnt[ICMP_FLAG], protocnt[TCP_FLAG], protocnt[UDP_FLAG], protocnt[ALIEN_FLAG]);
	offset += 2;
	refresh();
	return offset;
}
#endif
