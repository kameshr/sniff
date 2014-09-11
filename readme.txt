==========================================
sniff v2.2 $$Date: December 10, 2004
==========================================
Pre-compiled binaries are available in the bin directory.

Documentation is available in the docs directory.

Compilation instructions:
Go to the source directory and issue "make all"

Source Files:
sniff.c - The main file to be compiled to get the dual process executable

ether.h - Contains the definition of ehternet packet header and functions to analyze ethernet packet headers

ip.h - Definition of IP header and functions that analyze it

tcp.h, udp.h, icmp.h - Definitions of TCP, UDP and ICMP headers and functions to analyze them respectively

telnet.h, netbios.h - Handle appliction level packets of Telnet and MS File Share protocols

headers.h - Includes all required header files

sniff_dump.c - Dump all packets available in the network to a local file - preferably on a ramdisk

sniff_open.c - Analyze the packets offline from a dumpfile

semaphore.h - functions to perform semaphore operations

packet_dump.c - Contains the code for the process that dumps all the packets onto the memory

packet_analysis.c - Contains the code for the process that analyses the packets dumped onto the memory

packet_summary.c - Contains code for the process that periodically summarises the ongoing analysis of the packets

basket.h - Contains data structures and functions needed to create and maintain summary statistics in the shared memory

defs.h - Contains definitions of variables used in multiple processes

parse.h - Contains a parser to parse the user options config file

iitm_sniff.cgi - CGI script that spawns the web interface

ramsetup.sh - Setup a 64MB ramdisk partition at /mnt/ramdisk so that the packets captures may be written to it using sniff_dump

select.conf - A sample config file
====================================================================
Project developed by Kamesh Raghavendra (kameshr@gmail.com) under the guidance of Prof. R Kalyanakrishnan, IIT Madras
