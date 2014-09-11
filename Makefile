# SNIFF ver2.2 -- Makefile
# $$Date$$	December 09, 2004

CC = gcc
OPTIONS = -O2 -static
BIN = /sbin

sniff: sniff.c ethernet.h ip.h icmp.h tcp.h udp.h headers.h defs.h packet_dump.h packet_analyse.h packet_summary.h basket.h parse.h
	${CC} ${OPTIONS} sniff.c -o bin/iitm_sniff -lpcap -lncurses

sniff_dump: sniff_dump.c
	${CC} ${OPTIONS} sniff_dump.c -o bin/iitm_sniff_dump -lpcap -lncurses

sniff_open: sniff_open.c ethernet.h ip.h icmp.h tcp.h udp.h headers.h parse.h
	${CC} ${OPTIONS} sniff_open.c -o bin/iitm_sniff_open -lpcap -lncurses

clean:
	rm -f bin/*

all: sniff sniff_dump sniff_open

install: sniff sniff_open sniff_dump
	cp bin/iitm_sniff ${BIN}
	cp bin/iitm_sniff_open ${BIN}
	cp bin/iitm_sniff_dump ${BIN}
