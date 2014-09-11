/**
 * $$File$$ packet_summary.h 	$$Date$$ December 02, 2004
 * This file contains the code run by the third (grand-child!) process which
 * periodically summarizes the information extracted from the analysis.
 * It refreshes the output display with the latest summary.
 **/
#ifndef __PACKET_SUMMARY__
#define __PACKET_SUMMARY__
#define CONSOLE_REFRESH 2
#include "headers.h"
#include "defs.h"

/* Summarise the analysis being done periodically */
void summarise_analysis() {
	/* Summary shared memory initialization */
	char *summary = smread;
	int *pknum;
	int timer, offset, dynoff;
	struct timezone tz;
	struct timeval first, last;
	int prevpk = 0, i;
	float rate;
	char bufstr[40];
	char buftmr[40];
	
	publish = 0;
	tz.tz_minuteswest = 0;
	tz.tz_dsttime = 0;
	offset = 0;

	gettimeofday(&first,&tz);

	/*first = (struct timeval*)summary;
	last = (struct timeval*)(summary + sizeof(struct timeval));*/
	pknum = (int*)(summary + 2*sizeof(struct timeval));

	initscr();
	getmaxyx(stdscr, row, col);
	noecho();
	start_color();
	init_pair(1, COLOR_YELLOW, COLOR_BLACK);
	init_pair(2, COLOR_GREEN, COLOR_BLACK);
	init_pair(3, COLOR_WHITE, COLOR_BLACK);
	init_pair(4, COLOR_RED, COLOR_BLACK);

	attron(A_BOLD|COLOR_PAIR(2));
	mvprintw(offset,(col/2) - 18, "************ Sniff v2.2 ************");
	offset++;
	attroff(A_BOLD|COLOR_PAIR(2));

	attron(A_BOLD|COLOR_PAIR(1));
	mvprintw(offset, 5, "Time (HH:MM:SS):");
	mvprintw(offset, 51, "Total Packets:");
	mvprintw(offset + 1, 55, "Packets Dropped:");
	mvprintw(offset + 1, 0, "Packet Density:");
	mvprintw(offset +1 , 17, "Average:");
	mvprintw(offset + 1, 35, "Current:");
	attroff(A_BOLD|COLOR_PAIR(1));
	
	while(1) {
		sleep(CONSOLE_REFRESH);
		if(publish == WEB_REFRESH) {
			web = fopen("/tmp/sniffweb.txt", "w");
			fprintf(web, "%s %s %.2f %.2f %d\n", buftmr, bufstr, (float) ( ((double)(*pknum))/((double)(last.tv_sec - first.tv_sec)) ), rate, ps.ps_drop);
			/* Clean the slate off all stupid error messages! */
			for(i=0; i<25; i++) {
				mvprintw(i, 0, "                                                                                ");
			}

			/* Write everything from the begining */
			offset = 0;
			attron(A_BOLD|COLOR_PAIR(2));
			mvprintw(offset,(col/2) - 18, "************ Sniff v2.2 ************");
			offset++;
			attroff(A_BOLD|COLOR_PAIR(2));

			attron(A_BOLD|COLOR_PAIR(1));
			mvprintw(offset, 5, "Time (HH:MM:SS):");
			mvprintw(offset, 51, "Total Packets:");
			mvprintw(offset + 1, 55, "Packets Dropped:");
			mvprintw(offset + 1, 0, "Packet Density:");
			mvprintw(offset +1 , 17, "Average:");
			mvprintw(offset + 1, 35, "Current:");
			attroff(A_BOLD|COLOR_PAIR(1));
		}

		rate = (float) ( ((double)(*pknum - prevpk))/((double)CONSOLE_REFRESH) );
		gettimeofday(&last, &tz);
		timer = last.tv_sec - first.tv_sec;
		pcap_stats(descr, &ps);
		mvprintw(offset, 22, "%s", itoft(timer, buftmr));
		mvprintw(offset, 66, "%s", itofa(*pknum, bufstr));
		mvprintw(offset + 1, 26, "         ");
		mvprintw(offset + 1, 26, "%.2f",(float) ( ((double)(*pknum))/((double)(last.tv_sec - first.tv_sec)) ));
		mvprintw(offset + 1, 44, "         ");
		mvprintw(offset + 1, 44, "%.2f",rate);
		mvprintw(offset + 1, 72, "          ");
		mvprintw(offset + 1, 72, "%d", ps.ps_drop);
		refresh();
		prevpk = *pknum;

		dynoff = print_summary(basket_pool, offset+3);
		publish++;
		if(publish > WEB_REFRESH) {
			fclose(web);
			publish = 0;
		}
		if( (*pknum) >= numPacket ) {
			attron(A_BOLD|COLOR_PAIR(4));
			mvprintw(dynoff - 4, 5, "Analysis completed. Press any key to quit...");
			attroff(A_BOLD|COLOR_PAIR(4));
			getch();
			endwin();
			exit(0);
		}
	}
}
#endif
