/**
 * $$File$$ parse.h 	$$Date$$ December 07, 2004
 * Options config file parser
 **/
#ifndef __PARSE__
#define __PARSE__
#include "headers.h"

/** Parse the config file passed and return it as a string */
char* parse_file(char *file, char *res) {
	FILE *fp;
	char *ret;
	char hostmode = 0, portmode = 0, mechmode = 0; // Need to know whether to put OR
	char hostinit = 0, portinit = 0, mechinit = 0;
	char ishost = 0;
	char buf[80];
	char *net = " net ";
	char *netag = " or net ";
	char *port = " port ";
	char *portag = " or port ";
	char *netbegin = "<hosts>";
	char *netend = "</hosts>";
	char *portbegin = "<ports>";
	char *portend = "</ports>";
	char *mechbegin = "<machine>";
	char *mechend = "</machine>";
	char *mech = " ether host ";
	char *mechag = " or ether host ";
	
	res[0] = '\0';
	
	if( (fp = fopen(file, "r")) == NULL ) {
		fprintf(stderr, "[ERROR] Config file %s could not be opened.\n", file);
		exit(-1);
	}

	while(fgets(buf, 80, fp) != NULL ) {
		/* Remove the trailing newline */
		ret = strtok(buf, "\n");
		/* Pack empty lines */
		if(ret == NULL) {
			continue;
		}
		
		if( strcmp(netbegin, ret) == 0 ) {
			hostmode = 1;
			buf[0] = '\0';
			continue;
		}
		else if( strcmp(netend, ret) == 0) {
			hostmode = 0;
			buf[0] = '\0';
			continue;
		}
		else if( strcmp(portbegin, ret) == 0) {
			portmode = 1;
			buf[0] = '\0';
			continue;
		}
		else if( strcmp(portend, ret) == 0) {
			portmode = 0;
			buf[0] = '\0';
			continue;
		}
		else if( strcmp(mechbegin, ret) == 0) {
			mechmode = 1;
			buf[0] = '\0';
			continue;
		}
		else if( strcmp(mechend, ret) == 0) {
			mechmode = 0;
			buf[0] = '\0';
			continue;
		}

		
		if( hostmode == 1 ) {
			strcat(res, (hostinit == 0 && ishost==0)?net:netag);
			hostinit = 1;
			ishost = 1;
			strcat(res, ret);
			buf[0] = '\0';
		}
		else if( portmode == 1 ) {
			strcat(res, (portinit == 0 && ishost == 0)?port:portag);
			portinit = 1;
			ishost = 1;
			strcat(res, ret);
			buf[0] = '\0';
		}
		else if( mechmode == 1 ) {
			strcat(res, (mechinit == 0 && ishost == 0)?mech:mechag);
			mechinit = 1;
			ishost = 1;
			strcat(res, ret);
			buf[0] = '\0';
		}

	}

	fclose(fp);
	fprintf(stdout, "[INFO] Compiler parse string: %s\n", res);
	return res;
}
#endif
