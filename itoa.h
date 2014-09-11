/**
 * $$File$$ itoa.h 	$$Date$$ December 09, 2004
 * This file contains integer fomating functions which display
 * integers in a "neat" way using strings. Used for UI.
 **/
#ifndef __ITOA__
#define __ITOA__

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

char* strrev(char*);

/* Converts a positive integer into an ascii string */
char* itoa(int a, char* res) {
	char str[2];
	int digit;
	res[0] = '\0'; // Null string to start with
	str[1] = '\0';
	
	if(a == 0) {
		res[0] = 0x30;
		res[1] = '\0';
		return res;
	}

	while( a > 0 ) {
		/* Extract individual digits */
		digit = a % 10;
		a = a/10;
		str[0] = ( (char)digit ) + 0x30;
		res = strcat(res, str);
	}

	return (char*)strrev(res);
}

/* Reverse a string */
char* strrev(char* str) {
	char a[strlen(str) + 1];
	strcpy(a, str);
	int i,j;
    for(i = 0, j = strlen(str) - 1; i <= j; i++, j--) {
        str[i] = a[j];
        str[j] = a[i];
    }
    return str;
}

/* Converts a positive integer to a formated ascii string */
char* itofa(int a, char* res) {
	char bunch[10][4];
	int three;
	int zcnt;
	int cnt = 0;
	char comma[2];

	res[0] = '\0';
	comma[0] = ',';
	comma[1] = '\0';

	/* Divide the number into bunches of three */
	while( a > 0 ) {
		three = a % 1000;
		a = a/1000;
		itoa(three, bunch[cnt]);
		cnt++;
	}


	/* Convert each bunch into a string */
	for(three = cnt - 1; three >= 0; three--) {
		zcnt = strlen(bunch[three]);

		/* Take care of leading zeros */
		if(zcnt < 3 && three != cnt - 1) {
			if(zcnt == 1) {
				bunch[three][3] = '\0';
				bunch[three][2] = bunch[three][0];
				bunch[three][1] = '0';
				bunch[three][0] = '0';
			}
			if(zcnt == 2) {
				bunch[three][3] = '\0';
				bunch[three][2] = bunch[three][1];
				bunch[three][1] = bunch[three][0];
				bunch[three][0] = '0';
			}
		}

		/* Three digits at a time */
		res = strcat(res, bunch[three]);

		/* Put those commas in between */
		if(three > 0) {
			res = strcat(res,comma);
		}
	}

	return res;
}

/* Convert seconds to formated HH:MM:SS time ascii string */
char* itoft(int a, char* res) {
	int quo;
	char colon[2];
	char buf[10];
	
	res[0] = '\0';
	colon[0] = ':';
	colon[1] = '\0';

	quo = a/3600;
	a = a % 3600;

	if(quo < 10)
		res = strcat(res, itoa(0,buf));
	res = strcat(res, itoa(quo,buf));
	res = strcat(res, colon);

	quo = a/60;
	a = a % 60;

	if(quo < 10)
		res = strcat(res, itoa(0,buf));
	res = strcat(res, itoa(quo,buf));
	res = strcat(res, colon);

	if(a < 10)
		res = strcat(res, itoa(0,buf));
	res = strcat(res, itoa(a,buf));


	return res;
}
#endif
