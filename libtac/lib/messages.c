/* messages.c - Various messages returned to user.
 * 
 * Copyright (C) 2010, Pawel Krawczyk <pawel.krawczyk@hush.com> and
 * Jeroen Nijhof <jeroen@jeroennijhof.nl>
 * 2013, Guy Thouret <guythouret@wems.co.uk>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program - see the file COPYING.
 *
 * See `CHANGES' file for revision history.
 */

#include "messages.h"

char *protocol_err_msg = "(Protocol error)";
char *author_ok_msg = "(Service granted)";
char *author_fail_msg = "(Service not allowed)";
char *author_err_msg = "(Service not allowed. Server error)";
char *author_syserr_msg = "(Authorization system error)";
char *acct_ok_msg = "(Accounted ok)";
char *acct_fail_msg = "(Accounting failed)";
char *acct_err_msg = "(Accounting failed. Server error)";
char *acct_syserr_msg = "(Accounting system error)";

int allocString(int length, char **ptrptr) {
	char *ptr = malloc(length + 1);

	if(ptr == NULL)
		return 0;

	*ptrptr = ptr;

	return 1;
}

char *authen_type_string (u_char authen_type) {
	char *string = NULL;

	switch (authen_type) {
		case 1:
			if (allocString(strlen("ASCII"), &string)) {
				strcpy(string,"ASCII");
			}
		break;

		case 2:
			if (allocString(strlen("PAP"), &string)) {
				strcpy(string,"PAP");
			}
		break;

		case 3:
			if (allocString(strlen("CHAP"), &string)) {
				strcpy(string,"CHAP");
			}
		break;

		case 4:
			if (allocString(strlen("ARAP"), &string)) {
				strcpy(string,"ARAP");
			}
		break;

		default:
			if (allocString(strlen("Unknown"), &string)) {
				strcpy(string,"Unknown");
			}
		break;
	}

	return string;
}

char *authen_action_string (u_char authen_action) {
	char *string= NULL;

	switch (authen_action) {
		case 1:
			if (allocString(strlen("LOGIN"), &string)) {
				strcpy(string,"LOGIN");
			}
		break;

		case 2:
			if (allocString(strlen("CHPASS"), &string)) {
				strcpy(string,"CHPASS");
			}
		break;

		case 3:
			if (allocString(strlen("SENDPASS"), &string)) {
				strcpy(string,"SENDPASS");
			}
		break;

		default:
			if (allocString(strlen("Unknown"), &string)) {
				strcpy(string,"Unknown");
			}
		break;
	}

	return string;
}

char *authen_service_string (u_char authen_service) {
	char *string = NULL;

	switch (authen_service) {
		case 0:
			if (allocString(strlen("NONE"), &string)) {
				strcpy(string,"NONE");
			}
		break;

		case 1:
			if (allocString(strlen("LOGIN"), &string)) {
				strcpy(string,"LOGIN");
			}
		break;

		case 2:
			if (allocString(strlen("ENABLE"), &string)) {
				strcpy(string,"ENABLE");
			}
		break;

		case 3:
			if (allocString(strlen("PPP"), &string)) {
				strcpy(string,"PPP");
			}
		break;

		case 4:
			if (allocString(strlen("ARAP"), &string)) {
				strcpy(string,"ARAP");
			}
		break;

		case 5:
			if (allocString(strlen("PT"), &string)) {
				strcpy(string,"PT");
			}
		break;

		case 6:
			if (allocString(strlen("RCMD"), &string)) {
				strcpy(string,"RCMD");
			}
		break;

		case 7:
			if (allocString(strlen("X25"), &string)) {
				strcpy(string,"X25");
			}
		break;

		default:
			if (allocString(strlen("Unknown"), &string)) {
				strcpy(string,"Unknown");
			}
		break;
	}

	return string;
}
