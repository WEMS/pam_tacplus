/* messages.c - Various messages returned to user.
 * 
 * Copyright (C) 2010, Pawel Krawczyk <pawel.krawczyk@hush.com> and
 * Jeroen Nijhof <jeroen@jeroennijhof.nl>
 * Portions Copyright (C) 2013 Guy Thouret <guythouret@wems.co.uk>
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
char *errorString = "Error";

int allocString(unsigned int len, char** string_ptr) {
	// Allocate momory for string including the extra space for '\0'
	return ((*string_ptr = (char*)malloc(len + 1)) == NULL ? 0 : 1);
}

void authen_type_string (char** ptr, u_char authen_type) {
	switch (authen_type) {
		case 1:
			if (allocString(strlen("ASCII"), ptr)) {
				strcpy(*ptr,"ASCII");
			}
		break;

		case 2:
			if (allocString(strlen("PAP"), ptr)) {
				strcpy(*ptr,"PAP");
			}
		break;

		case 3:
			if (allocString(strlen("CHAP"), ptr)) {
				strcpy(*ptr,"CHAP");
			}
		break;

		case 4:
			if (allocString(strlen("ARAP"), ptr)) {
				strcpy(*ptr,"ARAP");
			}
		break;

		default:
			if (allocString(strlen("Unknown"), ptr)) {
				strcpy(*ptr,"Unknown");
			}
		break;
	}
}

void authen_action_string (char** ptr, u_char authen_action) {
	switch (authen_action) {
		case 1:
			if (allocString(strlen("LOGIN"), ptr)) {
				strcpy(*ptr,"LOGIN");
			}
		break;

		case 2:
			if (allocString(strlen("CHPASS"), ptr)) {
				strcpy(*ptr,"CHPASS");
			}
		break;

		case 3:
			if (allocString(strlen("SENDPASS"), ptr)) {
				strcpy(*ptr,"SENDPASS");
			}
		break;

		default:
			if (allocString(strlen("Unknown"), ptr)) {
				strcpy(*ptr,"Unknown");
			}
		break;
	}
}

void authen_service_string (char** ptr, u_char authen_service) {
	switch (authen_service) {
		case 0:
			if (allocString(strlen("NONE"), ptr)) {
				strcpy(*ptr,"NONE");
			}
		break;

		case 1:
			if (allocString(strlen("LOGIN"), ptr)) {
				strcpy(*ptr,"LOGIN");
			}
		break;

		case 2:
			if (allocString(strlen("ENABLE"), ptr)) {
				strcpy(*ptr,"ENABLE");
			}
		break;

		case 3:
			if (allocString(strlen("PPP"), ptr)) {
				strcpy(*ptr,"PPP");
			}
		break;

		case 4:
			if (allocString(strlen("ARAP"), ptr)) {
				strcpy(*ptr,"ARAP");
			}
		break;

		case 5:
			if (allocString(strlen("PT"), ptr)) {
				strcpy(*ptr,"PT");
			}
		break;

		case 6:
			if (allocString(strlen("RCMD"), ptr)) {
				strcpy(*ptr,"RCMD");
			}
		break;

		case 7:
			if (allocString(strlen("X25"), ptr)) {
				strcpy(*ptr,"X25");
			}
		break;

		default:
			if (allocString(strlen("Unknown"), ptr)) {
				strcpy(*ptr,"Unknown");
			}
		break;
	}
}
