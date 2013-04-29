/* messages.h
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

#ifndef _MESSAGES_H
#define _MESSAGES_H

#include <sys/types.h>
#include <string.h>

extern char *protocol_err_msg;
extern char *author_ok_msg;
extern char *author_fail_msg;
extern char *author_err_msg;
extern char *author_syserr_msg;
extern char *acct_ok_msg;
extern char *acct_fail_msg;
extern char *acct_err_msg;
extern char *acct_syserr_msg;

int allocString(unsigned int len, char** string_ptr);
void authen_type_string (char** ptr, u_char authen_type);
void authen_action_string (char** ptr, u_char authen_action);
void authen_service_string (char** ptr, u_char authen_service);

#endif
