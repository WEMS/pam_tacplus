/* xalloc.c - Failsafe memory allocation functions.
 *            Taken from excellent glibc.info ;)
 * 
 * Copyright (C) 2010, Pawel Krawczyk <pawel.krawczyk@hush.com> and
 * Jeroen Nijhof <jeroen@jeroennijhof.nl>
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

#include "xalloc.h"

void *xcalloc(size_t nmemb, size_t size) {
    register void *val = calloc(nmemb, size);
    if(val == 0) {
        TACSYSLOG((LOG_ERR, "%s: calloc(%u,%u) failed", __FUNCTION__,\
            (unsigned) nmemb, (unsigned) size))
        exit(1);
    }
    return val;
}

void *xrealloc(void *ptr, size_t size) {
    register void *val = realloc(ptr, size);
    if(val == 0) {
        TACSYSLOG((LOG_ERR, "%s: realloc(%u) failed", __FUNCTION__, (unsigned) size))
        exit(1);
    }
    return val;
}

char *xstrdup(char *s) {
    char *p;
    if (s == NULL) return NULL;

    if ( (p = strdup(s)) == NULL ) {
        TACSYSLOG((LOG_ERR, "%s: strdup(%s) failed: %m", __FUNCTION__, s))
        exit(1);
    }
    return p;
}
