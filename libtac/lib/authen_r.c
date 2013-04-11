/* authen_r.c - Read authentication reply from server.
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

#include "libtac.h"
#include "messages.h"

/* reads packet from TACACS+ server; returns:
 *  TAC_PLUS_AUTHEN_STATUS_PASS if the authentication succeded
 *  an other integer if failed. Check tacplus.h for all possible values
 *
 * return value:
 *   <  0 : error status code, see LIBTAC_STATUS_...
 *         LIBTAC_STATUS_READ_TIMEOUT
 *         LIBTAC_STATUS_SHORT_HDR
 *         LIBTAC_STATUS_SHORT_BODY
 *         LIBTAC_STATUS_PROTOCOL_ERR
 *   >= 0 : server response, see TAC_PLUS_AUTHEN_STATUS_...
 */
int tac_authen_read(int fd) {
    HDR th;
    struct authen_reply *tb = NULL;
    int len_from_header, r, len_from_body;
    char *hdr_err = NULL;
    int timeleft;
    int status;

    /* Message Body Fields */
	char *server_msg;
    u_char *data;

    /* read the reply header */
    if (tac_readtimeout_enable &&
        tac_read_wait(fd,tac_timeout*1000,TAC_PLUS_HDR_SIZE,&timeleft) < 0 ) {
        TACSYSLOG((LOG_ERR,\
            "%s: reply timeout after %d secs", __FUNCTION__, tac_timeout))
        status=LIBTAC_STATUS_READ_TIMEOUT;
        free(tb);
        return status;
    }
    r = read(fd, &th, TAC_PLUS_HDR_SIZE);
    if (r < TAC_PLUS_HDR_SIZE) {
        TACSYSLOG((LOG_ERR,\
            "%s: short reply header, read %d of %d: %m",\
            __FUNCTION__,\
            r, TAC_PLUS_HDR_SIZE))
        status=LIBTAC_STATUS_SHORT_HDR;
        free(tb);
        return status;
    }

    /* check the reply fields in header */
    hdr_err = _tac_check_header(&th, TAC_PLUS_AUTHEN);
    if(hdr_err != NULL) {
        status = LIBTAC_STATUS_PROTOCOL_ERR;
        free(tb);
        return status;
    }
 
    len_from_header = ntohl(th.datalength);
    tb = (struct authen_reply *) xcalloc(1, len_from_header);

    /* read reply packet body */
    if (tac_readtimeout_enable &&
        tac_read_wait(fd,timeleft,len_from_header,NULL) < 0 ) {
        TACSYSLOG((LOG_ERR,\
            "%s: reply timeout after %d secs", __FUNCTION__, tac_timeout))
        status=LIBTAC_STATUS_READ_TIMEOUT;
    }
    r = read(fd, tb, len_from_header);
    if (r < len_from_header) {
        TACSYSLOG((LOG_ERR,\
            "%s: short reply body, read %d of %d: %m",\
            __FUNCTION__,\
            r, len_from_header))
        status = LIBTAC_STATUS_SHORT_BODY;
        free(tb);
        return status;
    }

    /* decrypt the body */
    _tac_crypt((u_char *) tb, &th, len_from_header);

    /* Convert network byte order to host byte order */
    tb->msg_len  = ntohs(tb->msg_len);
    tb->data_len = ntohs(tb->data_len);

    /* check the length fields */
    len_from_body = sizeof(tb->status) + sizeof(tb->flags) +
        sizeof(tb->msg_len) + sizeof(tb->data_len) +
        tb->msg_len + tb->data_len;

    if(len_from_header != len_from_body) {
        TACSYSLOG((LOG_ERR,\
            "%s: inconsistent reply body, incorrect key?",\
            __FUNCTION__))
        status = LIBTAC_STATUS_PROTOCOL_ERR;
        free(tb);
        return status;
    }

    /* Extract server_msg and data */
    TACDEBUG((LOG_DEBUG, "%s: msg_len=%d", __FUNCTION__, tb->msg_len))
    TACDEBUG((LOG_DEBUG, "%s: data_len=%d", __FUNCTION__, tb->data_len))

    if (tb->msg_len > 0) {
    	server_msg = malloc(tb->msg_len+1);
    	memcpy(server_msg,tb->data,tb->msg_len);
    }

    if (tb->data_len > 0) {
    	data = malloc(tb->data_len);
    	memcpy(data,tb->data+tb->msg_len,tb->data_len);
    }

    /* save status and clean up */
    r = tb->status;
    status = r;

    switch (r) {
    	case TAC_PLUS_AUTHEN_STATUS_PASS:
    		TACDEBUG((LOG_DEBUG, "%s: authentication ok", __FUNCTION__))
    	break;

    	case TAC_PLUS_AUTHEN_STATUS_FAIL:
    		TACDEBUG((LOG_DEBUG, "%s: authentication failed, server reply msg=%s",\
    		        __FUNCTION__, server_msg))
    	break;

    	case TAC_PLUS_AUTHEN_STATUS_GETPASS:
    		TACDEBUG((LOG_DEBUG, "%s: continue packet with password needed", __FUNCTION__))
    	break;

    	case TAC_PLUS_AUTHEN_STATUS_GETDATA:
    		TACDEBUG((LOG_DEBUG, "%s: continue packet with requested data needed", __FUNCTION__))
    	break;
    }

    free(tb);
    return status;
}    /* tac_authen_read */
