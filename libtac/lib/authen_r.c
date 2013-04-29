/* authen_r.c - Read authentication reply from server.
 * 
 * Copyright (C) 2010, Pawel Krawczyk <pawel.krawczyk@hush.com> and
 * Jeroen Nijhof <jeroen@jeroennijhof.nl>
 * Portions Copyright (C) 2013 Guy Thouret <guythouret@wems.co.uk>
 *
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
#include "pam_tacplus.h"

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
void tac_authen_read(msg_status *msgstatus, int fd, int ctrl) {
    HDR th;
    struct authen_reply *tb = NULL;
    int len_from_header, r, len_from_body, msg_len, data_len;
    char *hdr_err = NULL;
    int timeleft;
    int status;

    /* Message Body Fields */
	char *server_msg = NULL;
    u_char *data = NULL;

    /* Return Struct */
    //msgstatus = malloc (sizeof(msg_status));

    /* read the reply header */
    if (tac_readtimeout_enable &&
        tac_read_wait(fd,tac_timeout*1000,TAC_PLUS_HDR_SIZE,&timeleft) < 0 ) {
        TACSYSLOG((LOG_ERR,\
            "%s: reply timeout after %d secs", __FUNCTION__, tac_timeout))
		msgstatus->status=LIBTAC_STATUS_READ_TIMEOUT;
        free(tb);
        exit;
    }
    r = read(fd, &th, TAC_PLUS_HDR_SIZE);
    if (r < TAC_PLUS_HDR_SIZE) {
        TACSYSLOG((LOG_ERR,\
            "%s: short reply header, read %d of %d: %m",\
            __FUNCTION__,\
            r, TAC_PLUS_HDR_SIZE))
		msgstatus->status=LIBTAC_STATUS_SHORT_HDR;
        free(tb);
        exit;
    }

    /* check the reply fields in header */
    hdr_err = _tac_check_header(&th, TAC_PLUS_AUTHEN);
    if(hdr_err != NULL) {
    	msgstatus->status = LIBTAC_STATUS_PROTOCOL_ERR;
        free(tb);
        exit;
    }
 
    len_from_header = ntohl(th.datalength);
    tb = (struct authen_reply *) xcalloc(1, len_from_header);

    /* read reply packet body */
    if (tac_readtimeout_enable &&
        tac_read_wait(fd,timeleft,len_from_header,NULL) < 0 ) {
        TACSYSLOG((LOG_ERR,\
            "%s: reply timeout after %d secs", __FUNCTION__, tac_timeout))
		msgstatus->status=LIBTAC_STATUS_READ_TIMEOUT;
    }
    r = read(fd, tb, len_from_header);
    if (r < len_from_header) {
        TACSYSLOG((LOG_ERR,\
            "%s: short reply body, read %d of %d: %m",\
            __FUNCTION__,\
            r, len_from_header))
		msgstatus->status = LIBTAC_STATUS_SHORT_BODY;
        free(tb);
        exit;
    }

    /* decrypt the body */
    _tac_crypt((u_char *) tb, &th, len_from_header);

    /* Convert network byte order to host byte order */
    msg_len  = ntohs(tb->msg_len);
    data_len = ntohs(tb->data_len);

    /* check the length fields */
    len_from_body = sizeof(tb->status) + sizeof(tb->flags) +
        sizeof(tb->msg_len) + sizeof(tb->data_len) +
        msg_len + data_len;

    if(len_from_header != len_from_body) {
        TACSYSLOG((LOG_ERR,\
            "%s: inconsistent reply body, incorrect key?",\
            __FUNCTION__))
		msgstatus->status = LIBTAC_STATUS_PROTOCOL_ERR;
        free(tb);
        exit;
    }

    /* Extract server_msg and data */
    if (msg_len > 0) {
    	server_msg = malloc(msg_len+1);
    	memcpy(server_msg,tb->data,msg_len);
    	server_msg[msg_len] = '\0';
    	msgstatus->server_msg = malloc(msg_len+1);
    	strcpy(msgstatus->server_msg,server_msg);
    }

    if (data_len > 0) {
    	data = malloc(data_len);
    	memcpy(data,tb->data+msg_len,data_len);
    }

    /* save status and clean up */
    r = tb->status;
    msgstatus->status = r;

    if (ctrl & PAM_TAC_DEBUG) {
		switch (r) {
			case TAC_PLUS_AUTHEN_STATUS_PASS:
				TACDEBUG((LOG_DEBUG, "%s: authentication ok", __FUNCTION__))
			break;

			case TAC_PLUS_AUTHEN_STATUS_FAIL:
				TACDEBUG((LOG_DEBUG, "%s: authentication failed, server reply msg=%s",__FUNCTION__, "t"))
			break;

			case TAC_PLUS_AUTHEN_STATUS_GETPASS:
				TACDEBUG((LOG_DEBUG, "%s: continue packet with password needed", __FUNCTION__))
			break;

			case TAC_PLUS_AUTHEN_STATUS_GETDATA:
				TACDEBUG((LOG_DEBUG, "%s: continue packet with requested data needed", __FUNCTION__))
			break;

			default:
				TACDEBUG((LOG_DEBUG, "%s: unknown reply packet status=0x%02x", __FUNCTION__,r));
			break;
		}
    }

	/* Packet Debug (In 'debug tacacs packet' format */
    if (ctrl & PAM_TAC_PACKET_DEBUG) {
		TACDEBUG((LOG_DEBUG, "T+: Version %u (0x%02X), type %u, seq %u, encryption %u",
			th.version, th.version, th.type, th.seq_no, th.encryption))
		TACDEBUG((LOG_DEBUG, "T+: session_id %u (0x%08X), dlen %u (0x%02X)",
			th.session_id, th.session_id, th.datalength, th.datalength))
		TACDEBUG((LOG_DEBUG, "T+: type:AUTHEN/REPLY status:%d flags:%02X msg_len:%u, data_len:%u",
			tb->status, tb->flags, msg_len, data_len))
		TACDEBUG((LOG_DEBUG, "T+: msg:  %s", server_msg))
		TACDEBUG((LOG_DEBUG, "T+: data: %s", data))
		TACDEBUG((LOG_DEBUG, "T+: End Packet"))
    }

    free(tb);
}    /* tac_authen_read */
