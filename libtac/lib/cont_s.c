/* cont_s.c - Send continue request to the server.
 * 
 * Copyright (C) 2010, Jeroen Nijhof <jeroen@jeroennijhof.nl>
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

#include "libtac.h"
#include "md5.h"
#include "pam_tacplus.h"

/* this function sends a continue packet do TACACS+ server, asking
 * for validation of given password
 *
 * return value:
 *      0 : success
 *   <  0 : error status code, see LIBTAC_STATUS_...
 *         LIBTAC_STATUS_WRITE_ERR
 *         LIBTAC_STATUS_WRITE_TIMEOUT  (pending impl)
 *         LIBTAC_STATUS_ASSEMBLY_ERR
 */
int tac_cont_send(int fd, char *pass, int ctrl, int seq) {
    HDR *th;        /* TACACS+ packet header */
    struct authen_cont tb;  /* continue body */
    int pass_len, bodylength, w;
    int pkt_len = 0;
    int ret = 0;
    u_char *pkt = NULL;

    th = _tac_req_header(TAC_PLUS_AUTHEN, 1);

    /* set some header options */
    th->version = TAC_PLUS_VER_0;
    th->seq_no = seq;
    th->encryption = tac_encryption ? TAC_PLUS_ENCRYPTED_FLAG : TAC_PLUS_UNENCRYPTED_FLAG;

    /* get size of submitted data */
    pass_len = strlen(pass);

    /* fill the body of message */
    tb.user_msg_len = htons(pass_len);
    tb.user_data_len = tb.flags = 0;

    /* fill body length in header */
    bodylength = TAC_AUTHEN_CONT_FIXED_FIELDS_SIZE+0+pass_len;

    th->datalength = htonl(bodylength);

    /* we can now write the header */
    w = write(fd, th, TAC_PLUS_HDR_SIZE);
    if (w < 0 || w < TAC_PLUS_HDR_SIZE) {
        TACSYSLOG((LOG_ERR, "%s: short write on header, wrote %d of %d: %m",\
            __FUNCTION__, w, TAC_PLUS_HDR_SIZE))
        free(pkt);
        free(th);
        return LIBTAC_STATUS_WRITE_ERR;
    }

    /* build the packet */
    pkt = (u_char *) xcalloc(1, bodylength);

    bcopy(&tb, pkt+pkt_len, TAC_AUTHEN_CONT_FIXED_FIELDS_SIZE); /* packet body beginning */
    pkt_len += TAC_AUTHEN_CONT_FIXED_FIELDS_SIZE;
    bcopy(pass, pkt+pkt_len, pass_len);  /* password */
    pkt_len += pass_len;

    /* pkt_len == bodylength ? */
    if (pkt_len != bodylength) {
        TACSYSLOG((LOG_ERR,\
            "%s: bodylength %d != pkt_len %d",\
            __FUNCTION__, bodylength, pkt_len))
        free(pkt);
        free(th);
        return LIBTAC_STATUS_ASSEMBLY_ERR;
    } 
    
    /* encrypt the body */
    _tac_crypt(pkt, th, bodylength);

    w = write(fd, pkt, pkt_len);
    if (w < 0 || w < pkt_len) {
        TACSYSLOG((LOG_ERR,\
            "%s: short write on body, wrote %d of %d: %m",\
            __FUNCTION__, w, pkt_len))
        ret=LIBTAC_STATUS_WRITE_ERR;
    }

    /* Packet Debug (In 'debug tacacs packet' format */
    if (ctrl & PAM_TAC_PACKET_DEBUG) {
		TACDEBUG((LOG_DEBUG, "T+: Version %u (0x%02X), type %u, seq %u, encryption %u",
			th->version, th->version, th->type, th->seq_no, th->encryption))
		TACDEBUG((LOG_DEBUG, "T+: session_id %u (0x%08X), dlen %u (0x%02X)",
			th->session_id, th->session_id, th->datalength, th->datalength))
		TACDEBUG((LOG_DEBUG, "T+: type:AUTHEN/CONT msg_len:%u, data_len:%u flags:%02X",
			ntohs(tb.user_msg_len), tb.user_data_len,tb.flags))
		/*TACDEBUG((LOG_DEBUG, "T+: User msg:  %s", pass)) hide user password (!)*/
		TACDEBUG((LOG_DEBUG, "T+: User msg:  <hidden>"))
		TACDEBUG((LOG_DEBUG, "T+: User data: "))
		TACDEBUG((LOG_DEBUG, "T+: End Packet"))
    }

    free(pkt);
    free(th);

    if (ctrl & PAM_TAC_DEBUG)
    	TACDEBUG((LOG_DEBUG, "%s: exit status=%d", __FUNCTION__, ret))

    return ret;
} /* tac_cont_send */
