/*
 * Copyright (c) 2020 Siddharth Chandrasekaran <siddharth@embedjournal.com>
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <logging/log.h>
LOG_MODULE_DECLARE(osdp, CONFIG_OSDP_LOG_LEVEL);

#include <stdlib.h>
#include <string.h>

#include "osdp_common.h"

#define TAG "PD: "

enum osdp_phy_state_e {
	PD_PHY_STATE_IDLE,
	PD_PHY_STATE_SEND_REPLY,
	PD_PHY_STATE_ERR,
};

void pd_enqueue_command(struct osdp_pd *p, struct osdp_cmd *cmd)
{
	struct osdp_cmd_queue *q = &p->queue;

	cmd->__next = NULL;
	if (q->front == NULL) {
		q->front = q->back = cmd;
	} else {
		assert(q->back);
		q->back->__next = cmd;
		q->back = cmd;
	}
}

/**
 * Returns:
 *  0: success
 *  2: retry current command
 */
int pd_decode_command(struct osdp_pd *p, struct osdp_cmd *reply,
		      uint8_t *buf, int len)
{
	int i, ret = -1, pos = 0;
	struct osdp_cmd *cmd;

	reply->id = 0;
	p->cmd_id = buf[pos++];
	len--;

	switch (p->cmd_id) {
	case CMD_POLL:
		reply->id = REPLY_ACK;
		ret = 0;
		break;
	case CMD_LSTAT:
		reply->id = REPLY_LSTATR;
		ret = 0;
		break;
	case CMD_ISTAT:
		reply->id = REPLY_ISTATR;
		ret = 0;
		break;
	case CMD_OSTAT:
		reply->id = REPLY_OSTATR;
		ret = 0;
		break;
	case CMD_RSTAT:
		reply->id = REPLY_RSTATR;
		ret = 0;
		break;
	case CMD_ID:
		pos++;		// Skip reply type info.
		reply->id = REPLY_PDID;
		ret = 0;
		break;
	case CMD_CAP:
		pos++;		// Skip reply type info.
		reply->id = REPLY_PDCAP;
		ret = 0;
		break;
	case CMD_OUT:
		if (len != 4)
			break;
		cmd = osdp_cmd_alloc();
		if (cmd == NULL) {
			LOG_ERR(TAG "cmd alloc error");
			break;
		}
		cmd->id = OSDP_CMD_OUTPUT;
		cmd->output.output_no    = buf[pos++];
		cmd->output.control_code = buf[pos++];
		cmd->output.tmr_count    = buf[pos++];
		cmd->output.tmr_count   |= buf[pos++] << 8;
		pd_enqueue_command(p, cmd);
		reply->id = REPLY_OSTATR;
		ret = 0;
		break;
	case CMD_LED:
		if (len != 14)
			break;
		cmd = osdp_cmd_alloc();
		if (cmd == NULL) {
			LOG_ERR(TAG "cmd alloc error");
			break;
		}
		cmd->id = OSDP_CMD_LED;
		cmd->led.reader = buf[pos++];
		cmd->led.led_number = buf[pos++];

		cmd->led.temporary.control_code = buf[pos++];
		cmd->led.temporary.on_count     = buf[pos++];
		cmd->led.temporary.off_count    = buf[pos++];
		cmd->led.temporary.on_color     = buf[pos++];
		cmd->led.temporary.off_color    = buf[pos++];
		cmd->led.temporary.timer        = buf[pos++];
		cmd->led.temporary.timer       |= buf[pos++] << 8;

		cmd->led.permanent.control_code = buf[pos++];
		cmd->led.permanent.on_count     = buf[pos++];
		cmd->led.permanent.off_count    = buf[pos++];
		cmd->led.permanent.on_color     = buf[pos++];
		cmd->led.permanent.off_color    = buf[pos++];
		pd_enqueue_command(p, cmd);
		reply->id = REPLY_ACK;
		ret = 0;
		break;
	case CMD_BUZ:
		if (len != 5)
			break;
		cmd = osdp_cmd_alloc();
		if (cmd == NULL) {
			LOG_ERR(TAG "cmd alloc error");
			break;
		}
		cmd->id = OSDP_CMD_BUZZER;
		cmd->buzzer.reader    = buf[pos++];
		cmd->buzzer.tone_code = buf[pos++];
		cmd->buzzer.on_count  = buf[pos++];
		cmd->buzzer.off_count = buf[pos++];
		cmd->buzzer.rep_count = buf[pos++];
		pd_enqueue_command(p, cmd);
		reply->id = REPLY_ACK;
		ret = 0;
		break;
	case CMD_TEXT:
		if (len < 7)
			break;
		cmd = osdp_cmd_alloc();
		if (cmd == NULL) {
			LOG_ERR(TAG "cmd alloc error");
			break;
		}
		cmd->id = OSDP_CMD_TEXT;
		cmd->text.reader     = buf[pos++];
		cmd->text.cmd        = buf[pos++];
		cmd->text.temp_time  = buf[pos++];
		cmd->text.offset_row = buf[pos++];
		cmd->text.offset_col = buf[pos++];
		cmd->text.length     = buf[pos++];
		if (cmd->text.length > 32)
			break;
		for (i = 0; i < cmd->text.length; i++)
			cmd->text.data[i] = buf[pos++];
		pd_enqueue_command(p, cmd);
		reply->id = REPLY_ACK;
		ret = 0;
		break;
	case CMD_COMSET:
		if (len != 5)
			break;
		cmd = osdp_cmd_alloc();
		if (cmd == NULL) {
			LOG_ERR(TAG "cmd alloc error");
			break;
		}
		cmd->id = OSDP_CMD_COMSET;
		cmd->comset.addr  = buf[pos++];
		cmd->comset.baud  = buf[pos++];
		cmd->comset.baud |= buf[pos++] << 8;
		cmd->comset.baud |= buf[pos++] << 16;
		cmd->comset.baud |= buf[pos++] << 24;
		pd_enqueue_command(p, cmd);
		reply->id = REPLY_COM;
		ret = 0;
		break;
	case CMD_KEYSET:
		if (len != 18)
			break;
		/**
		 * For CMD_KEYSET to be accepted, PD must be
		 * ONLINE and SC_ACTIVE.
		 */
		if (isset_flag(p, PD_FLAG_SC_ACTIVE) == 0) {
			reply->id = REPLY_NAK;
			reply->cmd_bytes[0] = OSDP_PD_NAK_SC_COND;
			LOG_ERR(TAG "Keyset with SC inactive");
			break;
		}
		/* only key_type == 1 (SCBK) and key_len == 16 is supported */
		if (buf[pos] != 1 || buf[pos + 1] != 16) {
			LOG_ERR(TAG "Keyset invalid len/type: %d/%d",
			      buf[pos], buf[pos + 1]);
			break;
		}
		cmd = osdp_cmd_alloc();
		if (cmd == NULL) {
			LOG_ERR(TAG "cmd alloc error");
			break;
		}
		cmd->id = OSDP_CMD_KEYSET;
		cmd->keyset.key_type = buf[pos++];
		cmd->keyset.len = buf[pos++];
		memcpy(cmd->keyset.data, buf + pos, 16);
		memcpy(p->sc.scbk, buf + pos, 16);
		pd_enqueue_command(p, cmd);
		clear_flag(p, PD_FLAG_SC_USE_SCBKD);
		clear_flag(p, PD_FLAG_INSTALL_MODE);
		reply->id = REPLY_ACK;
		ret = 0;
		break;
	case CMD_CHLNG:
		if (p->cap[CAP_COMMUNICATION_SECURITY].compliance_level == 0) {
			reply->id = REPLY_NAK;
			reply->cmd_bytes[0] = OSDP_PD_NAK_SC_UNSUP;
			break;
		}
		if (len != 8)
			break;
		osdp_sc_init(p);
		clear_flag(p, PD_FLAG_SC_ACTIVE);
		for (i = 0; i < 8; i++)
			p->sc.cp_random[i] = buf[pos++];
		reply->id = REPLY_CCRYPT;
		ret = 0;
		break;
	case CMD_SCRYPT:
		if (len != 16)
			break;
		for (i = 0; i < 16; i++)
			p->sc.cp_cryptogram[i] = buf[pos++];
		reply->id = REPLY_RMAC_I;
		ret = 0;
		break;
	default:
		break;
	}

	if (ret != 0 && reply->id == 0) {
		reply->id = REPLY_NAK;
		reply->cmd_bytes[0] = OSDP_PD_NAK_RECORD;
	}

	p->reply_id = reply->id;
	if (p->cmd_id != CMD_POLL) {
		LOG_DBG(TAG "IN(CMD): 0x%02x[%d] -- OUT(REPLY): 0x%02x",
		      p->cmd_id, len, p->reply_id);
	}

	return 0;
}

/**
 * Returns:
 * +ve: length of command
 * -ve: error
 */
int pd_build_reply(struct osdp_pd *p, struct osdp_cmd *reply, uint8_t *pkt)
{
	int i, len = 0;

	uint8_t *buf = phy_packet_get_data(p, pkt);
	uint8_t *smb = phy_packet_get_smb(p, pkt);

	// LOG_DBG(TAG "build reply: 0x%02x", reply->id);

	switch (reply->id) {
	case REPLY_ACK:
		buf[len++] = reply->id;
		break;
	case REPLY_PDID:
		buf[len++] = reply->id;
		buf[len++] = byte_0(p->id.vendor_code);
		buf[len++] = byte_1(p->id.vendor_code);
		buf[len++] = byte_2(p->id.vendor_code);

		buf[len++] = p->id.model;
		buf[len++] = p->id.version;

		buf[len++] = byte_0(p->id.serial_number);
		buf[len++] = byte_1(p->id.serial_number);
		buf[len++] = byte_2(p->id.serial_number);
		buf[len++] = byte_3(p->id.serial_number);

		buf[len++] = byte_3(p->id.firmware_version);
		buf[len++] = byte_2(p->id.firmware_version);
		buf[len++] = byte_1(p->id.firmware_version);
		break;
	case REPLY_PDCAP:
		buf[len++] = reply->id;
		for (i = 0; i < CAP_SENTINEL; i++) {
			if (p->cap[i].function_code != i)
				continue;
			buf[len++] = i;
			buf[len++] = p->cap[i].compliance_level;
			buf[len++] = p->cap[i].num_items;
		}
		break;
	case REPLY_LSTATR:
		buf[len++] = reply->id;
		buf[len++] = isset_flag(p, PD_FLAG_TAMPER);
		buf[len++] = isset_flag(p, PD_FLAG_POWER);
		break;
	case REPLY_RSTATR:
		buf[len++] = reply->id;
		buf[len++] = isset_flag(p, PD_FLAG_R_TAMPER);
		break;
	case REPLY_COM:
		buf[len++] = reply->id;
		buf[len++] = p->address;
		buf[len++] = byte_0(p->baud_rate);
		buf[len++] = byte_1(p->baud_rate);
		buf[len++] = byte_2(p->baud_rate);
		buf[len++] = byte_3(p->baud_rate);
		break;
	case REPLY_NAK:
		buf[len++] = reply->id;
		buf[len++] = reply->cmd_bytes[0];
		break;
	case REPLY_CCRYPT:
		if (smb == NULL)
			break;
		osdp_fill_random(p->sc.pd_random, 8);
		osdp_compute_session_keys(to_ctx(p));
		osdp_compute_pd_cryptogram(p);
		buf[len++] = REPLY_CCRYPT;
		for (i = 0; i < 8; i++)
			buf[len++] = p->sc.pd_client_uid[i];
		for (i = 0; i < 8; i++)
			buf[len++] = p->sc.pd_random[i];
		for (i = 0; i < 16; i++)
			buf[len++] = p->sc.pd_cryptogram[i];
		smb[0] = 3;
		smb[1] = SCS_12;
		smb[2] = isset_flag(p, PD_FLAG_SC_USE_SCBKD) ? 0 : 1;
		break;
	case REPLY_RMAC_I:
		if (smb == NULL)
			break;
		osdp_compute_rmac_i(p);
		buf[len++] = REPLY_RMAC_I;
		for (i = 0; i < 16; i++)
			buf[len++] = p->sc.r_mac[i];
		smb[0] = 3;
		smb[1] = SCS_14;
		if (osdp_verify_cp_cryptogram(p) == 0)
			smb[2] = 0x01;
		else
			smb[2] = 0x00;
		set_flag(p, PD_FLAG_SC_ACTIVE);
		if (isset_flag(p, PD_FLAG_SC_USE_SCBKD))
			LOG_WRN(TAG "SC Active with SCBK-D");
		else
			LOG_INF(TAG "SC Active");
		break;
	}

	if (smb && (smb[1] > SCS_14) && isset_flag(p, PD_FLAG_SC_ACTIVE)) {
		smb[0] = 2;
		smb[1] = (len > 1) ? SCS_18 : SCS_16;
	}

	if (len == 0) {
		buf[len++] = REPLY_NAK;
		buf[len++] = OSDP_PD_NAK_SC_UNSUP;
	}

	return len;
}

/**
 * pd_send_reply - blocking send; doesn't handle partials
 * Returns:
 *   0 - success
 *  -1 - failure
 */
int pd_send_reply(struct osdp_pd *p, struct osdp_cmd *reply)
{
	int ret, len;
	uint8_t buf[OSDP_PACKET_BUF_SIZE];

	/* init packet buf with header */
	len = phy_build_packet_head(p, reply->id, buf, OSDP_PACKET_BUF_SIZE);
	if (len < 0) {
		LOG_ERR(TAG "failed at phy_build_packet_head");
		return -1;
	}

	/* fill reply data */
	ret = pd_build_reply(p, reply, buf);
	if (ret <= 0) {
		LOG_ERR(TAG "failed at pd_build_reply %d", reply->id);
		return -1;
	}
	len += ret;

	/* finalize packet */
	len = phy_build_packet_tail(p, buf, len, OSDP_PACKET_BUF_SIZE);
	if (len < 0) {
		LOG_ERR(TAG "failed to build reply %d", reply->id);
		return -1;
	}

#ifdef OSDP_PACKET_TRACE
	if (p->cmd_id != CMD_POLL) {
		LOG_EM(TAG "bytes sent");
		osdp_dump(NULL, buf, len);
	}
#endif

	ret = p->channel.send(p->channel.data, buf, len);

	return (ret == len) ? 0 : -1;
}

/**
 * pd_process_command - received buffer from serial stream handling partials
 * Returns:
 *  0: success
 * -1: error
 *  1: no data yet
 *  2: re-issue command
 */
int pd_process_command(struct osdp_pd *p, struct osdp_cmd *reply)
{
	int ret;

	ret = p->channel.recv(p->channel.data, p->phy_rx_buf + p->phy_rx_buf_len,
			      OSDP_PACKET_BUF_SIZE - p->phy_rx_buf_len);

	if (ret <= 0)	/* No data received */
		return 1;
	p->phy_rx_buf_len += ret;

	ret = phy_decode_packet(p, p->phy_rx_buf, p->phy_rx_buf_len);
	switch(ret) {
	case -1: /* fatal errors */
		LOG_ERR(TAG "failed to decode packet");
		return -1;
	case -2: /* rx_buf_len != pkt->len; wait for more data */
		return 1;
	case -3: /* soft fail */
	case -4: /* rx_buf had invalid MARK or SOM */
		/* Reset rx_buf_len so next call can start afresh */
		p->phy_rx_buf_len = 0;
		return 1;
	}

	ret = pd_decode_command(p, reply, p->phy_rx_buf, ret);

#ifdef OSDP_PACKET_TRACE
	if (p->cmd_id != CMD_POLL) {
		LOG_EM(TAG "bytes received");
		osdp_dump(NULL, p->phy_rx_buf, p->phy_rx_buf_len);
	}
#endif

	p->phy_rx_buf_len = 0;
	return ret;
}

void pd_phy_state_update(struct osdp_pd *pd)
{
	int ret;
	struct osdp_cmd reply;

	switch (pd->phy_state) {
	case PD_PHY_STATE_IDLE:
		ret = pd_process_command(pd, &reply);
		if (ret == 1)	/* no data; wait */
			break;
		if (ret < 0) {	/* error */
			pd->phy_state = PD_PHY_STATE_ERR;
			break;
		}
		pd->phy_state = PD_PHY_STATE_SEND_REPLY;
		/* FALLTHRU */
	case PD_PHY_STATE_SEND_REPLY:
		if ((ret = pd_send_reply(pd, &reply)) == 0) {
			pd->phy_state = PD_PHY_STATE_IDLE;
			break;
		}
		if (ret == -1) {	/* send failed! */
			pd->phy_state = PD_PHY_STATE_ERR;
			break;
		}
		pd->phy_state = PD_PHY_STATE_IDLE;
		break;
	case PD_PHY_STATE_ERR:
		osdp_sc_init(pd);
		clear_flag(pd, PD_FLAG_SC_ACTIVE);
		pd->phy_state = PD_PHY_STATE_IDLE;
		pd->phy_rx_buf_len = 0;
		break;
	}
}

void osdp_pd_refresh()
{
	struct osdp *ctx = &g_osdp_ctx;
	struct osdp_pd *pd = to_pd(ctx, 0);

	pd_phy_state_update(pd);
}

int osdp_pd_get_cmd(struct osdp_cmd *cmd)
{
	struct osdp *ctx = &g_osdp_ctx;
	struct osdp_pd *pd = to_pd(ctx, 0);
	struct osdp_cmd *f;

	f = pd->queue.front;
	if (f == NULL)
		return -1;

	memcpy(cmd, f, sizeof(struct osdp_cmd));
	pd->queue.front = pd->queue.front->__next;
	osdp_cmd_free(f);
	return 0;
}
