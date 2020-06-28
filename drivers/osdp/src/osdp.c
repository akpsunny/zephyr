/*
 * Copyright (c) 2020 Siddharth Chandrasekaran <siddharth@embedjournal.com>
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr.h>
#include <init.h>
#include <device.h>
#include <drivers/uart.h>
#include <sys/ring_buffer.h>
#include <logging/log.h>

#include "osdp_common.h"

#define OSDP_UART_RX_BUFFER_LENGTH 512

struct device *g_osdp_uart_dev;
struct osdp g_osdp_ctx;
struct osdp_cp g_osdp_cp_ctx;
struct osdp_pd g_osdp_pd_ctx[CONFIG_OSDP_NUM_CONNECTED_PD];
static struct k_thread osdp_refresh_thread;
static K_THREAD_STACK_DEFINE(osdp_thread_stack, 512);
RING_BUF_DECLARE(uart_rx_buf, OSDP_UART_RX_BUFFER_LENGTH);
LOG_MODULE_REGISTER(osdp, CONFIG_OSDP_LOG_LEVEL);

static void osdp_uart_isr(struct device *dev)
{
	int rx;
	uint8_t tmp[64];
	uint32_t ret;

	while (uart_irq_update(dev) && uart_irq_is_pending(dev)) {

		if (!uart_irq_rx_ready(dev))
			continue;

		/* Character(s) have been received */

		rx = uart_fifo_read(dev, tmp, sizeof(tmp));
		if (rx < 0)
			continue;

		ret = ring_buf_put(&uart_rx_buf, tmp, sizeof(tmp));
		if (ret != sizeof(tmp)) {
			printk("RX overflow\n");
			break;
		}
	}
}

static void osdp_uart_init()
{
	uint8_t c;
	g_osdp_uart_dev =  device_get_binding(CONFIG_OSDP_UART_DEV_NAME);
	uart_irq_rx_disable(g_osdp_uart_dev);
	uart_irq_tx_disable(g_osdp_uart_dev);
	uart_irq_callback_set(g_osdp_uart_dev, osdp_uart_isr);
	/* Drain the fifo */
	while (uart_irq_rx_ready(g_osdp_uart_dev)) {
		uart_fifo_read(g_osdp_uart_dev, &c, 1);
	}
	uart_irq_rx_enable(g_osdp_uart_dev);
}

static int osdp_uart_receive(void *data, uint8_t *buf, int len)
{
	ARG_UNUSED(data);

	return (int)ring_buf_get(&uart_rx_buf, buf, len);
}

static int osdp_uart_send(void *data, uint8_t *buf, int len)
{
	ARG_UNUSED(data);
	int sent = 0;

	while (sent < len) {
		uart_poll_out(g_osdp_uart_dev, buf[sent]);
		sent++;
	}
	return sent;
}

static void osdp_event_loop(void *arg1, void *arg2, void *arg3)
{
	while (1) {
		osdp_pd_refresh();
		k_sleep(K_MSEC(50));
	}
}

static int osdp_init(struct device *arg)
{
	ARG_UNUSED(arg);
	int i;
	struct osdp *ctx;
	struct osdp_cp *cp;
	struct osdp_pd *pd;

	osdp_uart_init();

	ctx = &g_osdp_ctx;
	ctx->cp = &g_osdp_cp_ctx;
	cp = ctx->cp;
	node_set_parent(cp, ctx);

	cp->num_pd = CONFIG_OSDP_NUM_CONNECTED_PD;
	ctx->pd = &g_osdp_pd_ctx[0];
	set_current_pd(ctx, 0);
	pd = to_pd(ctx, 0);
	node_set_parent(pd, ctx);

	for (i = 0; i < CONFIG_OSDP_NUM_CONNECTED_PD; i++) {
		pd = to_pd(ctx, i);
		node_set_parent(pd, ctx);
		pd->seq_number = -1;
		pd->channel.send = osdp_uart_send;
		pd->channel.recv = osdp_uart_receive;
		pd->baud_rate = CONFIG_OSDP_UART_BAUD_RATE;
#if CONFIG_OSDP_MODE_PD
		pd->id.version = CONFIG_OSDP_PD_ID_VERSION;
		pd->id.model = CONFIG_OSDP_PD_ID_MODEL;
		pd->id.vendor_code = CONFIG_OSDP_PD_ID_VENDOR_CODE;
		pd->id.serial_number = CONFIG_OSDP_PD_ID_SERIAL_NUMBER;
		pd->id.firmware_version = CONFIG_OSDP_PD_ID_FIRMWARE_VERSION;
		set_flag(pd, PD_FLAG_PD_MODE);
#endif
	}
	set_current_pd(ctx, 0);

	/* kick off refresh thread */
	k_thread_create(&osdp_refresh_thread, osdp_thread_stack, 500,
			osdp_event_loop, NULL, NULL, NULL, K_PRIO_COOP(2),
			0, K_NO_WAIT);
	return 0;
}

SYS_INIT(osdp_init, POST_KERNEL, 10);
