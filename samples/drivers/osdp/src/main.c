/*
 * Copyright (c) 2020 Siddharth Chandrasekaran <siddharth@embedjournal.com>
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr.h>
#include <device.h>
#include <drivers/gpio.h>
#include <drivers/osdp.h>

/* The devicetree node identifier for the "led0" alias. */
#define LED0_NODE DT_ALIAS(led0)

#if DT_NODE_HAS_STATUS(LED0_NODE, okay)
#define LED0    DT_GPIO_LABEL(LED0_NODE, gpios)
#define PIN     DT_GPIO_PIN(LED0_NODE, gpios)
#if DT_PHA_HAS_CELL(LED0_NODE, gpios, flags)
#define FLAGS   DT_GPIO_FLAGS(LED0_NODE, gpios)
#endif
#else
#error "BOARD does not define a debug LED"
#define LED0    ""
#define PIN     0
#endif

#ifndef FLAGS
#define FLAGS   0
#endif

/* 1000 msec = 1 sec */
#define SLEEP_TIME	10

int cmd_handler(struct osdp_cmd *p)
{
	return 0;
}

void main(void)
{
	int ret;
	uint32_t cnt = 0;
	struct device *dev;
	struct osdp_cmd cmd;

	dev = device_get_binding(LED0);
	if (dev == NULL)
		return;
	ret = gpio_pin_configure(dev, PIN, GPIO_OUTPUT_ACTIVE | FLAGS);
	if (ret < 0)
		return;

	int led_state = 0;
	while (1) {
		if (osdp_pd_get_cmd(&cmd) == 0) {
			cmd_handler(&cmd);
		}

		if ((cnt & 0x7f) == 0x7f)
			led_state = !led_state;
		gpio_pin_set(dev, PIN, led_state);
		cnt++;

		k_msleep(SLEEP_TIME);
	}
}
