/*
 * Copyright (c) 2019 Vestas Wind Systems A/S
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr.h>
#include <drivers/gpio.h>
#include <power/reboot.h>
#include <settings/settings.h>
#include <canbus/canopen.h>

#define LOG_LEVEL CONFIG_CANOPEN_LOG_LEVEL
#include <logging/log.h>
LOG_MODULE_REGISTER(app);

#if defined(CONFIG_CANOPEN_INTERFACE_CAN_0)
#define CAN_INTERFACE DT_ALIAS_CAN_0_LABEL
#define CAN_BITRATE (DT_ALIAS_CAN_0_BUS_SPEED / 1000)
#elif defined(CONFIG_CANOPEN_INTERFACE_CAN_1)
#define CAN_INTERFACE DT_ALIAS_CAN_1_LABEL
#define CAN_BITRATE (DT_ALIAS_CAN_1_BUS_SPEED / 1000)
#else
#error CANopen CAN interface not set
#endif

#ifdef DT_ALIAS_GREEN_LED_GPIOS_CONTROLLER
#define LED_GREEN_PORT  DT_ALIAS_GREEN_LED_GPIOS_CONTROLLER
#define LED_GREEN_PIN   DT_ALIAS_GREEN_LED_GPIOS_PIN
#define LED_GREEN_FLAGS DT_ALIAS_GREEN_LED_GPIOS_FLAGS
#endif

#ifdef DT_ALIAS_RED_LED_GPIOS_CONTROLLER
#define LED_RED_PORT  DT_ALIAS_RED_LED_GPIOS_CONTROLLER
#define LED_RED_PIN   DT_ALIAS_RED_LED_GPIOS_PIN
#define LED_RED_FLAGS DT_ALIAS_RED_LED_GPIOS_FLAGS
#endif

#ifdef DT_ALIAS_SW0_GPIOS_CONTROLLER
#define BUTTON_PORT  DT_ALIAS_SW0_GPIOS_CONTROLLER
#define BUTTON_PIN   DT_ALIAS_SW0_GPIOS_PIN
#define BUTTON_FLAGS DT_ALIAS_SW0_GPIOS_FLAGS
static struct gpio_callback button_callback;
#endif

struct led_indicator {
	struct device *dev;
	u32_t pin;
	u32_t flags;
};

static struct led_indicator led_green;
static struct led_indicator led_red;
static u32_t counter;

/**
 * @brief Callback for setting LED indicator state.
 *
 * @param value true if the LED indicator shall be turned on, false otherwise.
 * @param arg argument that was passed when LEDs were initialized.
 */
static void led_callback(bool value, void *arg)
{
	struct led_indicator *led = arg;
	bool drive = value;

	if (!led || !led->dev) {
		return;
	}

	if ((led->flags & GPIO_INT_ACTIVE_HIGH) == GPIO_INT_ACTIVE_LOW) {
		drive = !drive;
	}

	gpio_pin_write(led->dev, led->pin, drive);
}

/**
 * @brief Configure LED indicators pins and callbacks.
 *
 * This routine configures the GPIOs for the red and green LEDs (if
 * available).
 *
 * @param nmt CANopenNode NMT object.
 */
static void config_leds(CO_NMT_t *nmt)
{
#ifdef LED_GREEN_PORT
	led_green.dev = device_get_binding(LED_GREEN_PORT);
	led_green.pin = LED_GREEN_PIN;
	led_green.flags = LED_GREEN_FLAGS;
	if (led_green.dev) {
		gpio_pin_configure(led_green.dev, LED_GREEN_PIN, GPIO_DIR_OUT);
	}
#endif /* LED_GREEN_PORT */
#ifdef LED_RED_PORT
	led_red.dev = device_get_binding(LED_RED_PORT);
	led_red.pin = LED_RED_PIN;
	led_red.flags = LED_RED_FLAGS;
	if (led_red.dev) {
		gpio_pin_configure(led_red.dev, LED_RED_PIN, GPIO_DIR_OUT);
	}
#endif /* LED_RED_PORT */

	canopen_leds_init(nmt,
			  led_green.dev ? led_callback : NULL, &led_green,
			  led_red.dev ? led_callback : NULL, &led_red);
}

/**
 * @brief Button press counter object dictionary handler function.
 *
 * This function is called upon SDO access to the button press counter
 * object (index 0x2102) in the object dictionary.
 *
 * @param odf_arg object dictionary function argument.
 *
 * @return SDO abort code.
 */
static CO_SDO_abortCode_t odf_2102(CO_ODF_arg_t *odf_arg)
{
	u32_t value;

	value = CO_getUint32(odf_arg->data);

	if (odf_arg->reading) {
		return CO_SDO_AB_NONE;
	}

	if (odf_arg->subIndex != 0U) {
		return CO_SDO_AB_NONE;
	}

	if (value != 0) {
		/* Preserve old value */
		memcpy(odf_arg->data, odf_arg->ODdataStorage, sizeof(u32_t));
		return CO_SDO_AB_DATA_TRANSF;
	}

	LOG_INF("Resetting button press counter");
	counter = 0;

	return CO_SDO_AB_NONE;
}

/**
 * @brief Button press interrupt callback.
 *
 * @param port GPIO device struct.
 * @param cb GPIO callback struct.
 * @param pins GPIO pin mask that triggered the interrupt.
 */
#ifdef BUTTON_PORT
static void button_isr_callback(struct device *port, struct gpio_callback *cb,
				u32_t pins)
{
	counter++;
}
#endif

/**
 * @brief Configure button GPIO pin and callback.
 *
 * This routine configures the GPIO for the button (if available).
 */
static void config_button(void)
{
#ifdef BUTTON_PORT
	struct device *dev;
	int err;

	dev = device_get_binding(BUTTON_PORT);
	if (!dev) {
		LOG_ERR("failed to get button device");
		return;
	}

	err = gpio_pin_configure(dev, BUTTON_PIN, GPIO_DIR_IN |
				 GPIO_INT_DEBOUNCE | GPIO_INT |
				 GPIO_INT_EDGE | BUTTON_FLAGS);

	gpio_init_callback(&button_callback, button_isr_callback,
			   BIT(BUTTON_PIN));

	err = gpio_add_callback(dev, &button_callback);
	if (err) {
		LOG_ERR("failed to add button callback");
		return;
	}

	err = gpio_pin_enable_callback(dev, BUTTON_PIN);
	if (err) {
		LOG_ERR("failed to enable button callback");
		return;
	}

#endif
}

/**
 * @brief Main application entry point.
 *
 * The main application thread is responsible for initializing the
 * CANopen stack and doing the non real-time processing.
 */
void main(void)
{
	CO_NMT_reset_cmd_t reset = CO_RESET_NOT;
	CO_ReturnError_t err;
	struct device *can;
	u16_t timeout;
	u32_t elapsed;
	s64_t timestamp;
	int ret;

	can = device_get_binding(CAN_INTERFACE);
	if (!can) {
		LOG_ERR("CAN interface not found");
		return;
	}

	ret = settings_subsys_init();
	if (ret) {
		LOG_ERR("failed to initialize settings subsystem (err = %d)",
			ret);
		return;
	}

	ret = settings_load();
	if (ret) {
		LOG_ERR("failed to load settings (err = %d)", ret);
		return;
	}

	OD_powerOnCounter++;

	config_button();

	while (reset != CO_RESET_APP) {
		elapsed =  0U; /* milliseconds */

		err = CO_init(can, CONFIG_CANOPEN_NODE_ID, CAN_BITRATE);
		if (err != CO_ERROR_NO) {
			LOG_ERR("CO_init failed (err = %d)", err);
			return;
		}

		LOG_INF("CANopen stack initialized");

		canopen_storage_attach(CO->SDO[0], CO->em);
		config_leds(CO->NMT);
		CO_OD_configure(CO->SDO[0], OD_2102_buttonPressCounter,
				odf_2102, NULL, 0U, 0U);

		CO_CANsetNormalMode(CO->CANmodule[0]);

		while (true) {
			timeout = 50U; /* default timeout in milliseconds */
			timestamp = k_uptime_get();
			reset = CO_process(CO, (uint16_t)elapsed, &timeout);

			if (reset != CO_RESET_NOT) {
				break;
			}

			if (timeout > 0) {
				CO_LOCK_OD();
				OD_buttonPressCounter = counter;
				CO_UNLOCK_OD();

				ret = canopen_storage_save(
					CANOPEN_STORAGE_EEPROM);
				if (ret) {
					LOG_ERR("failed to save EEPROM");
				}
				/*
				 * Try to sleep for as long as the
				 * stack requested and calculate the
				 * exact time elapsed.
				 */
				k_sleep(K_MSEC(timeout));
				elapsed = k_uptime_delta_32(&timestamp);
			} else {
				/*
				 * Do not sleep, more processing to be
				 * done by the stack.
				 */
				elapsed = 0U;
			}
		}

		if (reset == CO_RESET_COMM) {
			LOG_INF("Resetting communication");
		}
	}

	LOG_INF("Resetting device");

	CO_delete(CAN_INTERFACE);
	sys_reboot(SYS_REBOOT_COLD);
}
